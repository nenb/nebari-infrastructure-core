# ADR-0022: In-Pod Namespace Sandboxes (`in-pod-namespaces`) for Software Packs

## Status

Proposed (DRAFT, exploratory; expected fifth in order, after gVisor): a feasibility sketch that fits [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md)'s interface; not proposed for acceptance yet. Depends only on ADR-0021, which defines the capability contract and reserves the name `in-pod-namespaces`. This sketch would add entries to ADR-0021's published mapping ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#proposed-additions-more-mapping-entries-sketches)). Revised 2026-10-17: an unfiltered first implementation on AWS, with a NIC-owned seccomp profile as fallback. Revised 2026-10-28 after review: defines the capability, its qualified configurations and its capability test, with **no supported delivery route yet**; the unfiltered AL2023 result is recorded as evidence, not a product setting; bubblewrap inside gVisor is the intended first route; the NIC-owned profile is deferred. Detailed design and evidence are in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md), §20.5 and §20.9–§20.11.

## Date

2026-10-15

## Context

The motivating use case for workload sandboxing is a pack that confines the shell commands an agent runs, for example with [bubblewrap](https://github.com/containers/bubblewrap): each command sees a narrowed filesystem, no network and none of the pod's credentials. ADR-0021 describes `process-self-restriction` (Landlock), which covers filesystem and TCP-port confinement but not a separate filesystem view or a separate network stack. Those need Linux namespaces, which bubblewrap, nsjail, headless Chromium's sandbox and similar tools create inside the pod.

Most packs have another way to get them: run tool calls in a separate, credential-free sandbox pod, which needs no namespaces inside any pod. This capability matters mainly for **packs that cannot split tool execution into a separate pod**, such as an extension running inside a user's notebook server.

The threat model is ADR-0021's: keeping an agent's own commands (prompt injection, compromised dependencies, mistakes) away from what the pod can reach, including the agent's own credentials. It is not about containing a capable adversary determined to escape the host.

### What blocks it today

Four layers can block unprivileged namespace creation in a NIC-deployed pod, and packs can change none of them ([§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic)):

| Layer | What blocks it | Where it stands |
|---|---|---|
| 1. Node kernel | Unprivileged user namespaces disabled, or on Ubuntu 23.10+ restricted by an AppArmor sysctl | Allowed on AWS AL2023 (observed on EKS 1.34); restricted on Hetzner's Ubuntu 24.04 |
| 2. Seccomp | The runtime's default profile allows `unshare`, `clone` with namespace flags, `mount` and `pivot_root` only with `CAP_SYS_ADMIN` | Applies to pods that set `RuntimeDefault`, or to all pods when the kubelet's `seccompDefault` is on. It is off on EKS, hetzner-k3s and AKS as NIC deploys them, so pods that set no profile have **no syscall filter** |
| 3. AppArmor | The default container profile denies `mount` | Blocks on AppArmor nodes (Hetzner, AKS Ubuntu); not present on AWS AL2023 |
| 4. Masked `/proc` | A fresh procfs cannot be mounted inside a container | Not lifted on the host kernel |

So bubblewrap happens to work on AWS in pods that set no seccomp profile, and fails on Hetzner (at AppArmor, observed 2026-10-25) and AKS. No Kubernetes runtime maintains a default profile that allows namespace creation: containerd allows these calls only with `CAP_SYS_ADMIN`, and CRI-O removes them from the Podman profile it builds on. Allowing them on the host kernel under a filter therefore means someone owning a seccomp profile ([§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full)).

Under gVisor none of these layers applies: gVisor implements namespaces in its own kernel, so a non-root process with no capabilities can create them, and mount a fresh `/proc`, with no change to the host.

## Decision Drivers

- **The threat is inside the pod.** The aim is to fence an agent's commands away from the agent's credentials and the rest of the pod, which needs a boundary *inside* the pod, not only around it.
- **No endorsed absence of a filter.** NIC must not make "run with no syscall filter" a supported setting, which would also block hardening.
- **No privileged pack pods.** Packs never need `CAP_SYS_ADMIN`, `Unconfined` profiles or privileged pods.
- **Let someone else own the hard part.** Prefer a runtime whose filter is maintained upstream over a NIC-owned seccomp allowlist.
- **An upgradeable contract.** Packs written against the capability keep working when its delivery route changes.

## Considered Options

1. Do nothing; bubblewrap keeps working where it happens to, unchecked.
2. Allow unprivileged user namespaces on every node and give every pod a permissive profile.
3. Publish "leave `seccompProfile` unset" as a supported setting on AL2023, checked by NIC (the earlier draft of this ADR).
4. A NIC-owned, versioned seccomp profile on dedicated, opt-in node groups configured at boot.
5. Bubblewrap inside a pod under the gVisor implementation of ADR-0021's `mediated-kernel` level.
6. Let packs grant their pods `CAP_SYS_ADMIN`, with or without a pod user namespace (`hostUsers: false`).
7. Run each session's commands in a separate, credential-free sandbox pod instead.
8. Define the capability and its qualification now, with no supported route until Option 5 exists.

## Decision Outcome

Chosen option: "Option 8", with Option 5 as the intended first route. The capability's contract and qualified configurations are worth fixing now, because packs and probes already depend on them. Option 3 would endorse running with no syscall filter; Option 4 means NIC owning a complete seccomp allowlist per architecture indefinitely, plus AppArmor work for Hetzner and AKS, to strengthen the weakest boundary; Option 5 needs no host relaxation and was observed to work on every provider probed.

### The capability

**`in-pod-namespaces`:** a non-root process with no added capabilities, in a container that applies the values of a mapping entry that names this capability, can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed.

The guarantee names the published settings rather than a mechanism, so the delivery route can change without packs changing.

Qualification uses one pinned bubblewrap version in a capability test and two consumer configurations, which must not be confused:

- **The capability test** proves only that the namespaces can be created. It exposes the whole container read-only and is not a sandbox policy.
- **The qualified consumer configurations** are what packs start from and what the acceptance test runs against. They bind only what a command needs (system libraries including `/lib64` on x86, certificates, the work directory), mask the home directory and `/tmp`, bind no secrets, service-account token paths or socket directories, and clear the environment. There are two: **no network**, and **network only through a pack-provided proxy** reached over a Unix socket bound into the sandbox. Both create the network namespace with `unshare` before bubblewrap runs, because bubblewrap's own `--unshare-net` fails under gVisor ([gVisor #13438](https://github.com/google/gvisor/issues/13438)), and add a pid namespace (`--unshare-pid`, keeping the container's `/proc` read-only); the same form worked on runc and under gVisor. Under gVisor packs may mount a fresh `/proc` (`--proc /proc`), which hides other processes' command lines. Packs extend the configurations with specific paths (a virtualenv, `/usr/local`, a toolchain), never with `/` or the home directory.

The exact commands are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#qualified-configurations-and-profile-contents-adr-0022).

### Delivery routes

- **None is supported yet.** A mapping entry that names `in-pod-namespaces` fails to resolve, with "no qualified implementation provides in-pod-namespaces" until an implementation that has the capability as a property is built.
- **Intended first route: bubblewrap inside gVisor.** Once an implementation of `mediated-kernel` with gVisor exists (sketched in [ADR-0023](0023-user-space-kernel-capability.md)), a mapping entry `{level: mediated-kernel, capabilities: [in-pod-namespaces]}` resolves to it, and packs apply its values and the qualified configurations. Probed on a local VM, EKS (AL2023 x86 and arm64) and Hetzner (Ubuntu 24.04): the qualified configurations worked and hid canaries, the agent's socket, the network and the metadata address, and a fresh `/proc` hid other processes.
- **At `shared-kernel`: no route.** The AL2023 result (bubblewrap works when `seccompProfile` is unset and `seccompDefault` is off) is recorded as an observation ([§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-evidence-bubblewrap-on-the-host-kernel-without-a-filter)). NIC does not publish, check or support it; a pack that relies on it does so outside NIC's contract.
- **Deferred: the filtered NIC-owned profile (Option 4).** Kept in §20.9 for reference and reconsidered only if a pack needs the capability where gVisor cannot run.

### What a pack does

It uses a mapping entry naming the capability, with the entry's values copied into its Helm values (by hand until [ADR-0003](0003-software-pack-codegen.md)) and no runtime name hardcoded, starts from a qualified configuration, checks at startup that it can create the namespaces, and refuses to run commands unsandboxed if it cannot.

### Trust model

- **Trusted:** the operator, NIC, the runtime that implements the level, and the pack's launcher process that builds each sandbox.
- **A hostile workload** (a sandboxed command) may run any code as the pod's UID inside its namespaces, read and write whatever the pack bound in, and try any system call the runtime offers.
- **NIC enforces** that the published settings let the namespaces be created on the nodes the set resolves to, and the boundary of the level the set requires. It does not enforce the sandbox's policy.
- **The pack enforces** what is bound, the cleared environment, the network (none, or only its proxy, whose policy is the real boundary for networked commands), inherited descriptors, and refusal to fall back.
- **Outside the guarantee:** escapes from the runtime; other processes' command lines when the container's `/proc` is reused; separation between sessions in one pod (every session maps to the pod's own UID); storage endpoints reachable from the agent's own pod (below).

### Verification

Before a route is offered on a provider, architecture and OS family, a maintainer runs the probe there: the capability test and both consumer configurations succeed with the published settings, and Unix sockets on the container's filesystem are not reachable from the qualified configurations. Before the first release, a consumer passes an acceptance test with credential canaries, denied or proxied networking, an unreachable instance metadata service from inside the sandbox, and refusal of unsandboxed fallback, using a small reference consumer in NIC's user-journey tests until an upstream pack adopts the capability.

### Security

- **Declared seccomp is not enforced under gVisor:** gVisor ignores the pod's `seccompProfile` without `--oci-seccomp` (which would block bubblewrap); its own filter applies instead.
- **Storage endpoints are another path to other users' data.** Network filesystems that trust the user ID a client claims (NFS with default authentication, as used by FSx for OpenZFS in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705) with `no_root_squash`) can be spoken to directly by a user-space NFS client. In probe clusters (2026-10-25) an unprivileged pod, under runc or gVisor, read and wrote another user's volume as root. The no-network configuration blocks this for sandboxed commands; for the agent's own pod, an enforced default-deny egress policy or restricting the endpoint to node addresses is needed (#691, #675).
- Code an agent executes should be treated as attacker-influenced. See [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

### Consequences

**Good:**
- Packs get a fixed contract and qualified configurations to build against, without NIC endorsing pods with no syscall filter.
- No NIC-owned seccomp profile, AppArmor policy or node changes for this capability.
- The intended route reaches Hetzner as well as AWS and closes the signalling and command-line gaps of the host-kernel route.

**Bad:**
- No supported route until a gVisor implementation exists; packs that need the capability before then have none from NIC.
- The route depends on a runtime with I/O overhead and compatibility gaps, and on the network-namespace workaround until gVisor #13438 is fixed.
- Packs that already rely on the AL2023 behaviour get no check or warning from NIC.
- A reference consumer, maintained with NIC's user-journey tests until an upstream pack adopts the capability, is one more thing NIC's maintainers own.

## Options Detail

- **Option 1 (do nothing):** no cost, but packs cannot tell whether a cluster supports them, and there is no route to a filtered or stronger setting.
- **Option 2 (cluster-wide):** simplest for packs, but exposes the extra kernel surface on nodes running Keycloak, ArgoCD and other foundational services.
- **Option 3 (unfiltered on AL2023):** almost free, but makes running with no syscall filter (netfilter, `io_uring`, `keyctl` and more reachable from a user namespace; CVE-2024-1086 was reachable this way) an endorsed setting, works only on AWS, and turns any future `seccompDefault` hardening into a breaking change.
- **Option 4 (NIC-owned profile on dedicated node groups):** a reviewed filter confined to opted-in groups, at the cost of EKS module changes, an admission policy, a complete allowlist per architecture maintained indefinitely, profile rollouts that end sessions, and AppArmor work for Hetzner and AKS. Deferred.
- **Option 5 (bubblewrap inside gVisor):** no host relaxation and a stronger boundary around the pod; costs a gVisor installation, overhead and compatibility gaps. The intended first route.
- **Option 6 (`CAP_SYS_ADMIN` in pack pods):** on the default runtime it hands the workload much of the host kernel's privileged surface. With `hostUsers: false` it is scoped to the pod, but still needs an admission exception, applies to the whole container and does not lift AppArmor. Kept as the reserved `pod-user-namespaces`.
- **Option 7 (separate sandbox pod per session):** the strongest design where a pack can adopt it, and needs no namespaces inside a pod; it is a different pattern (guarantees around such pods are sketched in ADR-0025), not a route to this capability.

Full assessments are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full).

## Open Questions

- Does ADR-0021's `process-self-restriction` cover the need for most packs? A nested seccomp filter denying non-Unix sockets, with Landlock ABI 6's signal and abstract-socket scoping, could give "no network except a Unix socket to a proxy" under Pod Security `restricted`; ABI 6 is available on AL2023 (6.12) but not on Hetzner's Ubuntu 24.04 (ABI 4), and ADR-0021's reference consumer (§20.8) tests the combination at ABI 4 and 6 on Ubuntu VMs, not yet on provider nodes.
- Which packs cannot split tool execution into a separate pod, and do they need a separate filesystem view?
- If a host-kernel route is ever needed: a NIC-written profile, Podman's profile pinned, pack-supplied profiles through the Security Profiles Operator, or `pod-user-namespaces`?
- Should the capability ever cover pods running sandboxes for several users or sessions? Single-ID user namespaces map every session to the pod's own UID.

## Links

- [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [gVisor](https://gvisor.dev/)
- [gVisor #13438: bwrap --unshare-net fails](https://github.com/google/gvisor/issues/13438)
- [containerd default seccomp profile](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go)
- [Podman default seccomp profile](https://github.com/podman-container-tools/container-libs/blob/main/common/pkg/seccomp/seccomp.json)
