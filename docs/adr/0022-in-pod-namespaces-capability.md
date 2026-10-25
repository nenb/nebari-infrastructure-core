# ADR-0022: In-Pod Namespace Sandboxes (`in-pod-namespaces`) for Software Packs

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `in-pod-namespaces`; this ADR cannot be accepted before it. Revised 2026-10-17: the first implementation is a declared requirement that NIC checks, with no seccomp profile and no node changes; the NIC-owned seccomp profile on dedicated node groups is kept as a fallback, with `user-space-kernel` (gVisor), running bubblewrap inside it, as the preferred next step. Detailed design is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md), §20.5 and §20.9–§20.11.

## Date

2026-10-15

## Context

The motivating use case for workload sandboxing is a pack that confines the shell commands an agent runs, for example with [bubblewrap](https://github.com/containers/bubblewrap): each command sees a narrowed filesystem, no network and none of the pod's credentials. ADR-0021 delivers `process-self-restriction` (Landlock and seccomp), which covers filesystem and TCP-port confinement but not a separate filesystem view or a separate network stack. Those need Linux namespaces, which bubblewrap, nsjail, headless Chromium's sandbox and similar tools create inside the pod.

The threat model is ADR-0021's: keeping an agent's own commands (prompt injection, compromised dependencies, mistakes) away from what the pod can reach, including the agent's own credentials. It is not about containing a capable adversary determined to escape the host. Namespace sandboxes share the host kernel and are no protection against kernel exploits.

### What blocks it today

Four layers can block unprivileged namespace creation in a NIC-deployed pod, and packs can change none of them ([§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic)):

| Layer | What blocks it | Where it stands |
|---|---|---|
| 1. Node kernel | Unprivileged user namespaces disabled, or on Ubuntu 23.10+ restricted by an AppArmor sysctl | Allowed on AWS AL2023 (`user.max_user_namespaces` 30811, observed on EKS 1.34); restricted on Hetzner's Ubuntu 24.04 |
| 2. Seccomp | The runtime's default profile allows `unshare`, `clone` with namespace flags, `mount` and `pivot_root` only with `CAP_SYS_ADMIN` | Applies only to pods that set `RuntimeDefault`, or to all pods when the kubelet's `seccompDefault` is on. It is off on EKS, hetzner-k3s and AKS as NIC deploys them, so pods that set no profile have **no syscall filter** |
| 3. AppArmor | The default container profile denies `mount` | Blocks on AppArmor nodes (Hetzner, AKS Ubuntu); not present on AWS AL2023 (SELinux is present there but permissive) |
| 4. Masked `/proc` | A fresh procfs cannot be mounted inside a container | Not lifted: the capability keeps the container's `/proc` |

So bubblewrap already works on AWS in pods that set no seccomp profile, and fails on Hetzner and AKS. On Hetzner nodes deployed with NIC (2026-10-25), bubblewrap failed at the AppArmor layer (`Failed to make / slave: Permission denied`) even with the network namespace created first. A local probe on Ubuntu 24.04 with kernel 6.8, as on Hetzner, had confirmed each layer in turn: under the default seccomp profile namespace creation is refused; with seccomp unconfined, AppArmor refuses the first `mount`; with AppArmor also unconfined, Ubuntu's user-namespace restriction strips the namespace's capabilities and bubblewrap cannot configure loopback (2026-10-17). Nothing records that, nothing checks it, and a pack cannot tell before it is deployed whether a cluster will run it.

No Kubernetes runtime maintains a default profile that allows namespace creation: containerd allows these calls only with `CAP_SYS_ADMIN`, and CRI-O removes them from the Podman profile it builds on, citing the risk of letting unprivileged containers create namespaces. Allowing them under a filter therefore means someone owning a seccomp profile ([§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full)).

## Decision Drivers

- **The threat is inside the pod.** The aim is to fence an agent's commands away from the agent's credentials and the rest of the pod, which needs a boundary *inside* the pod, not only around it.
- **Check before building.** Follow ADR-0021: the operator declares a requirement and NIC errors when the nodes definitely cannot meet it, before adding node configuration or in-cluster components.
- **An upgradeable contract.** Packs written against the first implementation must keep working when a stronger implementation replaces it.
- **No privileged pack pods.** Packs never need `CAP_SYS_ADMIN`, `Unconfined` profiles or privileged pods.
- **Never block hardening.** A cluster that requires a syscall filter on every pod and also requires this capability gets an error, not a silent exception.
- **Honest about security.** State what each implementation does and does not protect.

## Considered Options

1. Do nothing; bubblewrap keeps working where it happens to, unchecked.
2. Allow unprivileged user namespaces on every node and give every pod a permissive profile.
3. A declared, checked capability whose pod settings NIC publishes; the first implementation publishes no seccomp profile and only checks the nodes, and a stronger implementation can replace it later.
4. A NIC-owned, versioned seccomp profile on dedicated, opt-in node groups configured at boot (the earlier draft of this ADR).
5. Run the pack's existing pod under a user-space kernel instead (`runtimeClassName: gvisor`), ADR-0021's reserved `user-space-kernel`.
6. Let packs grant their pods `CAP_SYS_ADMIN`, with or without a pod user namespace (`hostUsers: false`).
7. Run each agent session's commands in a separate, credential-free pod under gVisor.

## Decision Outcome

Chosen option: "Option 3", because it makes today's behaviour declared and checked at almost no cost to NIC, gives packs a contract they can build on now, and leaves room for stronger implementations of the same capability. The preferred next step is not more host-level work for bubblewrap but Option 5, a user-space kernel around the pod, with bubblewrap inside it providing the boundary within the pod (see "Next steps").

### The capability

**`in-pod-namespaces`:** a non-root process with no added capabilities, in a container that uses the pod settings NIC publishes for this capability, can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed.

The guarantee names the published settings rather than a particular profile. That is what lets the implementation change: today the published seccomp setting is **none**; a `user-space-kernel` implementation would add `runtimeClassName: gvisor`, and the fallback filtered implementation would publish a `Localhost` profile such as `nebari-sandbox-v1`. Packs that apply the published settings keep working without changes.

Qualification uses one pinned bubblewrap version in a capability test and two consumer configurations, which must not be confused:

- **The capability test** proves only that the namespaces can be created. It exposes the whole container read-only and is not a sandbox policy.
- **The qualified consumer configurations** are what packs start from and what the acceptance test runs against. They bind only what a command needs (system libraries, certificates, the work directory), mask the home directory and `/tmp`, bind no secrets, service-account token paths or socket directories, and clear the environment so credentials in environment variables do not pass through. There are two: **no network**, and **network only through a pack-provided proxy** reached over a Unix socket bound into the sandbox, so the proxy can decide destinations and inject credentials outside the sandbox. Both create the network namespace with `unshare` before bubblewrap runs and add a pid namespace (`--unshare-pid`, keeping the container's `/proc` read-only), a form that worked unchanged on runc and under gVisor, so packs need not detect which runtime they are in. Packs extend them with specific paths (a virtualenv, `/usr/local`, a toolchain), never with `/` or the home directory.

The exact commands are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#qualified-configurations-and-profile-contents-adr-0022).

### What the operator configures

A requirement, using ADR-0021's `sandbox.require`:

```yaml
sandbox:
  require:
    - capability: in-pod-namespaces
```

There is no node-group opt-in in the first implementation, because NIC changes no node; a per-node-group `sandbox` block would arrive only with an implementation that changes nodes.

### What NIC does

1. **`nic validate`.** Each cluster provider reports in `InfraSettings.Sandbox` whether its nodes are expected to allow the capability, from the node OS it provisions: AWS with AL2023 yes; Hetzner (Ubuntu 24.04: user namespaces restricted and AppArmor) no; AKS with Ubuntu (AppArmor) no; pinned images, `existing` and kind unknown. A known "no" with the capability required is an error, before any infrastructure exists.
2. **`nic deploy` check, per node.** Once nodes are up, NIC reads each node's kubelet configuration through the API (`/api/v1/nodes/<node>/proxy/configz`, no pod needed) and confirms `seccompDefault` is off, and reads the node's OS image (`node.status.nodeInfo.osImage`) and confirms it belongs to an OS family qualified for the capability (AL2023 today). A node that fails either fails the deploy when the capability is required. Results are shown by `nic outputs`. As in ADR-0021, the requirement applies to every node, because the first implementation does not steer pods to a subset of node groups.
3. **Publish the pod settings.** NIC publishes the capability's pod settings through the same documented route as ADR-0021's consumer integration, shown by `nic outputs`: today, "seccomp: none (leave `seccompProfile` unset)". Helm key names follow ADR-0003 and #670 when that settles.

NIC writes no profile, changes no node, adds no taint, installs no admission policy and adds no CLI command.

### What a pack does

The container that runs bubblewrap is non-root with every capability dropped and applies the published seccomp setting verbatim: today it leaves `seccompProfile` unset, which Pod Security Baseline allows and `restricted` does not, so its namespace must not enforce `restricted`. Setting is per container, so a pack can keep the agent in its own container and leave every other container on `RuntimeDefault`. The pack checks at startup that it can create the namespaces, refuses to run commands unsandboxed if it cannot, and starts from a qualified consumer configuration.

The most likely failure is a pod setting the pack does not notice: `seccompProfile: RuntimeDefault` is a common chart default and a frequent scanner recommendation, and in a JupyterLab-based pack the user's pod is generated by JupyterHub from configuration the extension author may not control. Either overrides the node default and blocks bubblewrap even though NIC's check passed, so pack documentation names it and the startup check's message points at it. Bubblewrap's own message is misleading here: it reports "No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces", though the cause is the seccomp profile.

### Verification

**AL2023 is qualified:** on an EKS 1.34 AL2023 x86 node (2026-10-19), the capability test and both consumer configurations worked in a pod with no seccomp profile, hiding environment, home-directory, Secret and service-account-token canaries, the agent's socket and the network, and the same pod with `RuntimeDefault` failed as predicted. The first run also found that the qualified configurations must provide `/lib64` on x86, where the dynamic loader lives. A maintainer runs the probe on a fresh node of each OS family before it is listed as qualified, and again when a provider changes kernel line for it: the capability test and both consumer configurations work in a pod with no seccomp profile, and Unix sockets on the container's filesystem are not reachable from the qualified configurations. Before the first release, a consumer passes an acceptance test with credential canaries, denied or proxied networking, an unreachable instance metadata service from inside the sandbox, and refusal of unsandboxed fallback, using a small reference consumer in NIC's user-journey tests until an upstream pack adopts the capability. Details are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-first-implementation-checks-and-verification).

### Security

The first implementation means **no syscall filter** on the containers that use it. A process there can reach the whole kernel interface, including the parts that become reachable from inside a user namespace: netfilter configuration (CVE-2024-1086 was reachable this way), `io_uring`, `keyctl` and others. On AL2023 nodes this exposure is not new: any pod that sets no seccomp profile can already create user namespaces today. What changes is that packs are now encouraged to rely on it, so pack-facing documentation states it plainly, and kernels must be patched promptly (NIC shows each node group's image age in `nic outputs`; the operator owns the cadence).

One limit of the qualified configurations remains: with the container's `/proc` reused, sandboxed commands can see other processes' command lines in the pod, which can contain credentials. Their pid namespace stops them signalling the agent (observed on AL2023). Under gVisor the sandbox can also mount a fresh procfs, closing the command-line gap too (see "Next steps"). The instance metadata service is unreachable from inside the sandbox's network namespace, and on AWS also from the pod itself, because NIC's EKS node groups already require IMDSv2 with a hop limit of 1. **Storage endpoints are another path to other users' data.** Network filesystems that trust the user ID a client claims (NFS with its default authentication, as used by FSx for OpenZFS in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705), whose export allows any client with `no_root_squash`, and by Longhorn's share-manager) can be spoken to directly by a user-space NFS client, which needs no mount privilege, so a process that can reach the storage endpoint can read or change any user's home. This was confirmed in probe clusters (2026-10-25): an unprivileged pod, under runc or gVisor and on another node, read another user's Longhorn volume through its share-manager, and read and wrote another user's FSx for OpenZFS volume as root. Bubblewrap's no-network configuration blocks it for sandboxed commands. For the agent's pod itself, a default-deny egress NetworkPolicy blocked it on both providers while the pod's own volumes still mounted, because the kubelet mounts from the node; but NetworkPolicy is not enforced on NIC's EKS clusters today (#691, #675). Restricting the storage endpoint to node addresses (security groups, export rules) is the other route. See ADR-0023's "Findings for NIC beyond sandboxing". Code an agent executes should be treated as attacker-influenced. See [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

**Hardening.** If a cluster's policy requires a syscall filter on every pod (the kubelet's `seccompDefault`, or a future hardened-mode admission rule under [ADR-0010](0010-high-security-mode.md) or the Pack Specification), the check fails and the deploy errors: hardening wins, and that cluster needs a stronger implementation (`user-space-kernel`, or the fallback). A future NIC release that turns `seccompDefault` on by default would be a breaking change for clusters that require this capability and is noted as such.

### Next steps

**Preferred: `user-space-kernel` (gVisor), with bubblewrap inside it.** Making bubblewrap work under a filter on more clusters means NIC owning a seccomp profile indefinitely, AppArmor policy for Hetzner and a delivery mechanism for AKS, all to strengthen the weakest boundary that needs this much work; and ADR-0021's Landlock already covers filesystem and TCP-port confinement, leaving bubblewrap's unique value as complete network isolation and a separate filesystem view. A gVisor `RuntimeClass` instead gives a much stronger boundary between the pod and the host, whose syscall filter and hardening the gVisor project maintains, needs no user namespaces, AppArmor changes or custom seccomp profiles on the host, and in its default mode needs no hardware virtualisation, so it can reach Hetzner Cloud. gVisor alone protects the host from the pod, not the pod's credentials from the agent's commands; but gVisor implements namespaces in its own kernel, so bubblewrap inside a gVisor pod can provide the boundary within the pod with no host changes at all. A local probe (gVisor `release-20261012.0`, 2026-10-17) confirmed this, with three findings the `user-space-kernel` ADR must carry: bubblewrap's own `--unshare-net` fails under gVisor because gVisor pre-configures the new namespace's loopback ([gVisor #13438](https://github.com/google/gvisor/issues/13438), open), so the network namespace is created first with `unshare` and bubblewrap runs without `--unshare-net`; the sandbox can also have its own pid namespace and a fresh `/proc`, closing the signalling and command-line gaps above; and gVisor ignores the pod's seccomp profile unless configured with `--oci-seccomp`, under which `RuntimeDefault` blocks bubblewrap again. JupyterLab and notebook execution ran with little overhead; metadata-heavy work on network-backed home directories was 1.5–2.3× slower than without gVisor, on top of network latency that already dominated it. Landlock is not available inside gVisor. Remaining checks are on x86 provider nodes, through a Kubernetes `RuntimeClass`, with EFS. ADR-0023 proposes this capability. Its costs are a per-provider gVisor install, following gVisor releases, I/O overhead and compatibility gaps, limited GPU support, and checking that the pack's stack runs under it; AKS's native option is Kata-based, which is `vm-boundary` instead. Option 7 (a credential-free gVisor pod per session) remains the strongest design for packs willing to re-architect.

**Fallback: the filtered implementation (Option 4),** if gVisor proves impractical for Nebari's workloads. When it lands, the published seccomp setting changes from none to a reviewed `Localhost` profile, the capability moves to dedicated, opt-in, tainted node groups with an admission policy, and `nic deploy` checks that the profile is installed instead of that `seccompDefault` is off. Its profile could be written by NIC, pinned from Podman's default profile, or supplied by packs through the Security Profiles Operator; and `pod-user-namespaces` (Option 6 with `hostUsers: false`) is an alternative route. The full design is in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-the-filtered-implementation-in-full). It would be reconsidered if a cluster needs hardened pods and this capability, Hetzner or AKS need the capability, packs run several users' sessions, or EKS turns `seccompDefault` on, and gVisor cannot meet that need.

### Consequences

**Good:**
- Packs get a declared, checked, documented path to bubblewrap-style sandboxes now, without privileged pods or `Unconfined` profiles.
- Almost no NIC cost: a field in `InfraSettings`, a `validate` check, a `deploy` check, published settings and documentation. No profile, no node changes, no in-cluster components.
- The contract survives the move to a stronger implementation; packs that apply published settings need no change.
- Hardening is never blocked: a conflict is reported as an error.

**Bad:**
- Containers using the capability run with no syscall filter; a gVisor pod or the fallback filtered implementation would narrow that.
- Packs using it cannot run under Pod Security `restricted`.
- AWS AL2023 only; Hetzner and AKS would get the capability through `user-space-kernel` (or the fallback plus AppArmor work).
- The check relies on EKS leaving `seccompDefault` off and on the OS image identifying the node's AppArmor and user-namespace posture; if either changes, the capability disappears from those clusters (with an error, not silently).
- A reference consumer, maintained with NIC's user-journey tests until an upstream pack adopts the capability, is one more thing NIC's maintainers own.

## Options Detail

- **Option 1 (do nothing):** no cost, but packs cannot tell whether a cluster supports them, operators get runtime failures instead of deploy-time errors, and there is no path to a stronger implementation.
- **Option 2 (cluster-wide):** simplest for packs, but exposes the extra kernel surface on nodes running Keycloak, ArgoCD and other foundational services, and contradicts guidance to grant user namespaces narrowly.
- **Option 3 (declared and checked, unfiltered first; chosen):** cheap and honest, with an upgrade path; costs no syscall filter on the containers that use it and AWS-only reach.
- **Option 4 (NIC-owned profile on dedicated node groups):** a reviewed filter, confined to opted-in node groups, configured at boot. It costs EKS module changes, an admission policy, a complete seccomp allowlist per architecture that NIC maintains and versions indefinitely, profile rollouts that replace nodes and end sessions, and testing system DaemonSets under `seccompDefault`. Kept as a fallback if `user-space-kernel` proves impractical.
- **Option 5 (`runtimeClassName: gvisor` on the existing pod):** a stronger boundary around the pod that needs no user namespaces, seccomp allowlist or AppArmor work, and could reach Hetzner Cloud and AKS sooner; it costs a per-provider gVisor install, compatibility and I/O overhead, and limited GPU support. It protects the **host from the pod**, not the **pod's credentials from the agent's commands**, so on its own it does not meet the threat model; with bubblewrap inside it, if probing confirms that works, it is the preferred next step.
- **Option 6 (`CAP_SYS_ADMIN` in pack pods):** on the default runtime it hands the workload a large part of the host kernel's privileged surface and fails Pod Security Baseline. With a pod user namespace (`hostUsers: false`) the capability is scoped to the pod and containerd's own default profile allows the namespace calls, so no one owns a custom profile; it still needs an admission exception, applies to the whole container, needs recent containerd and kernels, and does not lift AppArmor. Kept as the reserved `pod-user-namespaces`.
- **Option 7 (separate, credential-free gVisor pod per session):** meets the threat model without user namespaces on the host, but costs a pod start per session, workspace sharing between pods, permission for the pack to create pods, and re-architecting packs; it depends on `user-space-kernel` existing first.

Full assessments are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full).

## Open Questions

- Does bubblewrap inside gVisor, confirmed locally, also hold on x86 provider nodes through a Kubernetes `RuntimeClass`, and is JupyterLab acceptable with EFS-backed home directories? This decides whether `user-space-kernel` replaces the fallback.
- If the fallback is needed, which variant: a NIC-written profile, Podman's profile pinned, pack-supplied profiles through the Security Profiles Operator, or `pod-user-namespaces`?
- Under the fallback only: should NIC load an AppArmor profile at boot on Hetzner (once hetzner-k3s applies per-pool commands to autoscaled nodes), and which mechanism would deliver it on AKS, given NIC's AKS module has no node bootstrap hook?
- Should the capability ever cover pods running sandboxes for several users or sessions? Single-ID user namespaces map every session to the pod's own host UID, so files are not separated between sessions.

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [gVisor](https://gvisor.dev/)
- [containerd default seccomp profile](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go)
- [Podman default seccomp profile](https://github.com/podman-container-tools/container-libs/blob/main/common/pkg/seccomp/seccomp.json)
