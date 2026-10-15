# ADR-0022: In-Pod Namespace Sandboxes (`in-pod-namespaces`) for Software Packs

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `in-pod-namespaces`; this ADR cannot be accepted before it. Detailed design is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md), §20.5 and §20.9–§20.11.

## Date

2026-10-15

## Context

The motivating use case for workload sandboxing is a pack that confines the shell commands an agent runs, for example with [bubblewrap](https://github.com/containers/bubblewrap): each command sees a narrowed filesystem, no network and none of the pod's credentials. ADR-0021 delivers `process-self-restriction` (Landlock and seccomp), which covers filesystem and TCP-port confinement but not a separate filesystem view, a separate network stack or hiding the pod's other processes. Those need Linux namespaces, which bubblewrap, nsjail, headless Chromium's sandbox and similar tools create inside the pod.

The threat model is ADR-0021's: containing an agent's own commands (prompt injection, compromised dependencies, mistakes), not containing a capable adversary determined to escape the host. Namespace sandboxes share the host kernel and are no protection against kernel exploits.

### Why this needs NIC

Four layers block unprivileged namespace creation in a NIC-deployed pod, and packs can change none of them ([§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic)):

| Layer | What blocks it | Where it stands |
|---|---|---|
| 1. Node kernel | Unprivileged user namespaces disabled, or on Ubuntu 23.10+ restricted by an AppArmor sysctl | Expected allowed on AWS AL2023 *(unverified)*; restricted on Hetzner's Ubuntu 24.04 |
| 2. Seccomp | The runtime's default profile allows `unshare`, `clone` with namespace flags, `mount` and `pivot_root` only with `CAP_SYS_ADMIN` | Blocked on every provider under `RuntimeDefault` |
| 3. AppArmor | The default container profile denies `mount` | Blocks on AppArmor nodes (Hetzner, AKS Ubuntu); not present on AWS AL2023 |
| 4. Masked `/proc` | A fresh procfs cannot be mounted inside a container | Not lifted by this ADR: the capability keeps the container's `/proc` |

Today bubblewrap can appear to work on AWS only because pods without a seccomp profile run with no syscall filter at all, the default on EKS, hetzner-k3s and AKS as NIC deploys them. That is not a foundation packs can rely on: it breaks as soon as a pack adopts Pod Security `restricted` or the platform enables `seccompDefault`.

## Decision Drivers

- **Narrowly scoped relaxation.** Unprivileged user namespaces widen the kernel attack surface (CVE-2024-1086 was reachable via `CAP_NET_ADMIN` inside a user namespace), so they are allowed only on dedicated node groups, and only for pods that opt in.
- **No privileged pack pods.** Packs get namespaces through a reviewed `Localhost` seccomp profile, never through `CAP_SYS_ADMIN`, `Unconfined` profiles or privileged pods.
- **Deliverable now, extensible later.** Ship where the mechanism exists today, and widen to more providers as blocking problems are solved, rather than waiting for every provider.
- **Prefer community-maintained mechanisms** over NIC-owned node agents, where they can express the required policy.
- **Fail closed and observe.** Unlike `process-self-restriction`, this capability depends on components NIC installs, so NIC observes it per node before any workload can use that node.
- **Fit ADR-0021's contract** and ADR-0010's `security_level` ladder.

## Considered Options

1. Do nothing; packs keep relying on pods with no seccomp filter.
2. Allow unprivileged user namespaces on every node and give every pod a permissive profile.
3. Dedicated, opt-in node groups with a NIC-owned, versioned `Localhost` seccomp profile, delivered first on node groups without AppArmor.
4. Skip namespace sandboxes and go straight to `user-space-kernel` or `vm-boundary`.
5. Let packs grant their pods `CAP_SYS_ADMIN` (the approach some sandbox systems take inside an outer VM or gVisor boundary).

## Decision Outcome

Chosen option: "Option 3", because it gives packs a supported way to run bubblewrap-style sandboxes without privileged pods, confines the extra kernel exposure to opted-in node groups, and can ship now on providers without AppArmor while the AppArmor gap is solved.

### The capability

**`in-pod-namespaces`:** a non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed.

The qualified consumer is one pinned bubblewrap version with a fixed invocation of the form `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --ro-bind / / --ro-bind /proc /proc --dev /dev --tmpfs /tmp --die-with-parent --new-session -- <command>`. Other tools are potential consumers until qualified; rootless container engines in particular need subordinate ID mappings that such pods cannot use, and headless Chromium may need its own pid namespace.

### Scope of the first delivery

The first delivery is limited to node groups **without AppArmor**, which today means AWS (AL2023). Two blockers keep other providers out until they are solved, and each is lifted independently:

- **AppArmor nodes (Hetzner, AKS Ubuntu, possibly kind).** The Security Profiles Operator (v1.1.1) cannot express the AppArmor policy this needs (a `userns` grant and scoped `mount` rules). This needs upstream support or another maintained loader; a NIC-owned privileged loader would need its own decision.
- **Hetzner autoscaling.** hetzner-k3s v2.4.6 applies per-pool preparation to initially created workers but not to autoscaled ones, so autoscaling is rejected on Hetzner pools that request this capability until that is fixed and tested on an autoscaler-created node.

### What the operator configures

An opt-in on the node group, using the block ADR-0021 reserves, and optionally a requirement:

```yaml
cluster:
  aws:
    node_groups:
      agents:
        instance: m6i.xlarge
        sandbox:
          capabilities: [in-pod-namespaces]

sandbox:
  require:
    - capability: in-pod-namespaces
```

A node group may list only capabilities that are compatible with each other. Requesting `in-pod-namespaces` on a node group whose provider or image cannot provide it is a validation error.

### What NIC does

1. **Dedicated placement.** The provider labels the node group `sandbox.nebari.dev/in-pod-namespaces` and taints it `sandbox.nebari.dev/in-pod-namespaces=true:NoSchedule`, following the AWS GPU precedent. Pods already on a node group that is converted are drained.
2. **Node configuration.** The kubelet on these node groups runs with `seccompDefault: true`, so pods without a profile get `RuntimeDefault` and cannot create user namespaces; on AWS this is set through the node bootstrap configuration NIC already supplies.
3. **A versioned seccomp profile.** NIC owns a complete `Localhost` profile, `nebari-sandbox-v1`: a `Localhost` profile replaces `RuntimeDefault` rather than extending it, so NIC maintains the full allowlist per architecture. It permits the namespace syscalls, makes `clone3` fail with `ENOSYS` (seccomp cannot inspect its flags), and blocks netfilter configuration by filtering `socket()` on its arguments. A change is a new version (`-v2`), never an in-place edit, and old versions stay installed until declared consumers have migrated or the operator retires them.
4. **Profile distribution.** The [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator), pinned by digest, installs the profile on these node groups only; its daemon is restricted to them by node affinity and tolerations, and only NIC and cluster administrators may create or modify profile resources.
5. **Admission.** Only namespaces labelled for the capability may reference `nebari-sandbox-v*` or tolerate the dedication taint: through ADR-0010's hardened-mode admission policy in hardened mode, and a ValidatingAdmissionPolicy shipped with the capability in standard mode. The profile operator's daemon is the one admitted capability node agent.
6. **Readiness barrier.** New nodes in these node groups join with a startup taint, `sandbox.nebari.dev/in-pod-namespaces-unverified:NoSchedule`, removed only once the node has its profiles and passes a per-node probe. This covers autoscaled and replacement nodes. It holds only if consumers never tolerate the unverified taint, admission rejects wildcard tolerations and untrusted `spec.nodeName`, the cluster autoscaler is configured to treat the taint as a startup taint (NIC's AWS autoscaler configuration does not do this today), and the barrier's components can run outside the gated pool.

### Lifecycle

Unlike ADR-0021's capability, this one installs components, so it needs a **post-bootstrap phase**: after foundational services, wait for cert-manager (which the profile operator needs), install the operator and profiles, verify, then publish. Conditional components are currently installed inside the provider's `Deploy()`, before cert-manager exists, so this needs either a post-bootstrap hook in `pkg/nic` or an amendment to [ADR-0006](0006-conditional-foundational-software-helm.md). A required capability that fails makes `nic deploy` exit non-zero. Details are in [§20.7](../design-doc/implementation/20-workload-sandboxing.md#207-lifecycle).

### What a pack does

Its sandboxing pods carry the node selector and toleration for the dedication taint, reference the profile (`seccompProfile: Localhost` with the path NIC publishes), run in a namespace labelled for the capability, and invoke bubblewrap around each command. Without the profile, bwrap fails; without the label, admission rejects the pod; without the toleration, the pod cannot reach the nodes. A pack must refuse to run commands unsandboxed when the capability is unavailable.

### Verification

- **Per node:** the probe that clears the readiness barrier runs the qualified invocation with the profile, and confirms that a pod without the profile on the same node cannot create a user namespace and that netfilter and raw-socket creation fail inside a new user namespace.
- **Consumer acceptance:** before the first delivery, one real pack must show, with the capability in use, that credential canaries in the agent's environment, files and mounted secrets are unreadable by sandboxed commands, inherited descriptors are closed or allowed, networking is denied, its pod settings are correct, and it refuses unsandboxed fallback.

Full detail is in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-future-work-delivery-of-in-pod-namespaces-phase-2) and [§20.10](../design-doc/implementation/20-workload-sandboxing.md#2010-verification).

### Security

The capability adds real risk, bounded only by the measures above: seccomp on by default on its nodes, admission over profiles and taints, a locked-down profile API, a tested netfilter block, prompt kernel patching on its node groups with a named owner, re-verification at node start, and pack-facing documentation that states the threat model precisely. With the container's `/proc` reused, sandboxed commands can still see other processes' command lines in the pod, which can contain credentials. Code an agent executes should be treated as attacker-influenced. See [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

### Consequences

**Good:**
- Packs get a supported, documented path to bubblewrap-style sandboxes without privileged pods or `Unconfined` profiles.
- The extra kernel exposure is confined to opted-in, tainted node groups.
- The "works by accident" state on AWS is replaced by an observed, versioned mechanism.

**Bad:**
- AWS only at first; Hetzner and AKS wait on an AppArmor mechanism, and Hetzner autoscaling on an upstream fix.
- NIC owns a complete seccomp policy per architecture and must track runtime default changes.
- New components: the Security Profiles Operator and its CRDs, a per-node verifier and its permission to remove node taints, and an admission policy.
- A post-bootstrap lifecycle phase in `pkg/nic`, or an ADR-0006 amendment.
- Autoscaler configuration for the startup taint, tested per provider.
- Enabling user namespaces on these node groups widens the kernel attack surface there; kernels must be patched promptly.

## Options Detail

- **Option 1 (do nothing):** no cost, but bubblewrap works only where pods have no syscall filter, which breaks under Pod Security `restricted` and is forbidden by ADR-0010's hardened mode.
- **Option 2 (cluster-wide):** simplest for packs, but exposes the extra kernel surface on nodes running Keycloak, ArgoCD and other foundational services, and contradicts guidance to grant user namespaces narrowly.
- **Option 4 (stronger runtimes only):** a stronger boundary, but changes the pod model and needs runtime installation and, for VMs, KVM-capable nodes; kept as ADR-0021's reserved `user-space-kernel` and `vm-boundary`.
- **Option 5 (`CAP_SYS_ADMIN` in pack pods):** works with no node changes, but on the default runtime it hands the workload a large part of the host kernel's privileged surface and fails Pod Security Baseline. It is acceptable only inside a stronger boundary, where ADR-0021's composition rules allow it.

## Open Questions

- AppArmor: upstream Security Profiles Operator support, another maintained loader, or AppArmor nodes deferred indefinitely?
- Post-bootstrap hook in `pkg/nic`, or an amendment to ADR-0006?
- Where does the readiness barrier's taint removal run (a small NIC-owned controller or the probe DaemonSet), and with what RBAC?
- Is per-node-group opt-in the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Should the capability ever cover pods running sandboxes for several users or sessions? Single-ID user namespaces map every session to the pod's own host UID, so files are not separated between sessions.

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0006: Conditional Foundational Software](0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
