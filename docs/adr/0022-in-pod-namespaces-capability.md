# ADR-0022: In-Pod Namespace Sandboxes (`in-pod-namespaces`) for Software Packs

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `in-pod-namespaces`; this ADR cannot be accepted before it. Revised 2026-10-15 after review: the seccomp profile is written at node boot instead of by an operator, which removes the post-bootstrap phase and the readiness barrier from the first delivery. Detailed design, including the operator-based alternative kept for providers without boot-time customisation, is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md), §20.5 and §20.9–§20.11.

## Date

2026-10-15

## Context

The motivating use case for workload sandboxing is a pack that confines the shell commands an agent runs, for example with [bubblewrap](https://github.com/containers/bubblewrap): each command sees a narrowed filesystem, no network and none of the pod's credentials. ADR-0021 delivers `process-self-restriction` (Landlock and seccomp), which covers filesystem and TCP-port confinement but not a separate filesystem view or a separate network stack. Those need Linux namespaces, which bubblewrap, nsjail, headless Chromium's sandbox and similar tools create inside the pod.

The threat model is ADR-0021's: keeping an agent's own commands (prompt injection, compromised dependencies, mistakes) away from what the pod can reach, including the agent's own credentials. It is not about containing a capable adversary determined to escape the host. Namespace sandboxes share the host kernel and are no protection against kernel exploits.

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

- **The threat is inside the pod.** The aim is to fence an agent's commands away from the agent's credentials and the rest of the pod, which needs a boundary *inside* the pod, not only around it.
- **Narrowly scoped relaxation.** Unprivileged user namespaces widen the kernel attack surface (CVE-2024-1086 was reachable via `CAP_NET_ADMIN` inside a user namespace), so they are allowed only on dedicated node groups, for pods that opt in.
- **No privileged pack pods.** Packs get namespaces through a reviewed `Localhost` seccomp profile, never through `CAP_SYS_ADMIN`, `Unconfined` profiles or privileged pods.
- **Fewest moving parts.** Prefer configuration NIC already controls (node images, node bootstrap, node-group labels and taints) over new in-cluster components.
- **Deliverable now, extensible later.** Ship where the mechanism exists today, and widen to more providers as their blockers are solved.
- **Fit ADR-0021's contract** and ADR-0010's `security_level` ladder.

## Considered Options

1. Do nothing; packs keep relying on pods with no seccomp filter.
2. Allow unprivileged user namespaces on every node and give every pod a permissive profile.
3. Dedicated, opt-in node groups whose nodes are configured at boot with a NIC-owned, versioned seccomp profile, delivered first on AWS.
4. Run the pack's existing pod under a user-space kernel instead (`runtimeClassName: gvisor`), ADR-0021's reserved `user-space-kernel`.
5. Let packs grant their pods `CAP_SYS_ADMIN`.

## Decision Outcome

Chosen option: "Option 3", because it gives packs a boundary inside the pod, which is what the threat model needs, without privileged pods, confines the extra kernel exposure to opted-in node groups, and uses only node configuration NIC already controls. Option 4 is a stronger boundary *around* the pod and is the better choice where host-kernel exploits are in the threat model; it does not fence an agent's commands from the agent's own credentials, so the two are complementary rather than alternatives (see Options Detail).

### The capability

**`in-pod-namespaces`:** a non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed.

The qualified consumer is one pinned bubblewrap version with a fixed invocation of the form `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --ro-bind / / --ro-bind /proc /proc --dev /dev --tmpfs /tmp --die-with-parent --new-session -- <command>`. Other tools are potential consumers until qualified; rootless container engines need subordinate ID mappings such pods cannot use, and headless Chromium may need its own pid namespace. Whether `--unshare-pid` without a fresh procfs can be added to the qualified invocation is tested during qualification (see Security).

### Scope of the first delivery

The first delivery is **AWS** (AL2023 node groups), where NIC controls node bootstrap and there is no AppArmor. Other providers follow as their blockers are solved:

- **Hetzner** needs NIC to write and load an AppArmor profile at boot (a `userns` grant and scoped `mount` rules), which the same boot-time mechanism can do, and a hetzner-k3s fix so per-pool boot commands also reach autoscaled nodes (until then, autoscaling is rejected on Hetzner pools that request the capability).
- **AKS** offers no equivalent node bootstrap hook in NIC's module, so it needs a different mechanism, such as the operator-based design kept in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-future-work-delivery-of-in-pod-namespaces-phase-2).
- **`existing` and kind** clusters are not covered.

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

Requesting the capability on a node group whose provider or image cannot provide it is a validation error. As with ADR-0021, NIC knows which images qualify from a table, and an image enters it only after a manual probe run on that image confirms the capability (user namespaces allowed, no AppArmor, or NIC's AppArmor profile loaded).

### What NIC does

1. **Dedicated node groups.** The provider labels the node group `sandbox.nebari.dev/in-pod-namespaces` and taints it `sandbox.nebari.dev/in-pod-namespaces=true:NoSchedule`, following the AWS GPU precedent. Adding the capability to an existing node group is a node-group replacement (the usual managed-node-group rolling update), not an in-place drain.
2. **Boot-time node configuration.** The node's bootstrap writes the seccomp profile files into the kubelet's seccomp directory and sets the kubelet's `seccompDefault: true`, before the kubelet starts. Nodes are therefore ready the moment they join, including replacement and autoscaled nodes, with no installer and no readiness barrier.
3. **A versioned seccomp profile.** NIC owns a complete `Localhost` profile, `nebari-sandbox-v1` (a `Localhost` profile replaces `RuntimeDefault` rather than extending it, so NIC maintains the full allowlist per architecture). It permits the namespace syscalls, makes `clone3` fail with `ENOSYS` (seccomp cannot inspect its flags), and blocks netfilter configuration by filtering `socket()` on its arguments while allowing what bubblewrap needs to bring up a loopback interface. A change is a new version (`-v2`) shipped alongside the old ones; because profiles are written at boot, a new version reaches nodes through a node-group rolling update. Old versions stay until declared consumers have migrated or the operator retires them.
4. **Admission.** NIC applies a ValidatingAdmissionPolicy when the capability is enabled (in hardened mode, ADR-0010's admission policy does the same job). Only namespaces labelled for the capability may reference `nebari-sandbox-v*` or tolerate the dedication taint, and only cluster administrators may set that namespace label, so a namespace owner cannot grant it to themselves. Wildcard tolerations and direct node assignment (`spec.nodeName`) onto these nodes from unlabelled namespaces are rejected.
5. **Deploy-time check.** As in ADR-0021, `nic deploy` checks live nodes against the node group's prediction and records mismatches in the readiness record, shown by `nic outputs`.

### Concrete work this implies

- **NIC's EKS module (`terraform-aws-eks-cluster`):** per-node-group bootstrap configuration (a nodeadm `NodeConfig` setting kubelet `seccompDefault`, plus cloud-init writing the profile files), and node-group labels and taints. Today the module uses its pre-nodeadm hook only for the extra CA bundle.
- **NIC's AWS provider:** plumbing for the `sandbox` block, the image table and profile versions.
- **Cluster autoscaler:** confirm scale-from-zero works for tainted, labelled sandbox node groups.
- **System DaemonSets:** `seccompDefault: true` also applies to the VPC CNI, kube-proxy, CSI drivers and monitoring agents on these nodes; each must be tested under `RuntimeDefault`, with any needed exceptions documented as named `Localhost` profiles.
- **Admission policy, profile files and the image table** in NIC's repository, reviewed as security policy.

### What a pack does

Its sandboxing pods carry the node selector and toleration for the dedication taint, reference the profile (`seccompProfile: Localhost`, `localhostProfile: nebari-sandbox-v1.json`), run in a namespace an administrator has labelled for the capability, and invoke bubblewrap around each command. A pack must refuse to run commands unsandboxed when the capability is unavailable.

### Verification

- **Per node image, by hand:** before an image enters the table, a probe confirms the qualified invocation works with the profile, a pod without the profile on the same node cannot create a user namespace, and netfilter and raw-socket creation fail inside a new user namespace.
- **At deploy:** the consistency check described above.
- **Consumer acceptance, before the first delivery:** a consumer must show, with the capability in use, that credential canaries in the agent's environment, files and mounted secrets are unreadable by sandboxed commands, inherited descriptors are closed or allowed, networking is denied, its pod settings are correct, and it refuses unsandboxed fallback. Until an upstream pack adopts the capability, a small reference consumer maintained alongside NIC's user-journey tests fulfils this.

### Security

The capability adds real risk, bounded only by the measures above: `seccompDefault` on its nodes, admission over profiles, taints and the namespace label, a tested netfilter block, prompt kernel patching on these node groups with a named owner, and pack-facing documentation of the threat model. Two limits of the qualified configuration must be stated plainly: with the container's `/proc` reused, sandboxed commands can see other processes' command lines in the pod, which can contain credentials; and without a separate pid namespace, a sandboxed command runs as the same host user as the agent and can **signal** the pod's other processes, including killing the agent. Code an agent executes should be treated as attacker-influenced. See [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

### Consequences

**Good:**
- Packs get a supported, documented path to bubblewrap-style sandboxes without privileged pods or `Unconfined` profiles.
- No new in-cluster components: no operator, no installer, no verifier, no post-bootstrap phase and no change to ADR-0006.
- The extra kernel exposure is confined to opted-in, tainted node groups, configured before the kubelet starts.
- The "works by accident" state on AWS is replaced by a versioned, reviewed mechanism.

**Bad:**
- AWS only at first; Hetzner needs a NIC-owned AppArmor profile and an upstream hetzner-k3s fix, and AKS needs a different mechanism.
- NIC owns a complete seccomp policy per architecture and must track runtime default changes.
- Profile changes roll out by replacing nodes.
- `seccompDefault` on these nodes may need exceptions for system DaemonSets.
- EKS module changes for per-node-group bootstrap configuration.
- Enabling user namespaces on these node groups widens the kernel attack surface there; kernels must be patched promptly.

## Options Detail

- **Option 1 (do nothing):** no cost, but bubblewrap works only where pods have no syscall filter, which breaks under Pod Security `restricted` and is forbidden by ADR-0010's hardened mode.
- **Option 2 (cluster-wide):** simplest for packs, but exposes the extra kernel surface on nodes running Keycloak, ArgoCD and other foundational services, and contradicts guidance to grant user namespaces narrowly.
- **Option 4 (`runtimeClassName: gvisor` on the existing pod):** the pod stays as it is, and gVisor intercepts its syscalls in a user-space kernel, so a host-kernel exploit from the pod is far harder. It needs no unprivileged user namespaces, no NIC-owned seccomp allowlist and no AppArmor work, and its default mode needs no hardware virtualisation, so it could reach Hetzner Cloud and AKS sooner. Its costs: installing gVisor and a `RuntimeClass` per provider, compatibility gaps and I/O overhead for some workloads, limited GPU support, and checking that the pack's stack (for example JupyterLab and its kernels) runs under it. Above all, it protects the **host from the pod**, not the **pod's credentials from the agent's commands**, because everything in the pod shares gVisor's kernel. It is the right next capability where kernel-exploit risk matters, and it composes with this one: ADR-0021's composition rules allow namespace tools inside a `user-space-kernel` pod, subject to probing.
- **Option 5 (`CAP_SYS_ADMIN` in pack pods):** works with no node changes, but on the default runtime it hands the workload a large part of the host kernel's privileged surface and fails Pod Security Baseline. It is acceptable only inside a stronger boundary, where ADR-0021's composition rules allow it.

## Open Questions

- Hetzner: should NIC own and load an AppArmor profile at boot (a `userns` grant and scoped `mount` rules), making Hetzner the second provider once hetzner-k3s applies per-pool commands to autoscaled nodes?
- AKS: which mechanism, given NIC's AKS module has no node bootstrap hook (the operator-based design in §20.9, an AKS node customisation feature, or waiting for `user-space-kernel`)?
- Is a node-group rolling update an acceptable rollout path for new profile versions, or should a later revision add an in-cluster installer?
- Can the qualified invocation add `--unshare-pid` without a fresh procfs, closing the signalling gap?
- Is per-node-group opt-in the right granularity for AKS and `existing`?
- Should the capability ever cover pods running sandboxes for several users or sessions? Single-ID user namespaces map every session to the pod's own host UID, so files are not separated between sessions.

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [gVisor](https://gvisor.dev/)
