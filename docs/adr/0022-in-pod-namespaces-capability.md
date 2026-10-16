# ADR-0022: In-Pod Namespace Sandboxes (`in-pod-namespaces`) for Software Packs

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `in-pod-namespaces`; this ADR cannot be accepted before it. Detailed design is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md), §20.5 and §20.9–§20.11.

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
6. Run each agent session's commands in a separate, credential-free pod under gVisor (spectrum rows 4 and 5 combined).

## Decision Outcome

Chosen option: "Option 3", because it gives packs a boundary inside the pod, which is what the threat model needs, without privileged pods, confines the extra kernel exposure to opted-in node groups, and uses only node configuration NIC already controls. Option 4 is a stronger boundary *around* the pod and is the better choice where host-kernel exploits are in the threat model; it does not fence an agent's commands from the agent's own credentials, so the two are complementary rather than alternatives (see Options Detail).

### The capability

**`in-pod-namespaces`:** a non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed.

Qualification uses one pinned bubblewrap version in two configurations, which must not be confused:

- **The capability test** proves only that the namespaces can be created. It exposes the whole container read-only and is not a sandbox policy.
- **The qualified consumer configurations** are what packs start from and what the acceptance test runs against. They bind only what a command needs (system libraries, certificates, the work directory), mask the home directory and `/tmp`, bind no secrets, service-account token paths or socket directories, and clear the environment so credentials in environment variables do not pass through. There are two: **no network**, and **network only through a pack-provided proxy** reached over a Unix socket bound into the sandbox, so the proxy can decide destinations and inject credentials outside the sandbox. They are secure starting points that packs extend with specific paths (a virtualenv, `/usr/local`, a toolchain), never with `/` or the home directory.

The exact commands are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#qualified-configurations-and-profile-contents-adr-0022).

Other tools are potential consumers until qualified; rootless container engines need subordinate ID mappings such pods cannot use, and headless Chromium may need its own pid namespace. Whether `--unshare-pid` without a fresh procfs can be added to the qualified configuration is tested during qualification (see Security).

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
3. **A versioned seccomp profile.** NIC owns a complete `Localhost` profile, `nebari-sandbox-v1` (a `Localhost` profile replaces `RuntimeDefault` rather than extending it, so NIC maintains the full allowlist per architecture). It permits the namespace syscalls, makes `clone3` fail so programs fall back to the filterable `clone`, blocks netfilter configuration, and keeps denying the syscall families that widen the kernel surface reachable from a user namespace; mount-related kernel bugs are covered only by patching. A change is a new version (`-v2`) shipped alongside the old ones, reaching nodes through a node-group rolling update that ends users' running sessions on each node; if a fix ever has to land faster, the planned mechanism is a minimal in-node writer added by amending this ADR. Old versions stay until declared consumers have migrated or the operator retires them. The full contents are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#qualified-configurations-and-profile-contents-adr-0022).
4. **Admission.** The provider installs a small ValidatingAdmissionPolicy chart the way providers already install conditional charts (following [ADR-0006](0006-conditional-foundational-software-helm.md)'s provider-driven approach); in hardened mode, ADR-0010's admission policy does the same job. Only namespaces labelled for the capability may reference `nebari-sandbox-v*` or tolerate the dedication taint, and only cluster administrators (including ArgoCD, so GitOps repository write grants it, consistent with ADR-0010) may set that label. Wildcard tolerations and direct node assignment onto these nodes are rejected from unlabelled workload namespaces, with `kube-system` and NIC's foundational namespaces exempt because system DaemonSets rely on wildcard tolerations. Full policy in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full).
5. **Deploy-time check.** As in ADR-0021, `nic deploy` checks live nodes against the node group's prediction. For this capability it also reads each sandbox node's kubelet configuration through the API (`/api/v1/nodes/<node>/proxy/configz`, no pod needed) and confirms `seccompDefault` is on, so a node whose bootstrap failed is reported. A node missing the profile file fails safe: pods that reference the profile do not start there. Results go into the readiness record, shown by `nic outputs`.

### Concrete work this implies

- **NIC's EKS module (`terraform-aws-eks-cluster`):** per-node-group bootstrap configuration (a nodeadm `NodeConfig` setting kubelet `seccompDefault`, plus cloud-init writing the profile files), and node-group labels and taints. Today the module uses its pre-nodeadm hook only for the extra CA bundle.
- **NIC's AWS provider:** plumbing for the `sandbox` block, the image table and profile versions, and an IMDSv2 hop limit of 1 on sandbox node groups' launch template, so pods on them cannot reach the instance metadata service and the node's IAM credentials (later also enforceable with NetworkPolicy once [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) lands).
- **Cluster autoscaler:** confirm scale-from-zero works for tainted, labelled sandbox node groups.
- **System DaemonSets:** `seccompDefault: true` also applies to the VPC CNI, kube-proxy, CSI drivers and monitoring agents on these nodes; each must be tested under `RuntimeDefault`, with any needed exceptions documented as named `Localhost` profiles.
- **Admission policy, profile files and the image table** in NIC's repository, reviewed as security policy.

### What a pack does

Its sandboxing pods carry the node selector and toleration for the dedication taint, reference the profile (`seccompProfile: Localhost`, `localhostProfile: nebari-sandbox-v1.json`), run in a namespace an administrator has labelled for the capability, and invoke bubblewrap around each command, starting from a qualified consumer configuration and binding only what each command needs. A pack must refuse to run commands unsandboxed when the capability is unavailable.

### Verification

- **Per node image, by hand:** before an image enters the table, a probe confirms the capability test and the qualified consumer configuration work with the profile, a pod without the profile on the same node cannot create a user namespace, netfilter and raw-socket creation fail inside a new user namespace, and Unix sockets on the container's filesystem are not reachable from the qualified configuration.
- **At deploy:** the consistency check described above.
- **Consumer acceptance, before the first delivery:** a consumer must show, with the capability in use, that credential canaries in the agent's environment, files and mounted secrets are unreadable by sandboxed commands, inherited descriptors are closed or allowed, networking is denied or limited to the pack's proxy, the instance metadata service is unreachable, its pod settings are correct, and it refuses unsandboxed fallback. Until an upstream pack adopts the capability, a small reference consumer in NIC's user-journey tests fulfils this.

### Security

The capability adds real risk, bounded only by the measures above: `seccompDefault` on its nodes, admission over profiles, taints and the namespace label, a tested netfilter block, prompt kernel patching (NIC shows each node group's image age in `nic outputs`; the operator owns the cadence), and pack-facing documentation of the threat model. Two limits of the qualified configuration must be stated plainly: with the container's `/proc` reused, sandboxed commands can see other processes' command lines in the pod, which can contain credentials; and without a separate pid namespace, a sandboxed command runs as the same host user as the agent and can **signal** the pod's other processes, including killing the agent. Code an agent executes should be treated as attacker-influenced. See [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

### Consequences

**Good:**
- Packs get a supported, documented path to bubblewrap-style sandboxes without privileged pods or `Unconfined` profiles.
- No new long-running components: no operator, no installer, no verifier and no post-bootstrap phase; the admission policy uses ADR-0006's existing mechanism.
- The extra kernel exposure is confined to opted-in, tainted node groups, configured before the kubelet starts.
- The "works by accident" state on AWS is replaced by a versioned, reviewed mechanism.

**Bad:**
- AWS only at first; Hetzner needs a NIC-owned AppArmor profile and an upstream hetzner-k3s fix, and AKS needs a different mechanism.
- NIC owns a complete seccomp policy per architecture and must track runtime default changes.
- `seccompDefault` on these nodes may need exceptions for system DaemonSets.
- EKS module changes for per-node-group bootstrap configuration.
- Profile and kernel updates roll out by replacing nodes, which ends users' running sessions on those nodes.
- A reference consumer, maintained with NIC's user-journey tests until an upstream pack adopts the capability, is one more thing NIC's maintainers own.
- Enabling user namespaces on these node groups widens the kernel attack surface there; kernels must be patched promptly.

## Options Detail

- **Option 1 (do nothing):** no cost, but bubblewrap works only where pods have no syscall filter, which breaks under Pod Security `restricted` and is forbidden by ADR-0010's hardened mode.
- **Option 2 (cluster-wide):** simplest for packs, but exposes the extra kernel surface on nodes running Keycloak, ArgoCD and other foundational services, and contradicts guidance to grant user namespaces narrowly.
- **Option 4 (`runtimeClassName: gvisor` on the existing pod):** a stronger boundary around the pod that needs no user namespaces, NIC-owned seccomp allowlist or AppArmor work, and could reach Hetzner Cloud and AKS sooner; it costs a per-provider gVisor install, compatibility and I/O overhead, and limited GPU support. It protects the **host from the pod**, not the **pod's credentials from the agent's commands**, so it is the right next capability where kernel-exploit risk matters and composes with this one rather than replacing it.
- **Option 5 (`CAP_SYS_ADMIN` in pack pods):** works with no node changes, but on the default runtime it hands the workload a large part of the host kernel's privileged surface and fails Pod Security Baseline. It is acceptable only inside a stronger boundary, where ADR-0021's composition rules allow it.
- **Option 6 (separate, credential-free gVisor pod per session):** meets the threat model without user namespaces on the host, but costs a pod start per session, workspace sharing between pods, permission for the pack to create pods, and re-architecting packs; it depends on `user-space-kernel` existing first, and the Agent Sandbox project could provide its request layer.

Full assessments are in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#adr-0022-admission-policy-and-alternatives-in-full).

## Open Questions

- Hetzner: should NIC own and load an AppArmor profile at boot (a `userns` grant and scoped `mount` rules), making Hetzner the second provider once hetzner-k3s applies per-pool commands to autoscaled nodes?
- AKS: which mechanism, given NIC's AKS module has no node bootstrap hook (the operator-based design in §20.9, an AKS node customisation feature, or waiting for `user-space-kernel`)?
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
