# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `user-space-kernel`, and on [ADR-0022](0022-in-pod-namespaces-capability.md), whose "Next steps" name this capability as the preferred way to strengthen `in-pod-namespaces`; this ADR cannot be accepted before them. Evidence: a local probe (2026-10-17) and an EKS 1.34 run with gVisor installed by a test-only DaemonSet (2026-10-19); installation at node boot, autoscaling and Hetzner are not yet tested.

## Date

2026-10-19

## Context

ADR-0021 lets an agent's commands restrict themselves with Landlock. ADR-0022 lets them run in bubblewrap-style namespace sandboxes, but only where the host allows unprivileged namespaces in pods with no syscall filter: AWS AL2023 today, not Hetzner or AKS, and never under a hardened posture that requires a filter. Both share the host kernel.

[gVisor](https://gvisor.dev/) runs a pod behind its own user-space kernel: the workload's syscalls are handled by gVisor, which reaches the host kernel through a small, filtered set of its own calls. That gives two things NIC's capabilities lack:

- **A stronger boundary between the pod and the host.** A kernel exploit from the workload has to defeat gVisor first, and gVisor's syscall filter and hardening are maintained by the gVisor project, not NIC.
- **Namespaces without host relaxation.** gVisor implements namespaces in its own kernel, so bubblewrap can run inside a gVisor pod whatever the host's seccomp, AppArmor or user-namespace settings.

gVisor alone protects the **host from the pod**, not the **pod's credentials from the agent's commands**, which is the threat model in ADR-0021. Running bubblewrap inside a gVisor pod covers both.

### What a local probe showed

On an Ubuntu 24.04 VM (kernel 6.8, arm64; the OS and kernel Hetzner uses) with Docker and gVisor `release-20261012.0`, non-root and with every capability dropped (2026-10-17; `tests/sandbox-probe/gvisor-local/`):

- Bubblewrap's qualified configurations from ADR-0022 work inside gVisor and hide environment, home-directory and service-account canaries, sockets outside the bound paths, and the network (including `169.254.169.254`), with one workaround: bubblewrap's own `--unshare-net` fails because gVisor pre-configures the new namespace's loopback ([gVisor #13438](https://github.com/google/gvisor/issues/13438), open; [bubblewrap #745](https://github.com/containers/bubblewrap/issues/745), open). Creating the network namespace first with `unshare --user --map-current-user --net` and running bubblewrap without `--unshare-net` works.
- A sandbox can have its own pid namespace and a fresh `/proc`, which a normal container cannot. That closes the two limits ADR-0022 states: sandboxed commands can no longer signal the agent or read other processes' command lines.
- Landlock is not available inside gVisor (`ENOSYS`).
- gVisor ignores the pod's seccomp profile unless configured with `--oci-seccomp`; with it, `RuntimeDefault` blocks bubblewrap.
- JupyterLab startup and notebook execution ran with little overhead (about 0.1–0.25 s). Metadata-heavy work on an NFS-backed home directory was 1.5–2.3× slower than without gVisor, on top of network latency that already made it slow; large sequential I/O was unaffected.

### What an EKS probe showed

On an EKS 1.34 cluster deployed with NIC (AL2023 x86, kernel 6.12, containerd 2.3.5; 2026-10-19), with gVisor `release-20261012.0` installed on one node group behind a `RuntimeClass`:

- Every bubblewrap result above held, including the `--unshare-net` failure and its workaround, the fresh `/proc`, `RuntimeDefault` being ignored, and Landlock's absence.
- The node's `status.runtimeHandlers` listed `runsc` once containerd was configured, so the deploy check can read it without running a pod.
- With NetworkPolicy enforcement turned on in the VPC CNI (it is off in NIC's EKS clusters today, see #691), default-deny egress blocked gVisor pods exactly as it blocked runc pods, and an allow rule restored only the allowed destination.
- Secret and ConfigMap updates reached gVisor pods within the kubelet's sync period (about 45 s in this run).
- The instance metadata service was unreachable from gVisor pods, because NIC's EKS node groups require IMDSv2 with a hop limit of 1.
- With home directories on EFS, metadata-heavy work was 1.5–1.8× slower under gVisor than under runc (for example `pip install` 192 s against 132 s), on top of EFS latency that already dominated; JupyterLab started about 0.7 s slower.
- **EFS access points broke gVisor pods.** With NIC's `efs-sc` storage class, each volume's access point owns its directory as its own UID (50000 and up) with mode 700. A runc pod running as UID 1000 can write there, because the kernel's NFS client leaves the decision to EFS, which maps every request to the access point's UID. gVisor checks permissions itself against the owner and refuses. A storage class whose access points use the pod's UID and GID worked under both runtimes.
- The gVisor release ships as one archive per architecture; `runsc` needs the `gvisor-bin/` helper binaries from it (including `gvisor_sentry`) installed beside it.

### Precedents

GKE Sandbox installs gVisor on chosen node pools and pods opt in with `runtimeClassName: gvisor`. The [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project and many agent platforms use gVisor the same way. AKS's built-in equivalent, Pod Sandboxing, uses Kata VMs rather than gVisor.

## Decision Drivers

- **Meet the threat model with a stronger boundary.** Fence an agent's commands from the pod's credentials *and* the host from the pod.
- **Relax nothing on the host.** No user namespaces, AppArmor changes or custom seccomp profiles for pods.
- **Let someone else own the hard part.** Prefer a runtime whose security filter is maintained upstream over a NIC-owned policy.
- **Install at boot, not from inside the cluster.** No privileged installer pods.
- **Reuse ADR-0021's contract:** `sandbox.require`, `InfraSettings.Sandbox`, `nic validate` and `nic deploy` checks, published pod settings.
- **Reach more providers than ADR-0022.** In particular Hetzner Cloud, which has no nested virtualisation.

## Considered Options

1. Do nothing: `in-pod-namespaces` stays AWS-only, and nothing protects the host from the pod.
2. Install gVisor at node boot on every NIC-provisioned node group of a cluster that requires it, behind a `RuntimeClass`; no taints.
3. As Option 2, but only on dedicated, tainted node groups (the GKE Sandbox model).
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers (`vm-boundary`) instead of gVisor.
6. A separate, credential-free gVisor pod per agent session, with a request layer such as Agent Sandbox.
7. ADR-0022's fallback: a NIC-owned seccomp profile on dedicated node groups.

## Decision Outcome

Chosen option: "Option 2", because it delivers a stronger boundary than ADR-0021 and ADR-0022 with no host relaxation, can reach Hetzner as well as AWS, uses a filter the gVisor project maintains, and needs the least configuration: the operator only adds a requirement.

### The capability

**`user-space-kernel`:** a pod that sets the `runtimeClassName` NIC publishes for this capability runs behind a user-space kernel that implements the Linux syscall interface, so the workload does not call the host kernel directly. The guarantee names no product; gVisor is its first implementation.

The qualified consumer is a JupyterLab-style pod, non-root with every capability dropped, running ADR-0022's qualified bubblewrap configurations inside it with the network-namespace workaround, and with `--unshare-pid --proc /proc` added.

### What the operator configures

```yaml
sandbox:
  require:
    - capability: user-space-kernel
    - capability: in-pod-namespaces   # optional: bubblewrap inside the gVisor pod
```

No node-group setting is needed: gVisor relaxes nothing on the host, so it can be installed on every node group without dedicating any.

### What NIC does

1. **`nic validate`.** Each provider reports in `InfraSettings.Sandbox` whether it can install the runtime: AWS and Hetzner yes; Azure no (AKS's native option is Kata, which belongs to `vm-boundary`); `existing` and kind unknown. A known "no" with the capability required is an error.
2. **Installation at node boot.** When the capability is required, the provider installs a pinned gVisor release (the release archive, checksum-verified as NIC already does for `hetzner-k3s`, providing `runsc`, its `gvisor-bin/` helpers and the containerd shim) and registers a containerd runtime handler `runsc` before the kubelet starts:
   - **AWS:** through each node group's bootstrap (a nodeadm `NodeConfig` adding the containerd runtime handler, plus a pre-bootstrap step installing the binaries), so replacement and autoscaled nodes are ready when they join.
   - **Hetzner:** through hetzner-k3s's cluster-wide pre-k3s commands and k3s's containerd configuration template. Cluster-wide commands also reach autoscaled nodes, which per-pool commands currently do not.

   The handler is added to containerd's version 3 configuration (`plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc` with `runtime_type = "io.containerd.runsc.v1"`); AL2023's containerd configuration has no drop-in directory, so on AWS it goes through nodeadm's containerd configuration merge. gVisor runs in its default mode (systrap), which needs no hardware virtualisation, and without `--oci-seccomp`.
3. **The `RuntimeClass`.** After bootstrap, NIC creates a `RuntimeClass` named `gvisor` with handler `runsc` and a fixed per-pod `overhead`, measured during qualification, so the scheduler accounts for gVisor's memory. It needs no `scheduling` field, because every node group has the runtime.
4. **`nic deploy` check.** NIC confirms the `RuntimeClass` exists and that each node's `status.runtimeHandlers` lists `runsc` (reported by containerd 2.x, as on EKS AL2023); a node without it fails the deploy when the capability is required. For `existing` and kind clusters NIC installs nothing and checks only that a `RuntimeClass` named `gvisor` exists. Results are shown by `nic outputs`.
5. **Published pod settings:** `runtimeClassName: gvisor`, `seccompProfile` unset (gVisor ignores it, and NIC does not enable `--oci-seccomp`). These are this capability's settings only: requiring `user-space-kernel` does not change the published settings of any other capability (see "Combining capabilities").
6. **Storage for gVisor pods.** Volumes that gVisor pods write to must present files owned by the pod's UID, because gVisor enforces file permissions itself. For EFS, NIC configures the storage class used for home directories so its access points use the pod's UID and GID (the EFS CSI driver's `uid` and `gid` parameters), or provides a separate storage class for gVisor workloads; packs document the UID their pods run as. NIC's current `efs-sc` defaults (a per-volume UID from 50000 with mode 700) do not work under gVisor.

### Combining capabilities

Each capability's published settings mean the same thing on every cluster that provides it, and a capability never silently pulls in another. A pack that wants several applies each one's settings, so running bubblewrap inside gVisor is a choice the pack makes, not a side effect of the operator's configuration:

| The pack wants | It applies the settings of | Result |
|---|---|---|
| Bubblewrap only | `in-pod-namespaces` | Bubblewrap on the host kernel, where the host provides it (AL2023); no gVisor |
| Bubblewrap inside gVisor | `user-space-kernel` and `in-pod-namespaces` | Bubblewrap inside gVisor: the qualified consumer of this capability |
| gVisor only | `user-space-kernel` | The pod runs under gVisor with no inner sandbox |
| Landlock and bubblewrap | `process-self-restriction` and `in-pod-namespaces` | Host kernel (AL2023) |
| Landlock and gVisor | `process-self-restriction` and `user-space-kernel` | Not supported: Landlock is unavailable inside gVisor. Documented, and caught by the pack's startup check |

`in-pod-namespaces` inside a gVisor pod needs nothing from the host, so on a cluster that provides `user-space-kernel` the combination of both is available even where `in-pod-namespaces` alone is not. **Where the host cannot provide `in-pod-namespaces` (Hetzner), NIC does not advertise it on its own:** a pack there requires `user-space-kernel` and `in-pod-namespaces` together, and `nic validate` reports a requirement for `in-pod-namespaces` without `user-space-kernel` on such a provider as an error that names the combination. ADR-0022's host checks apply only to `in-pod-namespaces` used on its own; when both capabilities are required, the inner capability is checked as part of `user-space-kernel`.

### What a pack does

It sets the published `runtimeClassName` on the pod that runs the agent and applies the other published settings as given. If it uses bubblewrap inside the pod, it creates the network namespace with `unshare` before calling bubblewrap without `--unshare-net` until gVisor #13438 is fixed, adds `--unshare-pid --proc /proc`, checks at startup that the sandbox works, and refuses to run commands unsandboxed if it does not. It must not rely on Landlock inside the gVisor pod. Environments and package caches belong on local or ephemeral storage rather than a network-backed home directory, where metadata-heavy work is slow with or without gVisor.

### Verification

Before a provider and node image family are listed, a maintainer runs the probe on real nodes: bubblewrap's qualified configurations with the workaround and a fresh `/proc`, canaries hidden, no network from inside the sandbox, Landlock reported absent, `RuntimeDefault` ignored, Kubernetes volume updates visible in the pod, NetworkPolicy enforced for gVisor pods, and JupyterLab timings with EFS-backed home directories (sandbox probe brief, Part C). The `--unshare-net` workaround is re-tested on each gVisor upgrade, so the published guidance can drop it once the upstream bug is fixed.

### Security

- **Stronger than ADR-0021 and ADR-0022, but not a VM.** gVisor is a user-space kernel sharing the host; an escape from gVisor reaches the host. Code an agent executes should still be treated as attacker-influenced.
- **No host relaxation and no privileged pods.** Installation happens at boot, outside the cluster; the gVisor binaries are pinned and checksum-verified, so NIC takes on supply-chain responsibility for them and must follow gVisor security releases.
- **Shared nodes.** gVisor pods share nodes with foundational services. That fits ADR-0021's threat model; operators who want GKE-style separation can dedicate node groups (Option 3, an open question below).
- **Network.** gVisor uses its own network stack inside the pod, but traffic leaves through the pod's normal interface, and NetworkPolicy applies as for other pods (observed on EKS with VPC CNI enforcement on). On AWS the instance metadata service is unreachable from pods because NIC's node groups require IMDSv2 with a hop limit of 1; on Hetzner it depends on the provider's metadata service and NetworkPolicy.
- **Composition.** Landlock does not work inside gVisor, so `process-self-restriction` does not combine with this capability.

### Consequences

**Good:**
- A much stronger boundary between the pod and the host, maintained upstream, with no host relaxation, no taints and no in-cluster installer.
- Bubblewrap inside gVisor reaches Hetzner, where `in-pod-namespaces` alone cannot, and gains a fresh `/proc` and pid namespace, closing ADR-0022's signalling and command-line gaps.
- The operator adds one line of config; packs add `runtimeClassName`.

**Bad:**
- I/O overhead and compatibility gaps for some workloads; metadata-heavy work on network storage is the most visible cost.
- Storage classes must give gVisor pods files owned by their UID: NIC's current EFS access-point defaults do not work.
- Limited GPU support: GPU pods under gVisor need its `nvproxy` support, which this ADR does not qualify.
- No AKS support; AKS needs `vm-boundary` instead.
- NIC owns gVisor installation in each provider's bootstrap, version pinning, checksum verification and upgrades (which replace nodes and end users' sessions on them).
- The bubblewrap workaround is a wart in pack code until gVisor #13438 is fixed.
- Landlock is unavailable inside gVisor pods.

## Options Detail

- **Option 1 (do nothing):** no cost, but `in-pod-namespaces` stays AWS-only and unfiltered, and no capability protects the host from the pod.
- **Option 2 (boot-time install everywhere; chosen):** least configuration and no dedication, because gVisor relaxes nothing on the host; costs the runtime on every node of a cluster that requires it, and co-location with foundational services.
- **Option 3 (dedicated, tainted node groups):** GKE's model; separates gVisor workloads from foundational services and limits where the runtime is installed. It adds a per-node-group opt-in, labels, taints and a `RuntimeClass` `scheduling` field, and on Hetzner depends on the hetzner-k3s fix for autoscaled pools. Kept as an open question.
- **Option 4 (privileged DaemonSet installer):** avoids bootstrap changes, but is a privileged, host-trusted component in the cluster (ADR-0021's privileged node-agent tier), must restart containerd on running nodes, and races new nodes joining.
- **Option 5 (Kata, `vm-boundary`):** a hardware boundary with a guest kernel, but needs nested virtualisation or bare metal, which Hetzner Cloud and most EKS instance types lack, plus higher per-pod memory and start-up cost. The natural route on AKS, and a later ADR.
- **Option 6 (a gVisor pod per session):** the strongest design for the threat model, since commands run where the agent's credentials never are, but it costs a pod start per session, workspace sharing and permission for packs to create pods, and it re-architects packs. It builds on this ADR's `RuntimeClass` and can follow it, with Agent Sandbox as a candidate request layer.
- **Option 7 (NIC-owned seccomp profile):** keeps bubblewrap on the host kernel with a NIC-maintained allowlist per architecture, AppArmor work for Hetzner and no AKS route; weaker and more work. Remains ADR-0022's fallback if gVisor proves impractical.

## Open Questions

- Should the default be dedicated, tainted node groups (Option 3) rather than every node group?
- Does k3s on Hetzner report `node.status.runtimeHandlers` as EKS AL2023 does, or does the deploy check need a short-lived smoke pod there?
- Should NIC change `efs-sc` itself to use a fixed UID and GID for all clusters, or add a separate storage class only when this capability is required?
- What fixed `overhead` should the `RuntimeClass` declare?
- Should NIC publish a structured hint for the bubblewrap network-namespace workaround, or only document it until gVisor #13438 is fixed?
- Should GPU node groups qualify with `nvproxy`, and arm64 (Graviton) node groups?
- Does this capability make ADR-0022's first implementation unnecessary on AWS, or should both remain (host bubblewrap without gVisor's overhead, and bubblewrap inside gVisor)?

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0022: In-Pod Namespace Sandboxes](0022-in-pod-namespaces-capability.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [gVisor](https://gvisor.dev/)
- [gVisor #13438: bwrap --unshare-net fails](https://github.com/google/gvisor/issues/13438)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
