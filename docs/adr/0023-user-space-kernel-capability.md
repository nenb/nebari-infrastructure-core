# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `user-space-kernel`, and on [ADR-0022](0022-in-pod-namespaces-capability.md), whose "Next steps" name this capability as the preferred way to strengthen `in-pod-namespaces`; this ADR cannot be accepted before them. Evidence comes from probe runs on a local VM, EKS and Hetzner (summarised below, detail in [the design doc](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-probe-evidence-in-full)), using test-only installers rather than NIC's implementation.

## Date

2026-10-19

## Context

ADR-0021 lets an agent's commands restrict themselves with Landlock. ADR-0022 lets them run in bubblewrap-style namespace sandboxes, but only where the host allows unprivileged namespaces in pods with no syscall filter: AWS AL2023 today, not Hetzner or AKS, and never under a hardened posture that requires a filter. Both share the host kernel.

[gVisor](https://gvisor.dev/) runs a pod behind its own user-space kernel: the workload's syscalls are handled by gVisor, which reaches the host kernel through a small, filtered set of its own calls. That gives two things NIC's capabilities lack:

- **A stronger boundary between the pod and the host.** A kernel exploit from the workload has to defeat gVisor first, and gVisor's syscall filter and hardening are maintained by the gVisor project, not NIC.
- **Namespaces without host relaxation.** gVisor implements namespaces in its own kernel, so bubblewrap can run inside a gVisor pod whatever the host's seccomp, AppArmor or user-namespace settings.

gVisor alone protects the **host from the pod**, not the **pod's credentials from the agent's commands**, which is the threat model in ADR-0021. Running bubblewrap inside a gVisor pod covers both.

### Evidence

Probe runs used gVisor `release-20261012.0`, non-root pods with every capability dropped, on a local Ubuntu 24.04 VM (2026-10-17), EKS 1.34 AL2023 x86 (2026-10-19 and 2026-10-25, the latter with FSx for OpenZFS from [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705)) and Hetzner Ubuntu 24.04 x86 with k3s (2026-10-25):

| Claim | Result |
|---|---|
| Bubblewrap's qualified configurations (ADR-0022) run inside gVisor and hide environment, home, Secret and service-account canaries, the agent's socket, the network and `169.254.169.254` | Holds on all three; bubblewrap's own `--unshare-net` fails under gVisor ([gVisor #13438](https://github.com/google/gvisor/issues/13438), open), which the qualified configurations avoid by creating the network namespace with `unshare` |
| A sandbox under gVisor can have its own pid namespace and a fresh `/proc` | Holds: only the sandbox's processes are visible and the agent cannot be signalled |
| gVisor installs at node boot on opted-in pools only | Holds on Hetzner (cluster-wide pre-k3s command, including a node the autoscaler created from zero) and on AWS (node bootstrap pulling gVisor as an image from ECR) |
| A failed install never runs a pod unsandboxed | Holds: the node joins and a gVisor pod sent there stays in `ContainerCreating`; but `status.runtimeHandlers` still lists `runsc`, so it cannot detect the failure |
| Storage that presents real ownership works under gVisor | Holds for FSx for OpenZFS (via `fsGroup`) and Longhorn shared and single-writer volumes; EFS access points as NIC configures them fail, because gVisor checks permissions itself |
| Data-science tooling works | pixi, Python shared memory, Dask, file watching, `debugpy`, C-extension builds, SQLite WAL and sandboxed headless Chromium work; attaching `gdb` to an unrelated running process is refused (`ptrace_scope` 1, as on Ubuntu) |
| Performance is acceptable | Metadata-heavy work on network homes 1.4–1.8× slower (for example `pip install` 65 s against 46 s on FSx); JupyterLab startup 0.8–1.6 s slower; large sequential I/O unchanged; idle overhead about 18 MiB per pod |
| Kubernetes integration behaves normally | NetworkPolicy enforced as for runc pods (EKS with enforcement on, hetzner-k3s); Secret and ConfigMap updates reach pods; `dedicated` taint plus `RuntimeClass` toleration route as intended |
| Composition | Landlock is unavailable inside gVisor (`ENOSYS`); gVisor ignores the pod's seccomp profile unless run with `--oci-seccomp` |

Not yet tested: GPUs (`nvproxy`), arm64 nodes, NIC's own implementation of the installation and checks, and upgrading gVisor on existing nodes.

### Precedents

GKE Sandbox installs gVisor on chosen node pools and pods opt in with `runtimeClassName: gvisor`. The [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project and many agent platforms use gVisor the same way. AKS's built-in equivalent, Pod Sandboxing, uses Kata VMs rather than gVisor.

## Decision Drivers

- **Meet the threat model with a stronger boundary.** Fence an agent's commands from the pod's credentials *and* the host from the pod.
- **Relax nothing on the host.** No user namespaces, AppArmor changes or custom seccomp profiles for pods.
- **Let someone else own the hard part.** Prefer a runtime whose security filter is maintained upstream over a NIC-owned policy.
- **Install at boot, not from inside the cluster.** No privileged installer pods.
- **Contain the blast radius.** A failed download, a broken install or a gVisor upgrade must not affect nodes that run foundational services.
- **Reuse ADR-0021's contract:** `sandbox.require`, `InfraSettings.Sandbox`, `nic validate` and `nic deploy` checks, published pod settings.
- **Reach more providers than ADR-0022.** In particular Hetzner Cloud, which has no nested virtualisation.

## Considered Options

1. Do nothing: `in-pod-namespaces` stays AWS-only, and nothing protects the host from the pod.
2. Install gVisor at node boot on every node group of a cluster that requires it, behind a `RuntimeClass`.
3. Install gVisor at node boot only on node groups the operator opts in, route gVisor pods only to nodes whose install succeeded, deliver gVisor as a container image, and never let a failed install stop a node joining.
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers (`vm-boundary`) instead of gVisor.
6. A separate, credential-free gVisor pod per agent session, with a request layer such as Agent Sandbox.
7. ADR-0022's fallback: a NIC-owned seccomp profile on dedicated node groups.

## Decision Outcome

Chosen option: "Option 3", because it delivers a stronger boundary than ADR-0021 and ADR-0022 with no host relaxation, can reach Hetzner as well as AWS, uses a filter the gVisor project maintains, and confines gVisor's installation, upgrades and failures to node groups the operator chose, at the cost of one setting per node group.

### The capability

**`user-space-kernel`:** a pod that sets the `runtimeClassName` NIC publishes for this capability runs behind a user-space kernel that implements the Linux syscall interface, so the workload does not call the host kernel directly. The guarantee names no product; gVisor is its first implementation. It applies to any pod in any pack that sets that `runtimeClassName`: an agent's own pod, a JupyterLab server, an app, a batch job or a per-session sandbox pod.

The qualified consumer, the configuration this ADR has tested, is a long-running, non-root interactive pod with every capability dropped (a JupyterLab server is the reference, being the common case on Nebari today) running ADR-0022's qualified bubblewrap configurations inside it unchanged, optionally with `--proc /proc` in place of the read-only `/proc` bind, which only gVisor allows. Other workloads are expected to work but are not qualified until their pack has tested them.

### What the operator configures

```yaml
cluster:
  aws:
    node_groups:
      general:              # foundational services: untouched
        instance: m6i.xlarge
      user:                 # where pods that run agent code are scheduled
        instance: m6i.xlarge
        sandbox:
          capabilities: [user-space-kernel]
          dedicated: false  # true adds a taint that keeps other workloads off

sandbox:
  require:
    - capability: user-space-kernel
    - capability: in-pod-namespaces   # optional: bubblewrap inside the gVisor pod
```

Opt in whichever node groups host the pods that will request gVisor; when those are users' sessions, the usual choice is to opt in the existing user node group rather than add one. `dedicated: true` follows the GKE Sandbox model for operators who treat agent code as adversarial: the node group is tainted, so only gVisor pods and DaemonSets that tolerate the taint run there.

### What NIC does

1. **`nic validate`.** Each provider reports in `InfraSettings.Sandbox` whether it can install the runtime: AWS and Hetzner yes; Azure no (AKS's native option is Kata, which belongs to `vm-boundary`); `existing` and kind unknown. Requiring the capability with no node group opted in, or opting in a node group on a provider that cannot install it, is an error. On Hetzner it is also an error until the prerequisites below are in NIC.
2. **Installation at node boot, on opted-in node groups only.** The provider adds a boot step to those node groups that installs a pinned gVisor release and registers a containerd runtime handler `runsc` (`plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc`, `runtime_type = "io.containerd.runsc.v1"`) before the kubelet starts, so replacement and autoscaled nodes are covered:
   - **Artifact.** NIC publishes the pinned release archive (`runsc`, its `gvisor-bin/` helpers and the containerd shim, with gVisor's checksum) as a small OCI image, referenced by digest, in a public registry, and operators with private registries mirror it there. The boot step verifies the checksum before installing.
   - **AWS (observed working):** the node group's bootstrap pulls the image with the node's own containerd (AL2023 runs it before the kubelet), using the node role's registry credentials, and adds the handler through nodeadm's containerd configuration merge, since AL2023 has no containerd drop-in directory.
   - **Hetzner:** containerd is part of k3s, which is installed after pre-k3s commands run, so the boot step fetches the image's contents over HTTPS from the registry (with a small static tool such as `oras`, or the registry API) instead of pulling it with containerd, and writes k3s's containerd configuration template. Because per-pool commands do not reach autoscaled nodes, it runs as a cluster-wide pre-k3s command that acts only on nodes whose name shows an opted-in pool. The probe downloaded from gVisor's release bucket and needed `bzip2`, which Hetzner's image lacks; the image delivery above has not yet been tested on Hetzner.
   - **Failure is not fatal, and is recorded explicitly.** If the fetch or install fails, the node still joins without `runsc`. The step records success only after the binaries are verified in place, never by relying on shell error handling, which in the probe logged success after a failed pull.

   gVisor runs in its default mode (systrap), which needs no hardware virtualisation, without `--oci-seccomp`.
3. **Routing only to working nodes.** The step's last action, on success only, is to give the node the label `sandbox.nebari.dev/user-space-kernel-ready: "true"` at registration (k3s reads node labels from its configuration file, which the step writes; on AL2023 the label goes into the kubelet's node labels before nodeadm starts it). NIC creates a `RuntimeClass` named `gvisor` with handler `runsc`, a fixed per-pod `overhead` (64 MiB proposed, against about 18 MiB measured for an idle pod, to be confirmed under real workloads), and a `scheduling` field that selects the ready label (and, with `dedicated: true`, tolerates the node group's taint). Kubernetes adds that selector and toleration to every pod that sets `runtimeClassName: gvisor`, so packs set only the runtime class and their pods never land on a node whose install failed, including nodes added after the deploy. The node-group label `sandbox.nebari.dev/user-space-kernel: "true"`, set on the whole group, records the operator's intent.
4. **`nic deploy` check.** NIC confirms the `RuntimeClass` exists with handler `runsc`, and that every node in an opted-in node group carries the ready label; a node without it fails the deploy when the capability is required, and an opted-in group with no nodes is reported, not failed. `status.runtimeHandlers` is not used as evidence, because it lists `runsc` whenever containerd is configured for it, even when the install failed. Optionally, NIC also runs a short-lived smoke pod on each opted-in node to confirm it reports gVisor's kernel; this would be the first capability whose deploy runs pods, which ADR-0021 deliberately avoided, so it stays optional. For `existing` and kind clusters NIC installs nothing and checks that a `RuntimeClass` named `gvisor` exists and that its handler is listed on at least one node. Results are shown by `nic outputs`.
5. **Published pod settings:** `runtimeClassName: gvisor`, `seccompProfile` unset (gVisor ignores it, and NIC does not enable `--oci-seccomp`). These are this capability's settings only: requiring `user-space-kernel` does not change the published settings of any other capability (see "Combining capabilities").
6. **Storage for gVisor pods.** gVisor checks file permissions itself, against the ownership the filesystem reports, before a request reaches the storage. Volumes that gVisor pods write to must present real POSIX ownership matching the pod's UID or `fsGroup`; storage that rewrites identities on the server, such as EFS access points as NIC configures them today, does not work. The storage NIC is moving to ([PR #586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)) passed: FSx for OpenZFS homes through `fsGroup`, and Longhorn shared and single-writer volumes on Hetzner. NIC documents the rule for packs, which state the UID and `fsGroup` their pods run with.

**Hetzner prerequisites.** NIC's Hetzner provider needs, before this capability is offered there: node-pool labels and pre-k3s boot commands in its generated hetzner-k3s configuration (the probe used a local template patch for both); the NFS client on nodes, without which Longhorn shared volumes do not mount at all; and the NIC team's fix for the metadata service exposing the k3s join token to pods on autoscaled nodes (see "Related issues").

### Combining capabilities

Each capability's published settings mean the same thing on every cluster that provides it, and a capability never silently pulls in another. A pack that wants several applies each one's settings, so running bubblewrap inside gVisor is a choice the pack makes, not a side effect of the operator's configuration:

| The pack wants | It applies the settings of | Result |
|---|---|---|
| Bubblewrap only | `in-pod-namespaces` | Bubblewrap on the host kernel, where the host provides it (AL2023); no gVisor |
| Bubblewrap inside gVisor | `user-space-kernel` and `in-pod-namespaces` | Bubblewrap inside gVisor: the qualified consumer of this capability |
| gVisor only | `user-space-kernel` | The pod runs under gVisor with no inner sandbox |
| Landlock and bubblewrap | `process-self-restriction` and `in-pod-namespaces` | Host kernel (AL2023) |
| Landlock and gVisor | `process-self-restriction` and `user-space-kernel` | Not supported: Landlock is unavailable inside gVisor. Documented, and caught by the pack's startup check |

`in-pod-namespaces` inside a gVisor pod needs nothing from the host, so on a cluster that provides `user-space-kernel` the combination of both is available even where `in-pod-namespaces` alone is not. **Where the host cannot provide `in-pod-namespaces` (Hetzner), NIC does not advertise it on its own:** a pack there requires both, and `nic validate` reports a requirement for `in-pod-namespaces` without `user-space-kernel` on such a provider as an error that names the combination. ADR-0022's host checks apply only to `in-pod-namespaces` used on its own. When both are required, NIC's deploy check covers only gVisor; that bubblewrap works inside gVisor is a property of the pinned gVisor and bubblewrap releases, so it is established by maintainers' release testing on each upgrade rather than per cluster, and each pack's startup check remains the final guard.

### What a pack does

It sets the published `runtimeClassName` on the pod that runs the agent and applies the other published settings as given. If it uses bubblewrap inside the pod, it uses ADR-0022's qualified configurations as they are, so the same pack code runs on runc and under gVisor without detecting which; under gVisor it may add a fresh `/proc` (`--proc /proc`) to hide other processes' command lines. It checks at startup that the sandbox works, and refuses to run commands unsandboxed if it does not. It must not rely on Landlock inside the gVisor pod. Environments and package caches belong on local or ephemeral storage rather than a network-backed home directory, where metadata-heavy work is slow with or without gVisor.

### Verification

Before a provider and node image family are listed, and on every gVisor upgrade, a maintainer runs the probe on real nodes (sandbox probe brief, Part C): bubblewrap's qualified configurations and a fresh `/proc` inside gVisor, canaries hidden, no network from inside the sandbox, Landlock reported absent, `RuntimeDefault` ignored, Kubernetes volume updates visible, NetworkPolicy enforced, PVC-backed homes writable, and timings. The upgrade run also re-checks bubblewrap's own `--unshare-net`, so guidance can relax once gVisor #13438 is fixed.

### Security

- **Stronger than ADR-0021 and ADR-0022, but not a VM.** gVisor is a user-space kernel sharing the host; an escape from gVisor reaches the host and whatever else runs on the node. Code an agent executes should still be treated as attacker-influenced.
- **gVisor's own trade-offs.** By default gVisor uses *directfs*, which lets it open host files directly for performance rather than through a separate file proxy; that narrows the isolation around file access, and operators who want the stricter path can disable it at a performance cost. The default *systrap* platform, needed where there is no hardware virtualisation (Hetzner Cloud), intercepts syscalls without the extra isolation of gVisor's KVM platform. gVisor has shipped security fixes over time, so NIC follows its releases and rolls opted-in node groups promptly.
- **No host relaxation and no privileged pods.** Installation happens at boot, outside the cluster, and only on opted-in node groups. NIC publishes the gVisor artifact and takes on supply-chain responsibility for it: pinned by digest, checksum-verified against gVisor's release.
- **Shared or dedicated nodes.** By default opted-in node groups can also run other workloads, which fits ADR-0021's threat model as long as foundational services run elsewhere; with `dedicated: true` they run nothing else, the right choice where agent code is treated as adversarial.
- **Network.** gVisor uses its own network stack inside the pod, but traffic leaves through the pod's normal interface, and NetworkPolicy applies as for other pods. On AWS the instance metadata service is unreachable from pods because NIC's node groups require IMDSv2 with a hop limit of 1; on Hetzner this capability depends on the NIC team's fix for its metadata service.
- **Storage endpoints.** gVisor does not stop a pod from talking to network storage directly: in the probe, an unprivileged pod under runc or gVisor read another user's Longhorn shared volume and read and wrote another user's FSx for OpenZFS volume, using a user-space NFS client. The sandbox's no-network configuration blocks this for the agent's commands; for the pod itself it depends on the NIC team's storage and NetworkPolicy work (see "Related issues").
- **Composition.** Landlock does not work inside gVisor, so `process-self-restriction` does not combine with this capability.
- **Seccomp settings are ignored, and compliance tools will not notice.** Without `--oci-seccomp`, a gVisor pod's `seccompProfile` is not applied: a pod can declare `RuntimeDefault`, pass a policy check that requires it, and run without that filter. The workload is still behind gVisor's own syscall implementation and host-side filter, the stronger boundary, but what is declared is not what is enforced. Documentation for hardened mode ([ADR-0010](0010-high-security-mode.md)) and for auditors says so. Enabling `--oci-seccomp` would make declared profiles real, at the cost of blocking bubblewrap under `RuntimeDefault`; it is recorded here for operators who need that.

### Consequences

**Good:**
- A much stronger boundary between the pod and the host, maintained upstream, with no host relaxation and no in-cluster installer.
- Installation, upgrades and install failures touch only opted-in node groups, and pods are only routed to nodes whose install succeeded.
- Bubblewrap inside gVisor reaches Hetzner, where `in-pod-namespaces` alone cannot, and gains a fresh `/proc` and pid namespace, closing ADR-0022's signalling and command-line gaps.
- Packs add only `runtimeClassName`.

**Bad:**
- I/O overhead: metadata-heavy work on network homes 1.4–1.8× slower and JupyterLab startup up to 1.6 s slower; most data-science tooling works, but attaching a debugger to an unrelated running process does not.
- Storage must present real ownership: EFS access points as NIC configures them do not work, and each storage backend has to be qualified under gVisor.
- Implementation work in NIC: a per-node-group setting and boot step in each provider (on AWS, per-node-group bootstrap in NIC's EKS module; on Hetzner, pool labels and boot commands in the generated hetzner-k3s configuration, plus the NFS client on nodes), a published gVisor image, the ready label, the `RuntimeClass` and the checks.
- NIC owns version pinning, checksum verification and upgrades, which replace the opted-in nodes and end users' sessions on them.
- Limited GPU support: GPU pods under gVisor need its `nvproxy` support, which this ADR does not qualify. No AKS support; AKS needs `vm-boundary` instead.
- Landlock is unavailable inside gVisor pods, and bubblewrap's own `--unshare-net` stays unusable there until gVisor #13438 is fixed.

## Options Detail

- **Option 1 (do nothing):** no cost, but `in-pod-namespaces` stays AWS-only and unfiltered, and no capability protects the host from the pod.
- **Option 2 (boot-time install on every node group):** no per-node-group setting and no scheduling rules, but every node of the cluster then depends on the install succeeding, every gVisor upgrade rolls every node including foundational ones, and gVisor pods can land next to foundational services.
- **Option 3 (opt-in node groups, ready label, image delivery, non-fatal install; chosen):** confines download, failures and upgrades to the node groups that need gVisor, routes only to working nodes, and offers GKE-style dedication as a setting. Delivery alternatives considered within it: downloading from gVisor's release bucket at each boot (no NIC artifact, but every boot depends on an external site, which proxies or restricted egress break, and the release format has already changed once); a NIC-controlled copy in an S3 bucket created with the cluster (AWS only); and custom node images with gVisor baked in (nothing downloaded at boot, but a node-image pipeline per provider).
- **Option 4 (privileged DaemonSet installer):** easy to ship, and Kata's own installer works this way, but it is a privileged, host-trusted component in the cluster (ADR-0021's privileged node-agent tier), must restart containerd on running nodes, and races new nodes joining unless a startup taint holds them back.
- **Option 5 (Kata, `vm-boundary`):** a hardware boundary with a guest kernel, but it needs nested virtualisation or bare metal (unavailable on Hetzner Cloud and limited to particular instance families on EC2), plus higher per-pod memory and start-up cost. The natural route on AKS, and a later ADR.
- **Option 6 (a gVisor pod per session):** the strongest design for the threat model, since commands run where the agent's credentials never are, but it costs a pod start per session, workspace sharing and permission for packs to create pods, and it re-architects packs. It builds on this ADR's `RuntimeClass` and can follow it, with Agent Sandbox as a candidate request layer.
- **Option 7 (NIC-owned seccomp profile):** keeps bubblewrap on the host kernel with a NIC-maintained allowlist per architecture, AppArmor work for Hetzner and no AKS route; weaker and more work. Remains ADR-0022's fallback if gVisor proves impractical.

## Open Questions

- Where does NIC publish the gVisor image, and how do operators with private registries mirror it?
- How exactly is the ready label applied on AL2023, given nodeadm generates the kubelet's configuration (on k3s it is a line in its configuration file)?
- Is 64 MiB the right `RuntimeClass` overhead once measured under JupyterLab and agent workloads?
- Should GPU node groups qualify with `nvproxy`, and arm64 (Graviton) node groups?
- Does this capability make ADR-0022's first implementation unnecessary on AWS, or should both remain (host bubblewrap without gVisor's overhead, and bubblewrap inside gVisor)?

## Related issues

Found while probing for this ADR and being addressed by the NIC team; this ADR depends on the first and third on Hetzner:

- Hetzner's metadata service exposes the k3s join token to pods on autoscaled nodes.
- Pods can reach other users' shared volumes over NFS (Longhorn share-managers; FSx for OpenZFS as configured in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705)).
- Longhorn shared volumes do not mount on NIC's Hetzner nodes, which lack the NFS client.

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
