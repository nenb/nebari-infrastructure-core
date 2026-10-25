# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `user-space-kernel`, and on [ADR-0022](0022-in-pod-namespaces-capability.md), whose "Next steps" name this capability as the preferred way to strengthen `in-pod-namespaces`; this ADR cannot be accepted before them. Evidence: a local probe (2026-10-17), an EKS 1.34 run (2026-10-19), and Hetzner and EKS-with-FSx runs including installation at node boot and autoscaling (2026-10-25), using test-only installers and a local patch to NIC's Hetzner template. GPUs and arm64 nodes are not yet tested.

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

### What the Hetzner and FSx probe showed

On a Hetzner cluster deployed with NIC (Ubuntu 24.04, kernel 6.8, k3s with containerd 2.2) and an EKS 1.34 cluster with FSx for OpenZFS from [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705) (2026-10-25):

- **Bubblewrap inside gVisor works on Hetzner** with ADR-0022's single qualified configuration: canaries, the agent's socket, the network and the metadata address hidden, signalling blocked, and a fresh `/proc` showing only the sandbox's processes. On the same nodes, bubblewrap outside gVisor failed at AppArmor, as ADR-0022 predicts.
- **Installation at boot works on both providers.** On Hetzner, a cluster-wide pre-k3s command that acted only on nodes of opted-in pools installed gVisor and the k3s containerd template, including on a node the autoscaler created from zero (pod pending to running in under two minutes); pool labels routed the pod. Hetzner's image lacks `bzip2`, which the release archive needs. On AWS, a node group's bootstrap (a nodeadm `NodeConfig` adding the runtime handler, plus a script) pulled gVisor as an image from ECR with `ctr` and installed it.
- **A failed install is fail-safe but not visible to `runtimeHandlers`.** With a bad image tag, the node still joined; a gVisor pod sent there stayed in `ContainerCreating` (`failed to resolve runtime path`) rather than running unsandboxed. But the node still listed `runsc` in `status.runtimeHandlers`, which reflects containerd's configuration, not the installed binary. The probe's own install script also logged success after the failure, because shell error handling (`set -e`) is ignored inside a `( … ) || …` construct.
- **k3s reports `status.runtimeHandlers`**, with `runsc` listed only on nodes where it was configured.
- **Storage:** FSx for OpenZFS homes (owned through the pod's `fsGroup`) and Longhorn shared and single-writer volumes were writable from gVisor pods, with setgid directories passing their group on, as the ownership analysis predicted. Longhorn shared volumes needed the NFS client installed on the node first (see "Findings for NIC beyond sandboxing").
- **Compatibility:** under gVisor, pixi environments (about 1.5–2× slower to build on local disk), Python shared memory, a local Dask cluster, file watching, `debugpy`, C-extension builds, SQLite in WAL mode on the shared home, and headless Chromium with its own sandbox all worked. Attaching `gdb` to an unrelated running process was refused (gVisor reports `ptrace_scope` 1, as Ubuntu does); launching a program under `gdb` worked.
- **Performance (median of three):** with an FSx home, `pip install` into a fresh environment took 65 s under gVisor against 46 s under runc, and 5,000 small-file operations 40 s against 24 s; with a Longhorn shared home on Hetzner, 141 s against 100 s and 84 s against 49 s. JupyterLab startup was 1–1.6 s slower; large sequential I/O was unchanged.
- **Overhead:** an idle gVisor pod used about 18 MiB more memory than the same pod under runc.
- **`dedicated: true`:** with the node group tainted and the `RuntimeClass` carrying the toleration, gVisor pods landed on it, an ordinary pod pinned there stayed pending, and system DaemonSets kept running.
- **NetworkPolicy:** hetzner-k3s enforced it for gVisor pods as for runc pods.

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
3. Install gVisor at node boot only on node groups the operator opts in, labelled (and optionally tainted) so a `RuntimeClass` steers gVisor pods to them; deliver gVisor as a container image; never let a failed install stop a node joining.
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers (`vm-boundary`) instead of gVisor.
6. A separate, credential-free gVisor pod per agent session, with a request layer such as Agent Sandbox.
7. ADR-0022's fallback: a NIC-owned seccomp profile on dedicated node groups.

## Decision Outcome

Chosen option: "Option 3", because it delivers a stronger boundary than ADR-0021 and ADR-0022 with no host relaxation, can reach Hetzner as well as AWS, uses a filter the gVisor project maintains, and confines gVisor's installation, upgrades and failures to node groups the operator chose, at the cost of one setting per node group.

### The capability

**`user-space-kernel`:** a pod that sets the `runtimeClassName` NIC publishes for this capability runs behind a user-space kernel that implements the Linux syscall interface, so the workload does not call the host kernel directly. The guarantee names no product; gVisor is its first implementation. The capability applies to any pod in any pack that sets that `runtimeClassName`: an agent's own pod, a JupyterLab server, an app, a batch job or a per-session sandbox pod.

The qualified consumer, the configuration this ADR has tested, is a long-running, non-root interactive pod with every capability dropped (a JupyterLab server is the reference, being the common case on Nebari today) running ADR-0022's qualified bubblewrap configurations inside it unchanged (they already create the network namespace with `unshare` and add a pid namespace, a form that works on runc and gVisor alike), optionally with `--proc /proc` in place of the read-only `/proc` bind, which only gVisor allows. Other workloads are expected to work but are not qualified until their pack has tested them.

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

Opt in whichever node groups host the pods that will request gVisor; when those are users' sessions, the usual choice is to opt in the existing user node group rather than add one. `dedicated: true` follows the GKE Sandbox model for operators who treat agent code as adversarial: the node group is tainted, so only gVisor pods (and system DaemonSets, which tolerate every taint) run there.

### What NIC does

1. **`nic validate`.** Each provider reports in `InfraSettings.Sandbox` whether it can install the runtime: AWS and Hetzner yes; Azure no (AKS's native option is Kata, which belongs to `vm-boundary`); `existing` and kind unknown. Requiring the capability with no node group opted in, or opting in a node group on a provider that cannot install it, is an error.
2. **Installation at node boot, on opted-in node groups only.** The provider adds a boot step to those node groups that installs a pinned gVisor release and registers a containerd runtime handler `runsc` before the kubelet starts, so replacement and autoscaled nodes are ready when they join:
   - **Delivery.** gVisor is delivered as a small container image carrying the pinned, checksum-verified release archive (`runsc`, its `gvisor-bin/` helpers and the containerd shim), published by NIC and pulled at boot from a registry the cluster already uses, so registry mirrors, proxies and restricted-egress setups apply to it as to every other image. The boot step pulls the image with containerd and extracts the binaries.
   - **Failure is not fatal, and is reported explicitly.** If the pull or install fails, the node still joins without `runsc`. It still carries its node group's label, so a gVisor pod scheduled there fails to start rather than running unsandboxed (observed). The install step records success or failure explicitly (for example a marker file written only after the binaries are verified in place), rather than relying on shell error handling, which the probe showed can report success after a failure.
   - **AWS (observed working):** through those node groups' bootstrap (a nodeadm `NodeConfig` adding the runtime handler, plus a pre-bootstrap install step); AL2023's containerd configuration has no drop-in directory, so the handler goes through nodeadm's configuration merge.
   - **Hetzner (observed working, including autoscaled nodes):** hetzner-k3s per-pool commands do not reach autoscaled nodes, so the install runs as a cluster-wide pre-k3s command that acts only on nodes whose name shows an opted-in pool (hetzner-k3s includes the pool name in node names), together with k3s's containerd configuration template. Hetzner's image lacks `bzip2`, so the step installs it or uses the image delivery above. NIC's Hetzner provider needs node-pool label support for the next step.

   The handler is added to containerd's version 3 configuration (`plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc` with `runtime_type = "io.containerd.runsc.v1"`). gVisor runs in its default mode (systrap), which needs no hardware virtualisation, and without `--oci-seccomp`.
3. **Labels, taints and the `RuntimeClass`.** Opted-in node groups carry the node-group label `sandbox.nebari.dev/user-space-kernel: "true"`, through the same node-group label mechanism as GPU groups, and with `dedicated: true` the matching taint. NIC creates a `RuntimeClass` named `gvisor` with handler `runsc`, a fixed per-pod `overhead` (an idle gVisor pod measured about 18 MiB more than runc; 64 MiB is the proposed starting value, to be measured under real workloads), and a `scheduling` field selecting the label (and tolerating the taint). Kubernetes adds that node selector and toleration to every pod that sets `runtimeClassName: gvisor`, so packs set only the runtime class and their pods can land only on gVisor nodes.
4. **`nic deploy` check.** NIC confirms the `RuntimeClass` exists with handler `runsc`, and that each node in an opted-in node group can actually run gVisor. `status.runtimeHandlers` is not enough on its own: it lists `runsc` whenever containerd is configured for it, even if the binaries failed to install (observed). NIC therefore runs a short-lived smoke pod with `runtimeClassName: gvisor` on each opted-in node, which passes only if it reports gVisor's kernel, and deletes it afterwards; a node that fails fails the deploy when the capability is required. An opted-in node group with no nodes (scaled to zero) is reported, not failed. For `existing` and kind clusters NIC installs nothing and checks that a `RuntimeClass` named `gvisor` exists with a handler that one of these smoke pods confirms is gVisor. Results are shown by `nic outputs`.
5. **Published pod settings:** `runtimeClassName: gvisor`, `seccompProfile` unset (gVisor ignores it, and NIC does not enable `--oci-seccomp`). These are this capability's settings only: requiring `user-space-kernel` does not change the published settings of any other capability (see "Combining capabilities").
6. **Storage for gVisor pods.** gVisor checks file permissions itself, against the ownership the filesystem reports, before a request reaches the storage. Volumes that gVisor pods write to must therefore present real POSIX ownership that matches the pod's UID or its `fsGroup`; storage that rewrites identities on the server does not work. That rules out EFS access points as NIC configures them today (each volume owned by its own UID from 50000 with mode 700), which failed in the EKS probe. NIC's storage direction ([PR #586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586), ADR-0019 there) replaces them: FSx for OpenZFS for shared homes on AWS ([#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705)), whose volumes take the pod's `fsGroup` through the kubelet, EBS gp3 for single-writer volumes, node-local disk for rebuilt environments, and Longhorn on Hetzner. Each is expected to work under gVisor because none rewrites identities, and FSx for OpenZFS and Longhorn (shared and single-writer volumes) both passed in the probe. Longhorn shared volumes need the NFS client on every node, which NIC's Hetzner provider does not install today; that is a prerequisite for this capability on Hetzner. NIC documents the rule for packs, which state the UID and `fsGroup` their pods run with.
7. **The metadata address on Hetzner.** On autoscaled Hetzner nodes, the user data any pod can read from `169.254.169.254` contains the k3s join token (observed). Where the capability is required on Hetzner, NIC publishes, and packs apply in the namespaces of their gVisor pods, a NetworkPolicy that blocks egress to `169.254.169.254/32`; hetzner-k3s enforces it for gVisor and runc pods alike (observed). This is a stopgap for a cluster-wide problem (see "Findings for NIC beyond sandboxing").

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

It sets the published `runtimeClassName` on the pod that runs the agent and applies the other published settings as given. If it uses bubblewrap inside the pod, it uses ADR-0022's qualified configurations as they are, so the same pack code runs on runc and under gVisor without detecting which; under gVisor it may add a fresh `/proc` (`--proc /proc`) to hide other processes' command lines. It checks at startup that the sandbox works, and refuses to run commands unsandboxed if it does not. It must not rely on Landlock inside the gVisor pod. Environments and package caches belong on local or ephemeral storage rather than a network-backed home directory, where metadata-heavy work is slow with or without gVisor.

### Verification

Before a provider and node image family are listed, a maintainer runs the probe on real nodes: bubblewrap's qualified configurations with the workaround and a fresh `/proc`, canaries hidden, no network from inside the sandbox, Landlock reported absent, `RuntimeDefault` ignored, Kubernetes volume updates visible in the pod, NetworkPolicy enforced for gVisor pods, and JupyterLab timings with EFS-backed home directories (sandbox probe brief, Part C). The `--unshare-net` workaround is re-tested on each gVisor upgrade, so the published guidance can drop it once the upstream bug is fixed. As of 2026-10-25 the probe has passed on EKS 1.34 AL2023 x86 and Hetzner Ubuntu 24.04 x86 nodes, with test-only installers rather than NIC's implementation; GPUs and arm64 nodes are not yet tested.

### Security

- **Stronger than ADR-0021 and ADR-0022, but not a VM.** gVisor is a user-space kernel sharing the host; an escape from gVisor reaches the host. Code an agent executes should still be treated as attacker-influenced.
- **No host relaxation and no privileged pods.** Installation happens at boot, outside the cluster, and only on opted-in node groups; the gVisor binaries are pinned, checksum-verified and published by NIC as an image, so NIC takes on supply-chain responsibility for them and must follow gVisor security releases.
- **Shared or dedicated nodes.** gVisor pods run only on opted-in node groups. By default those can also run other workloads, which fits ADR-0021's threat model as long as foundational services run elsewhere; with `dedicated: true` they run nothing else, the right choice where agent code is treated as adversarial. An escape from gVisor reaches whatever else runs on the node. Dedication behaved as designed in the probe.
- **Network.** gVisor uses its own network stack inside the pod, but traffic leaves through the pod's normal interface, and NetworkPolicy applies as for other pods (observed on EKS with VPC CNI enforcement on). On AWS the instance metadata service is unreachable from pods because NIC's node groups require IMDSv2 with a hop limit of 1; on Hetzner it depends on the provider's metadata service and NetworkPolicy.
- **Storage endpoints.** gVisor does not stop a pod from talking to network storage directly. NFS endpoints that trust the user ID a client claims can be reached with a user-space NFS client, without any mount privilege. In probe clusters, an unprivileged pod under runc or gVisor, on another node, read another user's Longhorn shared volume through its share-manager, and read and wrote another user's FSx for OpenZFS volume as root (2026-10-25). The sandbox's no-network configuration blocks this for the agent's commands; for the pod itself, a default-deny egress NetworkPolicy blocked it on both providers while the pod's own volumes still mounted, but NIC's EKS clusters do not enforce NetworkPolicy today (#691, #675).
- **The metadata address on Hetzner.** Autoscaled Hetzner nodes expose the k3s join token to any pod through the metadata service (observed); NIC step 7 blocks it for the namespaces of gVisor pods.
- **Composition.** Landlock does not work inside gVisor, so `process-self-restriction` does not combine with this capability.
- **Seccomp settings are ignored, and compliance tools will not notice.** NIC runs gVisor without `--oci-seccomp`, so a gVisor pod's `seccompProfile` is not applied: a pod can declare `RuntimeDefault`, pass a Pod Security or policy check that requires it, and run without that filter. The workload is still behind gVisor's own syscall implementation and its host-side filter, which is the stronger boundary, but the declared setting is not what is enforced. Documentation for hardened mode ([ADR-0010](0010-high-security-mode.md)) and for auditors says so. Enabling `--oci-seccomp` would make declared profiles real, at the cost of blocking bubblewrap under `RuntimeDefault`; it is not chosen, and is recorded here for operators who need declared profiles enforced.

### Consequences

**Good:**
- A much stronger boundary between the pod and the host, maintained upstream, with no host relaxation and no in-cluster installer.
- Installation, upgrades and install failures touch only opted-in node groups; foundational nodes are unchanged.
- Bubblewrap inside gVisor reaches Hetzner, where `in-pod-namespaces` alone cannot, and gains a fresh `/proc` and pid namespace, closing ADR-0022's signalling and command-line gaps.
- The operator opts in node groups and adds a requirement; packs add only `runtimeClassName`.

**Bad:**
- I/O overhead: in the probe, metadata-heavy work on network-backed homes was about 1.4–1.7× slower under gVisor and JupyterLab started 1–1.6 s slower; most data-science tooling worked, but attaching a debugger to an unrelated running process does not.
- Storage must present real ownership to gVisor pods: identity-rewriting storage such as EFS access points does not work, and each storage backend has to be qualified under gVisor.
- Limited GPU support: GPU pods under gVisor need its `nvproxy` support, which this ADR does not qualify.
- No AKS support; AKS needs `vm-boundary` instead.
- NIC owns gVisor installation in each provider's bootstrap, a published gVisor image, version pinning, checksum verification and upgrades (which replace the opted-in nodes and end users' sessions on them).
- Operators size the opted-in node groups for agent sessions; Hetzner needs node-pool label support in NIC's provider.
- Bubblewrap's own `--unshare-net` stays unusable under gVisor until gVisor #13438 is fixed; the qualified configurations avoid it on every runtime.
- Landlock is unavailable inside gVisor pods.

## Options Detail

- **Option 1 (do nothing):** no cost, but `in-pod-namespaces` stays AWS-only and unfiltered, and no capability protects the host from the pod.
- **Option 2 (boot-time install on every node group):** no per-node-group setting and no scheduling rules, but every node of the cluster then depends on the install succeeding, every gVisor upgrade rolls every node including foundational ones, and gVisor pods can land next to foundational services.
- **Option 3 (opt-in node groups, image delivery, non-fatal install; chosen):** confines download, failures and upgrades to the node groups that need gVisor, and offers GKE-style dedication as a setting. Delivery alternatives considered within it: downloading from gVisor's release bucket at each boot (no NIC artifact, but every boot depends on an external site, which proxies or restricted egress break, and the release format has already changed once); a NIC-controlled copy in an S3 bucket created with the cluster (AWS only); and custom node images with gVisor baked in (nothing downloaded at boot, but a node-image pipeline per provider).
- **Option 4 (privileged DaemonSet installer):** easy to ship, and Kata's own installer works this way, but it is a privileged, host-trusted component in the cluster (ADR-0021's privileged node-agent tier), must restart containerd on running nodes, and races new nodes joining unless a startup taint holds them back.
- **Option 5 (Kata, `vm-boundary`):** a hardware boundary with a guest kernel, but needs nested virtualisation or bare metal, which Hetzner Cloud and most EKS instance types lack, plus higher per-pod memory and start-up cost. The natural route on AKS, and a later ADR.
- **Option 6 (a gVisor pod per session):** the strongest design for the threat model, since commands run where the agent's credentials never are, but it costs a pod start per session, workspace sharing and permission for packs to create pods, and it re-architects packs. It builds on this ADR's `RuntimeClass` and can follow it, with Agent Sandbox as a candidate request layer.
- **Option 7 (NIC-owned seccomp profile):** keeps bubblewrap on the host kernel with a NIC-maintained allowlist per architecture, AppArmor work for Hetzner and no AKS route; weaker and more work. Remains ADR-0022's fallback if gVisor proves impractical.

## Open Questions

- Where does NIC publish the gVisor image, and how do operators with private registries mirror it?

- Should the deploy check rely on per-node smoke pods, or should the install step also set a node label only on success (for example through k3s's node-label configuration or kubelet flags) so that the `RuntimeClass` cannot route pods to a node whose install failed?
- Is 64 MiB the right `RuntimeClass` overhead once measured under JupyterLab and agent workloads?

- Should GPU node groups qualify with `nvproxy`, and arm64 (Graviton) node groups?
- Does this capability make ADR-0022's first implementation unnecessary on AWS, or should both remain (host bubblewrap without gVisor's overhead, and bubblewrap inside gVisor)?

## Findings for NIC beyond sandboxing

The probes for this ADR found three problems in NIC that affect clusters whether or not they use any sandboxing capability. They are recorded here so they are not lost; each needs its own issue, and the first two are security issues to raise with the maintainers privately before any public report.

1. **Hetzner autoscaled nodes expose the k3s join token to every pod.** The user data hetzner-k3s gives autoscaled nodes includes `/etc/init-0.sh` with `K3S_TOKEN` and `K3S_URL`, and Hetzner's metadata service serves it to any process on the node, including unprivileged pods (observed with both runc and gVisor pods, 2026-10-25). With the token, a workload can join a node of its own to the cluster. A NetworkPolicy blocking `169.254.169.254/32` stopped it on hetzner-k3s; a cluster-wide fix (a default policy in every namespace, or keeping the token out of user data) is NIC's to decide.
2. **Any pod can read, and on FSx write, other users' shared volumes over NFS.** NFS with its default authentication trusts the user ID the client claims, and a user-space NFS client needs no mount privilege. In probe clusters an unprivileged pod read another user's Longhorn shared volume through its share-manager service, and read and wrote another user's FSx for OpenZFS volume as root through the export [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705) configures (any client, `no_root_squash`). A default-deny egress NetworkPolicy blocked both while volumes still mounted, but NIC's EKS clusters do not enforce NetworkPolicy today (#691, #675). Restricting the FSx export and security group to node addresses, and enforcing NetworkPolicy with storage endpoints excluded from pod egress, are the likely fixes; this bears directly on the storage strategy in [#586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586).
3. **Longhorn shared volumes do not mount on NIC's Hetzner nodes.** The nodes lack the NFS client (`nfs-common`, which provides `mount.nfs`), so every ReadWriteMany Longhorn volume fails to attach with `bad option; ... you might need a /sbin/mount.<type> helper`. NIC installs Longhorn's iSCSI prerequisites but not the NFS client. Single-writer Longhorn volumes are unaffected. Under the storage strategy, Longhorn remains the shared-filesystem option on Hetzner, so this blocks shared homes there.

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
