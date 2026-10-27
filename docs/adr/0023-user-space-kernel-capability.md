# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which defines the capability contract and reserves the name `user-space-kernel`, and on [ADR-0022](0022-in-pod-namespaces-capability.md), whose "Next steps" name this capability as the preferred way to strengthen `in-pod-namespaces`; this ADR cannot be accepted before them. Mechanisms, probe evidence and the verification checklist are in the design doc ([mechanisms](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full), [evidence](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-probe-evidence-in-full)).

## Date

2026-10-19

## Context

ADR-0021 lets an agent's commands restrict themselves with Landlock. ADR-0022 lets them run in bubblewrap-style namespace sandboxes, but only where the host allows unprivileged namespaces in pods with no syscall filter: AWS AL2023 today, not Hetzner or AKS, and never under a posture that requires a filter. Both share the host kernel.

[gVisor](https://gvisor.dev/) runs a pod behind its own user-space kernel, which reaches the host kernel through a small, filtered set of its own calls. That gives a **stronger boundary between the pod and the host**, maintained by the gVisor project rather than NIC, and **namespaces without host relaxation**, since gVisor implements them itself. gVisor alone protects the host from the pod, not the pod's credentials from the agent's commands, which is ADR-0021's threat model; bubblewrap inside a gVisor pod covers both.

**Evidence.** Probe runs on a local VM, EKS (AL2023 x86, with EFS and with FSx for OpenZFS) and Hetzner (Ubuntu 24.04 x86, k3s), using test-only installers, found that:

- bubblewrap's qualified configurations work inside gVisor, and a fresh `/proc` and pid namespace there close ADR-0022's remaining gaps;
- gVisor installs at boot on opted-in pools, including autoscaled nodes, can be swapped on a running k3s node through its upgrade controller, and a failed install never runs a pod unsandboxed;
- storage presenting real ownership works (FSx for OpenZFS), while EFS access points as NIC configures them do not;
- common data-science tooling works; file-heavy work on network homes is 1.4–1.8× slower, and under a 512 MiB limit gVisor pods were killed about 16 MiB earlier than runc pods;
- nodes may change their own labels but not their taints, and on k3s such a change reverts at the next agent restart.

The [evidence summary and detail](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-probe-evidence-in-full) are in the design doc.

**Precedents.** GKE Sandbox installs gVisor on chosen node pools and pods opt in with `runtimeClassName: gvisor`; the [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project and many agent platforms do the same. AKS's built-in equivalent uses Kata VMs.

## Decision Drivers

- **Meet the threat model with a stronger boundary.** Fence an agent's commands from the pod's credentials *and* the host from the pod.
- **Relax nothing on the host.** No user namespaces, AppArmor changes or custom seccomp profiles for pods.
- **Let someone else own the hard part.** Prefer a runtime whose security filter is maintained upstream over a NIC-owned policy.
- **Install at boot, not from inside the cluster.** No privileged installer pods, except where a provider's existing upgrade mechanism already runs privileged jobs.
- **Confine change.** Installation, upgrades and failures touch only node groups the operator chose, and a failure of this optional runtime never takes down a node's other workloads.
- **Promise only what is verified.** Every guarantee is backed by a check that exercises the path consumers use, and every limit is enforced in the cluster, not by NIC staying alive.
- **Reuse ADR-0021's contract:** `sandbox.require`, `InfraSettings.Sandbox`, `nic validate` and `nic deploy` checks, published pod settings.
- **Reach more providers than ADR-0022**, in particular Hetzner Cloud, which has no nested virtualisation.

## Considered Options

1. Do nothing: `in-pod-namespaces` stays AWS-only, and nothing protects the host from the pod.
2. Install gVisor at node boot on every node group of a cluster that requires it.
3. Install gVisor at node boot only on opted-in node groups, keep gVisor pods off nodes whose install failed, verify end to end, and upgrade by draining.
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers (`vm-boundary`) instead of gVisor.
6. A separate, credential-free gVisor pod per agent session, with a request layer such as Agent Sandbox.
7. ADR-0022's fallback: a NIC-owned seccomp profile on dedicated node groups.

## Decision Outcome

Chosen option: "Option 3", because it delivers a stronger boundary than ADR-0021 and ADR-0022 with no host relaxation, can reach Hetzner as well as AWS, uses a filter the gVisor project maintains, and confines change to node groups the operator chose. The first delivery favours guarantees NIC can back over convenience: upgrades drain gVisor pods rather than preserving running sessions, and failed nodes stay in service for other workloads rather than retiring themselves.

### The capability

**`user-space-kernel`:** a pod that sets the `runtimeClassName` NIC publishes runs behind a user-space kernel that implements the Linux syscall interface. The guarantee names no product; gVisor is its first implementation. It applies to any pod that sets that runtime class: an agent's pod, a JupyterLab server, an app, a batch job or a per-session sandbox pod.

The qualified consumer is a long-running, non-root interactive pod with every capability dropped (a JupyterLab server is the reference) running ADR-0022's qualified bubblewrap configurations inside it with a fresh `/proc` (`--proc /proc`), which hides other processes' command lines and is required for this consumer's confidentiality claim. Other workloads are expected to work but are not qualified until their pack has tested them.

### What the operator configures

```yaml
cluster:
  aws:
    node_groups:
      general:
        instance: m6i.xlarge
      user:                 # where pods that run agent code are scheduled
        instance: m6i.xlarge
        max_nodes: 5        # bounds the cost of repeated failed installs
        sandbox:
          capabilities: [user-space-kernel]
          dedicated: false  # true taints the group so other workloads stay off

sandbox:
  require:
    - capability: in-pod-namespaces
      within: user-space-kernel     # bubblewrap inside the gVisor pod
```

`within:` extends ADR-0021's `sandbox.require`: the inner capability is needed inside the named one, which it implies.

Opting a node group in changes only its boot configuration. It does **not** keep foundational services (Keycloak, its database, ArgoCD) off the group, because NIC does not pin those services; that needs `dedicated: true`. The default is `false` because ADR-0021's threat model is an agent's own commands rather than an adversary escaping the host, and dedication costs capacity; operators who treat agent code as adversarial should set it. Control-plane groups cannot opt in. Opting in, dedicating or opting out an existing group means replacing or draining its nodes.

### What NIC does

1. **`nic validate`** checks the requirement against a support matrix each provider reports in `InfraSettings.Sandbox`: CPU architecture, node OS family, and the **resolved** toolchain versions (container runtime; on Hetzner, the hetzner-k3s binary actually in use and the exact k3s release a short Kubernetes version resolves to). An unqualified or unverifiable toolchain, including a hetzner-k3s binary supplied through `NIC_HETZNER_K3S_PATH` or `PATH` without a qualified version, is an error when the capability is required. Azure is unsupported. Requiring the capability with no group opted in, or on Hetzner before its prerequisites are in NIC, is an error.
2. **Installation at node boot, on opted-in groups only.** A boot step fetches NIC's published image of the pinned gVisor release and verifies it in stages: the fetched manifest is hashed against NIC's pinned digest before its layer is trusted, the layer against the manifest, and each installed file against a per-file list. Each release installs into its own directory, and a single atomic switch makes it current; the containerd handler `runsc` always runs the current release through that path, so a crash at any point leaves either the old or the new release complete. A failed install never stops a node joining.
3. **End-to-end check on each node, and routing.** NIC creates a `RuntimeClass` named `gvisor` (handler `runsc`, a fixed `overhead`) whose `scheduling` field selects the opted-in group's label `sandbox.nebari.dev/user-space-kernel: "true"` and, with `dedicated: true`, tolerates the group's taint; the selector never names a release, because Kubernetes copies it into each pod at creation and a release in it would strand pods. After installing, the node runs a test container through containerd, the `runsc` handler and its shim, as a non-root user with the published security settings, and checks gVisor's kernel and ADR-0022's capability test inside it. Using its own credentials, it then records the result: on success a release label; on failure the group label set to `"false"` (nodes may change their own labels but not their taints) and a Kubernetes event. On k3s, which re-applies its command-line labels at every start, the check and label run at every start. Pods sent to a node in the seconds before it relabels itself fail to start; they never run unsandboxed.
4. **Failed nodes stay in service.** A node whose install fails keeps running its other workloads and is only excluded from gVisor routing. NIC does not retire it automatically: the cluster autoscaler counts a node that registers and reports Ready as a successful scale-up, so no node-side action makes it back off. Repeated failures (for example a registry outage) can therefore make a pending gVisor pod add failed nodes up to the group's maximum, which is the bound; NIC alerts through the event, and operators set modest maximums on opted-in groups. Smarter handling needs a component in the cluster that NIC does not have today.
5. **`nic deploy` check, mandatory.** When the capability is required, `nic deploy` runs a short-lived smoke pod on each node of each opted-in group, through the published `RuntimeClass` and pod settings, which must report gVisor's kernel and, for `in-pod-namespaces` within `user-space-kernel`, pass ADR-0022's capability test. Any failure fails the deploy; groups at zero nodes are reported as unverified until they scale up. On `existing` and kind clusters, where NIC installed nothing, the same check runs on each eligible node. `status.runtimeHandlers` is not used as evidence, because it lists `runsc` even after a failed install.
6. **Published pod settings:** `runtimeClassName: gvisor` and `seccompProfile: RuntimeDefault`. gVisor does not apply the pod's profile, so the pod passes Pod Security `restricted` without blocking bubblewrap. These are also the settings for `in-pod-namespaces` within `user-space-kernel`; ADR-0022's "leave `seccompProfile` unset" is only for bubblewrap on the host.
7. **Upgrades are staged and drain gVisor pods.** A release change is pre-flighted (the image resolves and verifies from inside the cluster), then applied to one canary node and promoted only if the end-to-end check passes there: on AWS a temporary one-node group with the new release, on Hetzner the first node of the in-place rollout. On AWS the rollout then replaces the managed node group's nodes one at a time. On Hetzner, where `hetzner-k3s create` does not replace existing servers, the system-upgrade-controller that hetzner-k3s already installs drains each opted-in node, installs and switches the release, runs the end-to-end check and returns the node to service, one node at a time. A node whose upgrade fails stays on its previous release and is marked so that the rollout skips it, a limit kept in the cluster rather than by NIC. Because nodes are drained, no session keeps an old release once the rollout completes; the boot configuration moves to the new release so new nodes match. `nic deploy` reports nodes not on the pinned release.
8. **Ownership.** NIC owns the `RuntimeClass`, the upgrade plans, the node services and the release directories (keeping the previous release for rollback). It refuses to adopt an existing `RuntimeClass` named `gvisor` that it did not create, and a failure to create or update any of them fails the deploy rather than being reported as a warning.

**Prerequisites.**

- **Supported storage.** gVisor checks file permissions itself, so volumes gVisor pods write to must present real ownership matching the pod's UID or `fsGroup`. FSx for OpenZFS qualifies and EBS is expected to, and whatever storage a provider uses for homes must present real ownership; EFS access points as NIC configures them today do not, and existing homes on them must move under NIC's storage plan ([PR #586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)) first. This ADR provides no migration.
- **AWS.** Per-node-group bootstrap in NIC's EKS module, and a rollout limited to one node at a time (the module's default allows a third of the group to be unavailable).
- **Hetzner.** Node-pool labels and pre-k3s boot commands in NIC's generated configuration, home storage that presents real ownership, validation of the resolved toolchain, and the NIC team's fix for the metadata service exposing the k3s join token to pods on autoscaled nodes.

### Combining capabilities

Each capability's published settings mean the same thing on every cluster, and a capability never silently pulls in another:

| The pack wants | Requirement | Result |
|---|---|---|
| Bubblewrap only | `in-pod-namespaces` | Bubblewrap on the host kernel where the host provides it (AL2023) |
| Bubblewrap inside gVisor | `in-pod-namespaces` `within: user-space-kernel` | The qualified consumer; available wherever `user-space-kernel` is, including Hetzner |
| gVisor only | `user-space-kernel` | gVisor with no inner sandbox |
| Landlock and bubblewrap | `process-self-restriction` and `in-pod-namespaces` | Host kernel (AL2023) |
| Landlock and gVisor | — | Not supported: Landlock is unavailable inside gVisor |

On Hetzner, requiring `in-pod-namespaces` without `within: user-space-kernel` is an error that names the combination. The node and deploy checks run bubblewrap's capability test inside gVisor whenever the combination is required, and each pack's startup check remains the final guard.

### What a pack does

It applies the published settings for the capabilities it uses, and does not pin gVisor pods to node groups that are not opted in, which would conflict with the `RuntimeClass`'s selector. For bubblewrap inside gVisor it uses ADR-0022's qualified configurations with a fresh `/proc`, checks at startup that the sandbox works, and refuses to run commands unsandboxed if it does not. It does not rely on Landlock inside gVisor, keeps environments and package caches on local or ephemeral storage rather than a network home, and tolerates its gVisor pods being restarted during upgrades.

### Verification

Before a provider, architecture, node OS family and toolchain are listed, and on every gVisor or k3s upgrade, a maintainer runs the probe with NIC's implementation against the [verification checklist](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full) in the design doc, which includes interrupting an upgrade at each step and killing `nic deploy` mid-rollout.

### Security

- **Stronger than ADR-0021 and ADR-0022, but not a VM.** An escape from gVisor reaches the host and whatever else runs on the node, which without `dedicated: true` can include foundational services. Code an agent executes should be treated as attacker-influenced.
- **gVisor's own trade-offs.** Its default *directfs* mode opens host files directly for performance (gVisor documents the restrictions it keeps), and its default *systrap* platform, needed without hardware virtualisation, lacks the extra isolation of its KVM platform. NIC pins one gVisor release per NIC release and treats gVisor security releases like its own security fixes.
- **Supply chain.** NIC publishes the gVisor artifact; nodes verify the manifest against the pinned digest, the layer against the manifest, and each file against its list.
- **Patch status.** Upgrades drain gVisor pods, so once a rollout completes no session runs an older release; nodes the rollout skipped after a failure, and groups not yet rolled, are reported. On Hetzner the upgrade jobs run privileged on opted-in nodes, through an existing component.
- **Network.** NetworkPolicy applies to gVisor pods as to others, but because policies are additive, no namespaced policy can guarantee a deny, so this ADR relies on none: on AWS the metadata service is unreachable because NIC's node groups require IMDSv2 with a hop limit of 1, and on Hetzner this capability waits for the NIC team's fix.
- **Storage endpoints.** gVisor does not stop a pod reaching network storage directly; the sandbox's no-network configuration blocks it for the agent's commands, and for the pod it depends on the NIC team's storage work.
- **Declared seccomp is not enforced.** Without `--oci-seccomp`, gVisor does not apply the pod's `seccompProfile`, so the published `RuntimeDefault` satisfies policy checks without being enforced; the workload is behind gVisor's own syscall implementation and host-side filter instead. Documentation for hardened mode ([ADR-0010](0010-high-security-mode.md)) and for auditors says so; `--oci-seccomp` would enforce it but block bubblewrap.

### Consequences

**Good:**
- A much stronger boundary between the pod and the host, maintained upstream, with no host relaxation and no in-cluster installer for installation.
- Every guarantee is backed by an end-to-end check; upgrades are staged, crash-consistent and limited in the cluster; and a gVisor failure never takes down a node's other workloads.
- Bubblewrap inside gVisor reaches Hetzner and closes ADR-0022's signalling and command-line gaps.

**Bad:**
- Upgrades restart users' gVisor sessions on both providers; preserving sessions across upgrades is future work.
- Failed nodes waste capacity until an operator replaces them, and repeated failures can grow an opted-in group to its maximum.
- File-heavy work on network homes is slower and JupyterLab starts slower; attaching a debugger to an unrelated process does not work; memory headroom under a limit is slightly lower, and how much the `RuntimeClass` overhead compensates is untested.
- Existing deployments on EFS access points cannot adopt it until their homes move to supported storage.
- Isolation from foundational services needs `dedicated: true`.
- Implementation work across NIC and its EKS module (bootstrap, one-at-a-time rollout, canary groups, the artifact, node services, checks, toolchain validation), and continuing work to follow gVisor releases and re-qualify on gVisor, k3s and node-image changes.
- No GPU qualification (`nvproxy`), no AKS support (it needs `vm-boundary`), and no Landlock inside gVisor.

## Options Detail

- **Option 1 (do nothing):** no cost, but `in-pod-namespaces` stays AWS-only and unfiltered, and nothing protects the host from the pod.
- **Option 2 (install everywhere):** no per-group setting, but every node depends on the install succeeding and every upgrade touches nodes running foundational services.
- **Option 3 (chosen):** confines change to opted-in groups, verifies end to end and upgrades by draining, at the cost of a per-group setting, a node-side check and restarted sessions on upgrade. Variants rejected after review (self-retiring failed nodes, a failure taint, a release-pinned label, session-preserving in-place swaps) and delivery alternatives are recorded in the design doc.
- **Option 4 (privileged DaemonSet installer):** easy to ship, but a privileged component in the cluster that restarts containerd on running nodes and races new nodes joining.
- **Option 5 (Kata, `vm-boundary`):** a hardware boundary, but it needs nested virtualisation or bare metal (unavailable on Hetzner Cloud) and costs more per pod. The route on AKS, and a later ADR.
- **Option 6 (a gVisor pod per session):** the strongest design for the threat model, since commands run where the agent's credentials never are, but it costs a pod start per session, workspace sharing and permission for packs to create pods. It can follow this ADR, using its `RuntimeClass`.
- **Option 7 (NIC-owned seccomp profile):** weaker and more work; remains ADR-0022's fallback if gVisor proves impractical.

## Open Questions

- Where does NIC publish the gVisor image, and how do operators with private registries mirror it?
- Should failed nodes be replaced automatically, and should scale-up stop for a group whose new nodes keep failing? Both need a component in the cluster.
- Should sessions survive upgrades in a later delivery, given crash-consistent activation and an inventory of which release each running sandbox uses?
- Should a startup taint close the window before a node records its result?
- How does the `RuntimeClass` overhead interact with container memory limits under gVisor, and what value should it be?
- Should GPU (`nvproxy`) and arm64 node groups be qualified?
- Does this capability make ADR-0022's first implementation unnecessary on AWS?

## Related issues

Found while probing for this ADR and reported to the NIC team (links to be added once the issues are public); on Hetzner this ADR depends on the first:

- Hetzner's metadata service exposes the k3s join token to pods on autoscaled nodes.
- Pods can reach other users' shared volumes over NFS (FSx for OpenZFS as configured in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705), and NFS-based storage generally).

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
