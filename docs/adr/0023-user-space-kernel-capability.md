# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT, exploratory; expected fourth in order, after the untrusted-execution profile): a feasibility sketch that fits [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md)'s interface; not proposed for acceptance yet. Depends only on ADR-0021, whose `mediated-kernel` boundary level it implements with gVisor. It adds entries to ADR-0021's published mapping ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#proposed-additions-more-mapping-entries-sketches)) and follows ADR-0021's guidance on placement labels and lifecycle. Related sketches, none of which it depends on: [ADR-0022](0022-in-pod-namespaces-capability.md) (bubblewrap inside gVisor as the route for `in-pod-namespaces`), [ADR-0024](0024-immutable-node-pool-rollouts.md) (one candidate upgrade mechanism) and [ADR-0025](0025-untrusted-execution-pods.md) (guarantees around tool-execution sandbox pods). Revised 2026-10-28 after review: narrowed to tool-execution sandbox pods first; an implementation-named `RuntimeClass`; placement only on a label nodes cannot write; lifecycle invariants instead of a dependency on ADR-0024. Mechanisms, probe evidence and the verification checklist are in the design doc ([mechanisms](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full), [evidence](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-probe-evidence-in-full)).

## Date

2026-10-19

## Context

ADR-0021 lets an agent's commands restrict themselves with Landlock, on the host kernel. Some designs need more: the strongest pattern for ADR-0021's threat model runs an agent's tool calls in a separate, credential-free **tool-execution sandbox pod**, where tools often need root, and root on the host kernel is a real escalation risk.

[gVisor](https://gvisor.dev/) runs a pod behind its own user-space kernel, which reaches the host kernel through a small, filtered set of its own calls. That gives a **stronger boundary between the pod and the host**, maintained by the gVisor project rather than NIC, and **namespaces without host relaxation**, since gVisor implements them itself. gVisor alone protects the host from the pod, not the pod's credentials from the code inside it; that comes from keeping credentials out of the sandbox pod, or from bubblewrap inside a gVisor pod.

**Evidence.** Probe runs on a local VM, EKS (AL2023 x86 and arm64, with EFS, EBS and FSx for OpenZFS) and Hetzner (Ubuntu 24.04 x86, k3s), using test-only installers, found that:

- tool-execution sandbox pods run as root under gVisor, reached over SSH and SFTP from a separate agent pod, with a PVC-backed workspace;
- bubblewrap's qualified configurations work inside gVisor, with a fresh `/proc` and pid namespace;
- gVisor installs at boot on opted-in pools, including autoscaled nodes, and a failed install never runs a pod unsandboxed;
- storage presenting real ownership works (FSx for OpenZFS, EBS, Hetzner Cloud Volumes), while EFS access points as NIC configures them do not;
- common data-science tooling works, but file watchers see changes made from other pods only by polling, and file-heavy work on network homes is 1.4–1.8× slower;
- nodes may change their own labels (outside reserved prefixes) but not their taints.

**Precedents.** GKE Sandbox installs gVisor on chosen node pools and pods opt in with `runtimeClassName: gvisor`; the [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project and many agent platforms do the same.

## Decision Drivers

- **A stronger boundary for code that runs as root.** Keep the host safe from tool-execution sandboxes without forbidding root inside them.
- **Relax nothing on the host.** No user namespaces, AppArmor changes or custom seccomp profiles for pods.
- **Let someone else own the hard part.** Prefer a runtime whose security filter is maintained upstream over a NIC-owned policy.
- **Install at boot, not from inside the cluster.** No privileged installer or upgrade pods.
- **Confine change.** Installation and failures touch only opted-in node groups, and a failure of this optional runtime never takes down a node's other workloads.
- **Never unsandboxed.** An unverified node or a broken runtime leaves pods Pending or failing, never running without gVisor.
- **Fit ADR-0021's contract:** an implementation-named class whose exact name is published in a mapping entry (its level label is inventory metadata only), placement labels following ADR-0021's guidance, and qualified expectation, baseline and enforcement kept separate.

## Considered Options

1. Do nothing: nothing protects the host from root in a sandbox pod.
2. Install gVisor at node boot on every node group of a cluster that requires it.
3. Install gVisor at node boot only on opted-in node groups, place pods only on nodes verified from the cluster side, and upgrade by replacing nodes.
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers instead of gVisor.

## Decision Outcome

Chosen option: "Option 3", because it gives root-running sandboxes a stronger boundary with no host relaxation, reaches Hetzner as well as AWS, uses a filter the gVisor project maintains, and confines change to opted-in groups. A node's runtime never changes after it joins, and no pod is placed on a node until something other than the node itself has verified it.

### The implementation

**gVisor** is an implementation of ADR-0021's **`mediated-kernel`** level (which this sketch calls the `user-space-kernel` family): a pod using its `RuntimeClass` runs behind a user-space kernel that implements the Linux syscall interface, so it never makes system calls directly to the host kernel. Under ADR-0021's acceptance policy it is offered for a mapping entry only where it has every property the entry needs:

| Property | gVisor |
|---|---|
| `process-self-restriction` (Landlock inside) | No (`ENOSYS`) |
| `in-pod-namespaces` (ADR-0022's qualified configurations) | Yes, with the network namespace created first ([gVisor #13438](https://github.com/google/gvisor/issues/13438)) |
| Pod's `seccompProfile` applied | No (gVisor's own filter applies instead) |
| Root inside | Contained; `NET_RAW` is removed even when requested, and without `NET_ADMIN` root cannot change routes or addresses |
| Fresh `/proc` in a pid namespace | Yes |
| inotify events for changes made by other pods | No (polling works) |
| Usable memory under a limit | The limit plus the class overhead (64 MiB) |

**Qualified consumer, first:** a **tool-execution sandbox pod**. An agent runs in its own pod and runs its tool calls in a separate pod, usually one per session, reached over SSH or `kubectl exec`. The sandbox pod holds no credentials, may run as root and needs no bubblewrap; gVisor is the boundary between it and the host, and network isolation must come from host-side policy (sketched in ADR-0025). Observed on EKS (2026-10-27): commands ran as root over SSH and files moved over SFTP to a PVC-backed workspace, and root could not change its own routes or open raw sockets.

**Second, later:** bubblewrap inside a long-running pod, using ADR-0022's qualified configurations with a fresh `/proc` (`--proc /proc`), for packs that cannot split the agent from its tools.

### What the operator configures

```yaml
cluster:
  aws:
    node_groups:
      sandbox:
        instance: m6i.xlarge
        max_nodes: 5          # bounds the cost of repeated failed installs
        sandbox:
          runtime: gvisor     # the implementation this group offers
          dedicated: true     # taints the group so other workloads stay off

sandbox:
  requirements:
    - name: tool-sandboxes
      boundary: mediated-kernel
```

The node group names the implementation, because in practice the instance type and provider decide which implementations a group can run, not NIC. `dedicated` defaults to `false`, but operators who treat agent code as adversarial should set it, since opting in does not keep foundational services off the group. Control-plane groups cannot opt in.

### What NIC does

1. **Declaration and `nic validate`.** The provider declares, per opted-in group, the implementation `gvisor` at level `mediated-kernel` with the properties above, and a support matrix (CPU architecture, node OS family and the resolved toolchain: containerd; on Hetzner the hetzner-k3s binary actually in use and the exact k3s release). NIC resolves each mapping entry; an entry that needs gVisor fails (unsupported or unverified, ADR-0021 rule (a)) on an unqualified toolchain, on Azure, with no opted-in group, or on Hetzner before its prerequisites are in NIC. On `existing` clusters, and kind clusters where the operator installed gVisor, NIC runs in **verification-only mode**: the operator names a `RuntimeClass` and its level, and NIC checks it and publishes its exact name in the mapping but never creates, changes or deletes it.
2. **Installation at node boot, on opted-in groups only.** A boot step fetches NIC's published image of the pinned gVisor release, verifies the manifest against a pinned digest and each file against a list, and installs it once, into a directory the runtime handler names. A node's release never changes after it joins, and a failed install never stops a node joining.
3. **Node-side check, failure only.** After containerd, the kubelet and the CNI are ready, a node service runs a test pod sandbox through the CRI with the `runsc` handler (not `ctr`, which bypasses the handler's configuration) and checks gVisor's kernel. On failure the node labels itself `sandbox.nebari.dev/gvisor: failed` and emits an event. It never labels itself as ready.
4. **Placement on a label nodes cannot write.** NIC creates `RuntimeClass` `nebari-gvisor` (handler `runsc`, a 64 MiB memory `overhead`, labelled `sandbox.nebari.dev/level: mediated-kernel`), whose `scheduling` selects `nebari.dev.node-restriction.kubernetes.io/sandbox-gvisor: "true"` (and tolerates the taint when `dedicated`). A small cluster-side component, whose only write permission is patching nodes (RBAC cannot narrow that to labels), sets that label only after confirming from the provider's records that the node belongs to an opted-in group, through a trustworthy node-to-instance binding (the instance as the provider's API reports it, never the node's own labels or an attacker-supplied `spec.providerID` alone), and that a check pod pinned to the node passed; it removes the label when the node reports failure. A node registered with a leaked join token, or one whose install failed, therefore never receives gVisor pods; they stay Pending. Following ADR-0021's guidance, this prevents only self-asserted eligibility through kubelet credentials: it relies on the Node authorizer, NodeRestriction and scoped kubelet identities, verified per provider with a negative test, and a compromised node that already carries the label is outside it.
5. **`nic deploy` check, mandatory.** A smoke pod runs on each labelled node of each opted-in group with the published settings and must report gVisor's kernel (the release string inside differs from the node's `kernelVersion` and names gVisor); any failure fails the deploy, and groups at zero nodes are reported as unverified. It is a diagnostic, not attestation. `status.runtimeHandlers` is not evidence: it lists `runsc` after a failed install.
6. **Published values.** In the published mapping, each entry that resolves to gVisor gets `runtimeClassName: nebari-gvisor` (in verification-only mode, the operator's class), `seccompProfile: RuntimeDefault` (which satisfies Pod Security `restricted` but is not enforced by the tested gVisor configuration), a `workspaceStorageClass` qualified with gVisor, and `implementation` with the gVisor release and property-set version. Packs receive these values as Helm values and never hardcode the class name or select it by label. A release can be withdrawn or revoked without renaming the class (ADR-0021's lifecycle guidance).
7. **Ownership.** NIC owns the `RuntimeClass`, the node services and the labeller, refuses to adopt a class of that name it did not create, and fails the deploy if it cannot create or update them. Mapping entries only gate resolution; provisioning follows opted-in groups; NIC never deletes the class on its own, since packs may still name it.

### Lifecycle

Any lifecycle mechanism, from the provider's own node replacement to a blue/green design such as ADR-0024, must meet these invariants:

- **Unverified nodes never run workloads that require the capability:** they never get the placement label.
- **A missing or broken runtime never causes unsandboxed fallback:** pods name only `nebari-gvisor`, whose handler fails closed.
- **Changes to execution semantics are explicit:** a gVisor release that changes a property updates the declared properties and is shown by `nic validate`, and a release that changes a capability's meaning follows ADR-0021's naming rule.
- **Security updates have a usable path:** a new pinned release reaches nodes by replacing them, through the provider's normal node-group update on AWS and by draining and deleting autoscaled nodes on Hetzner; new nodes are verified before they receive pods.
- **Interrupted operations have documented recovery:** re-running `nic deploy` converges; unlabelled nodes are inert for gVisor pods; operators can drain and delete any node.

**First operating model.** Changing what a node boots with replaces nodes, and per-session sandbox pods on a drained node end. A broken release leaves gVisor pods Pending, never unsandboxed; for per-session sandboxes that is acceptable, and reverting the release recovers. Keeping sessions alive across upgrades, and keeping capacity while a release is verified, are left to a later mechanism.

**Prerequisites.**

- **Supported storage.** gVisor checks file permissions itself, so volumes its pods write to must present real ownership matching the pod's UID or `fsGroup`. FSx for OpenZFS and EBS (gp3) on AWS, and Hetzner Cloud Volumes, qualify; EFS access points as NIC configures them do not. Opted-in groups need storage that keeps no data on the nodes, since nodes are replaced.
- **AWS.** Per-node-group bootstrap in NIC's EKS module, and autoscaler template tags carrying the placement label for scale-from-zero.
- **Hetzner.** Node-pool boot commands in NIC's generated configuration, gVisor on autoscaled pools only (since `hetzner-k3s create` reinstalls k3s on static nodes), homes on Hetzner Cloud Volumes, and the NIC team's fix for the metadata service exposing the k3s join token to pods. Scale-from-zero with a label the kubelet cannot set is not yet qualified, so pools keep a minimum of one node until it is.

### What a pack does

It applies the values of its mapping entry and never pins pods to groups that are not opted in. For tool-execution sandboxes it keeps every credential in the agent's pod and treats the shared workspace as untrusted input on the agent's side; for bubblewrap inside gVisor it uses ADR-0022's qualified configurations with a fresh `/proc`. It refuses to run commands unsandboxed if its startup check fails, keeps environments and package caches off network homes, watches files changed from other pods by polling, and recreates sessions that end when nodes are replaced.

### Verification

Before a provider, architecture, OS family and toolchain are listed, and on every gVisor or k3s upgrade, a maintainer runs the probe with NIC's implementation against the design doc's [verification checklist](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full).

### Trust model

- **Trusted:** the operator, NIC, gVisor (pinned per NIC release), the provider's node images, the labeller, and the pack's agent pod in the sense that it holds credentials (it is exposed to prompt injection, so it is not trusted to judge what the sandbox runs).
- **A hostile workload** in a sandbox pod may run as root, use any system call gVisor implements, write anything in its workspace and attempt any network connection.
- **NIC enforces** the runtime boundary on verified nodes, placement only on those nodes, and that pods naming the class never run on another runtime.
- **The pack enforces** keeping credentials out of sandbox pods, treating the workspace as untrusted input, and its own startup check. Network isolation is not provided here.
- **Outside the guarantee:** gVisor escapes and what they reach on the node (foundational services, unless `dedicated`); side channels between pods on one node; the pod's network.

### Security

- **Stronger than the default runtime, but not a VM.** An escape from gVisor reaches the host and whatever else runs on the node. Code an agent executes should be treated as attacker-influenced.
- **gVisor's own trade-offs.** Its default *directfs* mode opens host files directly, and its *systrap* platform, needed without hardware virtualisation, lacks the extra isolation of its KVM platform. NIC pins one gVisor release per NIC release and treats gVisor security releases like its own fixes.
- **Declared seccomp is not enforced.** Without `--oci-seccomp`, gVisor ignores the pod's `seccompProfile`, so `RuntimeDefault` satisfies policy checks without being enforced; documentation for hardened mode ([ADR-0010](0010-high-security-mode.md)) and for auditors says so. `--oci-seccomp` would block bubblewrap.
- **Network.** gVisor does not isolate a pod's network. On AWS the metadata service is unreachable (IMDSv2, hop limit 1); on Hetzner the capability waits for the join-token fix.

### Consequences

**Good:**
- A much stronger, upstream-maintained boundary between pod and host for root-running sandboxes, with no host relaxation and no privileged in-cluster component.
- No pod reaches a node that something other than the node has not verified, which also closes rogue-node registration and k3s's relabelling window.
- Reaches Hetzner as well as AWS; bubblewrap inside gVisor gives ADR-0022 a route.

**Bad:**
- A new in-cluster component (the labeller) that can patch any node, so it must itself be pinned and protected like other cluster-admin-adjacent components.
- Upgrades replace nodes and end per-session sandboxes on them; a broken release leaves sandboxes Pending until it is reverted.
- Failed nodes waste capacity until an operator replaces them, and repeated failures can grow a group to its maximum.
- File-heavy work on network homes and JupyterLab startup are slower, file watchers miss changes from other pods unless they poll, and memory headroom under a limit is slightly lower, which the class overhead compensates.
- Deployments with homes on EFS access points cannot adopt it until the homes move.
- Continuing work to follow gVisor releases and re-qualify on gVisor, k3s and node-image changes; no GPU qualification (`nvproxy`) and no Landlock inside gVisor.

## Options Detail

- **Option 1 (do nothing):** no cost, but root in a sandbox pod is root on the host kernel.
- **Option 2 (install everywhere):** no per-group setting, but every node depends on the install and every upgrade touches nodes running foundational services.
- **Option 3 (chosen):** confines change to opted-in groups, at the cost of a per-group setting, a node-side check and a small labeller. Rejected variants (self-retiring failed nodes, a failure taint, a node-written group label, a release-pinned label, in-place upgrades) are in the design doc.
- **Option 4 (privileged DaemonSet installer):** easy to ship, but a privileged component in the cluster that restarts containerd on running nodes and races new nodes joining.
- **Option 5 (Kata):** a hardware boundary, but it needs nested virtualisation or bare metal (unavailable on Hetzner Cloud) and costs more per pod. A separate implementation of `hardware-virtualised` (sketched in [ADR-0026](0026-vm-boundary-capability.md)), qualified on its own properties.

## Open Questions

- Where does NIC publish the gVisor image, and how do operators with private registries mirror it?
- Should failed nodes be replaced automatically, and scale-up stop for a failing group?
- Should sessions survive upgrades, and is a blue/green mechanism such as ADR-0024 the way to do it?
- How does scale-from-zero work on Hetzner with a placement label the kubelet cannot set?
- Should GPU (`nvproxy`) node groups, and arm64 on Hetzner, be qualified?

## Related issues

Found while probing for this ADR and reported to the NIC team (links to be added once the issues are public); on Hetzner this ADR depends on the first:

- Hetzner's metadata service exposes the k3s join token to pods on autoscaled nodes.
- hetzner-k3s v2.4.6's k3s upgrade hangs on k3s 1.34: its upgrade plans select `node-role.kubernetes.io/master`, which k3s 1.34 no longer sets.
- Pods can reach other users' shared volumes over NFS (FSx for OpenZFS as configured in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705), and NFS-based storage generally).

## Links

- [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0022: In-Pod Namespace Sandboxes](0022-in-pod-namespaces-capability.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [gVisor](https://gvisor.dev/)
- [gVisor #13438: bwrap --unshare-net fails](https://github.com/google/gvisor/issues/13438)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [Kubernetes NodeRestriction admission plugin](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
