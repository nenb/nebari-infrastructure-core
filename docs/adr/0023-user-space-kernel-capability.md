# ADR-0023: User-Space Kernel Sandboxes (`user-space-kernel`) with gVisor

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), whose `mediated-kernel` boundary level this ADR implements with gVisor (the `user-space-kernel` family), and on [ADR-0022](0022-in-pod-namespaces-capability.md), whose "Next steps" name this capability as the preferred way to strengthen `in-pod-namespaces`; and on [ADR-0024](0024-immutable-node-pool-rollouts.md), which supplies its upgrade mechanism. [ADR-0025](0025-untrusted-execution-pods.md) defines the guarantees around pods that run untrusted code, which this ADR's first qualified consumer relies on. This ADR cannot be accepted before them. Mechanisms, probe evidence and the verification checklist are in the design doc ([mechanisms](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full), [evidence](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-probe-evidence-in-full)).

## Date

2026-10-19

## Context

ADR-0021 lets an agent's commands restrict themselves with Landlock. ADR-0022 lets them run in bubblewrap-style namespace sandboxes, but only where the host allows unprivileged namespaces in pods with no syscall filter: AWS AL2023 today, not Hetzner or AKS, and never under a posture that requires a filter. Both share the host kernel.

[gVisor](https://gvisor.dev/) runs a pod behind its own user-space kernel, which reaches the host kernel through a small, filtered set of its own calls. That gives a **stronger boundary between the pod and the host**, maintained by the gVisor project rather than NIC, and **namespaces without host relaxation**, since gVisor implements them itself. gVisor alone protects the host from the pod, not the pod's credentials from the agent's commands, which is ADR-0021's threat model; bubblewrap inside a gVisor pod covers both.

**Evidence.** Probe runs on a local VM, EKS (AL2023 x86 and arm64, with EFS, EBS and FSx for OpenZFS) and Hetzner (Ubuntu 24.04 x86, k3s), using test-only installers, found that:

- tool-execution sandbox pods run as root under gVisor, reached over SSH and SFTP from a separate agent pod, with a PVC-backed workspace;
- bubblewrap's qualified configurations work inside gVisor, and a fresh `/proc` and pid namespace there close ADR-0022's remaining gaps;
- gVisor installs at boot on opted-in pools, including autoscaled nodes, and a failed install never runs a pod unsandboxed;
- storage presenting real ownership works (FSx for OpenZFS), while EFS access points as NIC configures them do not;
- common data-science tooling works, but file watchers in a gVisor pod see changes made from other pods only by polling; file-heavy work on network homes is 1.4–1.8× slower;
- nodes may change their own labels but not their taints, and on k3s such a change reverts at the next agent restart.

**Precedents.** GKE Sandbox installs gVisor on chosen node pools and pods opt in with `runtimeClassName: gvisor`; the [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project and many agent platforms do the same. AKS's built-in equivalent uses Kata VMs.

## Decision Drivers

- **Meet the threat model with a stronger boundary.** Fence an agent's commands from the pod's credentials *and* the host from the pod.
- **Relax nothing on the host.** No user namespaces, AppArmor changes or custom seccomp profiles for pods.
- **Let someone else own the hard part.** Prefer a runtime whose security filter is maintained upstream over a NIC-owned policy.
- **Install at boot, not from inside the cluster.** No privileged installer or upgrade pods.
- **Confine change.** Installation, upgrades and failures touch only opted-in node groups, and a failure of this optional runtime never takes down a node's other workloads.
- **Promise only what is verified.** Every guarantee is backed by a check on the path consumers use, and every limit is kept in the cluster, not by NIC staying alive.
- **Reuse ADR-0021's contract:** a boundary level resolved per provider, `InfraSettings.Sandbox`, `nic validate` and `nic deploy` checks, level-named published settings.
- **Reach more providers than ADR-0022**, in particular Hetzner Cloud, which has no nested virtualisation.

## Considered Options

1. Do nothing: `in-pod-namespaces` stays AWS-only, and nothing protects the host from the pod.
2. Install gVisor at node boot on every node group of a cluster that requires it.
3. Install gVisor at node boot only on opted-in node groups, keep gVisor pods off nodes whose install failed, verify end to end, and upgrade by replacing node groups (blue/green).
4. Install gVisor from inside the cluster with a privileged DaemonSet.
5. Kata Containers (`vm-boundary`) instead of gVisor.
6. A separate, credential-free gVisor pod per agent session, with a request layer such as Agent Sandbox.
7. ADR-0022's fallback: a NIC-owned seccomp profile on dedicated node groups.

## Decision Outcome

Chosen option: "Option 3", because it delivers a stronger boundary than ADR-0021 and ADR-0022 with no host relaxation, reaches Hetzner as well as AWS, uses a filter the gVisor project maintains, and confines change to opted-in groups. The first delivery favours guarantees NIC can back over convenience: a node's runtime never changes after it joins, upgrades replace whole node groups, and failed nodes stay in service rather than retiring themselves.

### The implementation

**`user-space-kernel`** is an implementation family of ADR-0021's **`mediated-kernel`** level: a pod that sets the level's published `RuntimeClass` runs behind a user-space kernel that implements the Linux syscall interface, so it never makes system calls directly to the host kernel. gVisor is its first implementation. Packs require the level, not gVisor; on AWS and Hetzner today NIC resolves `mediated-kernel` to gVisor, and ADR-0021's resolution picks a VM runtime instead (ADR-0026) only where one is available and a requirement or preference calls for it.

**Properties** (from the probes; ADR-0021's resolution uses them in place of combination rules):

| Property | gVisor |
|---|---|
| `process-self-restriction` (Landlock inside) | No (`ENOSYS`) |
| `in-pod-namespaces` (ADR-0022's qualified configurations) | Yes, with the network namespace created first (bubblewrap's own `--unshare-net` fails, [gVisor #13438](https://github.com/google/gvisor/issues/13438)) |
| Pod's `seccompProfile` applied | No (gVisor's own filter applies instead) |
| Root inside | Contained; `NET_RAW` is removed even when requested, and without `NET_ADMIN` root cannot change routes or addresses |
| Fresh `/proc` in a pid namespace | Yes |
| inotify events for changes made by other pods | No (polling works) |
| Usable memory under a limit | The limit plus the class overhead (64 MiB) |

Two consumers are qualified:

1. **A tool-execution sandbox pod** (the primary pattern): an agent runs in its own trusted pod, whatever that pod is (a coding agent, a chat assistant, a scheduled job, a notebook server), and runs its tool calls in a separate pod, usually one per session, reached over SSH or `kubectl exec`. The sandbox pod holds no credentials, may run as root, needs no bubblewrap, and has its network isolated from outside the pod under [ADR-0025](0025-untrusted-execution-pods.md); gVisor is the boundary between it and the host. Observed on EKS (2026-10-27): commands ran as root over SSH and files moved over SFTP to a PVC-backed workspace, and root could not change its own routes or open raw sockets; network isolation must still come from host-side policy, which held against root once enforced.
2. **Bubblewrap inside a long-running pod**: a non-root pod with every capability dropped that runs the agent and its tools together, fencing the tools with ADR-0022's qualified bubblewrap configurations and a fresh `/proc` (`--proc /proc`), which hides other processes' command lines and is required for this pattern's confidentiality claim. It suits packs that cannot split the agent from its tools.

Other workloads are expected to work but are not qualified until their pack has tested them.

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
          boundary: mediated-kernel  # this group offers the level; NIC resolves the implementation
          dedicated: false  # true taints the group so other workloads stay off

sandbox:
  require:
    boundary: mediated-kernel        # at least
    capabilities:
      - name: in-pod-namespaces      # only for the second consumer (bubblewrap inside)
```

Opting in changes only the group's boot configuration. It does **not** keep foundational services (Keycloak, its database, ArgoCD) off the group; that needs `dedicated: true`, which defaults to `false` because ADR-0021's threat model is an agent's own commands rather than a host escape, and dedication costs capacity. Operators who treat agent code as adversarial should set it. Control-plane groups cannot opt in. Opting an existing group in or out, or changing `dedicated`, is a rollout (step 7).

### What NIC does

As the first implementation above `shared-kernel`, this ADR also delivers the parts of ADR-0021's interface that ADR-0021 adopts but does not build: resolution among several implementations of a level, with operator preferences between them; recording each resolution in the node group's stored spec under ADR-0024, so it never changes silently; and the level-named `RuntimeClass` packs use. Steps 1, 3 and 6 below carry them.

1. **`nic validate`** checks the requirement against a support matrix each provider reports in `InfraSettings.Sandbox`: CPU architecture, node OS family and the **resolved** toolchain (container runtime; on Hetzner, the hetzner-k3s binary actually in use, including one from `NIC_HETZNER_K3S_PATH` or `PATH`, and the exact k3s release). When the level is required and resolves to gVisor, an unqualified or unverifiable toolchain, Azure, no opted-in group, or Hetzner before its prerequisites are in NIC is an error. On `existing` clusters, and kind clusters where the operator installed gVisor, NIC runs in **verification-only mode**: the operator names the `RuntimeClass`, NIC skips the provisioning checks and only runs the deploy check (step 5), and never creates, changes or deletes the `RuntimeClass`.
2. **Installation at node boot, on opted-in groups only.** A boot step fetches NIC's published image of the pinned gVisor release, verifies the manifest against a pinned digest and each file against a list, and installs it once, into a directory the runtime handler names. A node's release never changes after it joins. A failed install never stops a node joining.
3. **Node check and routing.** NIC creates the level's `RuntimeClass`, `nebari-mediated-kernel` (handler `runsc`, a fixed memory `overhead` of 64 MiB, which in the probes more than covered gVisor's lower headroom under a limit) whose `scheduling` selects the group label `sandbox.nebari.dev/user-space-kernel: "true"` (and tolerates the taint with `dedicated: true`); it never names a release, because Kubernetes copies the selector into pods and a release would strand them. Each node then runs a test pod sandbox through the CRI with the `runsc` handler pods use (not `ctr`, which bypasses the handler's configuration) and the published security settings, checking gVisor's kernel and ADR-0022's capability test, and labels itself: a release label on success; on failure the group label `"false"` and an event. On k3s, which resets command-line labels at each start, this repeats at every start. Pods that reach a node before it relabels fail to start; they never run unsandboxed (per-provider timing in the design doc).
4. **Failed nodes stay in service** for their other workloads; NIC does not retire them, since the autoscaler counts any Ready node as a successful scale-up. A persistent failure can therefore grow a group to its maximum, which operators keep modest.
5. **`nic deploy` check, mandatory.** A smoke pod runs on each node of each opted-in group with the published settings and must pass the same checks, including the level's promise (the kernel release inside differs from the node's); any failure fails the deploy, and groups at zero nodes are reported as unverified. In verification-only mode it runs on each node the named `RuntimeClass` can schedule to. `status.runtimeHandlers` is not evidence: it lists `runsc` after a failed install.
6. **Published pod settings:** `runtimeClassName: nebari-mediated-kernel` (in verification-only mode, the name the operator chose) and `seccompProfile: RuntimeDefault`. gVisor does not apply the pod's profile, so the pod passes Pod Security `restricted` without blocking bubblewrap. ADR-0022's "leave `seccompProfile` unset" applies only to bubblewrap on the host.
7. **Upgrades replace node groups.** Opted-in pools are immutable pools under [ADR-0024](0024-immutable-node-pool-rollouts.md): a node's runtime never changes after it joins, and any change to what a node boots with (gVisor release or artifact, node image, runtime configuration, installer), or to the pool's opt-in or `dedicated` setting, creates a new generation. ADR-0024 builds it beside the old one, qualifies its infrastructure with this ADR's node check and smoke pods (including a pod with a PVC-backed home), moves workloads to it and only then retires the old one. Pods without a controller (per-session sandboxes, interactive servers) end during a rollout rather than moving; whether a pack can recreate them on the new generation is the pack's acceptance test, which operators run before retiring the old one.
8. **Ownership.** On clusters NIC provisions, NIC owns the `RuntimeClass` and the node services (ADR-0024 owns generations and rollouts), refuses to adopt a `RuntimeClass` of that name it did not create, and fails the deploy if it cannot create or update them. `sandbox.require` only gates validation, provisioning follows opted-in groups, and NIC never deletes the `RuntimeClass` on its own, since packs may still name it.

**Prerequisites.**

- **Supported storage.** gVisor checks file permissions itself, so volumes its pods write to must present real ownership matching the pod's UID or `fsGroup`. FSx for OpenZFS and EBS (gp3) on AWS, and Hetzner Cloud Volumes, qualify; EFS access points as NIC configures them do not, and homes on them must move under NIC's storage plan ([PR #586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)) first. This ADR provides no migration. Retiring a group must not lose data, so opted-in groups need storage that keeps no data on the nodes: delivery depends on NIC's replacement for node-local block storage, and `nic validate` rejects opted-in groups until then.
- **AWS.** Per-node-group bootstrap in NIC's EKS module, and ADR-0024's AWS prerequisites.
- **Hetzner.** Node-pool labels and pre-k3s boot commands in NIC's generated configuration, ADR-0024's Hetzner prerequisites (including a lifecycle for individual pools, and gVisor on autoscaled pools only, since `hetzner-k3s create` reinstalls k3s on static nodes), homes on Hetzner Cloud Volumes, and the NIC team's fix for the metadata service exposing the k3s join token to pods.

### Combining with in-pod capabilities

Resolution uses the properties above. At `mediated-kernel`, `in-pod-namespaces` resolves to gVisor everywhere it is offered, including Hetzner; `process-self-restriction` does not (no Landlock), so a requirement for it at `mediated-kernel` resolves only where a VM runtime is available, or fails naming the gap, as on Hetzner. Requiring `in-pod-namespaces` at `shared-kernel` on Hetzner fails the same way. The node and deploy checks run bubblewrap's capability test inside gVisor whenever both are required, and each pack's startup check remains the final guard.

### What a pack does

It applies the level's published settings and never pins its pods to groups that are not opted in. For tool-execution sandboxes it keeps every credential in the agent's pod and creates sandbox pods under ADR-0025's profile; for bubblewrap inside gVisor it uses ADR-0022's qualified configurations with a fresh `/proc`. Either way it refuses to run commands unsandboxed if its startup check fails. It relies only on properties every implementation of its level has, or requires those it needs (Landlock, for example); keeps environments and package caches off network homes; watches files changed from other pods by polling; and tolerates restarts during rollouts.

### Verification

Before a provider, architecture, OS family and toolchain are listed, and on every gVisor or k3s upgrade, a maintainer runs the probe with NIC's implementation against the design doc's [verification checklist](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full).

### Security

- **Stronger than ADR-0021 and ADR-0022, but not a VM.** An escape from gVisor reaches the host and whatever else runs on the node, which without `dedicated: true` can include foundational services. Code an agent executes should be treated as attacker-influenced.
- **gVisor's own trade-offs.** Its default *directfs* mode opens host files directly, and its *systrap* platform, needed without hardware virtualisation, lacks the extra isolation of its KVM platform. NIC pins one gVisor release per NIC release and treats gVisor security releases like its own fixes.
- **Patch status.** A node's release never changes, so every sandbox on it runs the release its label records. A rollout is complete when the old generation is retired; until then `nic outputs` reports the pool as partly patched.
- **Network.** gVisor does not isolate a pod's network. Tool-execution sandboxes get it from ADR-0025's host-side default-deny, which on EKS held against root inside gVisor once enforcement was enabled (2026-10-27). Otherwise this ADR relies on no NetworkPolicy: on AWS the metadata service is unreachable (IMDSv2, hop limit 1), on Hetzner the capability waits for the NIC team's fix, and for bubblewrap inside gVisor the sandbox's no-network configuration blocks network storage for the agent's commands.
- **Declared seccomp is not enforced.** Without `--oci-seccomp`, gVisor ignores the pod's `seccompProfile`, so `RuntimeDefault` satisfies policy checks without being enforced; gVisor's own syscall implementation and host-side filter apply instead. Documentation for hardened mode ([ADR-0010](0010-high-security-mode.md)) and for auditors says so; `--oci-seccomp` would block bubblewrap.

### Consequences

**Good:**
- A much stronger, upstream-maintained boundary between pod and host, with no host relaxation and no in-cluster installer.
- Every guarantee is backed by an end-to-end check, runtimes never change on a running node, an interrupted rollout keeps capacity rather than losing it, and a gVisor failure never takes down a node's other workloads.
- Bubblewrap inside gVisor reaches Hetzner and closes ADR-0022's signalling and command-line gaps.
- Packs that require `mediated-kernel` run unchanged where another implementation of the level is resolved, such as a VM runtime on AKS.

**Bad:**
- Rollouts restart users' sessions and disrupt other workloads on shared groups, and need a second group's capacity while they run (ADR-0024).
- Failed nodes waste capacity until an operator replaces them, and repeated failures can grow a group to its maximum.
- File-heavy work on network homes and JupyterLab startup are slower, file watchers miss changes from other pods unless they poll, debugging unrelated processes does not work, and memory headroom under a limit is slightly lower (32–48 MiB at 1 GiB under JupyterLab), which the `RuntimeClass` overhead compensates; at the limit the whole pod is killed, server included, as under runc.
- Deployments with homes on EFS access points cannot adopt it until the homes move; isolation from foundational services needs `dedicated: true`.
- Implementation work across NIC and its EKS module, including ADR-0021's resolution, pinning and level-named publishing, plus ADR-0024, and continuing work to follow gVisor releases and re-qualify on gVisor, k3s and node-image changes.
- No GPU qualification (`nvproxy`) and no Landlock inside gVisor; on AKS the level comes from a VM runtime (ADR-0026), not gVisor.

## Options Detail

- **Option 1 (do nothing):** no cost, but `in-pod-namespaces` stays AWS-only and unfiltered, and nothing protects the host from the pod.
- **Option 2 (install everywhere):** no per-group setting, but every node depends on the install succeeding and every upgrade touches nodes running foundational services.
- **Option 3 (chosen):** confines change to opted-in groups, at the cost of a per-group setting, a node-side check and extra capacity during rollouts. Rejected variants (self-retiring failed nodes, a failure taint, a release-pinned label, in-place upgrades with or without draining) are in the design doc.
- **Option 4 (privileged DaemonSet installer):** easy to ship, but a privileged component in the cluster that restarts containerd on running nodes and races new nodes joining.
- **Option 5 (Kata, `vm-boundary`):** a hardware boundary, but it needs nested virtualisation or bare metal (unavailable on Hetzner Cloud) and costs more per pod. Not an alternative under ADR-0021's levels: [ADR-0026](0026-vm-boundary-capability.md) adds it as an implementation that also satisfies `mediated-kernel`, so packs need not choose.
- **Option 6 (a gVisor pod per session):** not an alternative but a way to consume Option 3, and now its primary qualified consumer; the request layer belongs to packs and the guarantees around such pods to ADR-0025.
- **Option 7 (NIC-owned seccomp profile):** weaker and more work; remains ADR-0022's fallback if gVisor proves impractical.

## Open Questions

- Where does NIC publish the gVisor image, and how do operators with private registries mirror it?
- Should failed nodes be replaced automatically, and scale-up stop for a failing group? Both need a component in the cluster.
- Should sessions survive upgrades in a later delivery?
- Should a startup taint close the window before a node records its result? Nodes cannot remove their own taints, so it needs a remover in the cluster; on k3s the window leaves the pod that triggered a scale-up stuck.
- Should GPU (`nvproxy`) node groups, and arm64 on Hetzner, be qualified?
- Does this capability make ADR-0022's first implementation unnecessary on AWS?

## Related issues

Found while probing for this ADR and reported to the NIC team (links to be added once the issues are public); on Hetzner this ADR depends on the first:

- Hetzner's metadata service exposes the k3s join token to pods on autoscaled nodes.
- hetzner-k3s v2.4.6's k3s upgrade hangs on k3s 1.34: its upgrade plans select `node-role.kubernetes.io/master`, which k3s 1.34 no longer sets.
- Pods can reach other users' shared volumes over NFS (FSx for OpenZFS as configured in [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705), and NFS-based storage generally).

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0022: In-Pod Namespace Sandboxes](0022-in-pod-namespaces-capability.md)
- [ADR-0024: Immutable Node-Pool Rollouts](0024-immutable-node-pool-rollouts.md)
- [ADR-0025: Guarantees for Untrusted-Execution Pods](0025-untrusted-execution-pods.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [gVisor](https://gvisor.dev/)
- [gVisor #13438: bwrap --unshare-net fails](https://github.com/google/gvisor/issues/13438)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
