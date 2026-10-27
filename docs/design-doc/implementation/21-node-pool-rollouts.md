# 21. Immutable Node-Pool Rollouts

Mechanisms for [ADR-0024](../../adr/0024-immutable-node-pool-rollouts.md). Each is a design target, not yet implemented or tested as NIC code. The first consumer is ADR-0023 ([§20](20-workload-sandboxing.md#adr-0023-mechanisms-in-full)), which supplies the generation inputs, the verification hook and the pods that end rather than move.

## 21.1 The rollout record

One record per immutable pool, in a ConfigMap NIC owns (the location is an open question in ADR-0024):

| Field | Meaning |
|---|---|
| `pool` | The operator's pool name |
| `current` | The serving generation's hash and full stored spec |
| `next` | During a rollout, the new generation's hash and spec |
| `phase` | The step NIC has **started** (intent), not the one it finished |
| `nicVersion` | The NIC version that started the rollout |

A stored spec holds everything NIC renders a group from: instance type, node image release, availability zones, sizes, labels, taints, every boot input (the trust bundle and the consumer's inputs) and the NIC and module versions. Renderers for immutable groups take a stored spec, not the config. On AWS, the tfvars for an immutable pool are built from `current` (and `next` during a rollout); a config change that alters the rendered spec becomes a new `next`. Steady state uses the same path, so a shared-input change never rewrites a serving group.

## 21.2 Phases

| Phase (recorded first) | Side effect | On resume, NIC observes |
|---|---|---|
| `creating` | Create `next` at verification size, with the staging taint in its group definition | Whether the group exists and all nodes registered tainted |
| `verifying` | Consumer's node and pod checks on every `next` node | Check results; a failure stops here |
| `scaling` | Grow `next` to at least `current`'s per-zone node count, all passing checks | Per-zone counts of checked, Ready nodes |
| `promoting` | Remove the staging taint at the group level | Taint state on group and nodes; from here `next` is treated as occupied |
| `retiring` | Add the retiring taint to `current`'s group definition and fix its size | Taint and size on group and nodes |
| `draining` | Drain `current`'s nodes one at a time, checking after each | Which nodes are empty; Pending pods; controllers' Ready replicas |
| `deleting` | Re-list `current`'s members; delete the group if no workload pods remain | Group existence |
| (done) | `next` becomes `current` | — |

`promoting` and `retiring` need `nic rollout promote` and `nic rollout retire` in the first delivery. Before `promoting`, a failed `next` holds no workloads; NIC discards it when the config moves on, and only then. From `promoting` on, nothing is discarded automatically.

**After each drained node:** no pod of the pool Pending for longer than a timeout (5 minutes proposed), except the consumer's declared pods; every controller with evicted pods back to its desired Ready replicas; no PersistentVolumeClaim of the pool's pods stuck attaching. Any failure stops the rollout with the node cordoned and both generations kept.

**Lease.** `coordination.k8s.io/v1` `Lease` `nic-rollout-<pool>`, renewed while NIC runs (15 s renew, 60 s duration proposed). A run that finds a live lease held by another identity refuses with its holder and age; an expired lease is taken over only after reconciling every phase's observations above.

## 21.3 Provider primitives

**AWS (managed node groups, NIC's EKS module).**

- Per-group boot inputs: the module passes one `extra_ca_bundle` to every group (v0.7.0 to v0.9.0); it needs a per-group input so a stored spec can keep its own.
- Group names by generation, two groups per pool during a rollout, both rendered from stored specs.
- Taints: managed node group taints are updated through `UpdateNodegroupConfig`; whether a change through the module's `taint` blocks applies to existing nodes without replacing them is to be qualified.
- Fixed size: `current`'s minimum, maximum and desired size set equal, so the cluster autoscaler (auto-discovery with `balance-similar-node-groups`, `pkg/providers/cluster/aws/cluster_autoscaler.go`) cannot scale it; the Auto Scaling group may still replace a failed instance, which registers with the retiring taint. Lowering the desired size is avoided until every node is drained, because the Auto Scaling group chooses which instance to terminate.
- Node image: the image release (`ami_release_version`, module v0.9.0) is pinned in the stored spec, so an image update is a new generation.

**Hetzner (hetzner-k3s).**

- Pools named `<pool>-<generation>` in NIC's generated configuration; adding one by re-running `hetzner-k3s create` must leave other pools untouched and update the autoscaler's per-pool configuration (to qualify).
- Retiring a pool: if removing it from the configuration does not delete its servers, NIC deletes the drained nodes through Kubernetes and their servers through the Hetzner API.
- Taints: hetzner-k3s passes pool taints to k3s at registration; whether a change reaches existing nodes, and how k3s treats it at agent restart, is to be qualified. If it does not, the staging and retiring barriers need another mechanism on Hetzner before it is supported.
- k3s upgrades: hetzner-k3s upgrades k3s in place through the system-upgrade-controller on every node. Immutable pools carry their k3s version in their spec and must be excluded (to qualify whether the upgrade plan's node selection allows it).

## 21.4 To qualify before implementation

1. Group-level taint changes without node replacement: EKS through NIC's module, and k3s through hetzner-k3s pools. Both barriers depend on it; this is the first probe.
2. A fixed-size group is never scaled by the cluster autoscaler while pods are pending, and replacement instances register with the group's taints.
3. Adding and retiring individual Hetzner pools, with the autoscaler's per-pool configuration updated.
4. Excluding a Hetzner pool from hetzner-k3s's in-place k3s upgrade.

## 21.5 Verification checklist

On each provider, with the consumer's verification hook:

- a full rollout with workloads created continuously: none lands on `next` before promotion, none is stranded, zonal volumes follow their pods;
- NIC killed after recording each phase and before its side effect, and after the side effect and before the next record; each resume reconciles and continues without deleting an occupied group;
- a second NIC process refused while the lease is live, and taking over after it expires;
- a `next` that fails verification discarded only when the config moves on, and never after `promoting`;
- a failed node in `current` replaced by the provider during `draining`, the replacement registering with the retiring taint;
- `next` short of capacity in one zone stopping the rollout before any drain;
- a drain blocked by a PodDisruptionBudget, and a controller whose pods stay Pending, each stopping the rollout with both generations kept;
- a trust-bundle edit and a NIC upgrade producing a new generation rather than changing a serving group, and a NIC upgrade refused mid-rollout;
- a third generation refused while a promoted rollout is unfinished.

## 21.6 Rejected alternatives

- **In-place updates, managed or per node with draining:** see ADR-0023's "Rejected after review" in §20.
- **A temporary canary group followed by a managed update:** the canary passing does not protect the update that follows.
- **Replacing nodes one at a time:** no verification point before the next node is removed.
- **Capping the old group at its current size to close it:** does not stop the provider replacing failed instances, which would register open to new work.
- **Recording only generation hashes:** a hash identifies a spec but cannot rebuild it once the config or NIC has changed.
- **Tainting new nodes through the API after registration:** work can land before the taint.
- **Treating a successful drain as a successful migration:** eviction succeeds even when replacements cannot schedule.
