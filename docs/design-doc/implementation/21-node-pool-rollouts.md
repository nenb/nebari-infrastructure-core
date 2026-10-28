# 21. Immutable Node-Pool Rollouts

Mechanisms for [ADR-0024](../../adr/0024-immutable-node-pool-rollouts.md). Each is a design target, not yet implemented or tested as NIC code. Its candidate first consumer is ADR-0023 ([§20](20-workload-sandboxing.md#adr-0023-mechanisms-in-full)), which would supply the generation inputs, the verification hook and the pods that end rather than move; ADR-0023 does not depend on it.

## 21.1 The rollout record

One record per immutable pool, in a ConfigMap NIC owns (the location is an open question in ADR-0024):

| Field | Meaning |
|---|---|
| `pool` | The operator's pool name |
| `current` | The serving generation's hash and full stored spec |
| `next` | During a rollout, the new generation's hash and spec |
| `phase` | The step NIC has **started** (intent), not the one it finished |
| `nicVersion` | The NIC version that started the rollout |
| `holder` | The lock holder that last wrote the record; every write is a compare-and-swap on the object's `resourceVersion` |

A stored spec holds everything NIC renders a group from: instance type, node image release, availability zones, sizes, labels, taints, every boot input (the trust bundle and the consumer's inputs, including the sandbox runtime the group names and its release, so a change of either is a new generation) and the NIC and module versions. Renderers for immutable groups take a stored spec, not the config. On AWS, the tfvars for an immutable pool are built from `current` (and `next` during a rollout); a config change that alters the rendered spec becomes a new `next`. Steady state uses the same path, so a shared-input change never rewrites a serving group.

## 21.2 Phases

| Phase (recorded first) | Side effect | On resume, NIC observes |
|---|---|---|
| `creating` | Create `next` at verification size, with the staging taint in its group definition | Whether the group exists and all nodes registered tainted |
| `verifying` | Consumer's node and pod checks on every `next` node | Check results; a failure stops here |
| `scaling` | Grow `next` (same instance type, architecture and zones as `current`) to at least `current`'s per-zone node count, all passing checks | Per-zone counts of checked, Ready nodes |
| `promoting` | Remove the staging taint at the group level | Taint state on group and nodes; from here `next` is treated as occupied |
| `retiring` | Re-check `next`'s per-zone count of checked, Ready nodes; then add the retiring taint to `current`'s group definition and fix its size | Taint and size on group and nodes |
| `draining` | Drain `current`'s nodes one at a time, checking after each | Which nodes are empty; Pending pods; controllers' Ready replicas |
| `deleting` | Re-list `current`'s members; delete the group if no workload pods remain | Group existence |
| (done) | `next` becomes `current` | — |

`promoting` and `retiring` need `nic rollout promote` and `nic rollout retire` in the first delivery. Before `promoting`, a failed `next` holds no workloads; NIC discards it when the config moves on, and only then. From `promoting` on, nothing is discarded automatically.

**After each drained node:** no pod of the pool Pending for longer than a timeout (5 minutes proposed), except the consumer's declared pods; every controller with evicted pods back to its desired Ready replicas; no PersistentVolumeClaim of the pool's pods stuck attaching. Any failure stops the rollout with the node cordoned and both generations kept.

**Lock.** One cluster-wide lock, held by every mutating command (`nic deploy`, `nic rollout`, `nic destroy`) from reading the record to the end of its last apply. On AWS it is an object beside the state file in the state bucket (`<project>/nic.lock`), created with a conditional write so only one holder can create it, and holding the holder's identity, start time and last renewal (renewed every 15 s, expiring after 60 s, proposed). OpenTofu's own state lock covers one operation; this one covers the whole command. Where there is no remote state (Hetzner), the lock is a `coordination.k8s.io/v1` `Lease` `nic-mutation` once the cluster exists. Applies use saved plans (`plan -out`, then `apply` of that file) instead of today's plan followed by an apply that plans again (`pkg/providers/cluster/aws/provider.go`), so OpenTofu rejects a plan whose state changed after it was made (observed with OpenTofu 1.11.3 on 2026-10-27, with a local backend and with the S3 backend using `use_lockfile`: `Saved plan is stale`, exit code 1, and the state kept the other process's change).

**Losing and finding the lock.** A holder that fails to renew starts no new step, lets provider operations already in flight finish, writes nothing more and exits with an error. A run that finds a lock it does not hold refuses, whether or not the lock has expired, and reports the holder and its last renewal; the operator confirms that process has stopped and runs `nic unlock`, which then reconciles every phase's observations before anything else. Record writes are compare-and-swap and name the holder, so a stale holder's record writes fail; direct provider API calls are not fenced, which is why there is no automatic takeover.

## 21.3 Provider primitives

Observations are from the probe run of 2026-10-27 (design doc §20, "EKS: node check, failures, storage, memory and arm64" and "Hetzner: pool lifecycle, failures, storage and memory").

**AWS (managed node groups, NIC's EKS module).**

- Per-group boot inputs: the module passes one `extra_ca_bundle` to every group (v0.7.0 to v0.9.0); it needs a per-group input so a stored spec can keep its own.
- Group names by generation, two groups per pool during a rollout, both rendered from stored specs. Custom per-group launch templates must keep NIC's node and VPC-endpoint security groups; without them `nodeadm` could not reach the EC2 API and nodes never joined.
- Taints: a taint added through the module's `taint` blocks was an in-place change ("1 to change") that reached the existing node without replacing it, and `update-nodegroup-config` added and removed taints on existing nodes within 60 s. The staging and retiring barriers are therefore group-level changes on AWS.
- Fixed size: `current`'s minimum, maximum and desired size set equal; the cluster autoscaler (auto-discovery with `balance-similar-node-groups`, `pkg/providers/cluster/aws/cluster_autoscaler.go`) did not scale a 1/1/1 group with pods pending ("max size reached"), and the Auto Scaling group's replacement for a terminated instance registered with the group's retiring taint. Lowering the desired size is avoided until every node is drained, because the Auto Scaling group chooses which instance to terminate.
- Node image: the image release (`ami_release_version`, module v0.9.0) is pinned in the stored spec, so an image update is a new generation.

**Hetzner (hetzner-k3s v2.4.6).**

- Autoscaled pools only: `create` reinstalls the cluster-wide `k3s_version` on every static node, including pools excluded from upgrades, so a static pool cannot be immutable. Autoscaled nodes are created from the pool's cloud-init and are not reinstalled; `min_nodes` keeps a floor.
- Adding a pool: NIC adds `<pool>-<generation>` to its generated configuration and re-runs `create`, which updated the autoscaler's arguments; the install script re-runs on every static node but restarts k3s only where its flags changed.
- Retiring a pool: removing it from the configuration leaves its servers and nodes, so NIC drains each node, deletes it through Kubernetes and deletes its server through the Hetzner API (observed working).
- Taints: k3s applies `--node-taint` only at registration, so a configuration change reaches new nodes only; taints added or removed through the API on existing nodes survived agent restarts. NIC therefore changes both: the configuration first, so later nodes register correctly, then the existing nodes through the API. The staging taint on a new pool comes from its configuration, so no node of it registers open.
- Fixed size: rejected by hetzner-k3s (min = max), so closing `current` relies on the retiring taint; the autoscaler built its node template from a live node, so it does not scale a closed pool for pods that do not tolerate the taint.
- k3s upgrades: the label `plan.upgrade.cattle.io/k3s-agent=disabled` excludes a pool from the system-upgrade-controller's plan; immutable pools carry it, and their k3s version is part of their spec. hetzner-k3s v2.4.6's own upgrade hangs on k3s 1.34 (its plans select `node-role.kubernetes.io/master`), a separate issue.
- Capacity: the project's server limits (20 shared vCPUs in the probe project) must leave room for a second generation.

## 21.4 Qualified on 2026-10-27

1. Group-level taint changes without node replacement: **AWS yes; Hetzner new nodes only**, with the API for existing nodes (above).
2. A fixed-size group is never scaled while pods are pending, and replacements register with the group's taints: **AWS yes; Hetzner cannot express a fixed size**, and the taint closes the pool instead; replacements registered with the configured taint.
3. Adding and retiring individual Hetzner pools: **adding yes; retiring needs NIC to delete nodes and servers itself.**
4. Excluding a Hetzner pool from k3s upgrades: **yes for upgrades, but `create` reinstalls static pools**, hence autoscaled pools only.

5. Saved-plan rejection: **yes**, with a local backend and with the S3 backend (`use_lockfile`), OpenTofu 1.11.3.

Still open: everything in §21.5 that needs NIC's implementation.

## 21.5 Verification checklist

On each provider, with the consumer's verification hook:

- a full rollout with workloads created continuously: none lands on `next` before promotion, none is stranded, zonal volumes follow their pods;
- NIC killed after recording each phase and before its side effect, and after the side effect and before the next record; each resume reconciles and continues without deleting an occupied group;
- two `nic deploy` runs on different pools serialised by the cluster-wide lock;
- a saved plan rejected after another process changed the state;
- a holder that loses its lock starting no new step and exiting with an error;
- a lock left by a killed process refusing every run, live or expired, until `nic unlock`;
- a shape change (instance type, architecture or zones) in an immutable pool rejected by `nic validate`;
- per-zone capacity re-checked at `nic rollout retire`, with a lost `next` node stopping retirement;
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
- **One lease per pool:** all node groups share one state and one apply on AWS, so a holder of one pool's lease can apply a stale snapshot that drops another pool's new group.
- **Automatic takeover after a lease expires:** expiry does not prove the previous holder stopped, and provider calls cannot be fenced.
- **Equal node counts across a shape change:** counts can match while no node is large enough for a workload; shape changes are excluded until a fit check exists.
- **A PVC-backed smoke pod as proof that a hub can start a server:** it bypasses the hub, its spawner configuration and per-user storage; that is the consumer's acceptance test.
- **Tainting new nodes through the API after registration:** work can land before the taint.
- **Treating a successful drain as a successful migration:** eviction succeeds even when replacements cannot schedule.
