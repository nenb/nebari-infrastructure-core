# ADR-0024: Immutable Node-Pool Rollouts

## Status

Proposed (DRAFT). Its first consumer is [ADR-0023](0023-user-space-kernel-capability.md), which cannot be accepted before it. Mechanisms, the qualification list and the verification checklist are in the [design doc](../design-doc/implementation/21-node-pool-rollouts.md).

## Date

2026-10-27

## Context

NIC updates node groups in place today:

- **AWS.** Every `nic deploy` regenerates the OpenTofu variables from the current config (`pkg/providers/cluster/aws/provider.go`, `tofu.go`), and a changed launch template makes the managed node group replace nodes, up to a third of the group at a time, as soon as replacements report Ready. Some boot inputs are shared by every group: the trust bundle reaches every group's boot data, so editing it, or upgrading NIC's EKS module, changes every group.
- **Hetzner.** `hetzner-k3s create` does not replace existing servers; k3s upgrades run in place on every node through the system-upgrade-controller.

That suits most pools, whose nodes are interchangeable once Ready. It does not suit pools where **Ready is not the same as working** and a running node must never change underneath its workloads. ADR-0023 is the first: a node can be Ready while its gVisor runtime is broken, and swapping the runtime on a running node mixes releases. Three rounds of review of ADR-0023 tried in-place upgrades with draining, rollback, a check for leftover sandboxes and a per-node attempt limit; each found a failure the protocol did not cover (recorded in [§20](../design-doc/implementation/20-workload-sandboxing.md#adr-0023-mechanisms-in-full) under "Rejected after review"). Replacing whole node groups removes those failures, but moves the risk to coordinating two groups: keeping the old one unchanged, keeping work off the new one until it is verified, proving the new one can carry the load, and surviving interruption.

The same need is likely for GPU pools with custom images and drivers, and for any pool whose node image an operator wants to change without risking the running nodes.

## Decision Drivers

- **A running node's boot configuration never changes.** Any change becomes a new generation of nodes.
- **No work before verification.** New nodes take no workloads until the consumer's checks pass on them.
- **Never lose capacity or data on interruption.** When in doubt, keep both groups; extra capacity is preferable to deleting the wrong one.
- **Resumable across NIC runs.** NIC is a CLI, not a controller: state survives NIC exiting, and the next run continues safely.
- **Small, explicit state.** A few recorded facts per pool, reconciled with what the cluster shows, rather than a general controller.
- **Opt-in per pool.** Pools that do not need this keep their provider's normal updates.
- **Provider-neutral contract.** Requirements stated once; each provider supplies the primitives.

## Considered Options

1. In-place managed updates (today's behaviour).
2. In-place updates on each node with draining (the system-upgrade-controller on Hetzner).
3. Replacing nodes one at a time (drain and delete, letting the autoscaler recreate them).
4. Blue/green per pool: build a verified new group beside the old one, move workloads, retire the old one, with recorded, resumable state.
5. An external lifecycle controller (Cluster API, Karpenter's drift replacement).

## Decision Outcome

Chosen option: "Option 4", because it is the only option in which the group that was verified is the group that serves, a running node never changes, and an interruption leaves extra capacity rather than broken nodes. Options 1–3 were tried or analysed for ADR-0023 and rejected; option 5 is a large dependency that does not exist for hetzner-k3s.

### Immutable pools

A pool is **immutable** when a consumer ADR requires it; ADR-0023's opted-in pools are the first. Operators keep naming the pool (`user`); NIC names its physical groups `user-<generation>` and labels every node with stable pool labels, which the consumer's scheduling rules, packs and operators select. Nothing selects a physical group name.

### What NIC does

1. **Stored generation specs.** NIC stores the full resolved spec of each immutable pool's current generation in a NIC-owned record in the cluster: instance type, node image release, every boot input (including the trust bundle and the consumer's inputs, such as ADR-0023's gVisor artifact digest), labels, taints and the NIC and module versions that rendered it. The generation is a hash of that rendered spec. NIC renders immutable groups **from their stored specs, never from the current config**; only a new generation is rendered from the config. A change to the config, a shared input or NIC itself that would alter an immutable pool's spec therefore creates a new generation, never an in-place change. While a rollout is unfinished, NIC refuses to run as a different version from the one that started it.
2. **Barriers at the group level, present at registration.** A new generation is created with a staging taint (`node.nebari.dev/staging:NoSchedule`) in its group definition, which only verification pods and node-level DaemonSets tolerate. The old generation, when retired, gets a retiring taint (`node.nebari.dev/retiring:NoSchedule`) in its group definition, so nodes the provider launches to replace failed ones register already closed. Both are changed at the group level without replacing nodes. Tainting nodes through the API after they register is not a barrier, since work can land first.
3. **Recorded intent before each step.** NIC records what it is about to do before doing it, and on every run reconciles the record with what it observes (groups, nodes, taints, pods) before any destructive action. Promotion is the critical step: NIC records `promoting` before removing the staging taint, and from then on the new generation counts as possibly holding workloads.
4. **Exclusive ownership.** A rollout is driven by one NIC process at a time, holding a Kubernetes `Lease` for its whole duration. OpenTofu's per-apply locks do not cover a multi-step rollout. A NIC run that finds a live lease refuses; an expired lease is taken over only after reconciling.
5. **Capacity before evacuation.** Before retiring the old generation, the new one is scaled until it has at least as many nodes in each availability zone as the old one, every one of them passing the consumer's checks. After each old node drains, NIC checks that no pod of the pool is left Pending and that evicted workloads' controllers have Ready replicas again, and stops if not. A consumer declares the pods that end rather than move (ADR-0023: JupyterHub user servers) and what success means for them.
6. **Retirement.** The old generation is closed (retiring taint, fixed size so the autoscaler cannot scale it), drained node by node within disruption budgets, and deleted only after NIC re-lists its actual members from the provider and Kubernetes and finds no workload pods.
7. **Failure.** NIC stops and keeps both generations. There is no automatic rollback once promotion has started. A generation that never reached `promoting` holds no workloads and is discarded when the config moves on. A pool has at most two generations: a new one is refused while a promoted rollout is unfinished.
8. **Operator control in the first delivery.** `nic deploy` creates and verifies a new generation automatically. Promotion and retirement each need an explicit operator command (`nic rollout promote <pool>` and `nic rollout retire <pool>`), and `nic rollout status` and `nic outputs` report every unfinished rollout. Automating them can follow once the checks have been qualified.

**Prerequisites.**

- **AWS.** Per-group boot inputs in NIC's EKS module, including the trust bundle; groups named by generation; tfvars rendered from stored specs, with both generations kept until retirement; managed node group taint changes applied without replacing nodes; and an autoscaler that cannot scale a fixed-size group.
- **Hetzner.** Adding and retiring individual pools (NIC wraps only cluster-wide `hetzner-k3s create` and `delete` today), with the autoscaler's per-pool configuration updated; pool-level taints that reach both existing and new nodes; and keeping hetzner-k3s's in-place k3s upgrades off immutable pools, whose k3s version becomes part of their spec.

### Consequences

**Good:**
- A running node never changes, and the group that was verified is the group that serves.
- An interruption at any point leaves both generations, never lost capacity or data.
- A small, explicit state model that NIC can resume without a controller running in the cluster.
- Usable beyond ADR-0023, for GPU pools and node-image changes.

**Bad:**
- A rollout runs a full second copy of the pool until the old one is retired.
- Workloads on the pool are disrupted; controller-less sessions end.
- New state for NIC to own: stored specs, the rollout record and the lease.
- Implementation work in NIC, its EKS module and the Hetzner provider, and operator steps (promote, retire) in the first delivery.
- Immutable pools no longer take shared-input changes (such as a new trust bundle) without a rollout.

## Options Detail

- **Option 1 (in-place managed updates):** no new work, but a node can be replaced by one that is Ready and broken, and shared inputs change every group.
- **Option 2 (in-place with draining):** keeps the nodes, but needed rollback, a check for leftover sandboxes and per-node attempt limits, each of which review showed incomplete.
- **Option 3 (one node at a time):** no second group, but no point at which a new node is verified before the next is removed, and on AWS no way to gate a managed update per node.
- **Option 4 (chosen):** the verified group serves and interruption keeps capacity, at the cost of a second group during rollouts and recorded state.
- **Option 5 (external controller):** Cluster API or Karpenter would own the lifecycle, but each is a large dependency, changes how NIC provisions clusters, and neither fits hetzner-k3s. Worth revisiting if NIC adopts one.

## Open Questions

- Should promotion and retirement become automatic once the capacity checks are qualified?
- Should operators be able to mark any pool immutable (for example GPU pools), not only through a consumer ADR?
- Where should stored specs live: a ConfigMap, a Secret (the trust bundle may be sensitive in some deployments) or the provider's state backend?
- Can very large pools stage a new generation in parts rather than at full size?
- Can hetzner-k3s's in-place k3s upgrades exclude a pool, or must immutable pools be excluded by other means?

## Links

- [ADR-0023: User-Space Kernel Sandboxes with gVisor](0023-user-space-kernel-capability.md)
- [Design doc: Immutable Node-Pool Rollouts](../design-doc/implementation/21-node-pool-rollouts.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [Amazon EKS: updating a managed node group's configuration](https://docs.aws.amazon.com/eks/latest/userguide/update-managed-node-group.html)
- [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/)
- [hetzner-k3s](https://github.com/vitobotta/hetzner-k3s)
