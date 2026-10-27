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
2. **Barriers present at registration.** A new generation is created with a staging taint (`node.nebari.dev/staging:NoSchedule`) in its group definition, which only verification pods and node-level DaemonSets tolerate. The old generation, when retired, gets a retiring taint (`node.nebari.dev/retiring:NoSchedule`) in its group definition, so nodes the provider launches to replace failed ones register already closed. Changes must also reach existing nodes without replacing them, which providers do differently (observed 2026-10-27): on AWS, EKS applies a managed node group's taint changes to its existing nodes in place; on Hetzner, k3s applies pool taints only at registration, so NIC changes the pool's configuration for future nodes and the existing nodes through the API, where taints survive agent restarts. The group definition is always the barrier for new nodes: tainting a new node through the API after it registers is not, since work can land first.
3. **Recorded intent before each step.** NIC records what it is about to do before doing it, and on every run reconciles the record with what it observes (groups, nodes, taints, pods) before any destructive action. Promotion is the critical step: NIC records `promoting` before removing the staging taint, and from then on the new generation counts as possibly holding workloads.
4. **One mutation lock per cluster.** Every command that changes the cluster (`nic deploy`, `nic rollout`, `nic destroy`) holds one cluster-wide lock from reading the rollout record to the end of its last apply. Per-pool locks are not enough: on AWS every node group shares one OpenTofu state and one apply, so a process holding pool A's lock could apply a stale snapshot that drops pool B's new group. The lock lives beside the provider's state where there is one (the state bucket on AWS), and as a Kubernetes `Lease` otherwise. Applies use saved plans, so OpenTofu rejects a plan whose state changed after it was made.
5. **No automatic takeover.** An expired lock does not prove its previous holder stopped: Kubernetes leader election, for example, offers no fencing. A NIC process that cannot renew its lock starts no new step, lets provider operations already in flight finish, writes nothing more and exits with an error. A NIC run that finds an unreleased lock refuses and names the holder; the operator confirms the holder has stopped and runs `nic unlock`. Writes to the rollout record are compare-and-swap and carry the holder's identity, so a stale holder's record writes fail. Direct provider API calls are not fenced.
6. **Same shape, then capacity before evacuation.** In the first delivery a new generation keeps the old one's instance type, architecture and availability zones; only what nodes boot with may change (node image, boot inputs, the consumer's runtime). `nic validate` rejects a shape change in an immutable pool, which instead needs a new pool that the operator migrates to. With the shape fixed, the new generation is scaled until it has at least as many nodes in each availability zone as the old one, every one passing the consumer's checks, and this is checked again at retirement, which may come days after promotion. After each old node drains, NIC checks that no pod of the pool is left Pending and that evicted workloads' controllers have Ready replicas again, and stops if not.
7. **Declared exceptions.** A consumer declares the pods that end rather than move (ADR-0023: JupyterHub user servers). NIC's checks qualify the infrastructure only; whether those pods' owners can recreate them on the new generation is the consumer's acceptance test, which operators run before retiring.
8. **Retirement.** The old generation is closed (retiring taint; on AWS also a fixed size, so the autoscaler cannot scale it; hetzner-k3s rejects a fixed size, so on Hetzner the taint alone closes it, and the autoscaler respects it because it builds its template from live nodes), drained node by node within disruption budgets, and deleted only after NIC re-lists its actual members from the provider and Kubernetes and finds no workload pods.
9. **Failure.** NIC stops and keeps both generations. There is no automatic rollback once promotion has started. A generation that never reached `promoting` holds no workloads and is discarded when the config moves on. A pool has at most two generations: a new one is refused while a promoted rollout is unfinished.
10. **Operator control in the first delivery.** `nic deploy` creates and verifies a new generation automatically. Promotion and retirement each need an explicit operator command (`nic rollout promote <pool>` and `nic rollout retire <pool>`), `nic rollout status` and `nic outputs` report every unfinished rollout, and `nic unlock` releases a lock whose holder the operator has confirmed stopped. Automating them can follow once the checks have been qualified.

**Prerequisites.**

- **AWS.** Per-group boot inputs in NIC's EKS module, including the trust bundle; groups named by generation; tfvars rendered from stored specs, with both generations kept until retirement; saved-plan applies and a lock in the state bucket; and custom per-group launch templates that keep NIC's node and VPC-endpoint security groups, without which nodes never join. Taint changes in place and fixed-size groups already behave as required (observed 2026-10-27).
- **Hetzner.** **Immutable pools are autoscaled pools only:** `hetzner-k3s create`, which NIC runs on every deploy, reinstalls the one cluster-wide k3s version on every static node, which would change a running node; autoscaled nodes are not reinstalled, and a minimum size keeps a floor. Also: adding pools by re-running `create` and retiring them by draining and deleting their nodes and servers through the APIs (NIC wraps only cluster-wide `create` and `delete` today, and removing a pool from the configuration leaves its servers); pool taints set in the configuration for new nodes and through the API for existing ones; immutable pools excluded from hetzner-k3s's k3s upgrades with the label `plan.upgrade.cattle.io/k3s-agent=disabled`, their k3s version being part of their spec; and room within the project's server limits for a second generation.

### Consequences

**Good:**
- A running node never changes, and the group that was verified is the group that serves.
- An interruption at any point leaves both generations, never lost capacity or data.
- A small, explicit state model that NIC can resume without a controller running in the cluster.
- Usable beyond ADR-0023, for GPU pools and node-image changes.
- The cluster-wide lock and saved plans also close an existing race between concurrent `nic deploy` runs.

**Bad:**
- A rollout runs a full second copy of the pool until the old one is retired.
- Workloads on the pool are disrupted; controller-less sessions end.
- New state for NIC to own: stored specs, the rollout record and the cluster-wide lock.
- Implementation work in NIC, its EKS module and the Hetzner provider, and operator steps (promote, retire) in the first delivery.
- Immutable pools no longer take shared-input changes (such as a new trust bundle) without a rollout, and cannot change instance type, architecture or zones in a rollout in the first delivery.
- On Hetzner, immutable pools must be autoscaled, and a rollout needs a second generation's servers within the project's limits.
- One lock serialises every change to a cluster, and a crashed holder needs an operator to run `nic unlock`.

## Options Detail

- **Option 1 (in-place managed updates):** no new work, but a node can be replaced by one that is Ready and broken, and shared inputs change every group.
- **Option 2 (in-place with draining):** keeps the nodes, but needed rollback, a check for leftover sandboxes and per-node attempt limits, each of which review showed incomplete.
- **Option 3 (one node at a time):** no second group, but no point at which a new node is verified before the next is removed, and on AWS no way to gate a managed update per node.
- **Option 4 (chosen):** the verified group serves and interruption keeps capacity, at the cost of a second group during rollouts and recorded state.
- **Option 5 (external controller):** Cluster API or Karpenter would own the lifecycle, but each is a large dependency, changes how NIC provisions clusters, and neither fits hetzner-k3s. Worth revisiting if NIC adopts one.

## Open Questions

- Should promotion and retirement become automatic once the capacity checks are qualified?
- Should a fit check (pods' requests against the new generation's allocatable resources, placement rules and volume zones) allow shape changes in a rollout?
- Can fencing extend to direct provider API calls, so that an expired lock can be taken over automatically?
- Should operators be able to mark any pool immutable (for example GPU pools), not only through a consumer ADR?
- Where should stored specs live: a ConfigMap, a Secret (the trust bundle may be sensitive in some deployments) or the provider's state backend?
- Can very large pools stage a new generation in parts rather than at full size?
- Should NIC support static immutable pools on Hetzner, which would need `hetzner-k3s create` to stop reinstalling k3s on them?

## Related issues (to do)

Found while probing for this ADR; not yet reported to the NIC team:

- **`nic destroy` on AWS times out deleting VPC endpoints.** NIC's EKS module creates about ten interface endpoints, each with a network interface per private subnet, and sets no `timeouts` on `aws_vpc_endpoint`, so the AWS provider's 10-minute default applies. AWS deletes them asynchronously and sometimes takes longer; the first `nic destroy` then fails and a second run completes (seen in two probe sessions). To do: a longer delete timeout (20–30 minutes) in the module's `vpc-endpoints` submodule, and possibly one automatic retry in NIC for this known transient error. Retiring generations (step 8) deletes node groups on every rollout, so slow AWS deletions matter here too.
- **Cost of the interface endpoints.** About ten endpoints across three availability zones cost roughly $200 a month per cluster, on top of the NAT gateway. To do: ask whether the set can be trimmed or made optional for small clusters.

## Links

- [ADR-0023: User-Space Kernel Sandboxes with gVisor](0023-user-space-kernel-capability.md)
- [Design doc: Immutable Node-Pool Rollouts](../design-doc/implementation/21-node-pool-rollouts.md)
- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [Amazon EKS: updating a managed node group's configuration](https://docs.aws.amazon.com/eks/latest/userguide/update-managed-node-group.html)
- [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/)
- [OpenTofu: applying a saved plan](https://opentofu.org/docs/cli/commands/apply/)
- [hetzner-k3s](https://github.com/vitobotta/hetzner-k3s)
