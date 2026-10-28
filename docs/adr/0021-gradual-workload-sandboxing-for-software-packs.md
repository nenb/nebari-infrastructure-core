# ADR-0021: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-15: narrowed to the first capability and the naming convention for later ones. Revised 2026-10-16: a support policy and a kernel floor checked by `nic validate` and `nic deploy` replaced a per-image table and node-group labels. Revised 2026-10-27: requirements state an ordered boundary level, separate from in-pod capabilities. Revised 2026-10-28 after review: requirement sets under operator policy, a normative ordering rule, implementation-named runtime classes behind a published requirement mapping, separate declaration, resolution and observation, per-node-group floors, placement labels nodes cannot write, and a trust model for later capabilities; forward commitments removed. Supporting design, including future capabilities, is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md). (Renumbered from 0019, which open pull requests already use.)

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

**Threat model.** The problem is containing an agent's own commands: code an agent runs because of a prompt injection, a compromised dependency or a plain mistake, which can then reach the credentials, files and network the surrounding pod can reach. Many agent-sandbox failures are of this kind, policy leakage rather than escape. This ADR is not about containing a capable adversary determined to escape the host. Shared-kernel mechanisms do not stop kernel exploits, and recent work argues that even VMs will not reliably contain cyber-capable agents ([Trail of Bits, 2026-08-26](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/), also cited in [ADR-0012](0012-crossplane-pack-infrastructure.md)). That argues for stronger boundaries where a threat model needs them, which later capabilities can provide, not against fencing an agent's commands away from what the pod can reach.

### The sandboxing spectrum

| # | Option | What isolates the code | Needs from NIC | In this ADR |
|---|---|---|---|---|
| 1 | Language runtime (WASM, V8 isolates, Pyodide, Monty) | The runtime | Nothing | Packs can do this today |
| 1b | The user's own browser | The browser, on the user's machine | Nothing | Packs can do this today |
| 2 | Process self-restriction (Landlock + seccomp) | The process restricts itself | A node kernel with Landlock ABI 3+ (ABI 4 for TCP rules) | **`process-self-restriction`, delivered** |
| 3 | Namespace sandbox in the pod (bubblewrap and similar) | Namespaces on the shared host kernel | Node prep and security profiles | Future ADR |
| 3b | Headless browser in the pod | Chromium's own namespace sandbox | As row 3 | Future ADR; not qualified |
| 3c | System-container runtime (Sysbox) | User namespaces plus virtualised `/proc` and `/sys` | A `RuntimeClass` or a privileged outer container | Not delivered here |
| 4 | Separate locked-down pod per task | Standard container isolation | Enforced NetworkPolicy for its network controls (#691/#675) | Packs can do this today |
| 5 | User-space kernel (gVisor) | gVisor's kernel; no direct host syscalls | Runtime install and a `RuntimeClass` | Future ADR |
| 6 | MicroVM per pod (Kata, Firecracker) | A guest kernel behind hardware virtualisation | Runtime install and KVM-capable nodes | Future ADR |
| 7 | Dedicated node or cluster | A separate machine | Provisioning | Out of scope |
| 8 | External sandbox service | Someone else's infrastructure | Nothing in the cluster | Packs can do this today |

Full rows, notes on egress, credentials, observability and GPUs, and the analysis of row 3 are in the design doc ([§20.2](../design-doc/implementation/20-workload-sandboxing.md#202-the-sandboxing-spectrum), [§20.3](../design-doc/implementation/20-workload-sandboxing.md#203-notes-on-the-sandboxing-spectrum), [§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic)).

### Why row 2 needs NIC

Row 2 needs no changes to the pod's security settings, but needs node kernels with Landlock enabled at a sufficient ABI, which packs cannot choose. On current defaults this is nearly always met: EKS AMIs for Kubernetes 1.33 and later (6.12, probed at ABI 6), Hetzner's Ubuntu 24.04 (6.8, probed at ABI 4) and AKS from 1.35 (Ubuntu 24.04; expected ABI 4, not yet probed). The exceptions are older Kubernetes versions (EKS 1.31–1.32, AKS below 1.35) and images an operator pins ([§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic)).

So NIC's job is to **promise** a kernel floor on the node images it provisions, back the promise with evidence, and **stop** a deploy that requires the capability on a cluster that cannot meet it.

**Precedents.** GKE Sandbox (gVisor), AKS Pod Sandboxing (Kata) and OpenShift's Security Context Constraints each name a capability, provide it on some nodes, and let workloads request it. NIC's contract follows that shape while staying provider-neutral, and starts with a capability that needs no new runtime.

This is an ADR because it changes public interfaces packs and operators will depend on (`InfraSettings.Sandbox`, a top-level `sandbox` block of requirement sets, the published requirement mapping, a support policy) and fixes the naming and rules later capabilities use.

## Decision Drivers

- **Build in steps.** Deliver something usable now, behind a contract that stronger options can be added to later without breaking packs that already rely on it.
- **Tool-neutral, but not tool-unqualified.** NIC provides cluster primitives, not a sandboxing tool. Each guarantee is qualified against at least one concrete consumer configuration, tested on each supported node image family before NIC promises it there.
- **Provider-neutral.** Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see [System Overview](../design-doc/architecture/02-system-overview.md)).
- **Prefer Pod Security `restricted`.** Capabilities that need no relaxation come first.
- **Fail closed where NIC can tell.** A required capability the cluster cannot provide stops `nic validate` or `nic deploy`. NIC's checks are inferences, not guarantees, so consumers still verify the guarantee themselves before relying on it.
- **Least machinery.** Prefer a promise NIC can keep with a version comparison over mechanisms that need tables, labels or in-cluster components.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

Drivers that apply only to later capabilities are recorded in [§20.15](../design-doc/implementation/20-workload-sandboxing.md#2015-guidance-for-later-capability-adrs).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible capability contract, starting with process self-restriction backed by a kernel floor, with stronger capabilities added by later ADRs.
4. Go straight to a stronger-isolation runtime (gVisor or Kata `RuntimeClass`) as the only sandbox option.
5. Adopt a full sandbox platform (for example Agent Substrate) instead of a capability contract.
6. Detect the capability per node with [Node Feature Discovery](https://nfd.sigs.k8s.io/).
7. Label qualifying node groups from a NIC-maintained table of node images.

## Decision Outcome

Chosen option: "Option 3". This ADR is a deliberately small first step: it delivers one capability that needs no relaxation of pod security and little from NIC, and fixes the interface later capabilities fit into, without committing to deliver them.

### The capability

**`process-self-restriction`:** a non-root process with no added capabilities, under the container runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; each provider publishes the ABI its node images provide) and with nested seccomp filters, including user notification. Seccomp user notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check on its own. The qualified consumer is a Landlock ruleset that denies a filesystem write (and, at ABI 4, restricts `connect` to one port) plus a nested seccomp user-notification filter that injects a descriptor.

**Support policy.** On supported Kubernetes versions, every node group NIC provisions from a provider's default node image provides `process-self-restriction` at Landlock ABI 3 or newer, and NIC targets ABI 4 where the provider's images allow it. Where a provider's defaults fall below the floor (today EKS below 1.33 and AKS below 1.35) or have not been probed (AKS from 1.35), the provider says so and NIC's checks report it.

### Naming, placement and rules for later capabilities

**Names.** Capability names are lowercase and hyphenated. Names reserved for later ADRs: `in-pod-namespaces` (namespace sandboxes inside a pod, sketched in [ADR-0022](0022-in-pod-namespaces-capability.md) and designed in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-future-work-delivery-of-in-pod-namespaces-phase-2)) and `pod-user-namespaces`; `user-space-kernel` (sketched in [ADR-0023](0023-user-space-kernel-capability.md)) and `vm-boundary` name families of implementations of the boundary levels below; `network-policy` is a candidate owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691). Changing what a name guarantees, including tightening it, needs a new or versioned name (for example `<name>-v2`); the old name keeps its meaning until retired.

**Placement labels are never writable by nodes.** Where a capability or implementation needs placement, the labels pods are routed on use the `node-restriction.kubernetes.io/` prefix (for example `node-restriction.kubernetes.io/nebari-sandbox-gvisor`), which the NodeRestriction admission plugin stops kubelets setting or changing, even at registration; NIC or a cluster-side component applies them through the API. Labels a node sets itself (under `sandbox.nebari.dev/`) may only signal failure, never attract workloads, so a compromised or rogue node cannot draw sandboxed pods to itself. `process-self-restriction` needs no labels, because every node of a cluster that meets the floor provides it.

**Rules for later capabilities and profiles.** Each must define its guarantee, qualified consumer, placement, cluster requirements, provisioning, verification and any scale limits, and a **trust model**: which actors are trusted, what a hostile workload may do, what NIC enforces, what the pack must enforce, and what is outside the guarantee ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#206-the-capability-contract-in-full)). Two distinctions apply throughout: declared settings are not enforcement (gVisor and Kata both ignore the pod's `seccompProfile`), and smoke tests are diagnostics, not attestation.

### Boundary levels

A requirement has three independent parts, so it says what is needed rather than which tool provides it:

1. **Boundary level** between the pod and the host, ordered: `shared-kernel` (code calls the host kernel directly; the default runtime) < `mediated-kernel` (code never makes system calls directly to the host kernel) < `hardware-virtualised` (a hardware virtualisation boundary separates code from the host). The order compares interfaces (what the code talks to), not a strict security ranking: a user-space kernel and a VM protect in different ways and expose different Linux behaviour (§20.6). `mediated-kernel` and `hardware-virtualised` are reserved; this ADR builds only `shared-kernel`.
2. **In-pod capabilities** a workload uses inside its pod: `process-self-restriction` (this ADR) and `in-pod-namespaces`.
3. **Profiles** of platform guarantees around the pod, such as network isolation and the absence of credentials (a later ADR).

**Ordering rule.** A stronger level satisfies the operator's isolation policy, but satisfies a workload's requirement only when every in-pod capability and property the workload needs also holds there. Packs are never promised that they run unchanged because a provider offers a nominally stronger level.

### Requirements and policy

The operator states requirements as a list of named **requirement sets**, one per kind of workload, and sets floors as **policy** that every set must meet:

```yaml
sandbox:
  policy:
    minBoundary: shared-kernel        # floor for every set; the default
  requirements:
    - name: agents                    # packs find their settings by this name
      boundary: shared-kernel         # at least this level; the default
      capabilities:
        - name: process-self-restriction
          minLandlockABI: 4
```

A pack's needs are written as a set, by hand until [ADR-0003](0003-software-pack-codegen.md). Real designs need several sets (an agent pod on the default runtime that uses Landlock, and a tool-execution sandbox pod at a higher level with root inside), which one cluster-wide requirement would merge. Only one set is used today; later ADRs add more without changing the shape. There is no resolver: no provider offers two implementations of one level, so resolving a set is a lookup.

### Declaration, resolution and observation

The three are kept separate: what the provider supports, derived from config; what was selected for each requirement set; and which checks ran, on what, with what result.

1. **Declaration.** Each cluster provider reports in `InfraSettings.Sandbox`, a pure function of config, **per node group** (GPU images and other OS families make mixed clusters normal), the Landlock ABI that group's node image provides: AWS ABI 6 for Kubernetes 1.33 and later and ABI 2 below; Hetzner ABI 4; Azure ABI 1 below 1.35 and, from 1.35, unknown until a maintainer has probed AKS (expected ABI 4). A pinned image, `existing` and kind report unknown.
2. **Resolution.** **`nic validate`** resolves each set against the declarations, offline and before any infrastructure exists, and fails naming the gap if it cannot be met. Because `process-self-restriction` has no placement, every node group must meet a set's `minLandlockABI`: a known floor below it is an error naming the group, and an unknown floor is reported and left to `nic deploy`. Today every set resolves to the default runtime with the pod's usual settings. The result is published as a **requirement mapping** from each set's name to the execution settings that satisfy it (runtime class, seccomp setting, any placement). The floor comparison is transitional: once every supported Kubernetes version on every provider qualifies, it can be removed.
3. **Observation.** Once the cluster is up, **`nic deploy`** reads each node's kernel version (`node.status.nodeInfo.kernelVersion`) and converts it to the Landlock ABI that version introduces upstream. A node below a set's requirement fails the deploy; a node below the floor when nothing is required is a warning. `nic outputs` shows which nodes of each group were checked and the result. This is a **diagnostic inference**, not enforcement or attestation: a kernel version shows the Landlock code exists, not that it is enabled at boot, and nodes added later are not checked. The same split lets NIC check a provider-managed runtime (such as AKS Pod Sandboxing) without implying it controls that runtime.
4. **Consumer integration.** Packs read their settings from the requirement mapping by set name and never hardcode an implementation or class name, so the mapping can change without breaking them. For `process-self-restriction` the settings are the pod's usual ones and no node selectors are needed. Packs check the Landlock ABI at startup, as every Landlock consumer must, and refuse sandboxed work rather than run unsandboxed when it is missing or too low. NIC documents this, with an operator page of qualifying provider and version combinations; enforcing pack requirements is future work tied to ADR-0003 and #670.

**Runtime classes for later levels.** An implementation of a higher level is published as a `RuntimeClass` named after the implementation (for example `nebari-gvisor`) and labelled with its level (`sandbox.nebari.dev/level: mediated-kernel`), never as a level-named alias: a class's handler is immutable, one class per level cannot serve sets with different property needs, and the ecosystem names runtimes directly (GKE's `gvisor`, AKS's own class, Agent Sandbox templates). "At least" is enforced by validation and, where a profile requires it, admission, not by aliasing. The reasoning and the Go types are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#declaration-resolution-and-observation).

### Evidence and lifecycle

NIC installs nothing in the cluster, adds no CLI command and sets no labels. The floor each provider reports rests on evidence: **before NIC promises a node image family, a maintainer runs the probe on a fresh node of that family**, confirming that Landlock is active at boot and enforces filesystem (and, at ABI 4, TCP) rules, and that nested seccomp user notification works under the default seccomp profile. The probe is rerun when a provider changes kernel line, as part of NIC's release testing, never on users' clusters. It has passed on EKS 1.34 AL2023 and Hetzner Ubuntu 24.04 nodes; AKS has not been probed ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-phase-1-process-self-restriction)).

Because the deploy-time check is an inference, consumers still check the guarantee themselves. NIC never changes node images on its own: moving a node group to a qualifying image is an operator change through the provider's own config.

**Clusters NIC does not provision.** For `existing` clusters and kind, the floor is unknown, so only `nic deploy`'s kernel check judges them; whether Landlock is enabled at boot is the operator's responsibility.

### Security

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`, so it needs no admission exception. It shares the host kernel and is no protection against kernel exploits; code an agent executes should be treated as attacker-influenced, and packs must not use a check-then-continue seccomp supervisor as their policy mechanism.

### Consequences

**Good:**
- A useful primitive with no relaxation of pod security, no long-running components and no admission exceptions.
- Pack developers get a documented, provider-neutral primitive and choose their own tool, and need no node selectors to use it.
- NIC's code is small: a per-node-group field in `InfraSettings`, a config block, a version comparison in `nic validate`, a kernel check in `nic deploy` and a published mapping, with no image table, labels or in-cluster components.
- The interface is fixed now, so stronger isolation arrives as implementations of higher levels and new requirement sets, without breaking packs that read the mapping.

**Bad:**
- The capability ties the platform to node kernel versions: EKS below Kubernetes 1.33 and AKS below 1.35 do not qualify by default, and neither do node groups pinned to older images.
- Without labels, NIC cannot steer pods in a cluster that mixes qualifying and non-qualifying node groups; it names the failing group and warns, or fails a deploy that requires the capability.
- The checks are inferences from version numbers: they cannot see Landlock disabled at boot or backported features, nodes added after a deploy are not checked, and a deploy-time failure comes after infrastructure exists.
- NIC maintainers keep each provider's floor current and rerun the probe when a provider changes kernel line.
- At higher levels in-pod capabilities depend on the implementation (gVisor lacks Landlock), so a stronger level does not mean a pack runs unchanged; and the interface is fixed before a second implementation exists, so later ADRs must fit it or amend it.
- Pack integration is manual until ADR-0003 exists.

## Options Detail

### Options 1–3

- **Option 1 (do nothing):** no NIC changes, but packs cannot choose node kernels and are pushed toward privileged pods or `Unconfined` profiles, which fail Pod Security Baseline and conflict with ADR-0010.
- **Option 2 (one tool):** concrete and easy to test, but couples the interface to a tool with no path to stronger isolation; Option 3 keeps its concreteness by qualifying each capability against a tested configuration.
- **Option 3 (chosen):** usable now with no relaxation, cheap, extensible and tool-independent; its shape is set before a second capability exists.

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

A much stronger boundary, but it needs provider-specific runtime installation (nested virtualisation or bare metal for Kata) and adds overhead and compatibility gaps. Kept as implementations of the `mediated-kernel` and `hardware-virtualised` levels.

### Option 5: Adopt a full sandbox platform (e.g. Agent Substrate)

A stronger boundary with egress, credential injection and suspend/resume built in. Agent Substrate (v0.6.0, pre-1.0, GKE and kind only) runs many actors per worker pod under runtimes it starts itself, from root workers with added capabilities and unconfined profiles, and needs pod-certificate APIs and enforced NetworkPolicy. It cannot run on NIC's providers today; where it can, it is separately trusted infrastructure, close to host root, not an implementation of a level.

### Option 6: Node Feature Discovery

Node Feature Discovery labels nodes from their kernel version and configuration, including on images NIC does not know. Discarded because it adds a DaemonSet, a controller and CRDs for what a version comparison does for the images NIC provisions, and like the kernel check it reads configuration rather than confirming Landlock is active.

### Option 7: Node-group labels from an image table

An earlier draft labelled qualifying node groups from a NIC-maintained table of node images. Discarded because nearly every image NIC provisions already qualifies, so the labels would help only mixed clusters, at the cost of a table, label support in every provider and a readiness record. The design is kept in [§20.16](../design-doc/implementation/20-workload-sandboxing.md#option-7-node-group-labels-from-an-image-table).

The full assessment of Options 4 and 5 is in [§20.16](../design-doc/implementation/20-workload-sandboxing.md#2016-alternatives-considered-in-detail).

## Open Questions

- Should NIC's AKS module expose an `os_sku` (node OS image) setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04 and qualify? (§20.4.)
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should Nebari also offer a request layer for sandboxes on top of the published requirement mapping, such as the Agent Sandbox project's `Sandbox`/`SandboxClaim` resources? That would be a separate decision.
- Is it worth **automating the probe** as short-lived pods that `nic deploy` runs on each node group, observing Landlock and nested seccomp directly? It would catch what version numbers miss, including on `existing` clusters, at the cost of maintaining a multi-architecture image; how often maintainers' probe runs disagree with the version check should decide it.

Questions specific to later capabilities are in [§20.14](../design-doc/implementation/20-workload-sandboxing.md#2014-future-work-deferred-from-adr-0021).

## Links

- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [ADR-0012: Crossplane Capability APIs for Software Pack Cloud Infrastructure](0012-crossplane-pack-infrastructure.md)
- [ADR-0017: User Journey Tests](0017-user-journey-tests-for-foundational-software.md)
- [Trail of Bits: VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Kubernetes NodeRestriction admission plugin](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Luis Cardoso, "Sandboxes for AI" (2026)](https://www.luiscardoso.dev/blog/sandboxes-for-ai)
