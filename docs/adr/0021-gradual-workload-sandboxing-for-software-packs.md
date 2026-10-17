# ADR-0021: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-15: narrowed to the first capability and the naming convention for later ones. Revised 2026-10-16: replaced the per-image table and node-group labels with a support policy and a kernel floor checked by `nic validate` and `nic deploy`, since nearly every node image NIC provisions on supported Kubernetes versions already qualifies. Supporting design, including future capabilities, is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md). (Renumbered from 0019, which open pull requests already use.)

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

Row 2 needs no changes to the pod's security settings, but needs node kernels with Landlock enabled at a sufficient ABI, which packs cannot choose. On current defaults this is nearly always met: on EKS, AMIs for Kubernetes 1.33 and later use a qualifying kernel (6.12); on Hetzner, the default Ubuntu 24.04 image qualifies (6.8); on AKS, Kubernetes 1.35 and later move to Ubuntu 24.04 (6.8). The exceptions are older Kubernetes versions (EKS 1.31–1.32 at 6.1, AKS below 1.35 at 5.15) and images an operator pins ([§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic)).

So NIC does not need to discover which nodes qualify one by one. Its job is to **promise** a kernel floor on the node images it provisions, back the promise with evidence, and **stop** a deploy that requires the capability on a cluster that cannot meet it.

This is an ADR rather than documentation because it changes NIC's public interfaces, which packs and operators will depend on: a new `InfraSettings.Sandbox` field, a top-level `sandbox.require` config field, and a support policy NIC commits to keep. It also fixes the naming convention later sandboxing capabilities will use.

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

Chosen option: "Option 3". This ADR is a deliberately small first step: it delivers one capability that needs no relaxation of pod security and little from NIC, and fixes how later capabilities will be named and advertised without committing to deliver them.

### The capability

**`process-self-restriction`:** a non-root process with no added capabilities, under the container runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; each provider publishes the ABI its node images provide) and with nested seccomp filters, including user notification. Seccomp user notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check on its own. The qualified consumer is a Landlock ruleset that denies a filesystem write (and, at ABI 4, restricts `connect` to one port) plus a nested seccomp user-notification filter that injects a descriptor.

The contract is an interface to the **node execution environment**: NIC states, by name, what the nodes it provisions will let a pod do, based on node image families it has qualified. Packs still write their own pod settings and run their own tools.

**Support policy.** On supported Kubernetes versions, every node group NIC provisions from a provider's default node image provides `process-self-restriction` at Landlock ABI 3 or newer, and NIC targets ABI 4 where the provider's images allow it. Where a provider's defaults fall below the floor (today EKS below 1.33 and AKS below 1.35), the provider says so and NIC's checks report it.

**Naming convention.** Capability names are lowercase and hyphenated. Where a capability needs placement, nodes that provide it carry the label `sandbox.nebari.dev/<capability>`, and attributes carry their own labels under the same prefix. `process-self-restriction` needs no labels, because on a cluster that meets the floor every node provides it. Names reserved for later ADRs: `in-pod-namespaces` (namespace sandboxes inside a pod, designed in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-future-work-delivery-of-in-pod-namespaces-phase-2)), `pod-user-namespaces`, `user-space-kernel` and `vm-boundary`; `network-policy` is a candidate owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691). Each later capability must define its guarantee, qualified consumer, placement, cluster requirements, provisioning, verification and any scale limits ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#206-the-capability-contract-in-full)).

### Interfaces

1. **The provider's floor.** Each cluster provider reports in `InfraSettings.Sandbox` the Landlock ABI its node images provide, as a pure function of config like the rest of `InfraSettings`. For example, the AWS provider reports ABI 6 for Kubernetes 1.33 and later and ABI 2 below; Azure reports ABI 4 from 1.35 and ABI 1 below; Hetzner reports ABI 4. Where the provider cannot know (an image pinned by the operator, `existing`, kind), it reports the floor as unknown.
2. **The requirement.** A top-level `sandbox.require` lists capabilities the operator requires, optionally with a minimum:

   ```yaml
   sandbox:
     require:
       - capability: process-self-restriction
         minLandlockABI: 4
   ```

   **`nic validate`** compares the requirement with the provider's floor, offline and before any infrastructure exists, and errors if the floor is known and too low. Without `sandbox.require` it reports nothing.
3. **The deploy-time check.** Once the cluster is up, **`nic deploy`** reads each node's kernel version from the Kubernetes API (`node.status.nodeInfo.kernelVersion`) and converts it to the Landlock ABI that kernel version introduces upstream. A node below the requirement fails the deploy; a node below the floor when nothing is required is a warning. The result per node group is shown by `nic outputs`. This also covers nodes the floor cannot predict: pinned images, `existing` clusters and kind.
4. **Consumer integration.** Packs need no node selectors: on a cluster that meets the floor, any node will do. Packs check the Landlock ABI at startup, as every Landlock consumer must, and refuse sandboxed work rather than running unsandboxed when it is missing or too low. NIC documents this for pack developers, alongside an operator page listing which provider and version combinations qualify. Enforcing pack requirements is future work tied to [ADR-0003](0003-software-pack-codegen.md) and #670.

The Go types are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#three-separate-interfaces).

### Evidence and lifecycle

NIC installs nothing in the cluster, adds no CLI command and sets no labels. The floor each provider reports rests on evidence: **before NIC promises a node image family, a maintainer runs the probe on a fresh node of that family**, confirming that Landlock is active at boot and enforces filesystem (and, at ABI 4, TCP) rules, and that nested seccomp user notification works under the default seccomp profile. The probe is rerun when a provider changes kernel line for a supported Kubernetes version, as part of NIC's release testing, and is never run on users' clusters ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-phase-1-process-self-restriction)).

The deploy-time check is an **inference, not an observation**: a kernel version shows the Landlock code exists, not that it is enabled at boot, and a node added after the deploy is not checked at all. That is why consumers must still check the guarantee themselves, and why automating the probe is an open question below. NIC never changes node images on its own: moving a node group to a qualifying image is an operator change through the provider's own config.

**Clusters NIC does not provision.** For `existing` clusters and kind (whose kernel is the host's), NIC does not choose the node image, so the floor is unknown and `nic validate` cannot judge. `nic deploy`'s kernel check still runs and reports, and fails a deploy whose `sandbox.require` the nodes' kernels cannot meet; whether Landlock is enabled at boot is the operator's responsibility.

### Security

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`, so it needs no admission exception. It shares the host kernel and is no protection against kernel exploits; code an agent executes should be treated as attacker-influenced, and packs must not use a check-then-continue seccomp supervisor as their policy mechanism.

### Consequences

**Good:**
- A useful primitive with no relaxation of pod security, no long-running components and no admission exceptions.
- Pack developers get a documented, provider-neutral primitive and choose their own tool, and need no node selectors to use it.
- NIC's code is small: a field in `InfraSettings`, a config field, a version comparison in `nic validate` and a kernel check in `nic deploy`. There is no image table, no labels and nothing installed in the cluster, and `existing` and kind clusters get a check they did not have before.
- Stronger isolation can be added later under reserved names without breaking packs that rely on this capability.

**Bad:**
- The capability ties the platform to node kernel versions: EKS below Kubernetes 1.33 and AKS below 1.35 do not qualify by default, and neither do node groups pinned to older images.
- Without labels, NIC cannot steer pods in a cluster that mixes qualifying and non-qualifying node groups; it only warns, or fails a deploy that requires the capability. A pod can still land on a non-qualifying node, where the pack's own check makes it refuse sandboxed work.
- The checks are inferences from version numbers: they cannot see Landlock disabled at boot or kernels with backported features, and nodes added after a deploy are not checked.
- A deploy-time failure happens after infrastructure exists; `nic validate` catches the common case first.
- NIC maintainers keep each provider's floor current and rerun the probe when a provider changes kernel line.
- The contract's shape is fixed before a second capability exists, so later capabilities must fit it or amend it.
- Pack integration is manual until ADR-0003 exists.

## Options Detail

### Option 1: Do nothing

- **Pros:** no NIC changes.
- **Cons:** packs cannot choose node kernels; pushes packs toward privileged pods or `Unconfined` profiles, which fail Pod Security Baseline and conflict with ADR-0010.

### Option 2: Support one tool (e.g. bubblewrap)

- **Pros:** concrete and easy to test.
- **Cons:** couples the interface to a tool and gives no path to stronger isolation. Its concreteness is kept in Option 3 by qualifying each capability against a tested configuration.

### Option 3: Tool-neutral, extensible capability contract (chosen)

- **Pros:** usable now with no relaxation; low cost to NIC; extensible; independent of tool choice.
- **Cons:** the contract's shape is set before a second capability exists.

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

A much stronger boundary, but it needs provider-specific runtime installation (nested virtualisation or bare metal for Kata), adds overhead and compatibility gaps, and changes the pod model rather than letting packs confine tools inside an existing pod. Kept as the future `user-space-kernel` and `vm-boundary` capabilities.

### Option 5: Adopt a full sandbox platform (e.g. Agent Substrate)

A stronger boundary with egress, credential injection and suspend/resume built in, but it replaces the pod model, cannot run on NIC's providers today, needs relaxed privileges for its worker pods, and has a large footprint for a pre-1.0 project. Such a platform is a candidate provider for later capabilities, not a replacement for the contract.

### Option 6: Node Feature Discovery

Node Feature Discovery, a Kubernetes SIG project, runs a DaemonSet that reads each node's kernel version and configuration, and a controller that turns those facts into node labels through `NodeFeatureRule` resources. It would label nodes automatically, including images NIC does not know, `existing` clusters and kind. It was discarded because it adds a DaemonSet, a controller with permission to patch nodes, and CRDs to the cluster for something NIC can do with a version comparison: the node images NIC provisions are known in advance and change rarely. Like the kernel check, it reads kernel configuration rather than confirming Landlock is active at boot. It remains an option if clusters NIC does not provision become important.

### Option 7: Node-group labels from an image table

An earlier draft of this ADR had NIC keep a table of the node images it provisions and the Landlock ABI each provides, predict the capability when it creates each node group, and set `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi` as node-group labels, so packs could select qualifying nodes and a read-only readiness record could report nodes that drifted from the prediction. It was discarded because nearly every image NIC provisions on supported versions already qualifies, so the labels would only help clusters that mix qualifying and non-qualifying node groups, at the cost of a table to keep current, label support in every provider (Hetzner node pools lack it today) and a readiness record. If mixed clusters become common, it can be added later without changing the capability's name or guarantee. The design is kept in [§20.16](../design-doc/implementation/20-workload-sandboxing.md#option-7-node-group-labels-from-an-image-table).

The full assessment of Options 4 and 5 is in [§20.16](../design-doc/implementation/20-workload-sandboxing.md#2016-alternatives-considered-in-detail).

## Open Questions

- Should NIC's AKS module expose an `os_sku` (node OS image) setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04 and qualify? (§20.4.)
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should Nebari offer a uniform API for packs to **request** sandboxes, independent of the provider underneath? The request mechanism differs by provider (`runtimeClassName` for a `RuntimeClass`, a platform's own API or SDK); a standard request layer, such as the Agent Sandbox project's `Sandbox`/`SandboxClaim` resources, would be a separate decision.
- Is it worth **automating the probe**: packaging it as a container image that `nic deploy` runs as short-lived pods on each node group, to observe the capability directly (Landlock enabled at boot and its real ABI, filesystem and TCP rules taking effect, nested seccomp user notification working under the default seccomp profile)? It would catch what version numbers miss, including on `existing` clusters, at the cost of building, publishing, pinning and maintaining a multi-architecture image and the code that runs it. How often the maintainers' probe runs disagree with the version check should decide it.
- Should capability names themselves be versioned, so a guarantee can be tightened without silently changing its meaning?

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
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
