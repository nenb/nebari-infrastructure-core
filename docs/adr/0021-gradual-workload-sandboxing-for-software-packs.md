# ADR-0021: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-15: narrowed to the first capability and the naming convention for later ones. Supporting design, including future capabilities, is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md). (Renumbered from 0019, which open pull requests already use.)

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

Row 2 needs no changes to the pod's security settings, but needs node kernels with Landlock enabled at a sufficient ABI, which packs cannot choose. On EKS, AMIs for Kubernetes 1.33 and later use a qualifying kernel (6.12); on Hetzner, the default Ubuntu 24.04 image qualifies (6.8); on AKS, the default image below Kubernetes 1.35 (Ubuntu 22.04) does not ([§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic)).

This is an ADR rather than documentation because it changes NIC's public interfaces, which packs and operators will depend on: a new `InfraSettings.Sandbox` field, a top-level `sandbox.require` config field, node labels and a readiness record. It also gives NIC concrete jobs that packs cannot do for themselves: knowing which node images qualify, labelling node groups when it creates them so packs can place their pods there, and stopping a deploy whose node groups cannot provide a required capability.

## Decision Drivers

- **Build in steps.** Deliver something usable now, behind a contract that stronger options can be added to later without breaking packs that already rely on it.
- **Tool-neutral, but not tool-unqualified.** NIC provides cluster primitives, not a sandboxing tool. Each guarantee is qualified against at least one concrete consumer configuration, tested by hand on each node image before NIC lists that image as providing it.
- **Provider-neutral.** Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see [System Overview](../design-doc/architecture/02-system-overview.md)).
- **Prefer Pod Security `restricted`.** Capabilities that need no relaxation come first.
- **Fail closed where NIC can tell.** A required capability that no node group is expected to provide stops the deploy. NIC's detection is a check, not a guarantee, so consumers still verify the guarantee themselves before relying on it.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

Drivers that apply only to later capabilities are recorded in [§20.15](../design-doc/implementation/20-workload-sandboxing.md#2015-guidance-for-later-capability-adrs).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible capability contract, starting with process self-restriction, with stronger capabilities added by later ADRs.
4. Go straight to a stronger-isolation runtime (gVisor or Kata `RuntimeClass`) as the only sandbox option.
5. Adopt a full sandbox platform (for example Agent Substrate) instead of a capability contract.

## Decision Outcome

Chosen option: "Option 3". This ADR is a deliberately small first step: it delivers one capability that needs no relaxation of pod security and little from NIC, and fixes how later capabilities will be named and advertised without committing to deliver them.

### The capability

**`process-self-restriction`:** a non-root process with no added capabilities, under the container runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; the expected ABI is published per node group) and with nested seccomp filters, including user notification. Seccomp user notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check on its own. The qualified consumer is a Landlock ruleset that denies a filesystem write (and, at ABI 4, restricts `connect` to one port) plus a nested seccomp user-notification filter that injects a descriptor.

The contract is an interface to the **node execution environment**: NIC states, by name, what the nodes it provisions will let a pod do, based on node images it has qualified. Packs still write their own pod settings and run their own tools.

**Naming convention.** Capability names are lowercase and hyphenated. Nodes that provide a capability carry the label `sandbox.nebari.dev/<capability>`, and attributes carry their own labels (for example `sandbox.nebari.dev/landlock-abi`). Names reserved for later ADRs: `in-pod-namespaces` (namespace sandboxes inside a pod, proposed in [ADR-0022](0022-in-pod-namespaces-capability.md) and designed in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-future-work-delivery-of-in-pod-namespaces-phase-2)), `pod-user-namespaces`, `user-space-kernel` and `vm-boundary`; `network-policy` is a candidate owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691). Each later capability must define its guarantee, qualified consumer, placement, cluster requirements, provisioning, verification and any scale limits ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#206-the-capability-contract-in-full)).

### Interfaces

1. **Desired configuration, and the single source of truth.** `process-self-restriction` needs no opt-in. When a provider creates a node group, it already knows the node image and kernel line, so it predicts which capabilities the group provides and reports them in `InfraSettings.Sandbox`. It applies the matching labels to the **node group itself** (`sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi`), through the same node-group label mechanism used for GPU groups, so every node, including replacements and autoscaled nodes, carries them from the moment it joins. A top-level `sandbox.require` lists capabilities the operator requires, optionally with a minimum such as `minLandlockABI`; a deploy whose node groups are not expected to meet it stops before any infrastructure changes.
2. **Readiness record.** After the cluster is up, NIC checks each node's kernel version and OS image (`node.status.nodeInfo`) against the prediction, and records the result per node group in a read-only record: expected capabilities and ABI, and any node that does not match its group's prediction (for example after a manual node upgrade). NIC reports mismatches; it does not relabel nodes. The record is informational: consumers fail closed by checking the guarantee themselves.
3. **Consumer integration.** Packs are integrated explicitly through documented Helm values, or by defaulting to the conventional labels, which are the stable interface. Helm key names will be aligned with the pack-wiring direction of [ADR-0003](0003-software-pack-codegen.md) and #670 when that settles; enforcing pack requirements is future work.

The Go types are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#three-separate-interfaces).

### Lifecycle and detection

NIC installs nothing in the cluster and adds no CLI command. The prediction comes from a table NIC maintains, mapping the node images it provisions to the Landlock ABI they provide. **A node image enters the table only after a one-off manual probe run on that image confirms the capability works under the capability's exact pod settings**, which makes the table evidence rather than assumption. Images not in the table are not labelled. The consistency check runs during `nic deploy`, and its results are shown by `nic outputs`, which already reads the live cluster.

The check against node metadata is an **inference, not an observation**: between manual runs it cannot see a node whose image changed in a way the table does not capture, for example Landlock disabled at boot by custom kernel parameters. That is why consumers must still check the guarantee themselves, and why automating the probe is an open question below ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-phase-1-process-self-restriction)). Discovery is passive: NIC labels node groups whose images qualify (targeting Landlock ABI 4) and never changes node images on its own.

**Clusters NIC does not provision.** For `existing` clusters and kind (whose kernel is the host's), NIC neither chooses the node image nor sets node-group labels, so it advertises nothing by default. Operators may apply the capability labels to their nodes themselves, at their own risk; NIC's check then reports whether each labelled node's kernel is consistent with the label.

### Security

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`, so it needs no admission exception. It shares the host kernel and is no protection against kernel exploits; code an agent executes should be treated as attacker-influenced, and packs must not use a check-then-continue seccomp supervisor as their policy mechanism.

### Consequences

**Good:**
- A useful primitive with no relaxation of pod security, no long-running components and no admission exceptions.
- Pack developers get a documented, provider-neutral primitive and choose their own tool.
- Detection needs no image, no pods, no in-cluster components and no new CLI command; labels set on node groups survive node replacement and autoscaling.
- Stronger isolation can be added later under reserved names without breaking packs that rely on this capability.

**Bad:**
- The capability ties the platform to node kernel versions: AKS below Kubernetes 1.35 does not qualify by default, node groups on older kernels cannot provide it, and `existing` and kind clusters get it only if operators label nodes themselves.
- What NIC advertises rests on a per-image table verified by hand; between runs, a node can carry the label and still lack the capability (for example if its kernel parameters disable Landlock).
- NIC gains a node-image table to keep current (each new image needs a manual probe run before it is listed), a deploy-time consistency check, a readiness record, node-group labels in each provider, and a section in `nic outputs`. Hetzner node pools need label support, which NIC's Hetzner provider does not yet expose.
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

The full assessment of Options 4 and 5 is in [§20.16](../design-doc/implementation/20-workload-sandboxing.md#2016-alternatives-considered-in-detail).

## Open Questions

- Should NIC's AKS module expose an `os_sku` (node OS image) setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04 and qualify? (§20.4.)
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should Nebari offer a uniform API for packs to **request** sandboxes, independent of the provider underneath? The request mechanism differs by provider (`runtimeClassName` for a `RuntimeClass`, a platform's own API or SDK); a standard request layer, such as the Agent Sandbox project's `Sandbox`/`SandboxClaim` resources, would be a separate decision.
- Is it worth **automating the probe**: packaging the manual probe as a container image that NIC runs as short-lived pods on each node group during deploy, to observe the capability directly (Landlock enabled at boot and its real ABI, filesystem and TCP rules taking effect, nested seccomp user notification working under the default seccomp profile)? It would catch nodes the table misjudges between manual runs, at the cost of building, publishing, pinning and maintaining a multi-architecture image and the code that runs it. How often the manual runs find the table wrong should decide it.
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
