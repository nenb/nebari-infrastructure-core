# ADR-0021: Workload Sandboxing Capability Contract for Software Packs

## Status

Proposed (DRAFT). Supporting design is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md) (§20).

## Date

2026-10-12

## The contract

NIC describes what a cluster offers sandboxed workloads on three independent axes, so that a pack states what it needs rather than which tool provides it:

| Axis | Values | In this ADR |
|---|---|---|
| **Boundary level** between pod and host | `shared-kernel` < `mediated-kernel` < `hardware-virtualised` | `shared-kernel` (the default runtime); the other two reserved |
| **In-pod capability** a workload uses inside its pod | `process-self-restriction`, `in-pod-namespaces` | `process-self-restriction` delivered; `in-pod-namespaces` reserved |
| **Profile** of platform guarantees around the pod | For example no network, or no credentials | Reserved; none named |

At `shared-kernel`, code calls the host kernel directly; at `mediated-kernel`, it never makes system calls directly to the host kernel (for example gVisor); at `hardware-virtualised`, a hardware virtualisation boundary and a guest kernel separate it from the host (for example Kata).

**Ordering rule.** A higher level is a stronger wall, not a superset of features. It satisfies an operator's "at least this strong" policy, but never promises that a workload runs unchanged: gVisor, for example, has no Landlock. So NIC publishes in-pod capabilities separately and never implies them from a level.

**What NIC publishes.**

- Higher-level runtimes as `RuntimeClass`es named after the implementation (`nebari-gvisor`, `nebari-kata`) and labelled `sandbox.nebari.dev/level: <level>`. They are not named after levels because a class's handler is immutable and the ecosystem names runtimes directly.
- For each node group, the in-pod capabilities it provides (today, its Landlock ABI), shown by `nic outputs`.

Packs and tools, including Agent Sandbox templates, find runtimes by the level label and read capabilities from what NIC publishes. They never hardcode provider-specific names.

**Rules.**

- **(a) Fail loudly.** A requirement the cluster cannot meet stops `nic validate` or `nic deploy`; nothing falls back to a weaker boundary or capability.
- **(b) Prove before promising.** A level, capability or profile is promised on a provider only after a maintainer has tested it on that provider's node image with a named, working consumer.
- **(c) Nodes cannot volunteer.** Labels that route pods use the `node-restriction.kubernetes.io/` prefix, which the NodeRestriction admission plugin stops kubelets setting, and are applied through the API by NIC or a cluster-side component. Labels a node sets about itself (under `sandbox.nebari.dev/`) may only signal failure, so a compromised node cannot attract sandboxed pods.
- **(d) Every new capability, runtime or profile states a trust model:** who is trusted, what hostile code may do, what NIC enforces, what the pack must enforce, and what is not covered.
- **(e) Settings are not enforcement, and tests are diagnostics, not attestation.** gVisor and Kata both ignore the pod's `seccompProfile`; a check that passes shows one path worked for one pod at one time.
- **(f) Changing what a name guarantees needs a new name** (for example `<name>-v2`); the old name keeps its meaning until retired.

## Context

Software packs increasingly run code the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps. Pack developers want to contain it, for example by confining an agent's shell commands to a project directory with no network and no service-account token.

**Threat model.** The problem is containing an agent's own commands: code it runs because of a prompt injection, a compromised dependency or a mistake, which can reach whatever credentials, files and network the pod can. Many agent-sandbox failures are this kind of policy leakage rather than escape. Containing an adversary determined to escape the host is a different problem: shared-kernel mechanisms do not stop kernel exploits, and even VMs may not reliably contain cyber-capable agents ([Trail of Bits, 2026-08-26](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)). That argues for higher levels where a threat model needs them.

**The spectrum.** Options run from language runtimes (WASM, Pyodide) through self-restricting processes (Landlock, seccomp), in-pod namespace sandboxes (bubblewrap), separate locked-down pods, user-space kernels (gVisor) and microVMs (Kata) to dedicated nodes and external services. Several need nothing from NIC. The full table is in [§20.2](../design-doc/implementation/20-workload-sandboxing.md#202-the-sandboxing-spectrum).

**Why NIC is involved.** Process self-restriction needs no change to pod security, but needs node kernels with Landlock enabled at a sufficient ABI, which packs cannot choose. Current default images nearly always qualify; the exceptions are older Kubernetes versions, unprobed images and images an operator pins ([§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic)). Stronger options need runtimes and node preparation only the cluster can provide.

**Precedents.** GKE Sandbox (gVisor), AKS Pod Sandboxing (Kata) and OpenShift's Security Context Constraints each name a capability, provide it on some nodes and let workloads request it; none orders them.

## Decision Drivers

- **Build in steps:** deliver something usable now, behind an interface stronger options can join without breaking packs.
- **Tool-neutral, not tool-unqualified:** NIC provides cluster primitives, each qualified against a concrete consumer.
- **Provider-neutral:** capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/`.
- **Prefer Pod Security `restricted`:** capabilities that need no relaxation come first.
- **Least machinery:** prefer a version comparison to tables, labels or in-cluster components.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral capability contract, starting with process self-restriction backed by a kernel floor.
4. Go straight to a stronger-isolation runtime (gVisor or Kata) as the only option.
5. Adopt a full sandbox platform (e.g. Agent Substrate).
6. Detect the capability per node with Node Feature Discovery.
7. Label qualifying node groups from a NIC-maintained table of node images.

## Decision Outcome

Chosen option: "Option 3". This ADR fixes the contract above and delivers one capability that needs no relaxation of pod security and nothing installed in the cluster.

### Delivered now: `process-self-restriction`

**Guarantee.** A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer) and with nested seccomp filters, including user notification. User notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check on its own. The qualified consumer is a Landlock ruleset that denies a filesystem write (and, at ABI 4, restricts `connect` to one port) plus a nested seccomp user-notification filter that injects a descriptor.

**Floors.** Each cluster provider reports in `InfraSettings.Sandbox`, per node group and as a pure function of config, the Landlock ABI that group's node image provides. Per node group, because GPU images and other OS families make mixed clusters normal:

| Provider | Floor |
|---|---|
| `aws` (AL2023) | ABI 6 from Kubernetes 1.33 (probed); ABI 2 below |
| `hetzner` (Ubuntu 24.04) | ABI 4 (probed) |
| `azure` (AKS) | ABI 1 below 1.35; from 1.35 unknown until probed (expected ABI 4) |
| Pinned images, `existing`, kind | Unknown |

NIC targets ABI 4 on default images and never changes node images itself; moving a group to a qualifying image is an operator change.

**Operator requirement.** One optional setting:

```yaml
sandbox:
  minLandlockABI: 4   # optional; validate/deploy fail if any node group falls below
```

**Checks.**

- **`nic validate`** compares each node group's declared floor with `minLandlockABI`, offline. A known floor below it is an error naming the group; an unknown floor is reported and left to `nic deploy`.
- **`nic deploy`** reads each node's kernel version (`node.status.nodeInfo.kernelVersion`), maps it to the Landlock ABI that version introduced upstream, and fails if any node is below `minLandlockABI`. When nothing is required, a node below ABI 3 is a warning. The result per node group is shown by `nic outputs`.

This is a **diagnostic inference**, not enforcement: a kernel version shows the Landlock code exists, not that it is enabled at boot, and nodes added later are not checked, so packs still check Landlock themselves (below). NIC installs nothing in the cluster for this and sets no labels. Until pack codegen ([ADR-0003](0003-software-pack-codegen.md)) exists, operators pass the requirement to packs through their documented values.

**Probe and evidence.** Before NIC promises a floor for a node image family, a maintainer runs the probe on a fresh node of that family: Landlock active at boot and enforcing filesystem (and, at ABI 4, TCP) rules, with positive controls, and nested seccomp user notification working under the default seccomp profile. The probe is rerun when a provider changes kernel line, as part of release testing, never on users' clusters. It has passed on EKS 1.34 AL2023 (2026-10-19) and Hetzner Ubuntu 24.04 (2026-10-25) nodes; AKS has not been probed ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-process-self-restriction)).

### What a pack author does

**Today, inside the pod.** A pack confines the commands it runs itself, with no change to its pod spec. At startup it reads the Landlock ABI and refuses sandboxed work if Landlock is missing or below what it needs. For each command it applies a Landlock ruleset in the process that will run it: writes only beneath a working directory and, at ABI 4, TCP `connect` only to listed ports and no `bind`. A pack that mediates system calls adds a nested seccomp user-notification filter. NIC publishes a recipe: the qualified consumer above as a short example, marking what the probe has and has not tested ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#recipe-confining-a-command)). It shows a working configuration and bundles no tool; any Landlock library that applies the same ruleset will do.

**Next, a separate sandbox pod with one setting.** The intended direction, outside this ADR's delivery, is that a pack puts the pod that runs untrusted code in a sandbox namespace and states the boundary level it needs. NIC would supply the runtime, default-deny networking, no ambient credentials and dedicated nodes, so the pack writes no isolation code. That serves agents that send tool calls to a separate pod, agents that run wholly inside a sandbox, and request layers such as Agent Sandbox. The contract fixed here is what makes that one setting mean the same on every provider.

### Out of scope

- Installing gVisor, Kata or any other higher-level runtime. The level names are reserved; delivering one needs its own ADR under the rules above.
- Profiles. NetworkPolicy enforcement, which a "no network" profile would need, is tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691).
- Creating sandbox pods. That belongs to the pack or to a request layer such as [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/), consuming what NIC publishes.
- Choosing between two implementations of one level, which no provider offers today.

### Evidence from the higher levels

The contract was checked against test-only installs on clusters deployed with NIC; results and dates are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#evidence-from-the-higher-levels).

- **gVisor** on EKS 1.34 AL2023 (x86 and arm64) and Hetzner k3s (2026-10-19 to 2026-10-27) worked behind a `RuntimeClass` as a `mediated-kernel` implementation, but Landlock returned `ENOSYS` and the pod's `seccompProfile` was ignored. That gave the ordering rule and rule (e). Home directories on EFS access points, as NIC configures them, were not writable under gVisor, so qualification covers storage (rule (b)).
- **Kata** (QEMU) on EKS 1.34 through EC2 nested virtualisation (2026-10-27) passed this ADR's probe inside the guest at Landlock ABI 7, while the declared `RuntimeDefault` was not applied. In-pod capabilities differ between implementations, which is why NIC publishes them separately from levels.
- **Bubblewrap in pods** on EKS AL2023 (2026-10-19) worked only with no seccomp profile set and failed under `RuntimeDefault`; on Hetzner, AppArmor blocked it. `in-pod-namespaces` therefore stays reserved.
- **Node self-labelling** on EKS (2026-10-26): with only its own credentials, a node rewrote its own node-group label, and the change survived a kubelet restart; it could not set `node-restriction.kubernetes.io/` labels or taints. That gave rule (c).
- **NetworkPolicy** is not enforced on NIC's EKS clusters by default; once enabled, default deny held against root under gVisor and Kata, except towards the pod's own node. Profiles stay out of scope until #691.

### Security

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`, so it needs no admission exception. It shares the host kernel and is no protection against kernel exploits. Code an agent executes should be treated as attacker-influenced, and packs must not use a check-then-continue seccomp supervisor as their policy mechanism.

### Consequences

**Good:**

- A useful primitive with no relaxation of pod security, no components and no admission exceptions.
- Packs get a provider-neutral primitive, choose their own tool and need no node selectors; NIC adds a per-node-group field, one setting and two checks.
- Stronger isolation can arrive as implementations of the reserved levels without breaking packs that use the contract.

**Bad:**

- The capability ties the platform to node kernel versions: EKS below 1.33, AKS below 1.35 and pinned older images do not qualify by default.
- Without labels, NIC cannot steer pods in a mixed cluster; it names the failing group and warns, or fails a deploy that requires the capability.
- The checks are inferences from version numbers, and a deploy-time failure comes after infrastructure exists.
- Maintainers keep each provider's floor current and rerun the probe when a kernel line changes.
- The interface is fixed before a second level is built, so later ADRs must fit it or amend it.
- Pack integration is manual until ADR-0003 exists.

## Options Detail

- **Option 1 (do nothing):** pushes packs towards privileged pods or `Unconfined` profiles, which conflict with ADR-0010.
- **Option 2 (one tool):** concrete and easy to test, but couples the interface to a tool with no path to stronger isolation. Option 3 keeps that concreteness through tested consumers.
- **Option 3 (chosen):** usable now with no relaxation, cheap and tool-independent; its shape is set before a second level exists.
- **Option 4 (a stronger runtime only):** a much stronger boundary, but needs provider-specific installation and adds overhead and compatibility gaps. Kept as the reserved levels.
- **Option 5 (a full sandbox platform):** Agent Substrate (v0.6.0, pre-1.0, GKE and kind only) runs its own runtimes from root worker pods and needs APIs NIC's providers lack. Where it can run, it is separately trusted infrastructure, not an implementation of a level.
- **Option 6 (Node Feature Discovery):** adds a DaemonSet, a controller and CRDs for what a version comparison does, and still does not confirm Landlock is active.
- **Option 7 (labels from an image table):** would steer pods in mixed clusters, but nearly every image NIC provisions qualifies, so it buys little for a table and label support in every provider.

The full assessment of Options 4, 5 and 7 is in the design doc ([§20](../design-doc/implementation/20-workload-sandboxing.md#option-4-stronger-isolation-runtime-only-gvisor-or-kata)).

## Open Questions

- Should NIC's AKS module expose an `os_sku` setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04 and qualify?
- Should the Pack Specification's security baseline point at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Is it worth automating the probe as short-lived pods that `nic deploy` runs on each node group? It would catch what version numbers miss, including on `existing` clusters, at the cost of maintaining a multi-architecture image.

## Links

- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [Trail of Bits: VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [Kubernetes NodeRestriction admission plugin](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
