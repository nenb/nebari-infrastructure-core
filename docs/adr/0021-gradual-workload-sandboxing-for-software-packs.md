# ADR-0021: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-15: narrowed to the first capability and the naming convention for later ones. Namespace sandboxes and runtime-backed capabilities are designed in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md) as future work, and each needs its own ADR before NIC delivers it. (Renumbered from 0019, which open pull requests already use.)

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

**Threat model.** The problem this ADR addresses is containing an agent's own commands: code an agent runs because of a prompt injection, a compromised dependency or a plain mistake, which can then reach the credentials, files and network that the surrounding pod can reach. Many agent-sandbox failures are of this kind, policy leakage rather than escape. This ADR is not about containing a capable adversary determined to escape the host. Shared-kernel mechanisms do not stop kernel exploits, and recent work argues that even VMs will not reliably contain cyber-capable agents ([Trail of Bits, 2026-08-26](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/), also cited in [ADR-0012](0012-crossplane-pack-infrastructure.md)). That is an argument for stronger boundaries where a threat model needs them, which later capabilities can provide; it is not an argument against fencing an agent's commands away from what the pod can reach.

There is no single right way to sandbox. The options form a spectrum that differs in strength, cost, what code it can run, and what it needs from the cluster. Several options need nothing from NIC. This ADR delivers the cheapest option that does depend on the cluster, process self-restriction (row 2), and fixes how later options will be named and advertised.

### The sandboxing spectrum

| # | Option | What isolates the code | Needs from NIC | In this ADR |
|---|---|---|---|---|
| 1 | Language runtime (WASM, V8 isolates, Pyodide, Monty) | The runtime | Nothing | Packs can do this today |
| 1b | The user's own browser | The browser, on the user's machine | Nothing | Packs can do this today |
| 2 | Process self-restriction (Landlock + seccomp) | The process restricts itself | A node kernel with Landlock ABI 3+ (ABI 4 for TCP rules) | **`process-self-restriction`, delivered** |
| 3 | Namespace sandbox in the pod (bubblewrap and similar) | Namespaces on the shared host kernel | Node prep and security profiles | `in-pod-namespaces`: name reserved, designed in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-delivery-phase-2-in-pod-namespaces), future ADR |
| 3b | Headless browser in the pod | Chromium's own namespace sandbox | As row 3 | Potential future consumer of `in-pod-namespaces`; not qualified (Chromium's sandbox may need more than the guarantee, such as its own pid namespace) |
| 3c | System-container runtime (Sysbox) | User namespaces plus virtualised `/proc` and `/sys` | A `RuntimeClass` or a privileged outer container | Not delivered here |
| 4 | Separate locked-down pod per task | Standard container isolation | Enforced NetworkPolicy for its network controls (#691/#675) | Packs can do this today; `pod-user-namespaces` later |
| 5 | User-space kernel (gVisor) | gVisor's kernel; no direct host syscalls | Runtime install and a `RuntimeClass` | `user-space-kernel`, future ADR |
| 6 | MicroVM per pod (Kata, Firecracker) | A guest kernel behind hardware virtualisation | Runtime install and KVM-capable nodes | `vm-boundary`, future ADR |
| 7 | Dedicated node or cluster | A separate machine | Provisioning | Out of scope |
| 8 | External sandbox service | Someone else's infrastructure | Nothing in the cluster | Packs can do this today |

The full table, with examples and limits, and notes on egress, credentials, observability and GPUs, are in the design doc ([§20.2](../design-doc/implementation/20-workload-sandboxing.md#202-the-sandboxing-spectrum), [§20.3](../design-doc/implementation/20-workload-sandboxing.md#203-notes-on-the-sandboxing-spectrum)).

### Why row 2 needs NIC

Row 2 runs with no changes to the pod's security settings, but needs node kernels with Landlock enabled at a sufficient ABI, which packs cannot choose. On EKS, AMIs for Kubernetes 1.33 and later use a qualifying kernel (6.12); on Hetzner, the default Ubuntu 24.04 image qualifies (6.8); on AKS, the default image below Kubernetes 1.35 (Ubuntu 22.04) does not. NIC is the component that knows which node images it deploys and can verify and advertise where the capability holds. Per-provider findings are in [§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic).

Row 3 needs considerably more from the cluster (node preparation, a custom seccomp profile, an AppArmor mechanism, dedicated node groups); it appears to work today only because pods without a seccomp profile run with no syscall filter at all, the default on EKS, hetzner-k3s and AKS as NIC deploys them. That analysis is in [§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic) and motivates the future `in-pod-namespaces` ADR.

## Decision Drivers

- **Build in steps.** Deliver something usable now, behind a contract that stronger options can be added to later without breaking packs that already rely on it.
- **Tool-neutral, but not tool-unqualified.** NIC provides cluster primitives, not a sandboxing tool. The interface names guarantees; each guarantee is qualified against at least one concrete, tested consumer configuration, and other tools are potential consumers until tested.
- **Provider-neutral.** Pack developers should not need to know which provider they are on. Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see [System Overview](../design-doc/architecture/02-system-overview.md)).
- **Prefer Pod Security `restricted`.** Capabilities that need no relaxation come first; relaxation is the exception a capability must justify.
- **Fail closed.** A capability the operator asked for either verifies or the deploy fails; nothing is advertised that has not been observed working.
- **Off by default and narrowly scoped.** Relaxations that later capabilities need, such as unprivileged user namespaces, widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so they are confined to dedicated node groups.
- **Prefer community-maintained mechanisms** over NIC-owned node agents, where they can express the required policy.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible capability contract, starting with process self-restriction, with stronger capabilities added by later ADRs.
4. Go straight to a stronger-isolation runtime (gVisor or Kata `RuntimeClass`) as the only sandbox option.
5. Adopt a full sandbox platform (for example Agent Substrate) instead of a capability contract.

## Decision Outcome

Chosen option: "Option 3 - a tool-neutral, extensible capability contract, starting with process self-restriction", because it gives pack developers a primitive now that needs no relaxation of pod security and little from NIC, and fixes the naming and shape later capabilities will follow without committing to deliver them. This ADR delivers one capability, `process-self-restriction`, and reserves the names of the others; each of those needs its own ADR before NIC delivers it. Option 2's concreteness is kept by qualifying each capability against a tested consumer; Option 4 remains the planned path for runtime-backed capabilities, and Option 5's platforms are candidate providers for those capabilities rather than a replacement for the contract.

### The contract

The contract is an interface to the **node execution environment**: NIC promises, by name and with verification, what the nodes' kernel, kubelet configuration, container runtime and security profiles will let a pod do. Packs still write their own pod settings and run their own sandboxing tools; networking (NetworkPolicy enforcement) and higher-level sandbox systems that build on these capabilities are outside it.

The cluster advertises a **set of capabilities**, not a single level, because the options are not strictly ordered. Capabilities name **guarantees, not mechanisms**, and each is qualified against at least one tested consumer configuration.

| Capability | Guarantee | Status |
|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3+, observed ABI reported) and nested seccomp filters | **Delivered by this ADR** |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace mapping only its own UID/GID, plus mount, network, IPC and UTS namespaces; the container's masked `/proc` is retained | Name reserved; designed in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-delivery-phase-2-in-pod-namespaces); future ADR |
| `pod-user-namespaces` | Pods may set `hostUsers: false` | Name reserved; future ADR |
| `user-space-kernel` | Workloads run behind a user-space kernel | Name reserved; future ADR |
| `vm-boundary` | Workloads run behind a hardware-virtualisation boundary | Name reserved; future ADR |
| `network-policy` | NetworkPolicies are enforced for ingress and egress | Candidate only; owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) |

**Naming convention.** Capability names are lowercase and hyphenated. Nodes that provide a capability carry the label `sandbox.nebari.dev/<capability>`, and capability attributes carry their own labels (for example `sandbox.nebari.dev/landlock-abi`). Every capability is defined by its guarantee, qualified consumer, placement, cluster requirements, provisioning, verification and any scale limits; later ADRs add capabilities by defining these. Capabilities backed by a `RuntimeClass` use its own `scheduling` field, so packs only set `runtimeClassName`. Full definitions, including the caveat that seccomp user notification is not a security-policy check on its own, are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#206-the-capability-contract-in-full).

### Three separate interfaces

1. **Desired configuration.** `process-self-restriction` needs no opt-in. A top-level `sandbox.require` lists capabilities the operator requires, optionally with a minimum such as `minLandlockABI`. `InfraSettings.Sandbox` reports which node groups are intended to provide which capabilities and stays a pure function of config. A per-node-group `sandbox` block is reserved for future opt-in capabilities.
2. **Observed readiness.** After the cluster is up, NIC records what it verified, per capability and node group, in a read-only record with an expiry. The record is informational: consumers fail closed by checking the guarantee themselves. Capability attributes such as the Landlock ABI are guarantees over the exact advertised placement.
3. **Consumer integration.** Until pack codegen ([ADR-0003](0003-software-pack-codegen.md)) exists, packs are integrated explicitly through documented Helm values, or by defaulting to the conventional names; enforcing pack requirements is future work.

Details, including the Go types and the withdrawal semantics, are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#three-separate-interfaces).

### Lifecycle

`process-self-restriction` installs nothing. NIC verifies it once the cluster is reachable, as an additional step in the existing deploy flow, and publishes the readiness record; a required capability that fails verification makes `nic deploy` exit non-zero. This needs no change to [ADR-0006](0006-conditional-foundational-software-helm.md). Future capabilities that install cluster components need a post-bootstrap phase, designed in [§20.7](../design-doc/implementation/20-workload-sandboxing.md#207-lifecycle).

### Delivery

- **`process-self-restriction` (this ADR).** No profiles, operators, admission exceptions or node preparation. Discovery is passive: NIC advertises the capability on node groups whose images qualify (targeting Landlock ABI 4) and never changes node images on its own. See [§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-phase-1-process-self-restriction).
- **Future work.** `in-pod-namespaces` is fully designed, including four release gates (an AppArmor mechanism, a hetzner-k3s autoscaling fix, versioned seccomp profiles, and a qualified consumer with a real-pack acceptance test), in [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-delivery-phase-2-in-pod-namespaces). It will be proposed as its own ADR once its gates are close to being met. Runtime-backed capabilities follow the same route.

### Verification and security

Probes run per node group, in both directions where a negative case exists, with positive controls on the same node, and on a schedule ([§20.10](../design-doc/implementation/20-workload-sandboxing.md#2010-verification)). `process-self-restriction` relaxes nothing and runs under Pod Security `restricted`, so it needs no admission exception. It shares the host kernel and is no protection against kernel exploits; code an agent executes should be treated as attacker-influenced, and packs using seccomp user notification must not rely on a check-then-continue supervisor as their policy mechanism. The security design for later capabilities is in [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations).

### Consequences

**Good:**
- The delivered capability is a useful primitive with no relaxation of pod security, no new cluster components and no new admission exceptions.
- Pack developers get a documented, provider-neutral primitive and choose their own tool, with a qualified configuration to start from.
- Desired configuration, observed readiness and pack integration are separate, so what NIC advertises is what it has observed.
- Stronger isolation can be added later as new capabilities, under names reserved now, without breaking packs that rely on this one.

**Bad:**
- `process-self-restriction` ties the platform to node kernel versions: AKS below Kubernetes 1.35 does not qualify by default, and node groups on older kernels cannot provide it.
- NIC gains a verification step, a probe image and a readiness record to maintain.
- The contract's shape is fixed before a second capability exists, so later capabilities must fit it or amend it.
- Until ADR-0003 exists, pack integration is manual and enforcement of pack requirements is the pack's own responsibility.

## Options Detail

### Option 1: Do nothing

Packs that want sandboxing set seccomp/AppArmor to `Unconfined`, add `CAP_SYS_ADMIN`, or run privileged.

- **Pros:** no NIC changes.
- **Cons:** packs cannot change node settings at all; pushes packs toward privileged pods; fails Pod Security Baseline and conflicts with ADR-0010.

### Option 2: Support one tool (e.g. bubblewrap)

- **Pros:** concrete and easy to test.
- **Cons:** couples the interface to a tool; developers who hit problems with it have no supported alternative; does not describe how stronger isolation would be offered later. Its concreteness is kept in Option 3 by qualifying each capability against a tested configuration.

### Option 3: Tool-neutral, extensible capability contract (chosen)

- **Pros:** usable now with no relaxation; low cost to NIC for the first capability; extensible; independent of tool choice; fits `InfraSettings` and ADR-0003 patterns.
- **Cons:** the contract's shape is set before a second capability exists; it has to stay stable across later capabilities.

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

- **Pros:** much stronger boundary; a kernel exploit in the workload does not directly yield the node.
- **Cons:** provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps; changes the pod model rather than letting packs confine tools inside an existing pod.

Kept as the planned `user-space-kernel` and `vm-boundary` capabilities.

### Option 5: Adopt a full sandbox platform (e.g. Agent Substrate)

Install a complete agent-sandbox platform as NIC's sandboxing answer and have packs run untrusted work on it. Agent Substrate is the leading example: a control plane that runs many "actors" on a pool of worker pods, isolates each with gVisor or a microVM it drives itself, suspends and resumes them from snapshots in object storage, and brokers egress with credential injection.

- **Pros:** a much stronger boundary than rows 2 and 3, appropriate for attacker-influenced or multi-tenant code; egress policy, credential injection, suspend/resume and density come built in rather than being assembled by each pack; an ecosystem is forming around it.
- **Cons:**
  - Solves a different problem: it replaces the pod model (work runs as actors in the platform's worker pods) rather than fencing tools inside an existing pod such as a JupyterLab server, so packs would have to be re-architected around it.
  - Cannot run on NIC's providers today: Agent Substrate needs Kubernetes 1.36 or later with beta pod-certificate APIs that managed services do not let you enable (realistically 1.37), enforced NetworkPolicy ([#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) is blocked), changes to GKE-specific node paths, and KVM-capable nodes for microVMs (not Hetzner Cloud).
  - A weaker pod-level posture: its worker pods need added capabilities with seccomp and AppArmor unconfined (the relaxed-workload tier), which ADR-0010's hardened mode would have to admit by exception, whereas `process-self-restriction` runs under Pod Security `restricted`.
  - A large operational footprint for a pre-1.0 project with no compatibility guarantees: API server, controller, router, egress gateway, node agent, Postgres and object storage.

Not chosen as the starting point. The contract is designed so that such a platform can later provide `user-space-kernel` or `vm-boundary` through its own API (a system-provided capability), with its cluster requirements and privilege tier set in that capability's ADR. If packs converge on such a platform, the future `in-pod-namespaces` work can be deprioritised; `process-self-restriction` remains useful either way.

## Open Questions

- Should NIC's AKS module expose an `os_sku` (node OS image) setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04 and qualify for `process-self-restriction`? (EKS AMIs already use a qualifying kernel from Kubernetes 1.33; AKS moves to Ubuntu 24.04 from 1.35; see §20.4.)
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should Nebari offer a uniform API for packs to **request** sandboxes, independent of the provider underneath? This ADR only advertises capabilities and names the system that provides each; the request mechanism still differs by provider (`runtimeClassName` for a `RuntimeClass`, a platform's own API or SDK). A standard request layer, such as the Agent Sandbox project's `Sandbox`/`SandboxClaim` resources, could sit on top of these capabilities and would be a separate decision.
- Should capability names themselves be versioned, so a guarantee can be tightened without silently changing its meaning?

Open questions specific to `in-pod-namespaces` and later capabilities are recorded in [§20.15](../design-doc/implementation/20-workload-sandboxing.md#2015-future-work-deferred-from-adr-0021).

## Links

- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [ADR-0012: Crossplane Capability APIs for Software Pack Cloud Infrastructure](0012-crossplane-pack-infrastructure.md)
- [ADR-0017: User Journey Tests](0017-user-journey-tests-for-foundational-software.md)
- [Trail of Bits: VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
