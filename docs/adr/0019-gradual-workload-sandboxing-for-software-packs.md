# ADR-0019: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-14 after review: delivery is now phased, lifecycle and readiness are explicit, and the first namespace consumer is qualified. The implementation detail behind this decision is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md).

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

There is no single right way to do this. The options form a spectrum that differs in strength, cost, what code it can run, and what it needs from the cluster. Several options need nothing from NIC. This ADR addresses the band where pack developers are blocked by settings only the cluster can change: process self-restriction (Landlock and seccomp) and namespace sandboxes inside the pod (bubblewrap and similar).

### The sandboxing spectrum

| # | Option | What isolates the code | Needs from NIC | In this ADR |
|---|---|---|---|---|
| 1 | Language runtime (WASM, V8 isolates, Pyodide, Monty) | The runtime | Nothing | Packs can do this today |
| 1b | The user's own browser | The browser, on the user's machine | Nothing | Packs can do this today |
| 2 | Process self-restriction (Landlock + seccomp) | The process restricts itself | A node kernel with Landlock ABI 3+ (ABI 4 for TCP rules) | **`process-self-restriction`, Phase 1** |
| 3 | Namespace sandbox in the pod (bubblewrap and similar) | Namespaces on the shared host kernel | Node prep and security profiles | **`in-pod-namespaces`, Phase 2** |
| 3b | Headless browser in the pod | Chromium's own namespace sandbox | As row 3 | Covered by `in-pod-namespaces` |
| 3c | System-container runtime (Sysbox) | User namespaces plus virtualised `/proc` and `/sys` | A `RuntimeClass` or a privileged outer container | Not delivered here |
| 4 | Separate locked-down pod per task | Standard container isolation | Enforced NetworkPolicy for its network controls (#691/#675) | Packs can do this today; `pod-user-namespaces` later |
| 5 | User-space kernel (gVisor) | gVisor's kernel; no direct host syscalls | Runtime install and a `RuntimeClass` | `user-space-kernel`, later ADR |
| 6 | MicroVM per pod (Kata, Firecracker) | A guest kernel behind hardware virtualisation | Runtime install and KVM-capable nodes | `vm-boundary`, later ADR |
| 7 | Dedicated node or cluster | A separate machine | Provisioning | Out of scope |
| 8 | External sandbox service | Someone else's infrastructure | Nothing in the cluster | Packs can do this today |

The full table, with examples and limits, and notes on egress, credentials, observability and GPUs, are in the design doc ([§20.2](../design-doc/implementation/20-workload-sandboxing.md#202-the-sandboxing-spectrum), [§20.3](../design-doc/implementation/20-workload-sandboxing.md#203-notes-on-the-sandboxing-spectrum)).

### Why rows 2 and 3 need NIC

Pack developers cannot enable rows 2 and 3 themselves. Row 2 runs with no changes to the pod's security settings, but needs node kernels with Landlock enabled at a sufficient ABI; On EKS, AMIs for Kubernetes 1.33 and later use a qualifying kernel (6.12); on AKS, the default image below Kubernetes 1.35 (Ubuntu 22.04) does not qualify. Row 3 is blocked in NIC-deployed pods by four layers: the node kernel (on Ubuntu 24.04, Hetzner's default, an AppArmor sysctl restricts unprivileged user namespaces), the runtime's default seccomp profile, the default AppArmor profile, and the masked `/proc`. Today it can appear to work only because pods without a seccomp profile run with no syscall filter at all (the default on EKS, hetzner-k3s and AKS as NIC deploys them), which is not a foundation packs can rely on. Per-provider findings are in the design doc ([§20.4](../design-doc/implementation/20-workload-sandboxing.md#204-why-row-2-process-self-restriction-needs-nic), [§20.5](../design-doc/implementation/20-workload-sandboxing.md#205-why-row-3-in-pod-namespaces-needs-nic)).

## Decision Drivers

- **Build in steps.** Deliver something usable now, behind a contract that stronger options can be added to later without breaking packs that already rely on it.
- **Tool-neutral, but not tool-unqualified.** NIC provides cluster primitives, not a sandboxing tool. The interface names guarantees; each guarantee is qualified against at least one concrete, tested consumer configuration, and other tools are potential consumers until tested.
- **Provider-neutral.** Pack developers should not need to know which provider they are on. Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see [System Overview](../design-doc/architecture/02-system-overview.md)).
- **Prefer Pod Security `restricted`.** Capabilities that need no relaxation come first; relaxation is the exception a capability must justify.
- **Fail closed.** A capability the operator asked for either verifies or the deploy fails; nothing is advertised that has not been observed working.
- **Off by default and narrowly scoped.** Unprivileged user namespaces widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so enable them only on dedicated node groups.
- **Prefer community-maintained mechanisms** over NIC-owned node agents, where they can express the required policy.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible capability contract, delivered in phases: process self-restriction first, then in-pod unprivileged namespaces.
4. Go straight to a stronger-isolation runtime (gVisor or Kata `RuntimeClass`) as the only sandbox option.

## Decision Outcome

Chosen option: "Option 3 - a tool-neutral, extensible capability contract, delivered in phases", because it gives pack developers a primitive now that needs no relaxation of pod security, adds namespace sandboxes once their delivery mechanism is proven, and defines a stable way to advertise stronger isolation later without tying NIC to a tool. Option 2's concreteness is kept by qualifying each capability against a tested consumer; Option 4 remains the planned path for runtime-backed capabilities.

### The contract

The contract is an interface to the **node execution environment**: NIC promises, by name and with verification, what the nodes' kernel, kubelet configuration, container runtime and security profiles will let a pod do. Packs still write their own pod settings and run their own sandboxing tools; networking (NetworkPolicy enforcement) and higher-level sandbox systems that build on these capabilities are outside it.

The cluster advertises a **set of capabilities**, not a single level, because the options are not strictly ordered. Capabilities name **guarantees, not mechanisms**, and each is qualified against at least one tested consumer configuration.

| Capability | Guarantee | Phase |
|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3+, observed ABI reported) and nested seccomp filters | **1** |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace mapping only its own UID/GID, plus mount, network, IPC and UTS namespaces; the container's masked `/proc` is retained | **2 (gated)** |
| `pod-user-namespaces` | Pods may set `hostUsers: false` | Later ADR |
| `user-space-kernel` | Workloads run behind a user-space kernel | Later ADR |
| `vm-boundary` | Workloads run behind a hardware-virtualisation boundary | Later ADR |
| `network-policy` | NetworkPolicies are enforced for ingress and egress | Candidate; owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) |

Every capability is defined by its guarantee, qualified consumer, placement, cluster requirements, provisioning, verification and any scale limits; later ADRs add capabilities by defining these. Capabilities backed by a `RuntimeClass` use its own `scheduling` field, so packs only set `runtimeClassName`. Full definitions, including caveats on seccomp user notification and on tools that need more than the qualified configuration, are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#206-the-capability-contract-in-full); composition rules and privilege tiers for later capabilities are in [§20.12](../design-doc/implementation/20-workload-sandboxing.md#2012-composition-and-privilege-tiers-for-later-capabilities).

### Three separate interfaces

1. **Desired configuration.** Provider config states which node groups should provide which opt-in capabilities; `InfraSettings.Sandbox` reports that intent and stays a pure function of config. A top-level `sandbox.require` lists capabilities the operator requires, optionally with a minimum such as `minLandlockABI`.
2. **Observed readiness.** After bootstrap, NIC records what it verified, per capability and node group, in a read-only record with an expiry. The record is informational: consumers fail closed by checking the guarantee themselves, and Phase 2 nodes that fail re-verification are quarantined. Capability attributes such as the Landlock ABI are guarantees over the exact advertised placement.
3. **Consumer integration.** Until pack codegen ([ADR-0003](0003-software-pack-codegen.md)) exists, packs are integrated explicitly through documented Helm values; enforcing pack requirements is future work.

Details, including the Go types and the withdrawal semantics, are in [§20.6](../design-doc/implementation/20-workload-sandboxing.md#three-separate-interfaces).

### Lifecycle

Capability components install in a **post-bootstrap phase**: provider `Deploy()`, then foundational services, then waiting for dependencies (for Phase 2, cert-manager), then installing components and versioned profiles, then verification, then publishing readiness. This needs a post-bootstrap hook in `pkg/nic` or an amendment to [ADR-0006](0006-conditional-foundational-software-helm.md). A required capability that fails makes `nic deploy` exit non-zero. See [§20.7](../design-doc/implementation/20-workload-sandboxing.md#207-lifecycle).

### Delivery

- **Phase 1, `process-self-restriction`.** No profiles, operators, admission exceptions or node preparation. Discovery is passive: NIC advertises the capability on node groups whose images qualify (targeting Landlock ABI 4) and never changes node images on its own. See [§20.8](../design-doc/implementation/20-workload-sandboxing.md#208-delivery-phase-1-process-self-restriction).
- **Phase 2, `in-pod-namespaces`**, ships only when four release gates are met: **A**, an AppArmor mechanism that can express the policy (until then, only node groups without AppArmor); **B**, hetzner-k3s applying per-pool preparation to autoscaled nodes; **C**, reviewed, versioned seccomp profiles with adversarial tests; **D**, a qualified bubblewrap invocation plus a real-pack acceptance test. It uses dedicated, tainted node groups with admission control, a per-node readiness barrier, and `seccompDefault: true` on those nodes. See [§20.9](../design-doc/implementation/20-workload-sandboxing.md#209-delivery-phase-2-in-pod-namespaces).

### Verification and security

Probes run per node group (and per node for Phase 2), in both directions, with positive controls and on a schedule; a separate consumer acceptance test covers credential canaries, inherited descriptors, denied networking and refusal without unsafe fallback ([§20.10](../design-doc/implementation/20-workload-sandboxing.md#2010-verification)). `in-pod-namespaces` adds risk that is bounded only by the measures in [§20.11](../design-doc/implementation/20-workload-sandboxing.md#2011-security-considerations): default seccomp on its nodes, admission over profiles and taints, a locked-down profile API, a tested netfilter block, prompt kernel patching, scheduled re-verification, and a precise threat model. Neither delivered capability protects against kernel exploits; code an agent executes should be treated as attacker-influenced.

### Consequences

**Good:**
- Phase 1 delivers a useful primitive with no relaxation of pod security, no new cluster components and no new admission exceptions.
- Pack developers get documented, provider-neutral primitives and choose their own tool, with at least one qualified configuration per capability.
- Desired configuration, observed readiness and pack integration are separate, so what NIC advertises is what it has observed.
- Stronger isolation can be added later as new capabilities without breaking packs that rely on these.

**Bad:**
- Phase 2 depends on external work (an AppArmor mechanism, a hetzner-k3s fix) and may be limited to non-AppArmor node groups for some time.
- NIC owns a complete seccomp policy per architecture and must track runtime default changes.
- A new post-bootstrap lifecycle phase in `pkg/nic`, or an ADR-0006 amendment.
- `process-self-restriction` ties the platform to node kernel versions: Azure needs a newer node OS image than today's default, and node groups on older kernels cannot provide it.
- Enabling user namespaces on dedicated node groups widens the kernel attack surface there.
- Until ADR-0003 exists, pack integration is manual and enforcement of pack requirements is the pack's own responsibility.

## Options Detail

### Option 1: Do nothing

Packs that want sandboxing set seccomp/AppArmor to `Unconfined`, add `CAP_SYS_ADMIN`, or run privileged.

- **Pros:** no NIC changes.
- **Cons:** packs cannot change node settings at all; pushes packs toward privileged pods; fails Pod Security Baseline and conflicts with ADR-0010.

### Option 2: Support one tool (e.g. bubblewrap)

- **Pros:** concrete and easy to test.
- **Cons:** couples the interface to a tool; developers who hit problems with it have no supported alternative; does not describe how stronger isolation would be offered later. Its concreteness is kept in Option 3 by qualifying each capability against a tested configuration.

### Option 3: Tool-neutral, phased capability contract (chosen)

- **Pros:** usable now with no relaxation (Phase 1); extensible; independent of tool choice; fits `InfraSettings`, ADR-0003 and ADR-0006 patterns.
- **Cons:** more moving parts than a one-off fix; Phase 2 depends on external gates; the contract has to stay stable across later capabilities.

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

- **Pros:** much stronger boundary; a kernel exploit in the workload does not directly yield the node.
- **Cons:** provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps; changes the pod model rather than letting packs confine tools inside an existing pod.

Kept as the planned `user-space-kernel` and `vm-boundary` capabilities.

## Open Questions

- Partly resolved (§20.4): EKS AMIs use kernel 6.12 for Kubernetes 1.33–1.35 and 6.18 for 1.36+, and AKS moves to Ubuntu 24.04 from 1.35. Still open: whether Landlock is in the active security-module list on AL2023 and Ubuntu nodes, and whether NIC's AKS module should expose `os_sku` so earlier Kubernetes versions can qualify.
- Gate A: upstream AppArmor support in the Security Profiles Operator, another maintained loader, or AppArmor nodes deferred indefinitely?
- Post-bootstrap lifecycle hook in `pkg/nic`, or an amendment to ADR-0006?
- Where the readiness barrier's taint removal runs (a small NIC-owned controller, or the probe DaemonSet itself), and what RBAC it needs to patch nodes.
- Partly resolved (§20.5): kind runs node containers AppArmor- and seccomp-unconfined. Still open: whether the containerd inside a kind node applies AppArmor profiles to pods on Linux hosts with AppArmor (needs a live test).
- Is per-node-group opt-in the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Should NetworkPolicy enforcement be advertised through this contract (the `network-policy` candidate), or stay a platform guarantee that packs assume? To agree with the owners of [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691).
- Several sandbox systems depend on the Agent Sandbox controller and CRDs and leave installing them to the cluster administrator. Should NIC offer it as conditional foundational software?
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should `in-pod-namespaces` ever cover pods that run sandboxes for several users or sessions? With single-ID user namespaces every session maps to the pod's own host UID, so files are not separated between sessions; separating them needs a distinct real UID per session, which needs root and belongs inside a stronger boundary.
- Should capability names themselves be versioned (as the profiles now are), so a guarantee can be tightened without silently changing its meaning?
- Confirm every *(unverified)* entry in the provider tables by running the probes on each provider.

## Links

- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [ADR-0017: User Journey Tests](0017-user-journey-tests-for-foundational-software.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
