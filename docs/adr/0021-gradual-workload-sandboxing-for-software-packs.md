# ADR-0021: Workload Sandboxing Capability Contract for Software Packs

## Status

Proposed. Supporting design is in the design doc [Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md) (§20).

## Date

2026-10-12

## The contract

### In short

Software packs increasingly run code nobody has reviewed line by line, such as commands from a coding agent. Pack authors want to limit what that code can do: which files it can touch, whether it can reach the network, and whether it can read the pod's credentials. Whether that's possible depends on the cluster, for example the node's kernel or which container runtimes are installed. A pack can't find that out for itself. This ADR gives NIC a shared vocabulary for "what sandboxing this cluster supports", and a list of ready-made settings packs can copy. Packs then ask for a kind of protection, not a specific tool, and the cluster's options can grow (for example adding gVisor or Kata) without packs having to change. For now it only covers what already works on standard nodes, a Linux feature called Landlock, and only where it has been tested.

### Details

The contract describes a cluster's sandboxing support in three independent parts:

| Axis | Values | In this ADR |
|---|---|---|
| **Boundary level** between pod and host | `shared-kernel`, `mediated-kernel`, `hardware-virtualised` | `shared-kernel` (the default runtime); the other two reserved |
| **In-pod capability** a workload uses inside its pod | `process-self-restriction`, `seccomp-user-notification`, `in-pod-namespaces` | `process-self-restriction` described; the other two reserved |
| **Profile** of guarantees enforced around the pod | Compositions of atomic guarantees | Reserved; none defined |

**Qualified** means a NIC maintainer has tested a configuration (provider, node image, architecture, kernel line and container runtime version) with a working consumer, such as the sandbox probe, and recorded the result in the qualification record. It is a tested claim about that one configuration, not an ongoing promise of support.

**Boundary levels.** At `shared-kernel`, code calls the host kernel directly; at `mediated-kernel`, it never makes system calls directly to the host kernel (for example gVisor); at `hardware-virtualised`, a hardware virtualisation boundary and a guest kernel separate it from the host (for example Kata).

Levels are an acceptance policy: an operator who accepts "at least `mediated-kernel`" accepts any qualified implementation at that level or above. This is a NIC policy convention, not an ecosystem standard or a security ranking: GKE, AKS and `RuntimeClass` expose concrete runtimes, and a user-space kernel and a VM protect in different ways. A higher level never promises that a pack runs unchanged (gVisor has no Landlock), so capabilities are never implied by a level, and NIC never substitutes one implementation for another on its own.

**In-pod capabilities.** An in-pod capability is something a workload does to itself inside its pod, such as confining its own commands with Landlock (`process-self-restriction`, described under Decision Outcome). Capabilities are separate from levels because a level never implies them.

**Profiles.** A profile is a set of guarantees the cluster enforces around a pod and the pod cannot change, composed of atomic guarantees that can each be enforced and checked from outside the workload, such as `no-service-account-token`, `no-secret-references`, `metadata-unreachable` or `default-deny-off-pod-egress`. Profiles are independent of the boundary level and form part of a requirement. NIC makes no blanket "no credentials" or "no network" claim: admission cannot see credentials in images, literal values or data, and "network" must say whether it covers off-pod, loopback and sidecar, own-node and request-layer traffic. Later ADRs define named profiles.

**The published mapping.** To be sandboxed, a pod needs specific settings: today its security context, and later things like which container runtime to use and which nodes to run on. Some of these will differ between clusters, and a pack can't look them up itself: under ArgoCD, Helm can't read the cluster, and a runtime has to be named literally. So NIC publishes them, and they reach the pack as ordinary Helm values, like the domain or storage class.

NIC shows the mapping in `nic outputs`. It lists named requirements, each with concrete values for a pod spec. A pack that creates sandbox pods through [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) (a Kubernetes SIG project for creating sandbox pods on demand) puts the same values in its `SandboxTemplate` instead. Today there is one entry, `default`, the cluster's normal runtime:

```yaml
version: 1
requirements:
  default:
    level: shared-kernel
    state: qualified          # or unknown / unsupported, derived from the node groups
    capabilities: [process-self-restriction]   # listed only when qualified
    podSecurityContext:       # together these meet Pod Security "restricted"
      runAsNonRoot: true
      seccompProfile: {type: RuntimeDefault}
    containerSecurityContext:
      allowPrivilegeEscalation: false
      capabilities: {drop: [ALL]}
```

**How values reach a pack.** Today's `default` security settings are the same on every cluster, so a pack author ships them as chart defaults and nobody copies anything. The only part that varies by cluster today is `state`. The operator, who reads `nic outputs`, uses it to decide whether to turn on a pack's sandboxed features. The pack's startup check still refuses sandboxed work on any node that can't enforce it. Once entries carry values that do vary by cluster, such as a `runtimeClassName` or `placement`, the operator sets them when installing a pack, as they already do for the domain and storage class. With pack codegen ([ADR-0003](0003-software-pack-codegen.md)), NIC would fill them in automatically for packs whose `values.yaml` has a `sandbox` key, the same convention ADR-0003 proposes for `sharedStorage.storageClass`.

Later entries add fields such as `runtimeClassName`, `placement`, `workspaceStorageClass`, `profile` and `implementation`. These names are reserved now so that adding them breaks nothing. Consumers ignore fields they don't recognise, and an incompatible change bumps `version`.

A later entry might name a `RuntimeClass` that NIC installs (named after the implementation, such as `nebari-gvisor`), a provider-managed one (such as AKS's `kata-vm-isolation`), or the operator's own on an `existing` cluster, together with storage known to work with it. NIC never selects a class automatically in this ADR. Labels on runtime classes are inventory only, and nothing selects a class by label. If automatic selection is added later, finding no match or more than one must be treated as a failure.

**What NIC's report means.** It is an expectation, not a guarantee. `state: qualified` means a matching configuration passed the probe and is in the qualification record. `unknown` means nobody has tested it, and NIC never upgrades it to `qualified` by comparing kernel versions. `nic outputs` also shows each node's kernel version and the Landlock version that kernel should provide (the *baseline*), but only as a hint: vendors backport features, and Landlock can be built in but not switched on. Whether a sandbox actually holds is decided only by the pack's startup check, on each node, every time. All of this concerns the cluster's normal runtime: gVisor and Kata run their own kernel, so later entries cover them.

**Rules.**

- **(a) Fail loudly.** A requirement is met, **failed** (tried and did not hold), **unsupported** (known not to hold) or **unverified** (not known). None of the last three falls back to weaker settings; a pack that cannot establish its sandbox refuses the work.
- **(b) Prove before promising.** A level, capability, implementation or profile is promised for a configuration only after a maintainer has tested it there with a named, working consumer (for `process-self-restriction`, the committed [probe](../../tests/sandbox-probe/README.md)) and recorded it in the qualification record.
- **(c) Every addition states a trust model:** who is trusted, what hostile code may do, what NIC enforces, what the pack must enforce, and what is not covered.
- **(d) Settings are not enforcement, and tests are diagnostics, not attestation.** The tested gVisor and Kata configurations ignored the pod's `seccompProfile`; a check that passes shows one path worked for one pod at one time.

### Guidance for later capabilities

These are not part of the contract; [§20.6](../design-doc/implementation/20-workload-sandboxing.md#guidance-for-later-capabilities) has the detail.

- **Placement labels.** For runtimes NIC installs, labels that route pods use a NIC-owned prefix kubelets cannot set (`nebari.dev.node-restriction.kubernetes.io/`). This stops only self-asserted eligibility through kubelet credentials, and its preconditions (Node authorizer, NodeRestriction, scoped kubelet identities) are verified per provider. Provider-managed runtimes are routed and trusted as the provider's.
- **Lifecycle.** Incompatible changes to a capability or profile definition need a new version. Implementations and releases can be added, withdrawn or revoked behind a stable class name. Availability is not permanent support, and guarantees must hold on every eligible placement, including mixed-version rollouts.
- **Admission.** A `ValidatingAdmissionPolicy` cannot read a `RuntimeClass`'s labels, so restricting runtimes uses a NIC-generated list of approved class names or a webhook.

## Context

Software packs increasingly run code the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps. Pack developers want to contain it, for example by confining an agent's shell commands to a project directory, away from the pod's credentials and network.

**Threat model.** The problem is containing an agent's own commands: code it runs because of a prompt injection, a compromised dependency or a mistake, which can reach whatever credentials, files and network the pod can. Many agent-sandbox failures are this kind of policy leakage rather than escape. Containing an adversary determined to escape the host is a different problem: shared-kernel mechanisms do not stop kernel exploits, and even VMs may not reliably contain cyber-capable agents ([Trail of Bits, 2026-08-26](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)). Sandboxing a whole agent protects its surroundings from the agent; it does not protect credentials deliberately given to that agent from prompt-injected decisions.

**What Landlock gives.** A process can restrict itself and its descendants: which files they may read, write, create or remove; at ABI 4, which TCP ports they may connect to or bind (by port, not address, and not UDP); at ABI 6, signals and abstract Unix sockets outside the sandbox. It does not cover metadata changes such as `chmod`, descriptors already open, or credentials in the environment. Keeping the service-account token out needs a pod setting (`automountServiceAccountToken: false`); no network needs a seccomp filter in the process or, from outside the pod, a later profile.

**Why NIC is involved.** Landlock needs no change to pod security, but needs node kernels with it enabled at a sufficient ABI, which packs cannot choose. Higher levels need runtimes and node preparation only the cluster can provide, and network guarantees need enforcement in the cluster's network plugin.

## Decision Drivers

- **Build in steps** behind an interface later options can join without breaking packs.
- **Packs consume plain values:** nothing a pack does may depend on looking up the cluster.
- **Tool-neutral, not tool-unqualified:** each guarantee is qualified against a concrete consumer.
- **Provider-neutral:** capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/`.
- **Prefer Pod Security `restricted`.**
- **Least machinery:** report what NIC knows; add configuration only for a real consumer.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do less: document supported node environments, maintain a fail-closed launcher, pass concrete `RuntimeClass` names as Helm values, treat NetworkPolicy as general infrastructure work and leave lifecycle to Agent Sandbox.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral contract with a published mapping of concrete values, starting with a qualified description of Landlock on the default runtime.
4. Go straight to a stronger-isolation runtime (gVisor or Kata) as the only option.
5. Adopt a full sandbox platform (e.g. Agent Substrate).
6. Detect the capability per node with Node Feature Discovery.
7. Label qualifying node groups from a NIC-maintained table of node images.

## Decision Outcome

Chosen option: "Option 3". This ADR fixes the contract above and delivers a **qualified description of the default runtime's host prerequisite (Landlock), plus an optional, read-only diagnostic preflight**. It is not an enforced sandbox: enforcement is the consumer's. NIC reports an incompatible cluster but does not block `nic deploy`; the pack's startup check refuses sandboxed work instead. An operator option that makes a requirement fail the deploy may be added later without changing the mapping.

### Delivered now

**`process-self-restriction`.** A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict its own and its descendants' filesystem access with Landlock at ABI 3 or newer, and TCP connect and bind at ABI 4 or newer. Its qualified consumer is the committed probe: in such a pod it applies filesystem and TCP rulesets against positive controls and reports a verdict for each, exiting non-zero if one fails. The reference launcher ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#example-confining-a-command)) is tested on local VMs, containers and in CI, awaiting provider qualification. Nested seccomp user notification is a separate capability, `seccomp-user-notification`, reserved: the probe gives it its own verdict, because container runtime and default-profile changes can break it independently of the kernel.

**Qualification record.** NIC maintainers keep it ([§20.8](../design-doc/implementation/20-workload-sandboxing.md#qualification-record)) by the probe's [requalification procedure](../../tests/sandbox-probe/README.md#requalification). Today:

| Configuration | Expectation |
|---|---|
| `aws`, `AL2023_x86_64_STANDARD`, x86_64, kernel 6.12 (Kubernetes 1.33–1.35), containerd 2.3; probed on 1.34, 2026-10-19 | Qualified, ABI 6 |
| `hetzner`, Ubuntu 24.04, x86_64, kernel 6.8, containerd 2.2; probed 2026-10-25 | Qualified, ABI 4 |
| `aws` below 1.33 (kernel 6.1); `azure` below 1.35 (Ubuntu 22.04, 5.15) | Unsupported |
| Every other combination: other AMI types (ARM, NVIDIA, Bottlerocket), pinned images, AKS from 1.35, `existing`, kind | Unknown |

An entry covers only the same image variant and architecture, kernel line and container runtime minor version; anything else is unknown until probed.

**Reporting.** Each cluster provider reports in `InfraSettings.Sandbox`, per node group and from config alone, its qualified expectation, plus a diagnostic selector that associates live nodes with the group (not a trusted scheduling label). `nic outputs` shows the expectation per group and, from a fresh read of the nodes when it runs (labelled with the time), the host-kernel baseline: each node's kernel version mapped to the Landlock ABI it introduced upstream. The `default` entry is `qualified` only if every node group that can run pods is, `unsupported` if every one is, and `unknown` otherwise. `nic deploy` prints the same report at its end. NIC labels no nodes for this. Nothing fails, nothing is stored, and the baseline is never treated as a qualification: backports, Landlock built in but not enabled at boot, and runtime seccomp profiles that predate Landlock all defeat it. This ADR adds no configuration.

### What a pack author does

**Today.** Ship the `default` entry's security settings as the chart's defaults. Do not mount the service-account token on pods that run agent commands, and keep credentials out of their environment and files. At startup, read the Landlock ABI and refuse sandboxed work if it is missing or below what the pack needs: this check, not NIC's report, is where the guarantee is enforced. Confine each command, for example as the reference launcher does (an example, not part of the contract): a helper confines itself, refusing if the kernel cannot enforce the whole policy, and then executes the command with a minimal environment and no inherited descriptors. Treat the work directory as untrusted input: files a confined command writes there (`.git/config` with `core.fsmonitor`, `.envrc`, `conftest.py`) run later if the unconfined agent's tools execute them, so run those tools through the launcher too or with hardened invocations.

**Next (future work).** A pod that runs untrusted code uses a mapping entry naming a level and a profile, and the pack writes no isolation code.

### Out of scope

- Installing higher-level runtimes, defining profiles (NetworkPolicy enforcement is [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691)) and delivering `seccomp-user-notification`.
- Creating sandbox pods, which belongs to the pack or a request layer such as [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/).
- Automatic resolution, including choosing between implementations of one level.

### Evidence from the higher levels

Test-only installs on clusters deployed with NIC (2026-10-19 to 2026-10-27) informed the contract ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#evidence-from-the-higher-levels)). Under gVisor (EKS x86_64 and arm64, Hetzner), Landlock returned `ENOSYS`, the pod's `seccompProfile` was ignored and EFS home directories were not writable; a Kata guest on EKS had Landlock ABI 7 and did not apply `RuntimeDefault`. Hence the acceptance policy, rule (d) and the reserved storage field. Bubblewrap in pods worked only with no seccomp profile, so `in-pod-namespaces` stays reserved. An EKS node rewrote its own node-group label, but not `node-restriction.kubernetes.io/` labels, hence the placement guidance. NetworkPolicy is not enforced on NIC's EKS clusters by default.

### Security

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`. It shares the host kernel and is no protection against kernel exploits. Code an agent executes should be treated as attacker-influenced.

### Consequences

**Good:**

- A qualified description of what the default runtime offers, with no relaxation, components or configuration.
- Packs consume plain values; later levels, capabilities and profiles add entries without breaking them.

**Bad:**

- Most configurations are unknown until probed, and older kernels do not qualify.
- `nic deploy` does not block an incompatible cluster, and NIC does not steer pods away from node groups that do not qualify; packs rely on their startup check.
- The baseline is an inference, and nodes added later are not seen.
- Maintainers keep the qualification record current.
- The mapping is versioned before a second entry exists, and pack integration is manual until ADR-0003.

## Options Detail

- **Option 1 (do less):** good practice that NIC follows (documentation, the reference launcher, concrete class names, Agent Sandbox for lifecycle), but packs cannot choose node images, install runtimes or rely on CNI enforcement, so each would rediscover what each cluster offers. The thin contract adds the shared, qualified description.
- **Option 2 (one tool):** no path to stronger isolation.
- **Option 3 (chosen):** usable now with no relaxation, cheap and tool-independent; its shape is set before a second entry exists.
- **Option 4 (a stronger runtime only):** needs provider-specific installation and adds overhead and compatibility gaps; kept as the reserved levels.
- **Option 5 (a full sandbox platform):** Agent Substrate (v0.6.0, pre-1.0) runs its own runtimes from root worker pods; it is not qualified or supported by NIC, and would be separately trusted infrastructure, not an implementation of a level.
- **Options 6 and 7 (Node Feature Discovery, labels from an image table):** components or tables for steering that buys little, without confirming Landlock is active.

The full assessment of Options 4, 5 and 7 is in the design doc ([§20](../design-doc/implementation/20-workload-sandboxing.md#option-4-stronger-isolation-runtime-only-gvisor-or-kata)).

## Open Questions

- Should NIC's AKS module expose an `os_sku` setting, so Azure clusters below Kubernetes 1.35 can use Ubuntu 24.04?
- Should the Pack Specification's security baseline point at this contract?
- Is it worth automating the probe as short-lived pods that `nic outputs` runs on each node group, at the cost of maintaining a multi-architecture image?

## Links

- [Design doc: Workload Sandboxing](../design-doc/implementation/20-workload-sandboxing.md)
- [Sandbox probe and reference launcher](../../tests/sandbox-probe/README.md)
- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [Trail of Bits: VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [go-landlock](https://github.com/landlock-lsm/go-landlock)
- [Kubernetes NodeRestriction admission plugin](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#noderestriction)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
