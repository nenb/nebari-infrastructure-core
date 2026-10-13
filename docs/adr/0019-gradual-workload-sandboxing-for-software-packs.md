# ADR-0019: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT)

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents (the Pi pack), notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

There is no single right way to do this, and the options differ in strength, cost and what they need from the cluster:

- **In-pod sandboxing tools** ([bubblewrap](https://github.com/containers/bubblewrap), nsjail, rootless podman/buildah, `unshare`) create Linux namespaces for a single command inside the user's existing pod. Cheap and fast; share the host kernel.
- **Pod user namespaces** (`hostUsers: false`, [GA in Kubernetes 1.36](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)) make root in the pod an unprivileged user on the host, and let in-pod tools mount a fresh `/proc`.
- **VM-grade runtimes** (gVisor, Kata, e.g. through [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)) put the whole pod behind a separate kernel boundary. Strongest, but costly and provider-specific.

Today NIC offers none of these, and pack developers cannot add them themselves: the deciding settings live on the nodes and in cluster-wide security profiles, not in a pack's chart. Concretely, an in-pod sandboxing tool fails in a NIC-deployed pod because four layers block unprivileged namespace creation:

| Layer | What blocks it | Owner |
|---|---|---|
| 1. Node kernel | `user.max_user_namespaces=0`, or on Ubuntu 23.10+ `kernel.apparmor_restrict_unprivileged_userns=1`. Not namespaced; cannot be set from a pod. | Cluster provider (node image) |
| 2. Seccomp | The container runtime's default profile only permits `unshare`, `clone(CLONE_NEWUSER)`, `mount`, `pivot_root` with `CAP_SYS_ADMIN`. `Unconfined` works but fails Pod Security Standards (PSS). | Cluster-wide |
| 3. AppArmor | On AppArmor nodes the default container profile denies `mount`. PSS Baseline forbids `Unconfined`. | Cluster-wide |
| 4. Masked `/proc` | The kernel refuses a fresh procfs mount inside a container with masked `/proc` paths. Lifted by pod user namespaces + `procMount: Unmasked`. | Cluster versions (Kubernetes, containerd, kernel) |

Where the providers stand on these layers. Entries marked *(unverified)* are inferred from the node image's defaults, not from running a sandboxing tool on a NIC-deployed cluster:

| Provider | Layer 1 (node kernel) | Layer 2 (seccomp) | Layer 3 (AppArmor) | Layer 4 (pod user namespaces) |
|---|---|---|---|---|
| `aws` (AL2023) | Expected OK *(unverified)* | Blocked under `RuntimeDefault`; profile needed | n/a (no AppArmor) | Depends on AMI kernel/containerd *(unverified)* |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | Blocked by the AppArmor sysctl | Blocked under `RuntimeDefault`; profile needed | Profile needed | Example config pins Kubernetes 1.32 |
| `azure` (AKS, Ubuntu 22.04) | Expected OK *(unverified)* | Blocked under `RuntimeDefault`; profile needed | Profile needed | 5.15 kernel; likely unsupported *(unverified)* |
| `local` (kind) | Host-dependent | Blocked under `RuntimeDefault`; profile needed | To verify | Host-dependent |
| `existing` | Unknown | Blocked under `RuntimeDefault`; profile needed | Unknown | Unknown; detect only |

Layer 2 is the same on every provider, so most of the work below is provider-neutral; only layer 1 (and layer 3 on AppArmor nodes) needs provider-specific changes.

**Why it can appear to work today.** No pack in `PACKS/` sets a seccomp profile, and neither does the bundled JupyterHub chart. A pod with no seccomp profile gets the kubelet's default, which is no filter at all (`Unconfined`) unless the kubelet's `seccompDefault` option is enabled. So on a node where layer 1 already passes (e.g. AWS), a user pod may run bubblewrap today in its reuse-`/proc` mode. This is not a foundation packs can rely on: it depends on running with no syscall filter, it stops working as soon as a pack follows Pod Security Standards `restricted` (which requires `RuntimeDefault` or `Localhost`) or the kubelet's `seccompDefault` is enabled, and ADR-0010's hardened mode is expected to forbid it.

## Decision Drivers

- **Build in steps.** Give pack developers something usable now, and a contract that later, stronger options can be added to without breaking packs that already rely on it.
- **Tool-neutral.** NIC provides cluster primitives, not a particular sandboxing tool. Packs choose their tool; a different tool, or a pack dropping one, should not require an ADR change.
- **Provider-neutral.** Pack developers should not need to know which provider they are on. Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see AGENTS.md).
- **Off by default and narrowly scoped.** Unprivileged user namespaces widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so enable them only on the nodes that need them.
- **Stay inside Pod Security Standards.** No privileged pack pods, no `CAP_SYS_ADMIN`, no `Unconfined` seccomp or AppArmor.
- **Prefer community-maintained mechanisms** over NIC-owned node agents.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible sandbox capability contract, delivered one capability at a time, starting with in-pod unprivileged namespaces.
4. Go straight to VM-grade isolation (gVisor/Kata `RuntimeClass`) as the only sandbox option.

## Decision Outcome

Chosen option: "Option 3 - a tool-neutral, extensible sandbox capability contract, delivered incrementally", because it gives pack developers a usable primitive now (the one bubblewrap and similar tools need), defines a stable way to advertise stronger isolation as it lands, and does not tie NIC to a specific tool. Options 2 and 4 are not rejected outright: tool-specific guidance belongs in pack documentation, and VM-grade runtimes are a planned later capability under the same contract.

### The contract

The cluster advertises a **set of sandbox capabilities**, not a single level, because the options are not strictly ordered (a VM-grade runtime is not a superset of in-pod namespaces). Packs ask for the capabilities they need; NIC refuses the deploy when the cluster cannot provide them.

| Capability | What a pack can rely on | Typical consumers | Delivered by |
|---|---|---|---|
| `in-pod-namespaces` | An unprivileged process in the pod can create user, mount, pid and network namespaces, with seccomp/AppArmor profiles that permit it. `/proc` is the container's own (tools bind it rather than mount a fresh one). | bubblewrap, nsjail, rootless podman/buildah, `unshare` | **This ADR** |
| `pod-user-namespaces` | The pod may set `hostUsers: false` and `procMount: Unmasked`; in-pod tools can then mount a fresh `/proc`. | The same tools, in their full-isolation modes | Follow-up ADR (needs Kubernetes >= 1.36, kernel >= 6.3, containerd >= 2.0, no NFS volumes in the pod) |
| `runtime-class:<name>` | A VM-grade `RuntimeClass` (gVisor, Kata) is installed and schedulable. | Untrusted, multi-tenant code; Agent Sandbox | Follow-up ADR |

Capabilities may be added to this table by later ADRs without changing this one, as long as they keep the same shape (a name, a guarantee, how packs consume it).

### Scope of this ADR

This ADR decides the contract and delivers the first capability, `in-pod-namespaces`. It deliberately does not:

- choose or ship a sandboxing tool, or a default sandbox policy for any tool;
- deliver `pod-user-namespaces` or any `RuntimeClass`;
- change the trust boundary between pods and nodes.

### Delivering `in-pod-namespaces`

1. **Opt-in per node group.** Each provider's node-group config gains an optional `sandbox: true`, next to `gpu`, `labels` and `taints`. NIC labels those nodes `nebari.dev/sandbox=true`. This mirrors the AWS `gpu: true` pattern and keeps the extra kernel surface off nodes running Keycloak, ArgoCD and other foundational services.
2. **`InfraSettings.Sandbox`.** A new field each cluster provider populates, so neither `pkg/argocd` nor the CLI needs to know the provider:
   ```go
   type SandboxSettings struct {
       Capabilities []string          // e.g. ["in-pod-namespaces"]
       NodeSelector map[string]string // where sandbox-capable nodes are
       AppArmor     bool              // nodes enforce AppArmor; an AppArmor profile is required
   }
   ```
3. **Per-provider node prep (layer 1)**, only where needed. Hetzner: per-pool pre-k3s commands that lift Ubuntu's restriction (preferably a scoped AppArmor `userns` grant rather than the global sysctl), plus pool labels. AWS/Azure: labels; extra node prep only if verification shows it is needed. `local`/`existing`: no node changes; documented host requirements and the probe below.
4. **Security profiles (layers 2-3) via the [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)**, installed as conditional foundational software ([ADR-0006](0006-conditional-foundational-software-helm.md)) when any capability is enabled. NIC ships a `nebari-sandbox` seccomp profile (runtime default plus the namespace syscalls, with high-risk families such as `bpf`, `io_uring` and netfilter configuration still denied) and, where `AppArmor` is true, a `nebari-sandbox` AppArmor profile granting `userns` and the required `mount` rules. The operator depends on cert-manager, which NIC already deploys. The profiles are named for the capability, not for a tool, and the same mechanism carries any profiles later capabilities need.
5. **Pack contract (ties into [ADR-0003](0003-software-pack-codegen.md)).** A `sandbox.*` Helm-value convention: `sandbox.capabilities`, `sandbox.nodeSelector`, `sandbox.seccompProfile`, `sandbox.appArmorProfile`. `nebari-integration.yaml` may declare `requires: { sandbox: [in-pod-namespaces] }`, and NIC fails the deploy if the cluster cannot satisfy it. Until pack codegen lands, NIC also publishes the same data in a cluster-capabilities ConfigMap.
6. **Verification.** A post-bootstrap probe in `pkg/nic` deploy runs a short-lived pod on a sandbox node that exercises each advertised capability, reporting the failing layer through the status channel. Bubblewrap is the reference tool for the probe and the tests because it exercises all of layers 1-3 in one command; this is a test-harness choice, not a contract. A user-journey test asserts both directions: a pod using the profile can create namespaces, and a pod with the default profile cannot.
7. **ADR-0010 alignment.** The hardened-mode admission policy (#480) gets a scoped exception for the Security Profiles Operator's privileged DaemonSet, and allows only the `nebari-sandbox` Localhost profiles, never `Unconfined`.

### Consequences

**Good:**
- Pack developers get a documented, provider-neutral primitive to build on, and choose their own tool. The Pi pack can confine agent tool execution without its current `PI_RUN_AS_ROOT` path.
- Stronger isolation can be added later as new capabilities without breaking packs that only need `in-pod-namespaces`.
- Extra kernel attack surface is confined to opted-in node groups.
- Upstream-maintained profile distribution instead of a NIC-owned node agent.

**Bad:**
- A new foundational component (Security Profiles Operator) with its own privileged DaemonSet and CRDs.
- Enabling user namespaces on sandbox nodes widens the kernel attack surface there; kernels must be patched promptly.
- With `in-pod-namespaces` alone, tools reuse the container's `/proc`, which exposes process information a fresh procfs would hide.
- Namespace-based sandboxing does not protect against kernel exploits; it is not a substitute for a VM-grade boundary for hostile multi-tenant code. The capability documentation must say so.
- More per-provider surface to verify and keep current as node images change.

## Options Detail

### Option 1: Do nothing

Packs that want sandboxing set seccomp/AppArmor to `Unconfined`, add `CAP_SYS_ADMIN`, or run privileged.

**Pros:**
- No NIC changes.

**Cons:**
- Packs cannot reach layer 1 at all; node settings are out of their control.
- Pushes packs toward privileged pods, the opposite of the intent.
- Fails PSS Baseline and conflicts with ADR-0010's admission policy.

### Option 2: Support one tool (e.g. bubblewrap)

Name a tool, ship profiles tuned to it, and document NIC as "bubblewrap-ready".

**Pros:**
- Concrete and easy to test.

**Cons:**
- The cluster requirements are the same for every namespace-based tool, so the tool-specific framing adds coupling without adding capability.
- Developers who hit problems with the chosen tool have no supported alternative.
- Does not describe how stronger isolation would be offered later.

### Option 3: Tool-neutral, incremental capability contract (chosen)

Described above.

**Pros:**
- Usable now, extensible later, independent of tool choice.
- Fits `InfraSettings`, ADR-0003 and ADR-0006 patterns.

**Cons:**
- More moving parts (node-group flag, operator, probe, pack contract) than a one-off fix.
- The contract has to be kept stable across later capabilities.

### Option 4: VM-grade runtime only

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

**Pros:**
- Much stronger boundary: a kernel exploit in the workload does not directly yield the node.

**Cons:**
- Provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps.
- Changes the pod model (separate sandbox pods) rather than letting packs confine tools inside the user's existing pod.
- A large first step; Agent Sandbox is still in development.

Kept as a planned `runtime-class:<name>` capability rather than the starting point.

## Open Questions

- Does PSS `restricted` admit `procMount: Unmasked` for `hostUsers: false` pods, or only `baseline`? Sources conflict; relevant to the `pod-user-namespaces` follow-up.
- Actual kernel, containerd and runc versions on the AL2023 EKS AMI, AKS node images, and hetzner-k3s v2.4.6's Ubuntu image.
- Does the Security Profiles Operator's AppArmor support meet our needs, or is a small NIC-owned loader required for AppArmor only?
- How does AppArmor apply to pods on kind nodes?
- Does hetzner-k3s v2.4.6 support per-pool pre-k3s commands, or only global ones?
- Is a per-node-group flag the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Does the EKS (AL2023/nodeadm) default kubelet configuration enable `seccompDefault`? Same question for k3s and AKS. This decides whether pods without an explicit profile are filtered today.
- Confirm every *(unverified)* entry in the provider table by running the probe described above on each provider.
- Should capability names be versioned (e.g. `in-pod-namespaces/v1`) so a guarantee can be tightened later without silently changing its meaning?

## Links

- [ADR-0003: Software Pack Codegen](0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](0010-high-security-mode.md)
- [ADR-0017: User Journey Tests](0017-user-journey-tests-for-foundational-software.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
