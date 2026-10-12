# ADR-0019: Enable Bubblewrap Sandboxing for Software Packs

## Status

Proposed (DRAFT)

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents (the Pi pack), notebook extensions that execute tool calls, and similar. The usual way to contain such a tool on Linux is [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`), the unprivileged sandbox used by Flatpak and by AI coding tools such as Claude Code. `bwrap` creates user, mount, pid (and optionally network) namespaces for a single command and gives it a hand-built filesystem view, so an agent's shell commands can be confined to, say, a project directory with no network and no access to the pod's service-account token.

`bwrap` runs inside the user's existing pod. It is not a VM and does not change the trust boundary between the pod and the node: it shares the host kernel, exactly as the pod already does. Its value is a second fence *inside* the pod, against an agent acting badly on a trusted user's behalf (prompt injection, accidental deletion, credential exfiltration).

Today `bwrap` does not work in a NIC-deployed pod. Four independent layers block it, and NIC configures none of them:

| Layer | What blocks `bwrap` | Owner |
|---|---|---|
| 1. Node kernel | `user.max_user_namespaces=0`, or on Ubuntu 23.10+ `kernel.apparmor_restrict_unprivileged_userns=1`. Not namespaced; cannot be set from a pod. | Cluster provider (node image) |
| 2. Seccomp | The container runtime's default profile only permits `unshare`, `clone(CLONE_NEWUSER)`, `mount`, `pivot_root` with `CAP_SYS_ADMIN`. `Unconfined` works but fails Pod Security Standards (PSS). | Cluster-wide |
| 3. AppArmor | On AppArmor nodes the default container profile denies `mount`. PSS Baseline forbids `Unconfined`. | Cluster-wide |
| 4. Masked `/proc` | The kernel refuses a fresh procfs mount inside a container with masked `/proc` paths, so `bwrap --proc /proc --unshare-pid` fails. Fixed by `hostUsers: false` + `procMount: Unmasked`. | Cluster versions (Kubernetes, containerd, kernel) |

Where the providers stand:

| Provider | Layer 1 | Layer 3 | Layer 4 (pod user namespaces) |
|---|---|---|---|
| `aws` (AL2023) | Expected OK; no AppArmor | n/a | Depends on AMI kernel/containerd; to verify |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | Blocked by the AppArmor sysctl | Profile needed | Example config pins Kubernetes 1.32 |
| `azure` (AKS, Ubuntu 22.04) | Expected OK | Profile needed | 5.15 kernel; likely unsupported |
| `local` (kind) | Host-dependent | To verify | Host-dependent |
| `existing` | Unknown | Unknown | Unknown; detect only |

## Decision Drivers

- Pack authors need a single, documented contract for "my workload can run `bwrap`" that works on every provider, without knowing which provider they are on.
- No provider-name switches outside `pkg/providers/cluster/`: capability flows through `InfraSettings` (see AGENTS.md).
- Off by default. Unprivileged user namespaces widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so the opt-in should be scoped to the nodes that need it.
- Stay inside Pod Security Standards: no privileged pack pods, no `CAP_SYS_ADMIN`, no `Unconfined` seccomp or AppArmor.
- Prefer upstream, community-maintained mechanisms over NIC-owned node agents.
- Compatible with the `security_level` ladder in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that want `bwrap` run privileged or with `Unconfined` profiles.
2. Enable unprivileged user namespaces cluster-wide and ship permissive profiles for every pod.
3. Tiered, opt-in sandbox capability: node-group opt-in, Security Profiles Operator-managed profiles, `InfraSettings` reporting the tier, with pod user namespaces as the upper tier.
4. Skip `bwrap`; provide a VM-grade `RuntimeClass` (gVisor / Kata, e.g. via [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)).

## Decision Outcome

Chosen option: "Option 3 - tiered, opt-in sandbox capability", because it uses the mechanisms the Kubernetes community recommends (Security Profiles Operator, pod user namespaces), works on every provider at some tier, keeps the extra kernel surface confined to opted-in node groups, and fits NIC's `InfraSettings` and conditional-foundational-software patterns. Option 4 is complementary, not competing, and remains open as future work for genuinely untrusted multi-tenant code.

### Tiers

| Tier | The cluster provides | `bwrap` mode packs should use | Availability |
|---|---|---|---|
| 0: off (default) | Nothing | n/a | All providers |
| 1: profiles | Layers 1-3: node prep plus Localhost seccomp/AppArmor profiles on opted-in node groups | Bind the container's existing `/proc` (`--ro-bind /proc /proc`, no `--unshare-pid`) | All providers (after node prep) |
| 2: user-namespaced pods | Tier 1 plus `hostUsers: false` and `procMount: Unmasked` support | Full: `--unshare-all --proc /proc` | Kubernetes >= 1.36, kernel >= 6.3, containerd >= 2.0, no NFS volumes in the pod |

### Shape of the change

1. **Opt-in per node group.** Each provider's node-group config gains an optional `sandbox: true`, next to `gpu`, `labels` and `taints`. NIC labels those nodes `nebari.dev/sandbox=bwrap`. Mirrors the AWS `gpu: true` pattern.
2. **`InfraSettings.Sandbox`.** A new field the provider populates:
   ```go
   type SandboxSettings struct {
       Tier         int               // 0, 1 or 2 (see Tiers)
       NodeSelector map[string]string // where sandbox-capable nodes are
       AppArmor     bool              // nodes enforce AppArmor; an AppArmor profile is required
   }
   ```
3. **Per-provider node prep (layer 1)**, only where needed. Hetzner: per-pool pre-k3s commands writing the sysctl (or a bwrap-scoped AppArmor `userns` grant), plus pool labels. AWS/Azure: labels; extra node prep only if verification shows it is needed. `local`/`existing`: no node changes; documented host requirements and the probe below.
4. **Profiles (layers 2-3) via the [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)**, installed as conditional foundational software ([ADR-0006](0006-conditional-foundational-software-helm.md)) when `Sandbox.Tier >= 1`. NIC ships a `nebari-bwrap` seccomp profile (runtime default plus the namespace syscalls `bwrap` needs, with high-risk families such as `bpf`, `io_uring` and netfilter configuration still denied) and, where `AppArmor` is true, a `nebari-bwrap` AppArmor profile granting `userns` and the required `mount` rules. The operator depends on cert-manager, which NIC already deploys.
5. **Pack contract (ties into [ADR-0003](0003-software-pack-codegen.md)).** A `sandbox.*` Helm-value convention: `sandbox.enabled`, `sandbox.tier`, `sandbox.nodeSelector`, `sandbox.seccompProfile`, `sandbox.appArmorProfile`. `nebari-integration.yaml` may declare `requires: [sandbox]` (or a minimum tier) so NIC fails the deploy if the cluster cannot satisfy it. Until pack codegen lands, NIC also publishes the same data in a cluster-capabilities ConfigMap.
6. **Verification.** A post-bootstrap probe in `pkg/nic` deploy runs a short-lived pod on a sandbox node that executes `bwrap` in the mode the tier promises, reporting the failing layer through the status channel. A user-journey test asserts both directions: a pod using the profile can run `bwrap`, and a pod with the default profile cannot create a user namespace.
7. **ADR-0010 alignment.** The hardened-mode admission policy (#480) gets a scoped exception for the Security Profiles Operator's privileged DaemonSet, and allows only the `nebari-bwrap` Localhost profiles, never `Unconfined`.

### Consequences

**Good:**
- Packs (starting with the Pi pack) can confine agent tool execution without running as root or privileged; the Pi pack's `PI_RUN_AS_ROOT` path becomes unnecessary.
- One provider-neutral contract for pack authors, expressed through `InfraSettings` and Helm values.
- Extra kernel attack surface is confined to opted-in node groups.
- Upstream-maintained profile distribution instead of a NIC-owned node agent.
- Tier 2 tracks the direction of upstream Kubernetes (user namespaces GA in 1.36).

**Bad:**
- A new foundational component (Security Profiles Operator) with its own privileged DaemonSet and CRDs.
- Enabling user namespaces on sandbox nodes widens the kernel attack surface there; kernels must be patched promptly.
- Tier 1's `/proc` bind exposes process information inside the sandbox that a fresh procfs would hide.
- Tier 2 is unavailable where pods mount NFS (including EFS-backed shared storage) or node images lag the version requirements.
- `bwrap` does not protect against kernel exploits; it is not a substitute for VM-grade isolation of hostile multi-tenant code.
- More per-provider surface to verify and keep current as node images change.

## Options Detail

### Option 1: Do nothing

Packs that want `bwrap` set seccomp/AppArmor to `Unconfined`, add `CAP_SYS_ADMIN`, or run privileged.

**Pros:**
- No NIC changes.

**Cons:**
- Each pack reinvents node-level setup it cannot actually perform (layer 1 is not reachable from a pod).
- Pushes packs toward privileged pods, the opposite of the intent.
- Fails PSS Baseline and conflicts with ADR-0010's admission policy.

### Option 2: Cluster-wide enablement

Turn on unprivileged user namespaces on every node and attach permissive profiles to every pod.

**Pros:**
- Simplest for pack authors; nothing to opt into.

**Cons:**
- Widens kernel attack surface on nodes running Keycloak, ArgoCD and other foundational services that never need it.
- Contradicts upstream guidance (e.g. Ubuntu's) to grant `userns` narrowly rather than globally.

### Option 3: Tiered, opt-in sandbox capability (chosen)

Described above.

**Pros:**
- Works on every provider at some tier, with a clear statement of what each tier guarantees.
- Uses community-standard mechanisms.
- Fits `InfraSettings`, ADR-0003 and ADR-0006 patterns.

**Cons:**
- More moving parts (node-group flag, operator, probe, pack contract).
- Two `bwrap` modes for pack authors to support.

### Option 4: VM-grade RuntimeClass (gVisor / Kata)

Run sandboxed workloads under a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`. The pod itself becomes the sandbox; `bwrap` is not needed.

**Pros:**
- Much stronger boundary: a kernel exploit in the workload does not directly yield the node.
- An emerging Kubernetes-native API for agent workloads.

**Cons:**
- Provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps.
- Changes the pod model (separate sandbox pods) rather than confining tools inside the user's existing pod.
- Agent Sandbox is still in development.

Not chosen for this ADR; worth a separate ADR if Nebari needs to run untrusted code from multiple tenants.

## Open Questions

- Does PSS `restricted` admit `procMount: Unmasked` for `hostUsers: false` pods, or only `baseline`? Sources conflict; check the current official PSS table.
- Actual kernel, containerd and runc versions on the AL2023 EKS AMI, AKS node images, and hetzner-k3s v2.4.6's Ubuntu image.
- Does the Security Profiles Operator's AppArmor support meet our needs, or is a small NIC-owned loader required for AppArmor only?
- How does AppArmor apply to pods on kind nodes?
- Does hetzner-k3s v2.4.6 support per-pool pre-k3s commands, or only global ones?
- Is a per-node-group flag the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?

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
