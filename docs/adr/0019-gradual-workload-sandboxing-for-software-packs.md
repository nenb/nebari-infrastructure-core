# ADR-0019: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT)

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents (the Pi pack), notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

There is no single right way to do this. The options form a spectrum that differs in strength, cost, what code they can run, and what they need from the cluster.

### The sandboxing spectrum

| # | Option | Examples | What isolates the code | Cluster changes needed | Main limits | Place in this ADR |
|---|---|---|---|---|---|---|
| 1 | Language runtime | WASM (wasmtime, WASI), V8 isolates, Deno with permission flags, Pyodide | The runtime: code can only do what the runtime exposes | None | Runs only code built for that runtime; no arbitrary binaries, shells, `pip install` or `git` | Packs can do this today |
| 1b | The user's own browser | JupyterLite, Pyodide or WebContainers on the client side | The browser sandbox, on the user's machine | None; the cluster is not involved | As row 1; nothing runs on the platform | Packs can do this today |
| 2 | Process self-restriction | Landlock plus seccomp filters, including seccomp user notification to mediate selected syscalls (the approach of several agent sandboxes on Linux) | The process drops its own filesystem (and, on newer kernels, TCP) rights and installs syscall filters before running a command | No pod relaxation: works under the runtime's default seccomp profile with no added capabilities. The node kernel must provide a recent enough Landlock ABI with Landlock enabled, which not every provider's default node image does (see below) | Covers filesystem access and syscall mediation; Landlock TCP rules need a newer kernel than filesystem rules; no process-visibility isolation on its own | **`process-self-restriction`, this ADR** |
| 3 | Namespace sandbox in the pod | bubblewrap, nsjail, minijail, rootless podman/buildah | Linux namespaces inside the pod, on the shared host kernel | Yes: node prep and security profiles (the four layers below) | Shares the host kernel; extra kernel attack surface from user namespaces | **`in-pod-namespaces`, this ADR** |
| 3b | Headless browser in the pod | Chromium/Playwright running untrusted pages or scripts | Chromium's own sandbox, which also uses user namespaces | Same as row 3, otherwise it runs with `--no-sandbox` | As row 3 | Covered by `in-pod-namespaces` |
| 4 | Separate locked-down pod per task | A Job or Agent Sandbox `Sandbox` with the default runtime: no service-account token, NetworkPolicy, read-only root, optionally `hostUsers: false` | Standard container isolation, on the shared host kernel | Pod security settings: none. NetworkPolicy: only takes effect where the network plugin enforces it, which is not the case on AWS or Azure as NIC deploys them today (tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). `hostUsers: false` needs recent Kubernetes, containerd and kernel | Start-up latency; the pack needs RBAC to create pods; still a shared kernel | Basic form: packs can do this today, and collab-hub-pack and Nebi are already adopting it (see Related work); its network controls depend on #691/#675. With `hostUsers: false`: `pod-user-namespaces`, follow-up |
| 5 | User-space kernel | gVisor (`runsc`) | gVisor implements the Linux syscall interface itself; the workload never calls the host kernel directly | Yes: install the runtime and a `RuntimeClass` (built into some managed offerings, otherwise installed per provider) | I/O and syscall overhead; some applications are incompatible | `user-space-kernel`, follow-up |
| 6 | MicroVM per pod | Kata Containers, Firecracker, Cloud Hypervisor | Hardware virtualisation with a separate guest kernel | Yes: runtime install, and nodes that expose `/dev/kvm` (bare metal, or instance types with nested virtualisation) | More memory per pod, slower start; usually a dedicated KVM-capable node group | `vm-boundary`, follow-up |
| 7 | Dedicated node or cluster | Per-tenant node pools, a separate cluster, confidential VMs | A separate machine | Yes: provisioning | Cost | Out of scope |
| 8 | External sandbox service | Hosted code-execution services (several are Firecracker-based) | Someone else's infrastructure | None in the cluster; outbound network and credentials only | Data leaves the environment; vendor dependency | Packs can do this today |

Two points the table makes explicit:

- **Several options need nothing from NIC** (rows 1, 1b, 4 in its basic form, and 8). This ADR is not a precondition for sandboxing in general; it addresses the band where pack developers are blocked by settings only the cluster can change. Row 2 needs no relaxation of pod security, but does depend on the node kernel, which only the cluster controls.
- **Isolation strength is only part of the picture.** In every row, outbound network policy, which credentials are visible to the sandboxed code (service-account token, cloud IAM, Git tokens), resource limits and filesystem write access usually matter as much as the isolation tier. A VM with cloud credentials mounted is weaker in practice than a namespace sandbox without them.
- **Egress can be enforced in three ways, and all are legitimate.** *Cluster-enforced* egress (NetworkPolicy) cannot be changed by anything inside the pod, but matches only IP addresses and ports. *In-pod* egress enforcement (a proxy or a sidecar running a DNS filter and packet rules in the pod's network namespace) can allow domain names, which NetworkPolicy cannot. A *mediating proxy outside the workload* (an egress gateway, or a dedicated proxy pod per sandbox that performs policy checks and opens approved upstream connections) can also allow domain names and keep credentials out of the workload, with NetworkPolicy denying the workload every other route. Domain-based egress therefore needs the in-pod kind or a mediating proxy. The mediating-proxy pattern only holds where NetworkPolicy is enforced for both ingress and egress; without that, the workload can bypass the proxy. An in-pod enforcer that programs packet rules needs `NET_ADMIN`, which Pod Security Baseline does not allow: on the default runtime it falls under the relaxed-workload terms under "Shared mechanics", step 4, and the workload container itself must not hold it.

- **NetworkPolicy enforcement is tracked separately and is not part of this ADR.** [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) makes enforcement a per-provider guarantee and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) covers the AWS VPC CNI. Row 4's network controls, and any sandbox system built on a mediating proxy, depend on that work; rows 2 and 3 do not, so the two can proceed independently.

This ADR delivers rows 2 and 3 and defines how rows 4-6 are added later.

### Why row 2 needs NIC

Row 2 needs nothing from the pod spec: it runs non-root, with every capability dropped and the runtime's default seccomp profile, so it is compatible with Pod Security `restricted`. What it needs is node kernel support, which packs cannot change:

- **Landlock** enabled in the kernel's active security modules, at a sufficient ABI version. ABI 3 (Linux 6.2) covers filesystem access including truncation; TCP bind/connect rules need ABI 4 (Linux 6.7). Distribution backports exist, so the version number alone does not decide it: the probe does.
- **Nested seccomp filters with user notification**, including the operations that let a supervising process inject descriptors into the workload, usable under the runtime's default seccomp profile. containerd's default profile allows the `seccomp` syscall, and, on kernels from 4.8, `ptrace` and `process_vm_readv`, which some mediators use to inspect the workload.

Where the providers' default node images stand *(unverified; inferred from distribution kernels)*:

| Provider | Default node kernel | Landlock ABI >= 3 |
|---|---|---|
| `aws` (AL2023) | 6.1 or 6.12, depending on the EKS AMI release | Only on 6.12 |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | 6.8 | Yes |
| `azure` (AKS, Ubuntu 22.04) | 5.15 | No: needs a newer node OS image |
| `local` (kind) | The host's kernel | Host-dependent |
| `existing` | Unknown | Detect only |

So the NIC work for row 2 is choosing qualifying node images, reporting what each node group supports, and probing it, not changing pod security.

### Why row 3 needs NIC

Pack developers cannot enable row 3 themselves: the deciding settings live on the nodes and in cluster-wide security profiles, not in a pack's chart. Concretely, an in-pod sandboxing tool fails in a NIC-deployed pod because four layers block unprivileged namespace creation:

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

**Why it can appear to work today.** No pack in `PACKS/` sets a seccomp profile, and neither does the bundled JupyterHub chart. A pod with no seccomp profile gets the kubelet's default, which is no filter at all (`Unconfined`) unless the kubelet's `seccompDefault` option is enabled. On AWS this is confirmed from source: the AL2023 kubelet configuration generated by nodeadm ([`amazon-eks-ami`](https://github.com/awslabs/amazon-eks-ami), `nodeadm/internal/kubelet/config.go`) does not set `seccompDefault`, containerd's `unset_seccomp_profile` is empty, and NIC's [`terraform-aws-eks-cluster`](https://github.com/nebari-dev/terraform-aws-eks-cluster) module (v0.7.0) adds no kubelet configuration. So on AWS, where layer 1 is also expected to pass, a user pod is predicted to run bubblewrap today in its reuse-`/proc` mode (not yet confirmed on a live cluster). This is not a foundation packs can rely on: it depends on running with no syscall filter, it stops working as soon as a pack follows Pod Security Standards `restricted` (which requires `RuntimeDefault` or `Localhost`) or the kubelet's `seccompDefault` is enabled, and ADR-0010's hardened mode is expected to forbid it.

## Decision Drivers

- **Build in steps.** Give pack developers something usable now, and a contract that later, stronger options can be added to without breaking packs that already rely on it.
- **Tool-neutral.** NIC provides cluster primitives, not a particular sandboxing tool. Packs choose their tool; a different tool, or a pack dropping one, should not require an ADR change.
- **Provider-neutral.** Pack developers should not need to know which provider they are on. Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see AGENTS.md).
- **Off by default and narrowly scoped.** Unprivileged user namespaces widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so enable them only on the nodes that need them.
- **Stay inside Pod Security Standards, preferring `restricted`.** No privileged pack pods, no `CAP_SYS_ADMIN`, no `Unconfined` seccomp or AppArmor. Capable sandbox systems can run entirely within Pod Security `restricted`, so capabilities that need no relaxation come first, and relaxation is the exception a capability must justify.
- **Prefer community-maintained mechanisms** over NIC-owned node agents.
- **Compatible with the `security_level` ladder** in [ADR-0010](0010-high-security-mode.md).

## Considered Options

1. Do nothing; packs that need sandboxing run privileged or with `Unconfined` profiles.
2. Bake support for one sandboxing tool (e.g. bubblewrap) into NIC.
3. A tool-neutral, extensible sandbox capability contract, delivered one capability at a time, starting with process self-restriction and in-pod unprivileged namespaces.
4. Go straight to a stronger-isolation runtime (gVisor or Kata `RuntimeClass`) as the only sandbox option.

## Decision Outcome

Chosen option: "Option 3 - a tool-neutral, extensible sandbox capability contract, delivered incrementally", because it gives pack developers usable primitives now (kernel self-restriction, which needs no relaxation of pod security, and the namespaces bubblewrap and similar tools need), defines a stable way to advertise stronger isolation as it lands, and does not tie NIC to a specific tool. Options 2 and 4 are not rejected outright: tool-specific guidance belongs in pack documentation, and gVisor- and Kata-backed runtimes are planned later capabilities under the same contract.

### The contract

**How capabilities combine.** In-pod namespace tools (row 3) can also run *inside* a `user-space-kernel` or `vm-boundary` workload, and there they may obtain namespaces through privileges that the outer boundary contains (running as root, `CAP_SYS_ADMIN`), with no node-level change. That is acceptable because the outer boundary, not the host kernel, absorbs the extra privilege. On the default runtime the only accepted route is the unprivileged one this ADR delivers: granting `CAP_SYS_ADMIN` to a default-runtime pod is never an accepted way to obtain `in-pod-namespaces`, outside the relaxed-workload terms a capability's ADR sets out ("Shared mechanics", step 4). Some stronger runtimes restrict namespace or mount operations inside the sandbox, so a combination is advertised only once the probe has exercised it. `process-self-restriction` is expected to combine with every other capability, but inside a `user-space-kernel` or `vm-boundary` workload it depends on that runtime's kernel, not the node's, so those combinations are probed too.

Capabilities name **guarantees, not mechanisms**. `user-space-kernel` may be provided by a gVisor `RuntimeClass`, or by a system that runs gVisor itself inside its own worker pods; `vm-boundary` by a Kata `RuntimeClass` or by a system that drives a VMM directly. The probe verifies the guarantee, not the mechanism. How a pack requests the capability does depend on the mechanism, so the contract carries it rather than leaving packs to guess: when a capability is provided through a `RuntimeClass`, its placement includes the `RuntimeClass` name (see `SandboxPlacement` below); when it is provided by a system with its own API (a custom resource or a service), the capability names that system and its documentation describes the request.

The cluster advertises a **set of sandbox capabilities**, not a single level, because the options are not strictly ordered (a gVisor or Kata runtime is not a superset of in-pod namespaces). Packs ask for the capabilities they need; NIC refuses the deploy when the cluster cannot provide them.

| Capability | What a pack can rely on | Typical consumers | Delivered by |
|---|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (at least ABI 3; the advertised ABI is reported) and with nested seccomp filters, including user-notification filters. | Agent sandboxes that confine and mediate a workload process in place; any tool that applies Landlock or seccomp itself | **This ADR** |
| `in-pod-namespaces` | An unprivileged process in the pod can create user, mount, pid and network namespaces, with seccomp/AppArmor profiles that permit it. `/proc` is the container's own (tools bind it rather than mount a fresh one). | bubblewrap, nsjail, rootless podman/buildah, `unshare` | **This ADR** |
| `pod-user-namespaces` | The pod may set `hostUsers: false` and `procMount: Unmasked`; in-pod tools can then mount a fresh `/proc`. | The same tools, in their full-isolation modes | Follow-up ADR (needs Kubernetes >= 1.36, kernel >= 6.3, containerd >= 2.0, no NFS volumes in the pod) |
| `network-policy` | NetworkPolicies are enforced on the cluster. | Row 4 (pod-per-task), egress restriction for any sandbox | Defined by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691); listed here only as a candidate for the same contract, to be agreed with that work |
| `user-space-kernel` | Workloads that request it run behind a user-space kernel that implements the Linux syscall interface, so they never call the host kernel directly. | Untrusted, multi-tenant code | Follow-up ADR |
| `vm-boundary` | Workloads that request it run behind a hardware-virtualisation boundary with their own guest kernel. | Untrusted, multi-tenant code; workloads whose threat model includes host-kernel exploits | Follow-up ADR |

Every capability, in this ADR or a later one, is defined by the same five things:

- **Guarantee:** what a pack can rely on (the table above).
- **Placement:** the node label that marks nodes providing it, whether its node groups are tainted, and therefore the node selector and tolerations a pod needs. Capabilities do not share one generic "sandbox node" label: a node group that allows unprivileged user namespaces and a dedicated, tainted node group that runs a VM-based runtime are different things.
- **Cluster requirements:** anything the nodes or the cluster itself must provide. On nodes: a kernel setting, KVM access, a runtime binary. On the cluster: a minimum Kubernetes version, or API-server features and APIs that are off by default and on some managed services can only be enabled at cluster creation. Where these need provider-specific settings, such as a custom launch template that enables nested virtualisation or API-server flags, they live in the provider's own config, as `gpu` and `ami_type` do today. Some providers may be unable to meet a requirement at all; they simply never advertise that capability. `InfraSettings` reports only the resulting capability.
- **Provisioning:** what has to be installed and by whom. A capability is about what is advertised and verified, not who installed it: NIC may install the components as conditional foundational software, or a cluster administrator or a pack's cluster-scoped install may provide them. Either way, the probe below confirms it before it is advertised. For capabilities provided through a `RuntimeClass` (gVisor, Kata), NIC installing them is the expected default: sandboxing systems built on a `RuntimeClass` typically treat installing the runtime as the cluster administrator's job and only check at start-up that the named `RuntimeClass` exists, so without NIC every operator would install and patch the runtime by hand.
- **Verification:** the probe that proves it, including in combination with other capabilities a pack requires.

Capabilities may be added to this table by later ADRs without changing this one, as long as they define these five things.

### Scope of this ADR

This ADR decides the contract and delivers two capabilities: `process-self-restriction` first, because it needs no relaxation of pod security, and `in-pod-namespaces`. It deliberately does not:

- choose or ship a sandboxing tool, or a default sandbox policy for any tool;
- deliver `pod-user-namespaces`, `user-space-kernel` or `vm-boundary`;
- change the trust boundary between pods and nodes.

### Shared mechanics

1. **`InfraSettings.Sandbox`.** A new field each cluster provider populates, so neither `pkg/argocd` nor the CLI needs to know the provider:
   ```go
   type SandboxSettings struct {
       // Capabilities maps each advertised capability (e.g. "in-pod-namespaces")
       // to where pods that need it must run.
       Capabilities map[string]SandboxPlacement
       LandlockABI  int  // lowest Landlock ABI across process-self-restriction node groups
       AppArmor     bool // in-pod-namespaces nodes enforce AppArmor; an AppArmor profile is required
   }

   type SandboxPlacement struct {
       NodeSelector     map[string]string
       Tolerations      []corev1.Toleration
       RuntimeClassName string // set when the capability is provided through a RuntimeClass
   }
   ```
   NIC labels the nodes that provide a capability with one label per capability, derived from its name (for example `sandbox.nebari.dev/in-pod-namespaces: "true"`; characters not allowed in a label name become `-`).
2. **Pack contract (ties into [ADR-0003](0003-software-pack-codegen.md)).** A `sandbox.*` Helm-value convention with placement per capability, mirroring `SandboxSettings`: `sandbox.capabilities.<name>.nodeSelector`, `sandbox.capabilities.<name>.tolerations` and, where set, `sandbox.capabilities.<name>.runtimeClassName`, plus capability-specific values such as `sandbox.landlockABI`, `sandbox.capabilities.in-pod-namespaces.seccompProfile` and `.appArmorProfile`. `nebari-integration.yaml` may declare `requires: { sandbox: [process-self-restriction] }` (optionally with a minimum Landlock ABI), and NIC fails the deploy if the cluster cannot satisfy it. Until pack codegen lands, NIC also publishes the same data in a cluster-capabilities ConfigMap.
3. **Verification.** A post-bootstrap probe in `pkg/nic` deploy runs short-lived pods, placed using each capability's own node selector and tolerations, that exercise every advertised capability, reporting the failing requirement through the status channel. A capability is advertised only after its probe passes. Where packs combine capabilities, the probe also tests the combination, because one capability can behave differently under another: for example, NetworkPolicy enforcement is checked separately for workloads under `user-space-kernel` and `vm-boundary`, since those change the workload's network path, and in-pod namespace and self-restriction tools are exercised inside each stronger runtime, since some restrict namespace, mount or Landlock operations. A user-journey test asserts each capability in both directions where a negative case exists. This follows the same pattern as the NetworkPolicy enforcement check proposed in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) (a positive and a negative case, run per provider), and the two should share their harness.
4. **ADR-0010 alignment.** Capabilities that run under Pod Security `restricted` need nothing from the hardened-mode admission policy (#480); `process-self-restriction` is one. Capability-providing node agents are privileged DaemonSets: the Security Profiles Operator for `in-pod-namespaces`, and runtime installers for later capabilities. The hardened-mode admission policy gets one general, scoped exception for such agents, pinned by namespace and limited to the node groups of the capability they provide, rather than a per-component exemption. It allows only the `nebari-sandbox` Localhost profiles, never `Unconfined`.

   Some later capabilities also need **workload** pods with more privilege than Pod Security Baseline allows: for example, worker pods that run a user-space kernel or a VMM themselves and need added capabilities and relaxed seccomp/AppArmor. That is a deliberate trade, more privilege in the worker in exchange for a strong boundary around the code it runs, and it is a policy decision for each capability's ADR, not something this ADR grants. Because sandbox systems exist that run entirely within `restricted`, a capability's ADR must justify any such relaxation against restricted-compatible alternatives, and name the dedicated namespace where such pods are admitted, the exact privileges they receive, and the node groups they are confined to. It should replace `Unconfined` with Localhost profiles distributed by the same mechanism as `nebari-sandbox`. Hardened mode admits them only under those terms.

### Delivering `process-self-restriction`

1. **No opt-in and no relaxation.** The capability needs no profiles, no added capabilities and no admission exception, so NIC advertises it on every node group whose kernel qualifies, without a per-node-group switch, and labels those nodes `sandbox.nebari.dev/process-self-restriction`.
2. **Qualifying node images (cluster requirements).** Where a provider's default node image does not qualify, NIC selects one that does through the provider's own config, as it does for GPU images: on AWS, an AL2023 AMI release with a qualifying kernel; on Azure, a newer node OS image than Ubuntu 22.04; on Hetzner, the default Ubuntu 24.04 image already qualifies. `local` and `existing` are detect-only. A node group that cannot qualify (for example a GPU image pinned to an older kernel) simply does not advertise the capability.
3. **Probe.** A non-root pod with every capability dropped and the default seccomp profile applies a Landlock ruleset and confirms a denied write fails, reports the highest Landlock ABI available, and installs a nested seccomp user-notification filter and exercises it. The lowest ABI across qualifying node groups becomes `SandboxSettings.LandlockABI`.

### Delivering `in-pod-namespaces`

1. **Opt-in per node group, by capability.** Each provider's node-group config gains an optional `sandbox` block naming the opt-in capabilities that node group provides, next to `gpu`, `labels` and `taints`:
   ```yaml
   node_groups:
     agents:
       sandbox:
         capabilities: [in-pod-namespaces]
   ```
   `in-pod-namespaces` node groups are untainted by default and may add a taint through the existing `taints` field; later capabilities define their own default (a VM-based runtime would normally require a dedicated, tainted node group). A node group lists only capabilities that are compatible with each other. This mirrors the AWS `gpu: true` pattern and keeps the extra kernel surface off nodes running Keycloak, ArgoCD and other foundational services.
2. **Per-provider node prep (layer 1)**, only where needed. Hetzner: per-pool pre-k3s commands that lift Ubuntu's restriction (preferably a scoped AppArmor `userns` grant rather than the global sysctl), plus pool labels. AWS/Azure: labels; extra node prep only if verification shows it is needed (on AWS, the EKS module's existing pre-nodeadm cloud-init hook, today used only for the extra CA bundle, is the natural place). `local`/`existing`: no node changes; documented host requirements and the probe.
3. **Security profiles (layers 2-3) via the [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)**, installed as conditional foundational software ([ADR-0006](0006-conditional-foundational-software-helm.md)) when `in-pod-namespaces` is enabled on any node group. NIC ships a `nebari-sandbox` seccomp profile (runtime default plus the namespace syscalls, with high-risk families such as `bpf`, `io_uring` and netfilter configuration still denied) and, where `AppArmor` is true, a `nebari-sandbox` AppArmor profile granting `userns` and the required `mount` rules. The operator depends on cert-manager, which NIC already deploys. The profiles are named for the capability, not for a tool, and the same mechanism carries any profiles later capabilities need. The operator's node agent is a DaemonSet that runs on every node by default; NIC restricts it to the node groups that need its profiles (those labelled `sandbox.nebari.dev/in-pod-namespaces`) through the scheduling settings on the operator's daemon configuration, so other nodes get neither the agent nor the profiles. Profiles are opt-in per pod: placing them on a node changes nothing for pods that do not reference them.
4. **Probe.** Bubblewrap is the reference tool for this capability's probe and tests because it exercises all of layers 1-3 in one command; this is a test-harness choice, not a contract. The user-journey test asserts both directions: a pod using the profile can create namespaces, and a pod with the default profile cannot.

### Consequences

**Good:**
- The first capability, `process-self-restriction`, needs no relaxation of pod security at all and runs under Pod Security `restricted`.
- Pack developers get documented, provider-neutral primitives to build on, and choose their own tool. The Pi pack can confine agent tool execution without its current `PI_RUN_AS_ROOT` path.
- Stronger isolation can be added later as new capabilities without breaking packs that only need `in-pod-namespaces`.
- Extra kernel attack surface is confined to opted-in node groups.
- Upstream-maintained profile distribution instead of a NIC-owned node agent.

**Bad:**
- A new foundational component (Security Profiles Operator) with its own privileged DaemonSet and CRDs.
- Enabling user namespaces on `in-pod-namespaces` nodes widens the kernel attack surface there; kernels must be patched promptly.
- With `in-pod-namespaces` alone, tools reuse the container's `/proc`, which exposes process information a fresh procfs would hide.
- Namespace-based sandboxing does not protect against kernel exploits; it is not a substitute for a VM-grade boundary for hostile multi-tenant code. The capability documentation must say so.
- More per-provider surface to verify and keep current as node images change.
- `process-self-restriction` ties the platform to node kernel versions: Azure needs a newer node OS image than today's default, and node groups on older kernels (for example pinned GPU images) cannot advertise it.
- Landlock's ABI differs across kernels, so packs that need TCP rules must check the advertised ABI rather than the capability alone.

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

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

**Pros:**
- Much stronger boundary: a kernel exploit in the workload does not directly yield the node.

**Cons:**
- Provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps.
- Changes the pod model (separate sandbox pods) rather than letting packs confine tools inside the user's existing pod.
- A large first step; Agent Sandbox is still in development.

Kept as the planned `user-space-kernel` and `vm-boundary` capabilities rather than the starting point.

## Related Work

**NetworkPolicy enforcement (platform).**

- [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) Enforce NetworkPolicy on every cluster provider (open). Records per-provider state: Azure's AKS module sets no `network_policy`; Hetzner's k3s should enforce but is untested; kind is unchecked; `existing` needs a documented requirement and a readiness check. Proposes a user-journey enforcement check.
- [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) Enforce NetworkPolicy on the VPC CNI addon, with an opt-in strict mode (open, blocked on the storage strategy in [#586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)). Includes trial results from a NIC-built EKS cluster, including the strict-mode requirement that every NIC namespace ships a NetworkPolicy.

**Multi-tenancy (the main driver of the above).**

- [#674](https://github.com/nebari-dev/nebari-infrastructure-core/pull/674) Multi-tenancy design doc (open; being split into a platform layer and a deployment-specific guide). Treats NetworkPolicy enforcement as precondition 1.
- [#676](https://github.com/nebari-dev/nebari-infrastructure-core/issues/676) Cluster preconditions for a tenant, and [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683) scheduled isolation checks. The scheduled-check idea applies equally to the sandbox probe.

**Packs already building isolation (rows 4 and 2-3 consumers).**

- [collab-hub-pack#167](https://github.com/nebari-dev/collab-hub-pack/issues/167) Plan hosted coding workspaces for Nebari and Collab Hub (planning). The closest match to the coding-agent use case that motivates this ADR.
- [collab-hub-pack#6](https://github.com/nebari-dev/collab-hub-pack/issues/6) Cog workers as separate pods with no ServiceAccount token, created only by a least-privilege controller (row 4).
- [collab-hub-pack#11](https://github.com/nebari-dev/collab-hub-pack/issues/11) Restrict worker egress to hub-mediated paths. Notes that a NetworkPolicy cannot allow a hostname, so model traffic goes through an in-cluster egress gateway; the same constraint applies to Landlock (row 2), which restricts by port, not host.
- [nebi#445](https://github.com/nebari-dev/nebi/issues/445) and [nebi#513](https://github.com/nebari-dev/nebi/issues/513) Untrusted environment builds run in a shared worker with database credentials; proposal to run each job in its own pod (row 4).
- [nebari-operator#197](https://github.com/nebari-dev/nebari-operator/issues/197) A shared NetworkPolicy helper for packs.

**Pack contract.**

- The [Nebari Pack Specification](https://github.com/nebari-dev/nebari-operator/blob/main/docs/pack-specification.md) (section 6, Security baseline) requires a hardened `securityContext` at GA and says packs SHOULD ship a NetworkPolicy. It says nothing about seccomp today. If it later requires `RuntimeDefault`, packs that currently run sandboxing tools with no syscall filter (see "Why it can appear to work today") stop working, so the `sandbox.*` contract here should be referenced from that section.

## Open Questions

- Does PSS `restricted` admit `procMount: Unmasked` for `hostUsers: false` pods, or only `baseline`? Sources conflict; relevant to the `pod-user-namespaces` follow-up.
- Actual kernel, containerd and runc versions on the AL2023 EKS AMI, AKS node images, and hetzner-k3s v2.4.6's Ubuntu image.
- Does the Security Profiles Operator's AppArmor support meet our needs, or is a small NIC-owned loader required for AppArmor only?
- Confirm the Security Profiles Operator's daemon can be pinned to a node selector (affinity/tolerations on its daemon configuration) in the release we would pin, and how `in-pod-namespaces` node groups that scale up get their profiles before pods are scheduled to them.
- How does AppArmor apply to pods on kind nodes?
- Does hetzner-k3s v2.4.6 support per-pool pre-k3s commands, or only global ones?
- Is per-node-group opt-in the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Do the k3s (hetzner-k3s) and AKS default kubelet configurations enable `seccompDefault`? This decides whether pods without an explicit profile are filtered today on those providers. (Resolved for EKS: not enabled; see Context.)
- Confirm every *(unverified)* entry in the provider table by running the probe described above on each provider.
- Which node images qualify for `process-self-restriction`: the kernel on each AL2023 EKS AMI release NIC would pin, the node OS images the AKS module can select, and whether Landlock is in the active security-module list on each? Should the baseline be ABI 3 (filesystem) or ABI 4 (adds TCP rules)?
- Several sandbox systems depend on the Agent Sandbox controller and CRDs and leave installing them to the cluster administrator. Should NIC offer it as conditional foundational software (ADR-0006)? It is an API dependency rather than an isolation guarantee, so it may sit outside the capability table.
- Should NetworkPolicy enforcement be advertised through this contract (the `network-policy` candidate) and `InfraSettings`, or stay a platform guarantee that packs assume? To agree with the owners of [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691).
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and should it say anything about `seccompProfile` for pods that do not sandbox?
- Should `in-pod-namespaces` cover pods that run sandboxes for several users or sessions at once? With unprivileged user namespaces, every session maps to the pod's own host UID, so files are not separated between sessions; separating them needs a distinct real UID per session, which needs root in the pod and so belongs inside a stronger boundary. For single-user pods this does not matter; the ADR should state whether multi-session pods are in scope.
- Should capability names be versioned (e.g. `in-pod-namespaces/v1`) so a guarantee can be tightened later without silently changing its meaning?

## Links

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
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
