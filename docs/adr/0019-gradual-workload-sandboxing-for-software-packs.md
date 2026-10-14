# ADR-0019: Gradual Workload Sandboxing Capability for Software Packs

## Status

Proposed (DRAFT). Revised 2026-10-14 after review: delivery is now phased, lifecycle and readiness are explicit, and the first namespace consumer is qualified.

## Date

2026-10-12

## Context

Software packs increasingly run code on a user's behalf that the user did not write line by line: coding agents, notebook extensions that execute tool calls, build steps, and similar. Pack developers want to contain that code, for example by confining an agent's shell commands to a project directory with no network and no access to the pod's service-account token.

There is no single right way to do this. The options form a spectrum that differs in strength, cost, what code it can run, and what it needs from the cluster. Several options need nothing from NIC. This ADR addresses the band where pack developers are blocked by settings only the cluster can change: process self-restriction (Landlock and seccomp) and namespace sandboxes inside the pod (bubblewrap and similar).

### The sandboxing spectrum

| # | Option | Examples | What isolates the code | Cluster changes needed | Main limits | Place in this ADR |
|---|---|---|---|---|---|---|
| 1 | Language runtime | WASM (wasmtime, WASI), V8 isolates, Deno with permission flags, Pyodide, Monty (a Python-subset interpreter written in Rust, with no filesystem, environment or network inside the sandbox; the host exposes only the functions it chooses) | The runtime: code can only do what the runtime exposes | None | Runs only code built for that runtime, or a subset of a language (no C extensions or third-party native packages); no arbitrary binaries, shells, `pip install` or `git` | Packs can do this today |
| 1b | The user's own browser | JupyterLite, Pyodide or WebContainers on the client side | The browser sandbox, on the user's machine | None; the cluster is not involved | As row 1; nothing runs on the platform | Packs can do this today |
| 2 | Process self-restriction | Landlock plus seccomp filters, including seccomp user notification to mediate selected syscalls (the approach of several agent sandboxes on Linux) | The process drops its own filesystem (and, on newer kernels, TCP) rights and installs syscall filters before running a command | No pod relaxation: works under the runtime's default seccomp profile with no added capabilities. The node kernel must provide a recent enough Landlock ABI with Landlock enabled, which not every provider's default node image does (see below) | Covers filesystem access and syscall mediation; Landlock TCP rules need a newer kernel than filesystem rules; no process-visibility isolation on its own | **`process-self-restriction`, this ADR** |
| 3 | Namespace sandbox in the pod | bubblewrap, nsjail, minijail, rootless podman/buildah | Linux namespaces inside the pod, on the shared host kernel | Yes: node prep and security profiles (the four layers below) | Shares the host kernel; extra kernel attack surface from user namespaces | **`in-pod-namespaces`, this ADR** |
| 3b | Headless browser in the pod | Chromium/Playwright running untrusted pages or scripts | Chromium's own sandbox, which also uses user namespaces | Same as row 3, otherwise it runs with `--no-sandbox` | As row 3 | Covered by `in-pod-namespaces` |
| 3c | System-container runtime | Sysbox, used to run `dockerd` or `systemd` inside a workspace | User namespaces plus virtualised `/proc` and `/sys`, on the shared host kernel | Yes: either a `RuntimeClass` installed on the nodes, or a privileged outer container that hosts an unprivileged inner one | Shares the host kernel; the privileged-outer-container variant is root on the node | Not delivered here. As a `RuntimeClass`, a later capability; the privileged-outer-container variant falls under the relaxed-workload or node-owning tiers (Appendix B) |
| 4 | Separate locked-down pod per task | A Job or Agent Sandbox `Sandbox` with the default runtime: no service-account token, NetworkPolicy, read-only root, optionally `hostUsers: false` | Standard container isolation, on the shared host kernel | Pod security settings: none. NetworkPolicy: only takes effect where the network plugin enforces it, which is not the case on AWS or Azure as NIC deploys them today (tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). `hostUsers: false` needs recent Kubernetes, containerd and kernel | Start-up latency; the pack needs RBAC to create pods; still a shared kernel | Basic form: packs can do this today, and collab-hub-pack and Nebi are already adopting it (see Related work); its network controls depend on #691/#675. With `hostUsers: false`: `pod-user-namespaces`, follow-up |
| 5 | User-space kernel | gVisor (`runsc`) | gVisor implements the Linux syscall interface itself; the workload never calls the host kernel directly | Yes: install the runtime and a `RuntimeClass` (built into some managed offerings, otherwise installed per provider) | I/O and syscall overhead; some applications are incompatible | `user-space-kernel`, follow-up |
| 6 | MicroVM per pod | Kata Containers, Firecracker, Cloud Hypervisor | Hardware virtualisation with a separate guest kernel | Yes: runtime install, and nodes that expose `/dev/kvm` (bare metal, or instance types with nested virtualisation) | More memory per pod, slower start; usually a dedicated KVM-capable node group | `vm-boundary`, follow-up |
| 7 | Dedicated node or cluster | Per-tenant node pools, a separate cluster, confidential VMs | A separate machine | Yes: provisioning | Cost | Out of scope |
| 8 | External sandbox service | Hosted code-execution services (several are Firecracker-based) | Someone else's infrastructure | None in the cluster; outbound network and credentials only | Data leaves the environment; vendor dependency | Packs can do this today |

Notes on egress, credentials and what each row needs from NIC are in Appendix A.

### Why row 2 (process self-restriction) needs NIC

Row 2 needs nothing from the pod spec: it runs non-root, with every capability dropped and the runtime's default seccomp profile, so it is compatible with Pod Security `restricted`. What it needs is node kernel support, which packs cannot change:

- **Landlock** enabled in the kernel's active security modules, at a sufficient ABI version. ABI 3 (Linux 6.2) covers filesystem access including truncation; TCP bind/connect rules need ABI 4 (Linux 6.7). ABI 3 is the floor for the capability, but **ABI 4 is the target**: TCP-port confinement (restricting which ports a process may `bind` or `connect` to) is the main agent use case, and it needs ABI 4. Landlock checks ports, not destination addresses, and does not restrict UDP, so port confinement is not by itself proxy enforcement (Appendix A). Distribution backports exist, so the version number alone does not decide it: the probe does.
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


### Why row 3 (in-pod namespaces) needs NIC

Pack developers cannot enable row 3 themselves: the deciding settings live on the nodes and in cluster-wide security profiles, not in a pack's chart. Concretely, an in-pod sandboxing tool fails in a NIC-deployed pod because four layers block unprivileged namespace creation:

| Layer | What blocks it | Owner |
|---|---|---|
| 1. Node kernel | `user.max_user_namespaces=0`, or on Ubuntu 23.10+ `kernel.apparmor_restrict_unprivileged_userns=1`. Not namespaced; cannot be set from a pod. | Cluster provider (node image) |
| 2. Seccomp | The container runtime's default profile only permits `unshare`, `clone(CLONE_NEWUSER)`, `mount`, `pivot_root` with `CAP_SYS_ADMIN`. `Unconfined` works but fails Pod Security Standards (PSS). | Cluster-wide |
| 3. AppArmor | On AppArmor nodes the default container profile denies `mount`. PSS Baseline forbids `Unconfined`. | Cluster-wide |
| 4. Masked `/proc` | The kernel refuses a fresh procfs mount inside a container with masked `/proc` paths. Lifted only by pod user namespaces plus `procMount: Unmasked`, which Pod Security `restricted` rejects even with `hostUsers: false`. | Cluster versions (Kubernetes, containerd, kernel) |

Where the providers stand on these layers. Entries marked *(unverified)* are inferred from the node image's defaults, not from running a sandboxing tool on a NIC-deployed cluster:

| Provider | Layer 1 (node kernel) | Layer 2 (seccomp) | Layer 3 (AppArmor) | Layer 4 (pod user namespaces) |
|---|---|---|---|---|
| `aws` (AL2023) | Expected OK *(unverified)* | Blocked under `RuntimeDefault`; profile needed | n/a (no AppArmor) | Depends on AMI kernel/containerd *(unverified)* |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | Blocked by the AppArmor sysctl | Blocked under `RuntimeDefault`; profile needed | Profile needed | Example config pins Kubernetes 1.32 |
| `azure` (AKS, Ubuntu 22.04) | Expected OK *(unverified)* | Blocked under `RuntimeDefault`; profile needed | Profile needed | 5.15 kernel; likely unsupported *(unverified)* |
| `local` (kind) | Host-dependent | Blocked under `RuntimeDefault`; profile needed | To verify | Host-dependent |
| `existing` | Unknown | Blocked under `RuntimeDefault`; profile needed | Unknown | Unknown; detect only |

Layer 2 is the same on every provider, so most of the work is provider-neutral; only layer 1 (and layer 3 on AppArmor nodes) needs provider-specific changes.


**Why it can appear to work today.** No pack in `PACKS/` sets a seccomp profile, and neither does the bundled JupyterHub chart. A pod with no seccomp profile gets the kubelet's default, which is no filter at all (`Unconfined`) unless the kubelet's `seccompDefault` option is enabled. On AWS this is confirmed from source: the AL2023 kubelet configuration generated by nodeadm ([`amazon-eks-ami`](https://github.com/awslabs/amazon-eks-ami), `nodeadm/internal/kubelet/config.go`) does not set `seccompDefault`, containerd's `unset_seccomp_profile` is empty, and NIC's [`terraform-aws-eks-cluster`](https://github.com/nebari-dev/terraform-aws-eks-cluster) module (v0.7.0) adds no kubelet configuration. So on AWS, where layer 1 is also expected to pass, a user pod is predicted to run bubblewrap today in its reuse-`/proc` mode (not yet confirmed on a live cluster). This is not a foundation packs can rely on: it depends on running with no syscall filter, it stops working as soon as a pack follows Pod Security Standards `restricted` (which requires `RuntimeDefault` or `Localhost`) or the kubelet's `seccompDefault` is enabled, and ADR-0010's hardened mode is expected to forbid it.


## Decision Drivers

- **Build in steps.** Deliver something usable now, behind a contract that stronger options can be added to later without breaking packs that already rely on it.
- **Tool-neutral, but not tool-unqualified.** NIC provides cluster primitives, not a sandboxing tool. The interface names guarantees; each guarantee is qualified against at least one concrete, tested consumer configuration, and other tools are potential consumers until tested.
- **Provider-neutral.** Pack developers should not need to know which provider they are on. Capability flows through `InfraSettings`, with no provider-name switches outside `pkg/providers/cluster/` (see AGENTS.md).
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

The cluster advertises a **set of capabilities**, not a single level, because the options are not strictly ordered (a VM runtime is not a superset of in-pod namespaces). Capabilities name **guarantees, not mechanisms**.

| Capability | Guarantee | Qualified consumer | Phase |
|---|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; the observed ABI is reported) and with nested seccomp filters, including user-notification filters. | A Landlock ruleset that denies a filesystem write and, at ABI 4, restricts `connect` to one port; a nested seccomp user-notification filter | **1 (this ADR)** |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed. | One pinned bubblewrap version with a fixed, tested invocation (Delivery, Phase 2) | **2 (this ADR, gated)** |
| `pod-user-namespaces` | Pods may set `hostUsers: false`. Permission to unmask `/proc` is a separate question: Pod Security `restricted` rejects `procMount: Unmasked` even with `hostUsers: false` as of Kubernetes 1.36. | n/a | Later ADR |
| `user-space-kernel` | Workloads that request it run behind a user-space kernel that implements the Linux syscall interface. | n/a | Later ADR |
| `vm-boundary` | Workloads that request it run behind a hardware-virtualisation boundary with their own guest kernel. | n/a | Later ADR |
| `network-policy` | NetworkPolicies are enforced for ingress and egress. | n/a | Candidate only; owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) |

Tools that need more than the qualified configuration are **potential** consumers, not implied ones. Rootless container engines are the main example: normal multi-UID operation uses `newuidmap`/`newgidmap` and subordinate ID ranges, which a non-root pod with `allowPrivilegeEscalation: false` and no capabilities cannot use, and they may also need FUSE, storage drivers or cgroup delegation. Supporting them would be a separately qualified configuration.

Every capability is defined by the same items: **guarantee**, **qualified consumer**, **placement**, **cluster requirements** (node kernel or OS, boot-time node settings, Kubernetes or API-server features, all expressed through provider config), **provisioning** (what is installed, by whom, and when in the lifecycle), **verification**, and any **scale limits**. Later ADRs may add capabilities by defining these items. For capabilities backed by a `RuntimeClass`, placement uses the `RuntimeClass`'s own `scheduling` field (node selector and tolerations merged into pods by Kubernetes), so packs only set `runtimeClassName`; NIC does not duplicate that mechanism.

Composition rules and the privilege tiers available to later capabilities are in Appendix B.

### Three separate interfaces

Desired configuration, observed readiness and consumer integration are separate mechanisms.

**1. Desired configuration (before provisioning).** Provider config states what each node group should provide; `InfraSettings` reports that intent and stays a pure function of config, as today:

```yaml
node_groups:
  agents:
    sandbox:
      capabilities: [in-pod-namespaces]   # opt-in capabilities only
```

```go
type SandboxSettings struct {
    // Intended capabilities and their placement, computed from config.
    Capabilities map[string]SandboxPlacement
    AppArmor     bool // in-pod-namespaces node groups run AppArmor; decides which profiles are needed
}

type SandboxPlacement struct {
    NodeSelector     map[string]string
    Tolerations      []corev1.Toleration
    RuntimeClassName string // RuntimeClass-backed capabilities; placement then comes from the RuntimeClass
}
```

A top-level `sandbox.require` list in NIC config names capabilities the operator requires, optionally with a minimum (for example `{ capability: process-self-restriction, minLandlockABI: 4 }`); requested capabilities include those opted into on node groups.

Capability attributes are **guarantees over the advertised placement**, not per-cluster summaries. Where node groups differ (one at Landlock ABI 3, another at ABI 4), each distinct level gets its own placement: nodes carry an attribute label as well as the capability label (`sandbox.nebari.dev/landlock-abi: "4"`), and the advertised minimum for a placement is the lowest value over exactly the nodes that placement selects. A pack that needs ABI 4 selects the ABI 4 placement, so its pods cannot land on an ABI 3 node group.

**2. Observed readiness (after bootstrap).** NIC records what it actually verified, per capability and node group, in a read-only `nebari-sandbox-capabilities` ConfigMap in a NIC-owned namespace: verified or not, observed Landlock ABI, profile version, and when it was last verified, with an **expiry**: a record not refreshed by scheduled verification before it expires reads as unverified, so a stopped verifier cannot leave a stale success in place.

The record is **informational**: it is a snapshot that tells operators and packs what was observed, not an enforcement point. Updating it does not change Helm values a pack was installed with, does not move pods, and does not stop a running worker from accepting new commands. The enforcement contract is therefore: (a) each consumer fails closed when it establishes each sandbox, by checking the guarantee itself (for example applying its Landlock ruleset or creating its namespace and refusing to run if that fails), never by reading the record; and (b) for capabilities with a readiness barrier (Phase 2), a node that fails re-verification is **quarantined** by re-applying its unverified taint, so no new pods schedule there. Already-running tasks are left running by default and reported; eviction is an operator choice, not automatic.

**3. Consumer integration (packs).** Until pack codegen ([ADR-0003](0003-software-pack-codegen.md)) exists, packs are integrated **explicitly**: they take documented Helm values (`sandbox.capabilities.<name>.nodeSelector`, `.tolerations`, `.runtimeClassName`, the profile name and version, and the placement's guaranteed minimum Landlock ABI) set by the operator from the readiness record, and are responsible for refusing to start sandboxed work without an unsafe fallback. Declaring `requires: { sandbox: [...] }` in `nebari-integration.yaml`, with NIC refusing incompatible packs, is **future work** that depends on ADR-0003. A ConfigMap alone does not make Helm, ArgoCD or KubeSpawner consume settings or reject workloads.

### Lifecycle

Capabilities that need cluster components are installed in a **post-bootstrap phase**, not inside the provider's `Deploy()`:

1. Provider `Deploy()`: node groups, node images, node labels and taints, and any boot-time node settings.
2. Foundational services bootstrap (ArgoCD and the foundational applications).
3. **Wait for the dependencies to be ready** (for Phase 2, cert-manager).
4. Install the capability's components and its versioned profiles.
5. Verify (Verification below).
6. Publish the readiness record.

Today, conditional software ([ADR-0006](0006-conditional-foundational-software-helm.md)) is installed inside the provider's `Deploy()`, before ArgoCD and cert-manager exist, and foundational-service failures are reported as warnings rather than failing the deploy. This ADR therefore needs either a post-bootstrap lifecycle hook in `pkg/nic` or an amendment to ADR-0006. Independently of ADR-0010's fail-closed hardened mode, a capability in `sandbox.require` (or opted into on a node group) that fails steps 3-5 makes `nic deploy` exit non-zero.

### Delivery, Phase 1: `process-self-restriction`

1. **No opt-in, no relaxation, no components.** No profiles, no operator, no admission exception and no node preparation are needed. Steps 3-4 of the lifecycle are empty.
2. **Qualifying node images: passive by default.** NIC discovers and advertises the capability on node groups whose current images qualify; it does **not** change node images on its own, and explicit image pins are preserved. Moving a node group to a qualifying image is an explicit, operator-requested migration through the provider's own config, as for GPU images. NIC targets Landlock ABI 4 (for example Ubuntu 24.04's 6.8 kernel, or AL2023 on a 6.12 kernel); node groups that reach only ABI 3 still qualify, with their ABI reported. Azure needs a newer node OS image than Ubuntu 22.04. `local` and `existing` are detect-only. A node group that cannot qualify (for example a GPU image pinned to an older kernel) is not listed as providing the capability.
3. **Placement.** Qualifying node groups are labelled `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi`. No taint is needed: nothing on these nodes is relaxed.
4. **Verification.** On each node group, a non-root pod with every capability dropped and the default seccomp profile applies a Landlock ruleset and confirms a denied write fails, reports the highest ABI available and, at ABI 4, confirms a disallowed `connect` fails, and installs a nested seccomp user-notification filter whose supervisor injects a descriptor into the child with `SECCOMP_IOCTL_NOTIF_ADDFD` (with `SECCOMP_ADDFD_FLAG_SEND`), and the child then uses that descriptor. Each denial check has a positive control on the same node (the same write or `connect` succeeds without the ruleset), so an unrelated filesystem or network failure cannot pass as successful confinement.

### Delivery, Phase 2: `in-pod-namespaces`

Phase 2 ships only when all of its **release gates** are met:

- **Gate A, AppArmor mechanism.** The Security Profiles Operator (v1.1.1) can distribute seccomp profiles, but its `AppArmorProfile` API offers only abstract executable, filesystem, network, capability and ptrace rules: it cannot express a `userns` grant, scoped `mount` rules, or raw policy. Until a maintained mechanism can express the required AppArmor policy (upstream SPO support, or another maintained loader), Phase 2 is offered **only on node groups without AppArmor** (for example AWS AL2023). A NIC-owned privileged AppArmor loader would be substantial additional scope and needs its own decision.
- **Gate B, Hetzner autoscaling.** hetzner-k3s v2.4.6 applies per-pool pre-k3s commands to initially created workers, but its autoscaler cloud-init uses the global settings instead of pool overrides. Until that is fixed upstream (and NIC pins the fixed version) or another verified preparation mechanism exists, NIC rejects autoscaling on Hetzner pools that request `in-pod-namespaces`. The gate is closed only by testing a node the autoscaler created.
- **Gate C, versioned profiles.** The seccomp profile exists as a reviewed, immutable artifact (Profiles below), with adversarial tests passing.
- **Gate D, qualified consumer.** The pinned bubblewrap invocation passes the primitive tests, and one real pack passes the consumer acceptance test (Verification).

When the gates are met:

1. **Opt-in per node group** through the `sandbox` block above.
2. **Dedicated placement.** `in-pod-namespaces` node groups are **tainted by default** (`sandbox.nebari.dev/in-pod-namespaces=true:NoSchedule`), following the AWS GPU precedent, which taints GPU node groups rather than only labelling them. A taint is a placement control, not authorization, so admission restricts which namespaces may carry the matching toleration (Security considerations, item 2). Pods already running on a node group when it is converted are drained as part of the change. Without the taint and the admission rule, the ADR makes no claim that foundational workloads are kept off these nodes.
3. **Node preparation (layer 1)**, only where needed: on Hetzner, per-pool pre-k3s commands that lift Ubuntu's restriction (preferably a scoped AppArmor `userns` grant rather than the global sysctl) once Gate A allows AppArmor nodes; elsewhere, labels and taints only, unless verification shows otherwise. The kubelet runs with `seccompDefault: true` on these node groups (Security considerations, item 1).
4. **Readiness barrier.** New nodes in these node groups register with a startup taint, `sandbox.nebari.dev/in-pod-namespaces-unverified:NoSchedule`, which is removed only once the node has its profiles installed and passes the per-node probe. This covers autoscaled and replacement nodes, which a deploy-time probe does not. The barrier holds only with these invariants:
   - **Consumers tolerate the dedication taint, never the unverified taint.** Only trusted installer, probe and system workloads (the profile operator's daemon, the verifier) tolerate the unverified taint.
   - **Admission rejects wildcard tolerations** (an empty key with `operator: Exists`) and tolerations of the unverified taint from untrusted namespaces, and rejects untrusted direct node assignment (`spec.nodeName`) that bypasses the scheduler.
   - **Each supported autoscaler recognises the unverified taint as a startup taint.** A taint is not a startup taint just because of its name: Cluster Autoscaler only treats its own prefix, or keys passed with `--startup-taint`, that way, and otherwise a scale-from-zero node group can look permanently unsuitable for waiting pods. NIC's AWS autoscaler configuration sets no such flag today, so NIC must configure it, and scale-from-zero is tested per provider.
   - **The bootstrap components have capacity outside the gated pool,** so the verifier and profile installer can always run before any gated node is ready.
5. **Profiles.** NIC owns a complete seccomp policy, not a delta: a `Localhost` profile **replaces** `RuntimeDefault` rather than extending it, and the operator's base-profile mechanism references another stored profile, not the node runtime's generated default. NIC therefore maintains the full allowlist, per architecture, and tracks runtime default changes. The profile:
   - is immutable and **versioned in its name** (`nebari-sandbox-v1`, then `-v2`); a change is a new version, and pods opt into a version explicitly;
   - blocks netfilter configuration by filtering `socket()` on its arguments (netlink netfilter and raw packet sockets), together with the relevant legacy socket options, with stated assumptions about inherited descriptors and compatibility syscall ABIs;
   - is installed through the Security Profiles Operator, pinned by digest, with its daemon restricted to these node groups by node affinity and tolerations.

   Rollout semantics differ by mechanism and are documented: a new seccomp version affects only processes started with it, so old versions stay installed until every declared consumer has migrated or the operator explicitly retires the version. Current pod count is not a retirement signal: a Deployment scaled to zero, a CronJob or a KubeSpawner configuration can launch the old version later. Newly added nodes receive every still-supported version, not only the newest; AppArmor policy replacement can change already-running processes, so AppArmor profiles (once Gate A allows them) are never replaced in place.
6. **Qualified invocation.** The primitive is qualified with one pinned bubblewrap version and a fixed invocation of the form `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --ro-bind / / --ro-bind /proc /proc --dev /dev --tmpfs /tmp --die-with-parent --new-session -- <command>` (exact flags fixed in the implementation), with no pid namespace and no fresh procfs.

### Verification

- **Per node group, then per node.** Probes run on each node group that should provide a capability, placed with that capability's own selectors and tolerations. For Phase 2, the per-node probe also gates the readiness barrier.
- **Primitive tests, in both directions.** For `process-self-restriction`: Landlock and seccomp cases above. For `in-pod-namespaces`: the qualified invocation succeeds with the profile; a pod without the profile on the same node cannot create a user namespace; netfilter and raw-socket creation fail from inside a new user namespace.
- **Consumer acceptance test (Gate D).** Separately from the primitive, one real pack (the Pi pack is the first candidate) must show, with the capability in use:
  - credential canaries placed in the agent's environment, files and mounted secrets are not readable by sandboxed commands;
  - inherited file and socket descriptors are closed or explicitly allowed;
  - networking is denied (or limited to the intended proxy);
  - the pack's generated worker-pod settings carry the expected profile, selectors and tolerations;
  - when the capability is absent, the pack refuses sandboxed work rather than falling back to running unsandboxed.

  This matters because node support alone changes nothing in a pack that, for example, passes credentials in environment variables or launches browsers with `--no-sandbox`.
- **Scheduled re-verification.** Probes also run on a schedule, following the pattern proposed in [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683); the readiness record and its expiry are refreshed; a failing node is reported and, for Phase 2, quarantined (see Observed readiness).
- The NetworkPolicy enforcement check proposed in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) uses the same positive/negative pattern, and the two should share their harness.

### Security considerations

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`. Today, by contrast, pods without a seccomp profile run with no syscall filter at all (confirmed on AWS), and packs that want isolation reach for root, privileged pods or `Unconfined` profiles; a sanctioned, narrower path improves on that. `in-pod-namespaces` adds real risk, bounded only if:

1. **Seccomp is on by default on `in-pod-namespaces` nodes.** Once a node permits unprivileged user namespaces, any pod there without a seccomp filter can create them, not only pods that reference the profile. These node groups run the kubelet with `seccompDefault: true`.
2. **Admission controls who may use the profile and the nodes.** Only namespaces explicitly labelled for the capability may reference `nebari-sandbox-v*` profiles or tolerate the `in-pod-namespaces` dedication taint (never the unverified taint; see the readiness-barrier invariants): through the hardened-mode admission policy (#480) in hardened mode, and a ValidatingAdmissionPolicy shipped with the capability in standard mode.
3. **The profile operator's API is locked down.** Only NIC and cluster administrators may create or modify `SeccompProfile` or `AppArmorProfile` resources; the operator's images are pinned by digest.
4. **The netfilter block is concrete and tested** (Profiles, above).
5. **Kernels on `in-pod-namespaces` node groups are patched promptly**, on a defined cadence with a named owner.
6. **Readiness is re-verified** at node start (readiness barrier) and on a schedule.
7. **Pack-facing documentation states the threat model precisely.** Both capabilities are fences inside a trusted user's pod; they share the host kernel and are not protection against kernel exploits or hostile multi-tenant code. With the container's `/proc` reused, sandboxed commands can still see the command lines of other processes in the pod, which can contain credentials, and they inherit whatever environment and descriptors the launcher passes; a fresh user namespace does not by itself let them read another process's environment or follow its `/proc/<pid>/root`, since the kernel's ptrace access checks still apply.

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

## Related Work

**NetworkPolicy enforcement (platform).**

- [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) Enforce NetworkPolicy on every cluster provider (open). Records per-provider state: Azure's AKS module sets no `network_policy`; Hetzner's k3s should enforce but is untested; kind is unchecked; `existing` needs a documented requirement and a readiness check. Proposes a user-journey enforcement check.
- [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) Enforce NetworkPolicy on the VPC CNI addon, with an opt-in strict mode (open, blocked on the storage strategy in [#586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)). Includes trial results from a NIC-built EKS cluster, including the strict-mode requirement that every NIC namespace ships a NetworkPolicy.

**Multi-tenancy (the main driver of the above).**

- [#674](https://github.com/nebari-dev/nebari-infrastructure-core/pull/674) Multi-tenancy design doc (open; being split into a platform layer and a deployment-specific guide). Treats NetworkPolicy enforcement as precondition 1.
- [#676](https://github.com/nebari-dev/nebari-infrastructure-core/issues/676) Cluster preconditions for a tenant, and [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683) scheduled isolation checks. The scheduled-check idea applies equally to the sandbox probe.

**Packs already building isolation (rows 4 and 2-3 consumers).**

- [collab-hub-pack#167](https://github.com/nebari-dev/collab-hub-pack/issues/167) Plan hosted coding workspaces for Nebari and Collab Hub (planning). The closest match to the coding-agent use case that motivates this ADR.
- [collab-hub-pack#6](https://github.com/nebari-dev/collab-hub-pack/issues/6) Cog workers as separate pods with no ServiceAccount token, created only by a least-privilege controller (row 4). A separate-worker implementation exists; its egress and controller work remain unfinished, so it is a precedent rather than a finished reference.
- [collab-hub-pack#11](https://github.com/nebari-dev/collab-hub-pack/issues/11) Restrict worker egress to hub-mediated paths. Notes that a NetworkPolicy cannot allow a hostname, so model traffic goes through an in-cluster egress gateway; the same constraint applies to Landlock (row 2), which restricts by port, not host.
- [nebi#445](https://github.com/nebari-dev/nebi/issues/445) and [nebi#513](https://github.com/nebari-dev/nebi/issues/513) Untrusted environment builds run in a shared worker with database credentials; proposal to run each job in its own pod (row 4). Proposed, not yet implemented.
- [nebari-operator#197](https://github.com/nebari-dev/nebari-operator/issues/197) A shared NetworkPolicy helper for packs.

**Pack contract.**

- The [Nebari Pack Specification](https://github.com/nebari-dev/nebari-operator/blob/main/docs/pack-specification.md) (section 6, Security baseline) requires a hardened `securityContext` at GA and says packs SHOULD ship a NetworkPolicy. It says nothing about seccomp today. If it later requires `RuntimeDefault`, packs that currently run sandboxing tools with no syscall filter (see "Why it can appear to work today") stop working, so the `sandbox.*` contract here should be referenced from that section.

## Open Questions

- Which node images qualify for `process-self-restriction`: the kernel on each AL2023 EKS AMI release NIC would pin, the node OS images the AKS module can select, and whether Landlock is in the active security-module list on each?
- Gate A: upstream AppArmor support in the Security Profiles Operator, another maintained loader, or AppArmor nodes deferred indefinitely?
- Post-bootstrap lifecycle hook in `pkg/nic`, or an amendment to ADR-0006?
- Where the readiness barrier's taint removal runs (a small NIC-owned controller, or the probe DaemonSet itself), and what RBAC it needs to patch nodes.
- How does AppArmor apply to pods on kind nodes?
- Is per-node-group opt-in the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Do the k3s (hetzner-k3s) and AKS default kubelet configurations enable `seccompDefault`? (Not enabled on EKS; see Context.)
- Should NetworkPolicy enforcement be advertised through this contract (the `network-policy` candidate), or stay a platform guarantee that packs assume? To agree with the owners of [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691).
- Several sandbox systems depend on the Agent Sandbox controller and CRDs and leave installing them to the cluster administrator. Should NIC offer it as conditional foundational software?
- Should the Pack Specification's security baseline add a sandboxing section that points at this contract, and say anything about `seccompProfile` for pods that do not sandbox?
- Should `in-pod-namespaces` ever cover pods that run sandboxes for several users or sessions? With single-ID user namespaces every session maps to the pod's own host UID, so files are not separated between sessions; separating them needs a distinct real UID per session, which needs root and belongs inside a stronger boundary.
- Should capability names themselves be versioned (as the profiles now are), so a guarantee can be tightened without silently changing its meaning?
- Confirm every *(unverified)* entry in the provider tables by running the probes on each provider.

## Appendix A: Notes on the sandboxing spectrum

These points follow from the spectrum table in Context.

- **Several options need nothing from NIC** (rows 1, 1b, 4 in its basic form, and 8). This ADR is not a precondition for sandboxing in general; it addresses the band where pack developers are blocked by settings only the cluster can change. Row 2 needs no relaxation of pod security, but does depend on the node kernel, which only the cluster controls.
- **Row 1 can carry a whole agent platform, not just code snippets.** If agents write code for the runtime instead of running shell commands, and every external action goes through brokers, a language-runtime sandbox can host a full agent platform with the strongest credential posture of any row: no ambient network at all. The trade-off is giving up arbitrary binaries and shells (no `git`, `pip` or compilers), which rules it out for general coding agents.
- **Isolation strength is only part of the picture.** In every row, outbound network policy, which credentials are visible to the sandboxed code (service-account token, cloud IAM, Git tokens), resource limits and filesystem write access usually matter as much as the isolation tier. A VM with cloud credentials mounted is weaker in practice than a namespace sandbox without them.
- **Egress can be enforced in four ways, and all are legitimate.** *Cluster-enforced* egress (NetworkPolicy) cannot be changed by anything inside the pod, but matches only IP addresses and ports. *In-pod* egress enforcement (a proxy or a sidecar running a DNS filter and packet rules in the pod's network namespace) can allow domain names, which NetworkPolicy cannot. A *mediating proxy outside the workload* (an egress gateway, or a dedicated proxy pod per sandbox that performs policy checks and opens approved upstream connections) can also allow domain names and keep credentials out of the workload, with NetworkPolicy denying the workload every other route. Domain-based egress therefore needs the in-pod kind or a mediating proxy. For the pod-network proxy topology described here, NetworkPolicy enforced for both ingress and egress provides the required bypass prevention; without it, the workload can bypass the proxy. Topologies that reach the proxy through a namespace with no other route, or through IPC, prevent bypass by other means. An in-pod enforcer that programs packet rules needs `NET_ADMIN`, which Pod Security Baseline does not allow: on the default runtime it falls under the relaxed-workload terms in Appendix B, and the workload container itself must not hold it. Landlock network rules (ABI 4) give **TCP-port confinement** with no added privilege: the workload may not `bind`, and may `connect` only to listed ports. That is **not** proxy enforcement on its own: Landlock checks the port, not the destination address, so a workload allowed to reach a proxy on `127.0.0.1:8080` can also reach any remote host on port 8080; it does not restrict UDP; and already-connected inherited sockets stay usable. Making an in-pod proxy non-bypassable additionally needs destination and protocol enforcement (for example a network namespace with only a loopback route to the proxy, or qualified syscall mediation that enforces approved destinations, combined with protocol restrictions) and descriptor hygiene. A consumer qualified as proxy-enforcing must show that the proxy connection succeeds, the same port at another address fails, direct UDP fails, and unapproved inherited sockets are unavailable. Finally, *capability-scoped brokers* remove the network altogether: the workload has no outbound network, only typed calls to broker services that hold the credentials and scope each call to the resource the user granted. Row 1 runtimes make this easy, because they can be given no network at all, but it is not exclusive to them: a native workload can also run with no ambient network and reach a credential-holding broker only through tightly controlled pipes or other IPC. Credential posture is a property of configuration, not of the isolation tier.

- **NetworkPolicy enforcement is tracked separately and is not part of this ADR.** [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) makes enforcement a per-provider guarantee and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) covers the AWS VPC CNI. Row 4's network controls, and sandbox systems that place a mediating proxy on the pod network, depend on that work; rows 2 and 3 do not, so the two can proceed independently.


## Appendix B: Composition and privilege tiers for later capabilities

**Composition.** In-pod namespace tools can also run *inside* a `user-space-kernel` or `vm-boundary` workload, where they may obtain namespaces through privileges the outer boundary contains (root, `CAP_SYS_ADMIN`), with no node-level change. On the default runtime the only accepted route is the unprivileged one: `CAP_SYS_ADMIN` on a default-runtime pod is never an accepted way to obtain `in-pod-namespaces`. `process-self-restriction` is expected to combine with every capability, but inside a stronger runtime it depends on that runtime's kernel, not the node's. Every combination a pack relies on is probed before it is advertised; for example, NetworkPolicy enforcement is checked separately under each stronger runtime, and where a capability's workloads bypass the pod network entirely (for example VMs networked by a host-level process), NetworkPolicy does not apply and that capability's ADR must state how egress is enforced.

**Privilege tiers.** Later capabilities may need more privilege than these two. Each tier is admitted in hardened mode only on the stated terms, and each later capability's ADR must justify its tier against restricted-compatible alternatives, which exist for capable sandbox systems:

| Tier | Example | Terms |
|---|---|---|
| Restricted-compatible | `process-self-restriction` | Nothing needed |
| Capability node agents, non-privileged | Host-management agents that need specific capabilities or host paths but not `privileged: true` (for example a seccomp-only profile installer) | One general exception, pinned to a namespace and to the capability's node groups; enforceable Localhost profiles, never `Unconfined` |
| Capability node agents, privileged | Runtime installers and other agents that need `privileged: true` | Treated as **host-trusted** exceptions: for privileged containers, Kubernetes runs seccomp unconfined and ignores AppArmor profiles, so a Localhost profile field confines nothing. Pinned to a namespace, an image digest and the capability's node groups, and justified in the capability's ADR |
| Relaxed workload pods | Worker pods that run a user-space kernel or a VMM themselves, needing added capabilities and relaxed seccomp/AppArmor | Dedicated namespace, exact privileges, confined node groups, set by the capability's ADR; Localhost profiles rather than `Unconfined` |
| Node-owning systems | Engines that run privileged in host namespaces, mount the host filesystem, or run as root directly on the host | A dedicated, tainted node group treated as a separate trust zone: no other workloads, admission only there and in the system's namespace, no NIC node preparation for other capabilities |

Scale limits are part of a capability's definition: where a provider's system runs on a single node in its open-source form, the capability's ADR says so and packs must not assume horizontal scale.

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
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
