# Workload Sandboxing

## 20.1 Scope

This document holds the implementation design behind [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](../../adr/0021-gradual-workload-sandboxing-for-software-packs.md). The ADR records the decision: a tool-neutral contract on three axes (boundary level, in-pod capability, profile) with rules for later additions, delivering `process-self-restriction` behind a per-node-group kernel floor that `nic validate` and `nic deploy` check. This document records the detail that implements and justifies it: the sandboxing spectrum, provider findings, the full contract, delivery, evidence from probes of the higher levels, verification, security considerations and related work. Where the two disagree, the ADR is authoritative for the decision and this document is updated to match.

## 20.2 The sandboxing spectrum

| # | Option | Examples | What isolates the code | Cluster changes needed | Main limits | Place in this ADR |
|---|---|---|---|---|---|---|
| 1 | Language runtime | WASM (wasmtime, WASI), V8 isolates, Deno with permission flags, Pyodide, Monty (a Python-subset interpreter written in Rust, with no filesystem, environment or network inside the sandbox; the host exposes only the functions it chooses) | The runtime: code can only do what the runtime exposes | None | Runs only code built for that runtime, or a subset of a language (no C extensions or third-party native packages); no arbitrary binaries, shells, `pip install` or `git` | Packs can do this today |
| 1b | The user's own browser | JupyterLite, Pyodide or WebContainers on the client side | The browser sandbox, on the user's machine | None; the cluster is not involved | As row 1; nothing runs on the platform | Packs can do this today |
| 2 | Process self-restriction | Landlock plus seccomp filters, including seccomp user notification to mediate selected syscalls (the approach of several agent sandboxes on Linux) | The process drops its own filesystem (and, on newer kernels, TCP) rights and installs syscall filters before running a command | Node kernel only: Landlock ABI >= 3 enabled (ABI 4 for TCP rules); nothing else. Not every provider's default node image qualifies (see §20.4) | Covers filesystem access and syscall mediation; Landlock TCP rules need a newer kernel than filesystem rules; no process-visibility isolation on its own | **`process-self-restriction`, this ADR** |
| 3 | Namespace sandbox in the pod | bubblewrap, nsjail, minijail, rootless podman/buildah | Linux namespaces inside the pod, on the shared host kernel | Yes: node prep and security profiles (the four layers below) | Shares the host kernel; extra kernel attack surface from user namespaces | `in-pod-namespaces`, reserved for a later ADR |
| 3b | Headless browser in the pod | Chromium/Playwright running untrusted pages or scripts | Chromium's own sandbox, which also uses user namespaces | Same as row 3, otherwise it runs with `--no-sandbox` | As row 3 | Potential consumer of `in-pod-namespaces`; not qualified (Chromium's sandbox may need more than the guarantee, such as its own pid namespace) |
| 3c | System-container runtime | Sysbox, used to run `dockerd` or `systemd` inside a workspace | User namespaces plus virtualised `/proc` and `/sys`, on the shared host kernel | Yes: either a `RuntimeClass` installed on the nodes, or a privileged outer container that hosts an unprivileged inner one | Shares the host kernel; the privileged-outer-container variant is root on the node | Not delivered here. As a `RuntimeClass`, a possible later implementation; the privileged-outer-container variant is root on the node and would need its own trust model |
| 4 | Separate locked-down pod per task | A Job or Agent Sandbox `Sandbox` with the default runtime: no service-account token, NetworkPolicy, read-only root, optionally `hostUsers: false` | Standard container isolation, on the shared host kernel | Pod security settings: none. NetworkPolicy: only takes effect where the network plugin enforces it, which is not the case on AWS or Azure as NIC deploys them today (tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). `hostUsers: false` needs recent Kubernetes, containerd and kernel | Start-up latency; the pack needs RBAC to create pods; still a shared kernel | Basic form: packs can do this today. collab-hub-pack already runs workers as separate pods with no ServiceAccount token (egress restriction still in progress); Nebi has proposed the same for its builds (see Related work). Its network controls depend on #691/#675. With `hostUsers: false`: a possible later capability |
| 5 | User-space kernel | gVisor (`runsc`) | gVisor implements the Linux syscall interface itself; the workload never calls the host kernel directly | Yes: install the runtime and a `RuntimeClass` (built into some managed offerings, otherwise installed per provider) | I/O and syscall overhead; some applications are incompatible | An implementation of the reserved `mediated-kernel` level; later ADR |
| 6 | MicroVM per pod | Kata Containers, Firecracker, Cloud Hypervisor | Hardware virtualisation with a separate guest kernel | Yes: runtime install, and nodes that expose `/dev/kvm` (bare metal, or instance types with nested virtualisation) | More memory per pod, slower start; usually a dedicated KVM-capable node group | An implementation of the reserved `hardware-virtualised` level; later ADR |
| 7 | Dedicated node or cluster | Per-tenant node pools, a separate cluster, confidential VMs | A separate machine | Yes: provisioning | Cost | Out of scope |
| 8 | External sandbox service | Hosted code-execution services (several are Firecracker-based) | Someone else's infrastructure | None in the cluster; outbound network and credentials only | Data leaves the environment; vendor dependency | Packs can do this today |

Notes on egress, credentials and what each row needs from NIC are in §20.3.

## 20.3 Notes on the sandboxing spectrum

These points follow from the spectrum table in §20.2.

- **Several options need nothing from NIC** (rows 1, 1b, 4 in its basic form, and 8). This ADR is not a precondition for sandboxing in general; it addresses the band where pack developers are blocked by settings only the cluster can change. Row 2 needs no relaxation of pod security, but does depend on the node kernel, which only the cluster controls.
- **Row 1 can carry a whole agent platform, not just code snippets.** If agents write code for the runtime instead of running shell commands, and every external action goes through brokers, a language-runtime sandbox can host a full agent platform with the strongest credential posture of any row: no ambient network at all. The trade-off is giving up arbitrary binaries and shells (no `git`, `pip` or compilers), which rules it out for general coding agents.
- **Isolation strength is only part of the picture.** In every row, outbound network policy, which credentials are visible to the sandboxed code (service-account token, cloud IAM, Git tokens), resource limits (including process counts) and filesystem write access usually matter as much as the isolation tier, and so does observability: logging the process tree and network egress, so that misuse can be detected. Lifecycle is a separate dimension again (a fresh sandbox per run, a long-lived workspace, or snapshot and restore); it is outside the capability contract and is the pack's choice, with long-lived workspaces needing an explicit policy for secrets.
- **GPUs widen the attack surface.** Passing a GPU into a sandbox exposes large driver code paths through device interfaces, whatever the boundary. Where possible, keep general code execution in CPU-only sandboxes and reach model execution through a separate GPU service. A VM with cloud credentials mounted is weaker in practice than a namespace sandbox without them.
- **Egress can be enforced in four ways, and all are legitimate.** *Cluster-enforced* egress (NetworkPolicy) cannot be changed by anything inside the pod, but matches only IP addresses and ports. *In-pod* egress enforcement (a proxy or a sidecar running a DNS filter and packet rules in the pod's network namespace) can allow domain names, which NetworkPolicy cannot. A *mediating proxy outside the workload* (an egress gateway, or a dedicated proxy pod per sandbox that performs policy checks and opens approved upstream connections) can also allow domain names and keep credentials out of the workload, with NetworkPolicy denying the workload every other route. Domain-based egress therefore needs the in-pod kind or a mediating proxy. For the pod-network proxy topology described here, NetworkPolicy enforced for both ingress and egress provides the required bypass prevention; without it, the workload can bypass the proxy. Topologies that reach the proxy through a namespace with no other route, or through IPC, prevent bypass by other means. An in-pod enforcer that programs packet rules needs `NET_ADMIN`, which Pod Security Baseline does not allow: on the default runtime it needs an admission exception for that container alone, and the workload container itself must not hold it. Landlock network rules (ABI 4) give **TCP-port confinement** with no added privilege: the workload may not `bind`, and may `connect` only to listed ports. That is **not** proxy enforcement on its own: Landlock checks the port, not the destination address, so a workload allowed to reach a proxy on `127.0.0.1:8080` can also reach any remote host on port 8080; it does not restrict UDP; and already-connected inherited sockets stay usable. Making an in-pod proxy non-bypassable additionally needs destination and protocol enforcement (for example a network namespace with only a loopback route to the proxy, or qualified syscall mediation that enforces approved destinations, combined with protocol restrictions) and descriptor hygiene. A consumer qualified as proxy-enforcing must show that the proxy connection succeeds, the same port at another address fails, direct UDP fails, and unapproved inherited sockets are unavailable. Finally, *capability-scoped brokers* remove the network altogether: the workload has no outbound network, only typed calls to broker services that hold the credentials and scope each call to the resource the user granted. Row 1 runtimes make this easy, because they can be given no network at all, but it is not exclusive to them: a native workload can also run with no ambient network and reach a credential-holding broker only through tightly controlled pipes or other IPC. Credential posture is a property of configuration, not of the isolation tier.

- **NetworkPolicy enforcement is tracked separately and is not part of this ADR.** [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) makes enforcement a per-provider guarantee and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) covers the AWS VPC CNI. Row 4's network controls, and sandbox systems that place a mediating proxy on the pod network, depend on that work; rows 2 and 3 do not, so the two can proceed independently.

## 20.4 Why row 2 (process self-restriction) needs NIC

Row 2 needs nothing from the pod spec: it runs non-root, with every capability dropped and the runtime's default seccomp profile, so it is compatible with Pod Security `restricted`. What it needs is node kernel support, which packs cannot change:

- **Landlock** enabled in the kernel's active security modules, at a sufficient ABI version. ABI 3 (Linux 6.2) covers filesystem access including truncation; TCP bind/connect rules need ABI 4 (Linux 6.7). ABI 3 is the floor for the capability, but **ABI 4 is the target**: TCP-port confinement (restricting which ports a process may `bind` or `connect` to) is the main agent use case, and it needs ABI 4. Landlock checks ports, not destination addresses, and does not restrict UDP, so port confinement is not by itself proxy enforcement (§20.3). Distribution backports exist, so the version number alone does not decide it: the probe does.
- **Nested seccomp filters with user notification**, including the operations that let a supervising process inject descriptors into the workload, usable under the runtime's default seccomp profile. containerd's default profile allows the `seccomp` syscall, and, on kernels from 4.8, `ptrace` and `process_vm_readv`, which some mediators use to inspect the workload.

Where the providers' default node images stand, from AMI release notes and module source (checked 2026-10-14). Whether Landlock is in each kernel's active security-module list at boot (`/sys/kernel/security/lsm`) has been observed on Ubuntu 24.04's 6.8 kernel in a local probe (2026-10-17: `lockdown,capability,landlock,yama,apparmor`, ABI 4) and on an EKS 1.34 AL2023 node (2026-10-19: `lockdown,capability,landlock,yama,safesetid,selinux,bpf,ima`, ABI 6, where the full `process-self-restriction` probe passed under both `RuntimeDefault` and no profile); and on Hetzner nodes deployed with NIC (2026-10-25: kernel 6.8.0-138, `lockdown,capability,landlock,yama,apparmor`, ABI 4, full probe passed); it is still to be confirmed on AKS nodes:

| Provider | Default node kernel | Landlock ABI >= 3 |
|---|---|---|
| `aws` (AL2023 EKS AMI) | Set by Kubernetes version (amazon-eks-ami v20261012): 6.1 for 1.31–1.32, 6.12 for 1.33–1.35, 6.18 for 1.36–1.37. NIC's AWS example (1.34) gets 6.12 | Yes from Kubernetes 1.33 (6.12 provides ABI 6). AL2023 enabled `CONFIG_SECURITY_LANDLOCK` in its 6.1 and 6.12 kernels in release 2023.8.20250804; observed active at boot on kernel 6.12.111 (AMI release 2023.12.20261012) |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | 6.8 | Yes (ABI 4); observed active at boot on Hetzner nodes (6.8.0-138), full probe passed |
| `azure` (AKS) | NIC's AKS module (v0.2.0) sets no `os_sku`, so AKS defaults apply: Ubuntu 22.04 (5.15) below Kubernetes 1.35, and Ubuntu 24.04 (6.8) from 1.35, to which AKS migrates node pools automatically on upgrade. NIC's Azure example (1.34) gets 22.04 | No below 1.35. From 1.35 expected ABI 4, but **not yet probed**: until a maintainer runs the probe on AKS, the Azure provider reports the floor as unknown and only `nic deploy`'s kernel check judges AKS nodes. Selecting Ubuntu 24.04 earlier (`Ubuntu2404`, available from 1.32) or Azure Linux 3 needs an `os_sku` setting the module does not expose today |
| `local` (kind) | The host's kernel | Host-dependent |
| `existing` | Unknown | Detect only |

So nearly every default image on a supported Kubernetes version qualifies, and the NIC work for row 2 is promising a kernel floor per node group, backing it with a probe run on each node image family, and checking it in `nic validate` and `nic deploy`, not changing pod security or labelling nodes.

## 20.5 Why row 3 (in-pod namespaces) needs NIC

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
| `local` (kind) | Host-dependent | Blocked under `RuntimeDefault`; profile needed | kind runs its node containers with `apparmor=unconfined` and `seccomp=unconfined`; whether the containerd inside a node applies AppArmor to pods depends on the host (live test needed on Linux hosts with AppArmor; kind's known issues advise disabling interfering host profiles) | Host-dependent |
| `existing` | Unknown | Blocked under `RuntimeDefault`; profile needed | Unknown | Unknown; detect only |

Layer 2 is the same on every provider, so most of the work is provider-neutral; only layer 1 (and layer 3 on AppArmor nodes) needs provider-specific changes.


**Why it can appear to work today.** No pack in `PACKS/` sets a seccomp profile, and neither does the bundled JupyterHub chart. A pod with no seccomp profile gets the kubelet's default, which is no filter at all (`Unconfined`) unless the kubelet's `seccompDefault` option is enabled. On AWS this is confirmed from source: the AL2023 kubelet configuration generated by nodeadm ([`amazon-eks-ami`](https://github.com/awslabs/amazon-eks-ami), `nodeadm/internal/kubelet/config.go`) does not set `seccompDefault`, containerd's `unset_seccomp_profile` is empty, and NIC's [`terraform-aws-eks-cluster`](https://github.com/nebari-dev/terraform-aws-eks-cluster) module (v0.7.0) adds no kubelet configuration. So on AWS, where layer 1 is also expected to pass, a user pod is predicted to run bubblewrap today in its reuse-`/proc` mode (not yet confirmed on a live cluster). This is not a foundation packs can rely on: it depends on running with no syscall filter, it stops working as soon as a pack follows Pod Security Standards `restricted` (which requires `RuntimeDefault` or `Localhost`) or the kubelet's `seccompDefault` is enabled, and ADR-0010's hardened mode is expected to forbid it. The same default holds on the other providers (checked from source and docs): hetzner-k3s passes only `cloud-provider` and `resolv-conf` kubelet arguments, NIC adds none, and k3s does not enable `seccompDefault`; on AKS the default is `Unconfined`, `RuntimeDefault` is available only through a custom kubelet configuration (behind the `KubeletDefaultSeccompProfilePreview` feature flag at the time of writing), and NIC's AKS module sets no kubelet configuration.

## 20.6 The capability contract in full

In short, the contract is an interface to the **node execution environment**: NIC promises, by name and with verification, what the nodes' kernel, kubelet configuration, container runtime and security profiles will let a pod do. Packs still write their own pod settings and run their own sandboxing tools; networking (NetworkPolicy enforcement) and higher-level sandbox systems that build on these capabilities are outside it.

ADR-0021 states the contract on three independent axes: an ordered **boundary level** between pod and host, **in-pod capabilities** the workload uses inside its pod, and **profiles** of platform guarantees around the pod. In-pod capabilities are not ordered against levels (a VM is not a superset of in-pod namespaces), which is why they are a separate axis. All of them name **guarantees, not mechanisms**; how levels, implementations and properties fit together is in "Boundary levels, properties and the ordering rule" below.

| Capability | Guarantee | Qualified consumer | Status |
|---|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; the observed ABI is reported) and with nested seccomp filters, including user-notification filters. User notification is a mechanism for emulating syscalls or injecting descriptors, not a security-policy check on its own: a supervisor that inspects a syscall's arguments and then lets it continue can race with changes to that memory or filesystem state, as the Linux manual warns. | A Landlock ruleset that denies a filesystem write and, at ABI 4, restricts `connect` to one port; a nested seccomp user-notification filter | **Delivered (ADR-0021)** |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed. | One pinned bubblewrap version with a fixed, tested invocation | Reserved; needs its own ADR |

NetworkPolicy enforcement, which a profile such as "no network" would build on, is tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) rather than named here. Profiles themselves are reserved; none is named yet.

Every capability, implementation and profile is defined by the same items: **guarantee**, **qualified consumer**, **placement**, **cluster requirements** (node kernel or OS, boot-time node settings, Kubernetes or API-server features, all expressed through provider config), **provisioning** (what is installed, by whom, and when in the lifecycle), **verification**, any **scale limits**, and a **trust model**:

- which actors are trusted (the operator, NIC, the pack's own components, the provider's runtime);
- what a hostile workload may do (run as root inside, rewrite files it can reach, call any API it can reach);
- what NIC enforces, from outside the workload;
- what the pack must enforce itself;
- what is outside the guarantee.

Two distinctions apply to every trust model. **Declared settings are not enforcement:** a pod's `seccompProfile` is ignored by gVisor (without `--oci-seccomp`) and by Kata in the tested configuration, so a setting that satisfies Pod Security may confine nothing. **Smoke tests are not attestation:** a check pod that passes shows the path worked for that pod at that time; it does not prove what runs on a node, and a compromised node can pass it.

**Changing a capability's meaning.** A name's guarantee never changes silently. Tightening or loosening it needs a new or versioned name (`<name>-v2`), published alongside the old one, which keeps its meaning until retired; new evidence and newly qualified providers keep the name.

**Placement labels.** Labels that route pods are never writable by nodes. They use the `node-restriction.kubernetes.io/` prefix, which the NodeRestriction admission plugin stops kubelets setting or changing, including through `--node-labels` at registration (a kubelet given such a label refuses to start), so NIC or a cluster-side component applies them through the API after it has established that the node belongs where the label says. A node may set labels under `sandbox.nebari.dev/` about itself, but only to signal failure (for example `sandbox.nebari.dev/gvisor: failed`); nothing routes pods towards such a label. Without this rule, a compromised node, or a rogue one registered with a leaked join token, could label itself and attract every sandboxed pod. One consequence for later capabilities: autoscaler templates for scale-from-zero must carry a label the kubelet will never set (on AWS through the node group's autoscaler template tags), which each provider must qualify.

Tools that need more than the qualified configuration are **potential** consumers, not implied ones. Rootless container engines are the main example: normal multi-UID operation uses `newuidmap`/`newgidmap` and subordinate ID ranges, which a non-root pod with `allowPrivilegeEscalation: false` and no capabilities cannot use, and they may also need FUSE, storage drivers or cgroup delegation. Supporting them would be a separately qualified configuration.

For capabilities backed by a `RuntimeClass`, placement uses the `RuntimeClass`'s own `scheduling` field (node selector and tolerations merged into pods by Kubernetes), so packs only set `runtimeClassName`; NIC does not duplicate that mechanism.

### Boundary levels, properties and the ordering rule

ADR-0021 adopts this model as NIC's interface but builds only its first level, `shared-kernel`, with `process-self-restriction`. Later ADRs would add implementations and their properties.

**Levels.** Each level is defined by its promise:

| Level | Promise | Diagnostic check on a running pod (not attestation) | Example implementation |
|---|---|---|---|
| `shared-kernel` | Code runs on the host kernel; only in-pod capabilities fence it | Nothing beyond the in-pod capabilities required | The default runtime (runc) |
| `mediated-kernel` | Code never makes system calls directly to the host kernel | The kernel release seen inside the pod differs from the node's (`node.status.nodeInfo.kernelVersion`), plus evidence specific to the implementation | A user-space kernel (gVisor) |
| `hardware-virtualised` | A hardware virtualisation boundary separates code from the host | As above, plus evidence specific to the implementation that the pod runs in its guest. The CPU's hypervisor flag alone is not enough: EC2 nodes already show it, so a gVisor pod on EC2 would pass | A VM runtime (Kata) |

**Ordering rule (normative).** A stronger level satisfies the operator's isolation policy, but satisfies a workload's requirement only when every in-pod capability and property the workload needs also holds there. The order is a policy choice: the levels describe different interfaces between code and host, not points on one security scale. A user-space kernel exposes a small, filtered set of host system calls and implements Linux itself, with gaps; a VM exposes KVM and the VMM's virtual devices and runs a full guest kernel that must also be patched. Each moves the host's protection to different code, either can be weakened by configuration, and they expose different Linux behaviour, so packs are never promised that they run unchanged at a nominally stronger level. NIC ranks the hardware boundary higher because it contains even a compromised guest kernel, and says so where it publishes the order (Luis Cardoso, "Sandboxes for AI", 2026, makes the same point).

**Properties.** Each implementation carries a list of properties, each established by the probe on each qualified provider, architecture and node OS, and re-established on runtime upgrades. NIC publishes them with the implementation, so packs read what they depend on rather than infer it from the level; properties replace pairwise combination rules. Properties are qualified per implementation, so two implementations of one level (for example Kata installed by NIC on AWS and AKS Pod Sandboxing) are qualified separately and share nothing by default. Values observed so far, from test-only installs recorded in this document (ADR-0021 delivers neither runtime):

| Property | Default runtime | gVisor | Kata (QEMU, AWS) |
|---|---|---|---|
| `process-self-restriction` (Landlock inside) | Where the node kernel meets the floor | No (`ENOSYS`) | Yes (guest ABI 7) |
| `in-pod-namespaces` (bubblewrap's qualified configurations) | Observed only on AL2023 with no syscall filter (`seccompProfile` unset); not a supported setting | Yes (network namespace created first) | Not yet probed |
| Pod's `seccompProfile` applied | Yes | No (without `--oci-seccomp`) | No (in the tested configuration) |
| Root inside contained from the host kernel | No | Yes | Yes |
| Fresh `/proc` in a pid namespace | No | Yes | Not yet probed |
| inotify events for changes made by other pods | Yes | No (polling only) | Not yet probed |
| Usable memory under a limit | The limit | The limit plus the class overhead | Less than the limit (about 947 MiB at 1 GiB) |

**Precedents.** Managed platforms expose sandboxing in the same shape: GKE Sandbox enables gVisor per node pool and pods opt in with `runtimeClassName: gvisor`; AKS Pod Sandboxing does the same with Kata under its own class name; OpenShift admits workloads to security profiles through Security Context Constraints. Each names a capability or runtime, provides it on some nodes, and lets workloads request it; none orders them, which is what the levels add.

**Limits.** Portability costs features: code written against a level may assume only properties every implementation of that level has, or must name the ones it needs. Properties are qualified per release of each runtime and may change with it.

### What NIC publishes and checks

Two layers are kept separate so that neither is read as the other, and a third is added by later levels:

| Layer | Meaning | Where it lives |
|---|---|---|
| Declaration | What each node group provides, derived from config | `InfraSettings.Sandbox`, a pure function of config, shown by `nic outputs` |
| Observation | Which checks ran, their scope and their result | `nic deploy` results, shown by `nic outputs` |
| Runtime classes (later levels) | One `RuntimeClass` per implementation, labelled with its level | The cluster; none in ADR-0021 |

**Configuration.** The operator may state one requirement:

```yaml
sandbox:
  minLandlockABI: 4   # optional; nic validate and nic deploy fail if any node group falls below
```

Named requirement sets, one per kind of workload with its own level and capabilities, were considered and left out until a real need appears; they can be added alongside this setting later.

```go
// Parsed by pkg/config.
type SandboxConfig struct {
    MinLandlockABI int // optional; 0 means nothing is required
}

// Declaration: reported by each cluster provider in InfraSettings.Sandbox,
// computed from config only.
type SandboxSettings struct {
    NodeGroups map[string]NodeGroupSandbox // keyed by node group; one entry for existing and kind
}

type NodeGroupSandbox struct {
    LandlockABI int // from the group's node image; 0 when unknown
}

// Observation: one entry per check NIC ran.
type CheckResult struct {
    Check     string // for example "landlock-kernel-version"
    NodeGroup string
    Node      string
    Time      time.Time
    Result    string // "pass", "fail", "warning" or "not-run"
    Detail    string
}
```

**Runtime classes for later levels.** A later level is published as one `RuntimeClass` per implementation, named after it (`nebari-gvisor`, `nebari-kata`) and labelled `sandbox.nebari.dev/level: <level>`. Level-named aliases (a class named after a level, pointing at whichever implementation was chosen) were rejected: `RuntimeClass.handler` is immutable, so such a class cannot be moved from `runsc` to `kata` without deleting it, which breaks admission for replacement pods that still name it; one class per level cannot serve two workloads that need different properties at the same level; and the ecosystem names runtimes directly (GKE's `gvisor`, AKS Pod Sandboxing's own class, Agent Sandbox's `SandboxTemplate`s), so an alias would be one more name to translate. Packs and tools select a class by its level label and the properties NIC publishes for it, and never hardcode `nebari-gvisor` or any other implementation name. "At least" is enforced by validation and, where a profile requires a level, by admission that accepts only pods whose class carries a qualifying level label.

**Observation.** For `process-self-restriction` the only observation is `nic deploy`'s kernel check (§20.8), recorded per node with the time it ran and shown by `nic outputs`; NIC writes no in-cluster record. It is a diagnostic inference, not enforcement or attestation. Observation is also how NIC checks runtimes it does not install, such as a provider-managed runtime or an operator's `RuntimeClass` on `existing` clusters: NIC reports what it saw without implying it controls the runtime's installation or version.

The enforcement contract is therefore: each consumer fails closed when it establishes each sandbox, by checking the guarantee itself (for example applying its Landlock ruleset or creating its namespace and refusing to run if that fails), never by reading NIC's results. An in-cluster readiness record with expiry, scheduled re-verification and quarantine of failing nodes was designed for capabilities with installed components; it is deferred, and any capability that wants it must justify it in its own ADR.

**Consumer integration.** Until pack codegen ([ADR-0003](../../adr/0003-software-pack-codegen.md)) exists, packs are integrated **explicitly**: the operator passes the requirement to the pack through its documented Helm values (for `process-self-restriction`, the minimum Landlock ABI; for a later level, the `runtimeClassName` and any settings NIC publishes with it), and the pack refuses to start sandboxed work rather than fall back. `process-self-restriction` needs no placement values: packs schedule normally and check the Landlock ABI at startup. Declaring `requires: { sandbox: [...] }` in `nebari-integration.yaml`, with NIC refusing incompatible packs, is **future work** that depends on ADR-0003.

### Evidence from the higher levels

Before the contract was fixed, the higher levels were exercised on clusters deployed with NIC, using test-only installers that ADR-0021 does not adopt. Each row names what it informed.

| Run | Result | Informed |
|---|---|---|
| gVisor `release-20261012.0` behind a `RuntimeClass` on EKS 1.34 AL2023, x86 (2026-10-19, 2026-10-27) and arm64 (2026-10-27) | Non-root and root pods ran; Landlock returned `ENOSYS`; the pod's `RuntimeDefault` was ignored (`Seccomp: 0`) | The ordering rule; rule (e); properties published per implementation |
| gVisor on Hetzner k3s, Ubuntu 24.04 (2026-10-25, 2026-10-27) | As on EKS; k3s enforced NetworkPolicy for gVisor pods as for runc pods | As above |
| gVisor with home directories on NIC's `efs-sc` (EKS, 2026-10-19) | Not writable: each EFS access point owns its directory as its own UID with mode 700, and gVisor checks permissions itself; access points using the pod's UID and GID worked under both runtimes | Rule (b): qualification covers storage |
| A deliberately failed gVisor install (EKS and Hetzner, 2026-10-25) | Pods sent to the node stayed in `ContainerCreating` rather than run unsandboxed, but `status.runtimeHandlers` still listed `runsc` | Rule (a); `runtimeHandlers` is not evidence of a working runtime |
| Kata 4.2.0 (QEMU) on EKS 1.34 through EC2 nested virtualisation, `m8i-flex.large` (2026-10-27) | ADR-0021's probe passed inside the guest at Landlock ABI 7; the guest reported `seccomp_mode` 0, so the declared `RuntimeDefault` was not applied | Rule (e); in-pod capabilities differ between implementations of the higher levels |
| Bubblewrap in a non-root pod on EKS 1.34 AL2023 (2026-10-19), and on Hetzner (2026-10-25) | On EKS it worked only with `seccompProfile` unset (the EKS kubelet default) and failed under `RuntimeDefault`; on Hetzner AppArmor blocked it | `in-pod-namespaces` stays reserved: there is no supported route on the host kernel |
| Node self-labelling on EKS 1.34 (2026-10-26) | With only its own credentials, a node rewrote its own node-group label, and the change survived a kubelet restart; it could not change taints or set labels under `node-restriction.kubernetes.io/` | Rule (c) |
| NetworkPolicy on EKS 1.34 (2026-10-19, 2026-10-27) | Not enforced in NIC's EKS clusters by default; once enabled in the VPC CNI, default deny held against root under gVisor and Kata, except towards the pod's own node | Profiles left out until [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) |

## 20.7 Lifecycle

*`process-self-restriction` installs nothing and does not use this phase (ADR-0021); it applies to capabilities with cluster components.* Capabilities that need cluster components are installed in a **post-bootstrap phase**, not inside the provider's `Deploy()`:

1. Provider `Deploy()`: node groups, node images, node labels and taints, and any boot-time node settings.
2. Foundational services bootstrap (ArgoCD and the foundational applications).
3. **Wait for the dependencies to be ready** (for example cert-manager).
4. Install the capability's components and its versioned profiles.
5. Verify (§20.9).
6. Publish the runtime classes, the capabilities and the check results.

Today, conditional software ([ADR-0006](../../adr/0006-conditional-foundational-software-helm.md)) is installed inside the provider's `Deploy()`, before ArgoCD and cert-manager exist, and foundational-service failures are reported as warnings rather than failing the deploy. A capability with components therefore needs either a post-bootstrap lifecycle hook in `pkg/nic` or an amendment to ADR-0006. Independently of ADR-0010's fail-closed hardened mode, a capability the operator requires (or opts into on a node group) that fails steps 3-5 makes `nic deploy` exit non-zero.

## 20.8 Delivery: `process-self-restriction`

1. **No opt-in, no relaxation, no components.** No profiles, no operator, no admission exception and no node preparation are needed. Steps 3-4 of the lifecycle are empty.
2. **Support policy and floor.** On supported Kubernetes versions, every node group NIC provisions from a provider's default image provides the capability at Landlock ABI 3 or newer; NIC targets ABI 4 (for example Ubuntu 24.04's 6.8 kernel, or AL2023 on 6.12). Each provider reports the floor of each node group in `InfraSettings.Sandbox.NodeGroups[<group>].LandlockABI` as a function of config, from §20.4: AWS ABI 6 from Kubernetes 1.33 and ABI 2 below; Hetzner ABI 4; Azure ABI 1 below 1.35 and, from 1.35, unknown until a maintainer has probed AKS (Ubuntu 24.04 is expected to give ABI 4; earlier versions could qualify if NIC's AKS module exposed `os_sku`). A node group pinned to an image the provider cannot vouch for (for example a GPU image on an older kernel), `existing` and kind report 0 (unknown). NIC does **not** change node images on its own, and explicit image pins are preserved; moving to a qualifying image is an operator change through the provider's own config, as for GPU images.
3. **`nic validate`.** If the operator sets `sandbox.minLandlockABI`, NIC compares it with the floor of every node group, offline, since the capability has no placement and pods may land on any group. A known floor below the requirement is an error naming the group; an unknown floor is reported and left to `nic deploy`. Without the setting nothing is reported. No labels are set, so NIC's Hetzner provider needs no node-pool label support for this capability.
4. **`nic deploy` kernel check.** Once nodes are up, NIC reads each node's `node.status.nodeInfo.kernelVersion` and converts it to the Landlock ABI that kernel version introduced upstream (5.13 ABI 1, 5.19 ABI 2, 6.2 ABI 3, 6.7 ABI 4, 6.10 ABI 5, 6.12 ABI 6). A node below `minLandlockABI` fails the deploy; a node below ABI 3 when nothing is required is a warning. Results per node group and node, with the time of the check, are shown by `nic outputs`, which already reads the live cluster. It installs nothing and adds no CLI command. It is a diagnostic inference, not enforcement or attestation: a kernel version does not show Landlock enabled at boot or account for distribution backports, and nodes added after the deploy (autoscaling, replacement) are not checked, which is why consumers check the guarantee themselves. For `existing` clusters and kind (whose kernel is the host's) NIC does not choose the node image, so the floor is unknown and this check is the only judgement: it still fails a deploy whose requirement the nodes' kernels cannot meet.
5. **Probe: maintainers' release testing; automating it is an open question in ADR-0021.** The probe is the evidence behind each provider's floor. A maintainer runs it on a fresh node of each supported image family before NIC promises the floor there, and again when a provider changes kernel line for a supported Kubernetes version; it is not run on users' clusters. A non-root pod with every capability dropped and the default seccomp profile applies a Landlock ruleset and confirms a denied write fails, reports the highest ABI available and, at ABI 4, confirms a disallowed `connect` fails, and installs a nested seccomp user-notification filter whose supervisor injects a descriptor into the child with `SECCOMP_IOCTL_NOTIF_ADDFD` (with `SECCOMP_ADDFD_FLAG_SEND`), and the child then uses that descriptor. Each denial check has a positive control on the same node (the same write or `connect` succeeds without the ruleset), so an unrelated filesystem or network failure cannot pass as successful confinement. The run also records `/sys/kernel/security/lsm`, so a family whose kernel has Landlock compiled in but not enabled at boot is caught. In-cluster scheduled re-verification applies only to capabilities with installed components.
6. **Documentation.** A pack-developer page (declare the requirement, check the Landlock ABI at startup, refuse sandboxed work rather than fall back) and an operator page (the support policy, qualifying provider and version combinations, and what the `nic validate` and `nic deploy` messages mean).

## 20.9 Verification

- **Per node group, then per node.** For `process-self-restriction`, NIC checks each node's kernel version against the requirement during `nic deploy`, and the probe runs only in maintainers' release testing unless automating it is adopted (§20.8). Where probes are used, they run on each node group that should provide a capability, placed with that capability's own selectors and tolerations.
- **Primitive tests, in both directions.** For `process-self-restriction`: the Landlock and seccomp cases in §20.8, each denial with a positive control. A later capability states its own, including a negative case on the same node.
- **Consumer acceptance test (later capabilities).** Separately from the primitive, before a later capability is promised, one real pack must show, with the capability in use:
  - credential canaries placed in the agent's environment, files and mounted secrets are not readable by sandboxed commands;
  - inherited file and socket descriptors are closed or explicitly allowed;
  - networking is denied (or limited to the intended proxy);
  - the pack's generated worker-pod settings carry the expected profile, selectors and tolerations;
  - when the capability is absent, the pack refuses sandboxed work rather than falling back to running unsandboxed.

  This matters because node support alone changes nothing in a pack that, for example, passes credentials in environment variables or launches browsers with `--no-sandbox`.
- **Scheduled re-verification (later capabilities with components).** Probes also run on a schedule, following the pattern proposed in [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683); a failing node is reported (the readiness record and quarantine in §20.6 are deferred).
- The NetworkPolicy enforcement check proposed in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) uses the same positive/negative pattern, and the two should share their harness.

## 20.10 Security considerations

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`. Today, by contrast, pods without a seccomp profile run with no syscall filter at all (confirmed on AWS), and packs that want isolation reach for root, privileged pods or `Unconfined` profiles; a sanctioned, narrower path improves on that.

Pack-facing documentation states the threat model precisely. `process-self-restriction` shares the host kernel and is not protection against kernel exploits or hostile multi-tenant code. Code an agent executes should be classified by what an adversary can influence (prompt injection, compromised dependencies), not by who owns the pod: a single-tenant deployment does not make that code trusted. The capability is appropriate where a kernel exploit from that code is an acceptable risk; where it is not, a higher boundary level is needed. Packs using seccomp user notification must not rely on a check-then-continue supervisor as their policy mechanism.

A later `in-pod-namespaces` capability on the host kernel would add real risk, since permitting unprivileged user namespaces on a node widens its kernel attack surface for every pod there. Its ADR would have to bound that risk, for example with seccomp on by default on its nodes, admission controlling which namespaces may use its profile and nodes, a tested block on netfilter configuration from inside a new user namespace, prompt kernel patching and re-verification of each node.

## 20.11 Related work

**NetworkPolicy enforcement (platform).**

- [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) Enforce NetworkPolicy on every cluster provider (open). Records per-provider state: Azure's AKS module sets no `network_policy`; Hetzner's k3s should enforce but is untested; kind is unchecked; `existing` needs a documented requirement and a readiness check. Proposes a user-journey enforcement check.
- [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) Enforce NetworkPolicy on the VPC CNI addon, with an opt-in strict mode (open, blocked on the storage strategy in [#586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)). Includes trial results from a NIC-built EKS cluster, including the strict-mode requirement that every NIC namespace ships a NetworkPolicy.

**Multi-tenancy (the main driver of the above).**

- [#674](https://github.com/nebari-dev/nebari-infrastructure-core/pull/674) Multi-tenancy design doc (open; being split into a platform layer and a deployment-specific guide). Treats NetworkPolicy enforcement as precondition 1.
- [#676](https://github.com/nebari-dev/nebari-infrastructure-core/issues/676) Cluster preconditions for a tenant, and [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683) scheduled isolation checks. The scheduled-check idea applies equally to the sandbox probe.

**Packs already building isolation (rows 4 and 2-3 consumers).**

- [collab-hub-pack#167](https://github.com/nebari-dev/collab-hub-pack/issues/167) Plan hosted coding workspaces for Nebari and Collab Hub (planning). The closest match to the coding-agent use case that motivates this ADR.
- [collab-hub-pack#6](https://github.com/nebari-dev/collab-hub-pack/issues/6) Workers as separate pods with no ServiceAccount token, created only by a least-privilege controller (row 4). A separate-worker implementation exists; its egress and controller work remain unfinished, so it is a precedent rather than a finished reference.
- [collab-hub-pack#11](https://github.com/nebari-dev/collab-hub-pack/issues/11) Restrict worker egress to hub-mediated paths. Notes that a NetworkPolicy cannot allow a hostname, so model traffic goes through an in-cluster egress gateway; the same constraint applies to Landlock (row 2), which restricts by port, not host.
- [nebi#445](https://github.com/nebari-dev/nebi/issues/445) and [nebi#513](https://github.com/nebari-dev/nebi/issues/513) Untrusted environment builds run in a shared worker with database credentials; proposal to run each job in its own pod (row 4). Proposed, not yet implemented.
- [nebari-operator#197](https://github.com/nebari-dev/nebari-operator/issues/197) A shared NetworkPolicy helper for packs.

**Pack contract.**

- The [Nebari Pack Specification](https://github.com/nebari-dev/nebari-operator/blob/main/docs/pack-specification.md) (section 6, Security baseline) requires a hardened `securityContext` at GA and says packs SHOULD ship a NetworkPolicy. It says nothing about seccomp today. If it later requires `RuntimeDefault`, packs that currently run sandboxing tools with no syscall filter (see "Why it can appear to work today") stop working, so the `sandbox.*` contract here should be referenced from that section.

## 20.12 Alternatives considered in detail

ADR-0021 summarises Options 4, 5 and 7; their full assessment is recorded here.

### Option 4: Stronger-isolation runtime only (gVisor or Kata)

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

- **Pros:** much stronger boundary; a kernel exploit in the workload does not directly yield the node.
- **Cons:** provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps.

Kept as implementations of the `mediated-kernel` and `hardware-virtualised` levels (§20.6).

### Option 5: Adopt a full sandbox platform (e.g. Agent Substrate)

Install a complete agent-sandbox platform as NIC's sandboxing answer and have packs run untrusted work on it. Agent Substrate is the leading example (v0.6.0, released 2026-10-22; pre-1.0 with no compatibility guarantees; documented for GKE and kind only): a control plane that runs up to 1,000 "actors" in each worker pod, isolates each under gVisor or a Kata guest on Cloud Hypervisor that the worker downloads, verifies and starts itself rather than through a `RuntimeClass`, suspends and resumes them from snapshots in object storage, and brokers egress with credential injection through a shared gateway.

- **Pros:** a much stronger boundary than rows 2 and 3, appropriate for attacker-influenced or multi-tenant code; egress policy, credential injection, suspend/resume and density come built in rather than being assembled by each pack; an ecosystem is forming around it.
- **Cons:**
  - A different isolation unit: many actors share a worker pod, so NIC's pod-level guarantees (network policy, admission) cannot separate actors; that is the platform's job, and its isolation between actors on one node is still a roadmap item. (The earlier objection that it replaces the pod model no longer separates it from NIC's own direction, which also runs untrusted work in separate sandbox pods.)
  - Cannot run on NIC's providers today: Agent Substrate needs Kubernetes 1.36 or later with beta pod-certificate APIs (`PodCertificateRequest`, `ClusterTrustBundle`) that managed services do not let you enable (realistically 1.37), enforced NetworkPolicy ([#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) is blocked), changes to GKE-specific node paths, and KVM-capable nodes for its microVM class (not Hetzner Cloud; its gVisor class needs none).
  - A weaker pod-level posture: its worker pods are no longer `privileged`, but run as root with 13 added capabilities (including `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`), seccomp and AppArmor unconfined, and `/dev/kvm` and `/dev/net/tun` for microVMs; its node agent mounts host paths. ADR-0010's hardened mode would have to admit that by exception, whereas `process-self-restriction` runs under Pod Security `restricted`.
  - A large operational footprint: API server, controller, router, egress gateway, node agent, an identity (OIDC) server, a pod-certificate signer, embedded OpenFGA, PostgreSQL and object storage.

Not chosen as the starting point. Because actors are not pods with published settings and the platform runs its own runtime binaries, it cannot provide a level through NIC's runtime classes; where it can run, it is separately trusted infrastructure on dedicated node groups, close to host root, not an implementation of a level. If packs converge on such a platform, the future `in-pod-namespaces` work can be deprioritised; `process-self-restriction` remains useful either way.

### Option 6: Node Feature Discovery

Node Feature Discovery, a Kubernetes SIG project, runs a DaemonSet that reads each node's kernel version and configuration, and a controller that turns those facts into node labels through `NodeFeatureRule` resources. It would label nodes automatically, including images NIC does not know, `existing` clusters and kind. It was discarded because it adds a DaemonSet, a controller with permission to patch nodes, and CRDs for something NIC can do with a version comparison: the node images NIC provisions are known in advance and change rarely. Like the kernel check, it reads kernel configuration rather than confirming Landlock is active at boot. It remains an option if clusters NIC does not provision become important.

### Option 7: Node-group labels from an image table

An earlier draft of ADR-0021 advertised `process-self-restriction` per node group rather than through a provider-wide floor:

1. **Image table.** NIC kept a table mapping each node image it provisions to the Landlock ABI it provides. An image entered the table only after a manual probe run on it confirmed the capability under the exact pod settings; images not in the table were not advertised.
2. **Placement at node-group creation.** The provider predicted the capability from the node group's image when creating the group, reported it in `InfraSettings.Sandbox`, and applied `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi` as node-group labels (the same mechanism as GPU groups), so replacement and autoscaled nodes carried them from the start. Where node groups differed in ABI, each level got its own placement, and packs that needed ABI 4 selected it. NIC's Hetzner provider needed node-pool label support added. For `existing` and kind clusters NIC labelled nothing; operators could label nodes themselves at their own risk.
3. **Consistency check and readiness record.** During `nic deploy`, NIC compared each node's kernel version and OS image (`node.status.nodeInfo`) with its group's prediction and recorded mismatches (for example a manually upgraded node) in a read-only readiness record shown by `nic outputs`, reporting but not relabelling.

- **Pros:** steers pods away from non-qualifying node groups in mixed clusters; per-placement ABI guarantees.
- **Cons:** nearly every image NIC provisions on supported versions qualifies, so the steering rarely matters; a table to keep current, label plumbing in every provider and a readiness record for that small benefit.

It can be added later, without changing the capability's name or guarantee, if mixed clusters become common.

## 20.13 Links

- [ADR-0003: Software Pack Codegen](../../adr/0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](../../adr/0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](../../adr/0010-high-security-mode.md)
- [ADR-0017: User Journey Tests](../../adr/0017-user-journey-tests-for-foundational-software.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
