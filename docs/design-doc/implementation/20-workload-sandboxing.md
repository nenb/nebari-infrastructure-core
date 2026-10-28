# Workload Sandboxing

## 20.1 Scope

This document holds the implementation design behind [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](../../adr/0021-gradual-workload-sandboxing-for-software-packs.md). The ADR records the decision: a tool-neutral contract on three axes (boundary level, in-pod capability, profile), a published mapping of concrete values packs copy, and rules for later additions, delivering a qualified description of `process-self-restriction` (Landlock on the default runtime) with a read-only diagnostic report. This document records the detail that implements and justifies it: the sandboxing spectrum, provider findings, the full contract, delivery, evidence from probes of the higher levels, verification, security considerations and related work. Where the two disagree, the ADR is authoritative for the decision and this document is updated to match.

It also holds detail for the exploratory ADRs built on that contract (ADR-0022 onwards). They are sketches, not decisions, and propose entries for ADR-0021's published mapping and other additions it does not adopt; the sections that belong to them (§20.9, §20.12, §20.14, §20.15, "Proposed additions: more mapping entries (sketches)" in §20.6, and subsections named after an ADR) say so.

## 20.2 The sandboxing spectrum

| # | Option | Examples | What isolates the code | Cluster changes needed | Main limits | Place in this ADR |
|---|---|---|---|---|---|---|
| 1 | Language runtime | WASM (wasmtime, WASI), V8 isolates, Deno with permission flags, Pyodide, Monty (a Python-subset interpreter written in Rust, with no filesystem, environment or network inside the sandbox; the host exposes only the functions it chooses) | The runtime: code can only do what the runtime exposes | None | Runs only code built for that runtime, or a subset of a language (no C extensions or third-party native packages); no arbitrary binaries, shells, `pip install` or `git` | Packs can do this today |
| 1b | The user's own browser | JupyterLite, Pyodide or WebContainers on the client side | The browser sandbox, on the user's machine | None; the cluster is not involved | As row 1; nothing runs on the platform | Packs can do this today |
| 2 | Process self-restriction | Landlock, optionally with seccomp filters, including seccomp user notification to mediate selected syscalls (the approach of several agent sandboxes on Linux) | The process drops its own filesystem (and, on newer kernels, TCP) rights and installs syscall filters before running a command | Node kernel only: Landlock ABI >= 3 enabled (ABI 4 for TCP rules); nothing else. Not every provider's default node image qualifies (see §20.4) | Covers filesystem access; Landlock TCP rules need a newer kernel than filesystem rules; no process-visibility isolation on its own | **`process-self-restriction` (Landlock), described by this ADR**; `seccomp-user-notification` reserved |
| 3 | Namespace sandbox in the pod | bubblewrap, nsjail, minijail, rootless podman/buildah | Linux namespaces inside the pod, on the shared host kernel | Yes: node prep and security profiles (the four layers below) | Shares the host kernel; extra kernel attack surface from user namespaces | `in-pod-namespaces`, reserved for a later ADR |
| 3b | Headless browser in the pod | Chromium/Playwright running untrusted pages or scripts | Chromium's own sandbox, which also uses user namespaces | Same as row 3, otherwise it runs with `--no-sandbox` | As row 3 | Potential consumer of `in-pod-namespaces`; not qualified (Chromium's sandbox may need more than the guarantee, such as its own pid namespace) |
| 3c | System-container runtime | Sysbox, used to run `dockerd` or `systemd` inside a workspace | User namespaces plus virtualised `/proc` and `/sys`, on the shared host kernel | Yes: either a `RuntimeClass` installed on the nodes, or a privileged outer container that hosts an unprivileged inner one | Shares the host kernel; the privileged-outer-container variant is root on the node | Not delivered here. As a `RuntimeClass`, a possible later implementation; the privileged-outer-container variant is root on the node and would need its own trust model |
| 4 | Separate locked-down pod per task | A Job or Agent Sandbox `Sandbox` with the default runtime: no service-account token, NetworkPolicy, read-only root, optionally `hostUsers: false` | Standard container isolation, on the shared host kernel | Pod security settings: none. NetworkPolicy: only takes effect where the network plugin enforces it, which is not the case on AWS or Azure as NIC deploys them today (tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). `hostUsers: false` needs recent Kubernetes, containerd and kernel | Start-up latency; the pack needs RBAC to create pods; still a shared kernel | Basic form: packs can do this today. At least one Nebari pack already runs workers as separate pods with no ServiceAccount token (egress restriction still in progress); Nebi has proposed the same for its builds (see Related work). Its network controls depend on #691/#675. With `hostUsers: false`: a possible later capability |
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
- For the separate, reserved `seccomp-user-notification` capability: **nested seccomp filters with user notification**, including the operations that let a supervising process inject descriptors into the workload, usable under the runtime's default seccomp profile. containerd's default profile allows the `seccomp` syscall, and, on kernels from 4.8, `ptrace` and `process_vm_readv`, which some mediators use to inspect the workload. Because a runtime's default profile can change independently of the kernel, this is probed and reported separately.

Where the providers' default node images stand, from AMI release notes and module source (checked 2026-10-14). Whether Landlock is in each kernel's active security-module list at boot (`/sys/kernel/security/lsm`) has been observed on Ubuntu 24.04's 6.8 kernel in a local probe (2026-10-17: `lockdown,capability,landlock,yama,apparmor`, ABI 4) and on an EKS 1.34 `AL2023_x86_64_STANDARD` node, x86_64 (2026-10-19: `lockdown,capability,landlock,yama,safesetid,selinux,bpf,ima`, ABI 6, where the full probe passed under both `RuntimeDefault` and no profile); and on Hetzner Ubuntu 24.04 nodes, x86_64, deployed with NIC (2026-10-25: kernel 6.8.0-138, `lockdown,capability,landlock,yama,apparmor`, ABI 4, full probe passed). It is still to be confirmed on AKS nodes and on every arm64 image:

| Provider | Default node kernel | Landlock ABI >= 3 |
|---|---|---|
| `aws` (AL2023 EKS AMI) | Set by Kubernetes version (amazon-eks-ami v20261012): 6.1 for 1.31–1.32, 6.12 for 1.33–1.35, 6.18 for 1.36–1.37. NIC's AWS example (1.34) gets 6.12 | Qualified for `AL2023_x86_64_STANDARD` on x86_64 with the 6.12 kernel (Kubernetes 1.33–1.35, ABI 6): observed active at boot on kernel 6.12.111 (AMI release 2023.12.20261012). AL2023 enabled `CONFIG_SECURITY_LANDLOCK` in its 6.1 and 6.12 kernels in release 2023.8.20250804. Unsupported on 6.1 (ABI 2). Unknown for 6.18, arm64, NVIDIA and Bottlerocket AMIs until probed |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | 6.8 | Qualified on x86_64 (ABI 4); observed active at boot on Hetzner nodes (6.8.0-138), full probe passed |
| `azure` (AKS) | NIC's AKS module (v0.2.0) sets no `os_sku`, so AKS defaults apply: Ubuntu 22.04 (5.15) below Kubernetes 1.35, and Ubuntu 24.04 (6.8) from 1.35, to which AKS migrates node pools automatically on upgrade. NIC's Azure example (1.34) gets 22.04 | Unsupported below 1.35. From 1.35 expected ABI 4, but **not yet probed**: until a maintainer runs the probe on AKS, the Azure provider reports the expectation as unknown. Selecting Ubuntu 24.04 earlier (`Ubuntu2404`, available from 1.32) or Azure Linux 3 needs an `os_sku` setting the module does not expose today |
| `local` (kind) | The host's kernel | Host-dependent |
| `existing` | Unknown | Detect only |

So the default x86_64 images on recent Kubernetes versions qualify where they have been probed, older kernel lines do not, and much else is unknown. The NIC work for row 2 is recording qualified configurations, reporting the expectation per node group with a diagnostic baseline, and probing each configuration before recording it, not changing pod security or labelling nodes.

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
| `aws` (AL2023) | OK (observed on EKS 1.34, 2026-10-19) | Blocked under `RuntimeDefault` (observed); no filter when unset | n/a (no AppArmor; SELinux permissive) | Masked: a fresh procfs fails (observed) |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | Restricted by the AppArmor sysctl (`apparmor_restrict_unprivileged_userns=1`, observed) | Blocked under `RuntimeDefault`; profile needed | Blocks `mount` (observed on NIC-deployed nodes, 2026-10-25) | Masked |
| `azure` (AKS, Ubuntu 22.04) | Expected OK *(unverified)* | Blocked under `RuntimeDefault`; profile needed | Profile needed | 5.15 kernel; likely unsupported *(unverified)* |
| `local` (kind) | Host-dependent | Blocked under `RuntimeDefault`; profile needed | kind runs its node containers with `apparmor=unconfined` and `seccomp=unconfined`; whether the containerd inside a node applies AppArmor to pods depends on the host (live test needed on Linux hosts with AppArmor; kind's known issues advise disabling interfering host profiles) | Host-dependent |
| `existing` | Unknown | Blocked under `RuntimeDefault`; profile needed | Unknown | Unknown; detect only |

Layer 2 is the same on every provider, so most of the work is provider-neutral; only layer 1 (and layer 3 on AppArmor nodes) needs provider-specific changes.


**Why it can appear to work today.** None of the packs surveyed sets a seccomp profile, and neither does the bundled JupyterHub chart. A pod with no seccomp profile gets the kubelet's default, which is no filter at all (`Unconfined`) unless the kubelet's `seccompDefault` option is enabled. On AWS this is confirmed from source: the AL2023 kubelet configuration generated by nodeadm ([`amazon-eks-ami`](https://github.com/awslabs/amazon-eks-ami), `nodeadm/internal/kubelet/config.go`) does not set `seccompDefault`, containerd's `unset_seccomp_profile` is empty, and NIC's [`terraform-aws-eks-cluster`](https://github.com/nebari-dev/terraform-aws-eks-cluster) module (v0.7.0) adds no kubelet configuration. So on AWS a user pod can run bubblewrap today in its reuse-`/proc` mode: observed on an EKS 1.34 AL2023 x86_64 node with `seccompProfile` unset (2026-10-19, §20.6), and refused under `RuntimeDefault`. This is not a foundation packs can rely on: it depends on running with no syscall filter, it stops working as soon as a pack follows Pod Security Standards `restricted` (which requires `RuntimeDefault` or `Localhost`) or the kubelet's `seccompDefault` is enabled, and ADR-0010's hardened mode is expected to forbid it. The same default holds on the other providers (checked from source and docs): hetzner-k3s passes only `cloud-provider` and `resolv-conf` kubelet arguments, NIC adds none, and k3s does not enable `seccompDefault`; on AKS the default is `Unconfined`, `RuntimeDefault` is available only through a custom kubelet configuration (behind the `KubeletDefaultSeccompProfilePreview` feature flag at the time of writing), and NIC's AKS module sets no kubelet configuration.

## 20.6 The capability contract in full

In short, the contract is an interface to the **node execution environment**: NIC describes, by name and with qualification, what the nodes' kernel, kubelet configuration, container runtime and security profiles let a pod do, and publishes the concrete values a pack uses. Packs still write their own pod settings and run their own sandboxing tools; networking (NetworkPolicy enforcement) and higher-level sandbox systems that build on these capabilities are outside it.

ADR-0021 states the contract on three independent axes: an ordered **boundary level** between pod and host, **in-pod capabilities** the workload uses inside its pod, and **profiles** of guarantees enforced around the pod. In-pod capabilities are not ordered against levels (a VM is not a superset of in-pod namespaces), which is why they are a separate axis. All of them name **guarantees, not mechanisms**.

| Capability | Guarantee | Qualified consumer | Status |
|---|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict its own and its descendants' filesystem access with Landlock at ABI 3 or newer, and TCP connect and bind at ABI 4 or newer (the ABI is part of each qualification). | The probe (§20.8): filesystem and TCP rulesets against positive controls in a restricted pod, with a verdict for each. The reference launcher (§20.8) is tested on local VMs, containers and in CI, awaiting provider qualification | **Described (ADR-0021)**: qualified per configuration; enforcement is the consumer's |
| `seccomp-user-notification` | The same process can install nested seccomp filters with user notification, including `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. User notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check: a supervisor that inspects arguments and then lets the call continue can race with changes to that memory, as the Linux manual warns. | The probe's notification path (two stacked filters, listener transfer, descriptor injection) | Reserved. Probed separately because a container runtime or default-profile change can break it independently of the kernel |
| `in-pod-namespaces` | A non-root process with no added capabilities, applying the published settings, can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed. | One pinned bubblewrap version: a capability test and two qualified configurations (§20.9) | Sketched in [ADR-0022](../../adr/0022-in-pod-namespaces-capability.md); no supported route yet |

**Profiles.** A profile is a composition of **atomic guarantees**, each of which the cluster enforces around a pod and can check from outside it, for example:

| Atomic guarantee | Enforced by | What it does not cover |
|---|---|---|
| `no-service-account-token` | Admission: `automountServiceAccountToken: false` and no projected token volume | Tokens copied into images, files or environment values |
| `no-secret-references` | Admission: no `secretKeyRef`, `secretRef` or Secret volumes | Literal values in the pod spec, ConfigMaps, images, data |
| `controller-scoped-secrets-only` (ADR-0025 sketch, in namespaces that allow per-pod controller credentials, instead of `no-secret-references`) | Namespace RBAC NIC sets up: only the named controller may create Secrets and pods there | Cluster-wide grants; what the controller puts in each Secret |
| `metadata-unreachable` | Network policy and node settings (for example IMDS hop limit 1) | Other in-cluster credential services |
| `default-deny-off-pod-egress` | Enforced NetworkPolicy | Loopback and sidecars in the pod; traffic to the pod's own node, which the tested policies did not block; policies a request layer creates |

A blanket "no credentials" or "no network" claim is not made: admission cannot see credentials in images, literal environment values, ConfigMaps or data, and network guarantees must say which of off-pod, loopback and sidecars, own-node and request-layer traffic they cover. Profiles are independent of the boundary level and are reserved; NetworkPolicy enforcement, which several of them need, is tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691).

Every capability, implementation and profile is defined by the same items: **guarantee**, **qualified consumer**, **placement**, **cluster requirements** (node kernel or OS, boot-time node settings, Kubernetes or API-server features, all expressed through provider config), **provisioning** (what is installed, by whom, and when in the lifecycle), **verification**, any **scale limits**, and a **trust model**:

- which actors are trusted (the operator, NIC, the pack's own components, the provider's runtime);
- what a hostile workload may do (run as root inside, rewrite files it can reach, call any API it can reach);
- what NIC enforces, from outside the workload;
- what the pack must enforce itself;
- what is outside the guarantee.

Two distinctions apply to every trust model. **Declared settings are not enforcement:** the tested gVisor configuration (without `--oci-seccomp`) and the tested Kata configuration ignored the pod's `seccompProfile`, so a setting that satisfies Pod Security may confine nothing. **Smoke tests are not attestation:** a check pod that passes shows the path worked for that pod at that time; it does not prove what runs on a node, and a compromised node can pass it.

Tools that need more than the qualified configuration are **potential** consumers, not implied ones. Rootless container engines are the main example: normal multi-UID operation uses `newuidmap`/`newgidmap` and subordinate ID ranges, which a non-root pod with `allowPrivilegeEscalation: false` and no capabilities cannot use, and they may also need FUSE, storage drivers or cgroup delegation.

### Boundary levels, properties and the acceptance policy

ADR-0021 adopts this model as NIC's interface but builds only its first level, `shared-kernel`.

| Level | Promise | Diagnostic check on a running pod (not attestation) | Example implementation |
|---|---|---|---|
| `shared-kernel` | Code runs on the host kernel; only in-pod capabilities fence it | Nothing beyond the in-pod capabilities required | The default runtime (runc) |
| `mediated-kernel` | Code never makes system calls directly to the host kernel | The kernel release seen inside the pod differs from the node's (`node.status.nodeInfo.kernelVersion`), plus evidence specific to the implementation | A user-space kernel (gVisor) |
| `hardware-virtualised` | A hardware virtualisation boundary separates code from the host | As above, plus evidence specific to the implementation that the pod runs in its guest. The CPU's hypervisor flag alone is not enough: EC2 nodes already show it, so a gVisor pod on EC2 would pass | A VM runtime (Kata) |

**Acceptance policy (normative).** The order is used only as an operator acceptance policy: "at least `mediated-kernel`" means the operator accepts any qualified implementation at that level or above. It is a NIC convention, not an ecosystem standard or a security ranking. GKE (`gvisor`), AKS Pod Sandboxing (`kata-vm-isolation`) and `RuntimeClass` itself expose concrete runtimes, and the levels describe different interfaces between code and host: a user-space kernel exposes a small, filtered set of host system calls and implements Linux itself, with gaps; a VM exposes KVM and the VMM's virtual devices and runs a full guest kernel that must also be patched. NIC ranks the hardware boundary higher because it contains even a compromised guest kernel (Luis Cardoso, "Sandboxes for AI", 2026, makes the same point), but packs are never promised that they run unchanged at a nominally stronger level, and NIC never substitutes one implementation for another. If more than one implementation could satisfy a requirement, resolution fails unless the operator lists the implementations they accept, in order of preference; that mechanism is future work.

**Properties.** Each implementation carries a versioned **property set**, established by the probe on each qualified provider, architecture and node OS and re-established on runtime upgrades, and published in the mapping entries that use it, so packs read what they depend on rather than infer it from the level. Two implementations of one level (for example Kata installed by NIC on AWS and AKS Pod Sandboxing on Azure Linux) are qualified separately and share nothing by default. Values observed so far, from test-only installs (ADR-0021 delivers neither runtime):

| Property | Default runtime | gVisor | Kata (QEMU, AWS) |
|---|---|---|---|
| `process-self-restriction` (Landlock inside) | Where the configuration is qualified | No (`ENOSYS`) | Yes (guest ABI 7) |
| `in-pod-namespaces` (bubblewrap's qualified configurations) | Observed only on AL2023 with no syscall filter (`seccompProfile` unset); not a supported setting | Yes (network namespace created first) | Not yet probed |
| Pod's `seccompProfile` applied | Yes | No (tested configuration, without `--oci-seccomp`) | No (tested configuration) |
| Root inside contained from the host kernel | No | Yes | Yes |
| Fresh `/proc` in a pid namespace | No | Yes | Not yet probed |
| inotify events for changes made by other pods | Yes | No (polling only) | Not yet probed |
| Usable memory under a limit | The limit | The limit plus the class overhead | Less than the limit (about 947 MiB at 1 GiB) |

Measured overheads and incidental compatibility observations such as these are evidence, not semantic promises.

### Three states, and what NIC reports

Everything NIC reports about a capability is in one of three states, kept apart in the data and in the text NIC prints:

| State | Meaning | Source | Values |
|---|---|---|---|
| Qualified expectation | What NIC expects of a bounded configuration (provider, image variant, architecture, version range) | The qualification record (§20.8), applied by the provider to config; `InfraSettings.Sandbox` | `qualified` (with ABI), `unsupported`, `unknown` |
| Host-kernel baseline | What a node's kernel version implies upstream | A fresh read of the nodes when `nic outputs` (or the end of `nic deploy`) runs, labelled with its time | An ABI, or `not checked` for a group with no nodes; `unassigned` for a node in no group |
| Enforcement | Whether the sandbox actually holds | Only the consumer, each time it creates a sandbox | Not reported by NIC |

`unknown` stays unknown: a baseline at or above the needed ABI never turns it into `qualified`, and a qualified expectation is never upgraded by a newer kernel. Everything here concerns the **default runtime's host environment**: a node can also run gVisor (no Landlock) or Kata (a guest kernel with its own ABI), whose properties are published per implementation. NIC stores no history of these reads.

### The published mapping

NIC publishes a versioned mapping from requirement name to concrete values. In ADR-0021 it is computed from config and shown by `nic outputs`; there is no automatic resolution, and `default` is the only entry. The operator copies the values into the pack's Helm values until pack codegen ([ADR-0003](../../adr/0003-software-pack-codegen.md)); packs copy them into pod specs and Agent Sandbox `SandboxTemplate`s, which take an exact `runtimeClassName`. Packs never look anything up in the cluster and nothing selects a `RuntimeClass` by label.

```yaml
# nic outputs -o yaml (sandbox section; illustrative)
sandbox:
  observedAt: 2026-10-28T10:00:00Z        # fresh read of the nodes; nothing is stored
  mapping:
    version: 1
    requirements:
      default:
        level: shared-kernel
        state: unknown                     # the gpu group is unknown (rule below)
        capabilities: []                   # process-self-restriction only when state is qualified
        podSecurityContext:
          runAsNonRoot: true
          seccompProfile: {type: RuntimeDefault}
        containerSecurityContext:
          allowPrivilegeEscalation: false
          capabilities: {drop: [ALL]}
  nodeGroups:
    user:
      expectation: {state: qualified, landlockABI: 6, record: aws-al2023-x86_64-6.12}
      baseline:
        - {node: <name>, kernel: 6.12.111-136.204.amzn2023.x86_64, landlockABI: 6}
    gpu:
      expectation: {state: unknown}
      baseline: not checked                # no nodes when observed
  unassigned: []
```

**The `default` entry.** It describes the cluster's normal runtime with no `runtimeClassName`. Its `state` is derived from the expectations of the node groups that can run pods (every group whose configured maximum size is above zero): `qualified` if all of them are qualified, `unsupported` if all of them are unsupported, and `unknown` otherwise, including a mix of qualified and unsupported groups. `capabilities` lists `process-self-restriction` only when the state is `qualified`; under `unknown` or `unsupported` it is empty, and the per-group report says which groups are the reason. An operator may still pass the values to a pack under `unknown`: the pack's startup check decides on each node, and NIC blocks nothing. The security settings meet Pod Security `restricted`, each at the level it belongs: `runAsNonRoot` and `seccompProfile` at pod level, so they also cover init containers, and `allowPrivilegeEscalation: false` and `capabilities.drop: [ALL]` per container, where Kubernetes defines them. The pack still sets `runAsUser` where its image has no numeric non-root user.

**Placement is reserved.** The `default` entry has no placement, and NIC labels no node groups for it. In a mixed cluster the pack's startup check refuses work on a node that does not qualify; steering pods away from such groups is future work (see Option 2 and the placement-label guidance below).

**Extension space, not a frozen schema.** Only fields a consumer uses today are defined. These names are reserved for later entries, with their intended meaning: `runtimeClassName` (an exact class); `placement` (node selector, affinity and tolerations NIC renders, so packs never hardcode provider or node-group labels); `workspaceStorageClass` (a class known to work with that entry's runtime, with access-mode and ownership notes: the tested gVisor configuration could not write to EFS access points as NIC configures them, so storage is part of an entry, not a promise that any storage works); `profile` (settings such as a namespace); and `implementation` (release and property-set version). Consumers ignore fields they do not know. Adding a field or an entry keeps `version`; removing or redefining one, or changing what a value means, bumps it.

Later entries may name `RuntimeClass`es NIC installs, one per implementation and named after it (`nebari-gvisor`, `nebari-kata`); provider-managed classes (AKS's `kata-vm-isolation`); or a class the operator owns on an `existing` cluster. Implementation names are NIC's convention for classes it installs, not a requirement on others. Level-named aliases were rejected: `RuntimeClass.handler` is immutable, so such a class cannot be moved from `runsc` to `kata` without deleting it; one class per level cannot serve two workloads that need different properties at the same level; and the ecosystem names runtimes directly. NIC may label its classes `sandbox.nebari.dev/level: <level>` as inventory metadata for its own tooling. For capabilities backed by a `RuntimeClass`, placement can also use the class's own `scheduling` field, which Kubernetes merges into pods.

When automatic resolution is introduced, it must treat a requirement with no matching implementation, or more than one without an operator preference, as a failure (rule (a)).

```go
// Reported by each cluster provider in InfraSettings.Sandbox, from config only.
type SandboxSettings struct {
    NodeGroups map[string]NodeGroupSandbox // one entry for existing and kind
    // NodeGroupOf associates a live Node with a node group, using whatever the
    // provider knows (for example its own node-group label). It is diagnostic
    // only, never a trusted scheduling label. "" means unassigned.
    NodeGroupOf func(node *corev1.Node) string
}

type NodeGroupSandbox struct {
    Expectation Expectation
    CanRunPods  bool // false when the configured maximum size is zero; not counted in the entry's state
}

type Expectation struct {
    State       string // "qualified", "unsupported" or "unknown"
    LandlockABI int    // when qualified or unsupported; 0 when unknown
    Record      string // qualification record entry, when qualified
}

// Computed by pkg/nic from InfraSettings and config; shown by nic outputs.
type Mapping struct {
    Version      int // 1; bumped only by an incompatible change
    Requirements map[string]Requirement
}

// Only fields used today. Reserved for later entries, not yet defined:
// RuntimeClassName, Placement, WorkspaceStorageClass, Profile, Implementation.
type Requirement struct {
    Level                    string
    State                    string   // "qualified", "unknown" or "unsupported"
    Capabilities             []string // process-self-restriction only when State is "qualified"
    PodSecurityContext       *corev1.PodSecurityContext // runAsNonRoot, seccompProfile
    ContainerSecurityContext *corev1.SecurityContext    // allowPrivilegeEscalation, capabilities
}

// Computed live by nic outputs; never stored.
type Baseline struct {
    ObservedAt time.Time
    NodeGroups map[string][]NodeBaseline // a group with no entries is "not checked"
    Unassigned []NodeBaseline
}

type NodeBaseline struct {
    Node        string
    Kernel      string
    LandlockABI int // upstream ABI for the kernel version; an inference
}
```

### Guidance for later capabilities

**Placement labels.** For runtimes NIC installs, labels that route pods are never writable by nodes. They use a NIC-owned name under the `node-restriction.kubernetes.io/` suffix, `nebari.dev.node-restriction.kubernetes.io/<name>`, which the NodeRestriction admission plugin stops kubelets setting or changing (including through `--node-labels` at registration), and NIC or a cluster-side component applies them through the API. This prevents only **self-asserted scheduling eligibility through kubelet credentials**. It depends on the Node authorizer and NodeRestriction being enabled, kubelet identities scoped to their own nodes, and label-writer permissions being controlled; each provider must verify these with an active negative test using a kubelet identity, and on `existing` clusters they are unknown and treated as failing. Where provider membership authorises placement (for example "this node is in node group `gv`"), the labeller needs a trustworthy node-to-instance binding and must not trust an attacker-supplied `spec.providerID` alone. Compromise of a node that is already authorised is outside the guarantee. A node may set labels under `sandbox.nebari.dev/` about itself only to signal failure; nothing routes pods towards such a label. Autoscaler templates for scale-from-zero must carry a label the kubelet will never set, which each provider must qualify. Provider-managed runtimes (AKS's Kata) are routed by the provider's own labels and trusted as the provider's, and their trust model says so.

**Lifecycle.** Three things change on different terms:

1. **Contract semantics** (capability and profile definitions): an incompatible change needs a new version (`<name>-v2`), published alongside the old one, which keeps its meaning until retired. New evidence and newly qualified configurations keep the name.
2. **Qualified implementations and releases:** can be added, withdrawn or revoked. A security revocation does not keep an unsafe release for compatibility. Object names such as `nebari-gvisor` stay stable; the release and property-set version are published in the mapping.
3. **Availability:** what a cluster offers today is not permanent support.

Advertised guarantees must hold on every eligible placement, including during mixed-version rollouts. Managed runtimes such as AKS's upgrade on the provider's schedule, so their qualification records name the provider's versions they cover.

**Admission.** "At least" is not enforced by admission via labels: a `ValidatingAdmissionPolicy` cannot dereference a `RuntimeClass`'s labels, and Kubernetes has no primitive that does. A later profile that restricts runtimes admits pods by a NIC-generated list of approved class names (a parameter object) or a webhook, with fail-closed updates of that list and controlled ownership of the classes it names. The probe policy used in testing was a fixed name list.

**Consumer integration.** Until pack codegen exists, packs are integrated **explicitly**, through the mapping's values in Helm values, and refuse sandboxed work rather than fall back. Declaring `requires: { sandbox: [...] }` in `nebari-integration.yaml`, with NIC refusing incompatible packs, is future work that depends on ADR-0003. An in-cluster readiness record with expiry, scheduled re-verification and quarantine of failing nodes was designed for capabilities with installed components; it is deferred, and any capability that wants it must justify it in its own ADR.

### Proposed additions: more mapping entries (sketches)

ADR-0021 publishes the mapping with one entry, `default`, and no configuration. The exploratory ADRs (ADR-0022 onwards) would add entries to that mapping, in the same shape (§20.6, "The published mapping"); none of this is part of ADR-0021:

1. **Operator-declared entries.** One per kind of workload, each naming a level, the in-pod capabilities it needs and, once a later ADR defines one, a profile:

   ```yaml
   sandbox:
     requirements:
       tool-sandboxes:                  # becomes a mapping entry of the same name
         level: mediated-kernel         # accepted: this level or above
         capabilities: []               # gVisor has no Landlock, so none are asked for here
         accept: [gvisor]               # implementations the operator accepts, in order of preference
   ```

2. **An acceptance list.** Because NIC never substitutes implementations, an entry that more than one qualified implementation could satisfy names the ones the operator accepts. Resolution fails when nothing in the list qualifies, or when more than one could and there is no list, naming the gap (for example "tool-sandboxes: mediated-kernel on hetzner: no qualified implementation"). Pinning the chosen implementation in node groups' stored specs is left to the ADR that first offers two on one provider.

3. **Implementations per node group.** Each provider would report, beside the group's Landlock expectation, the implementations a group offers, with their level, release and qualified property-set version; the resolved entry copies those into `implementation` and fills `runtimeClassName`, `placement` and `workspaceStorageClass`.

```go
// Additions to InfraSettings.Sandbox for the sketches.
type NodeGroupSandbox struct {
    Expectation     Expectation
    Placement       map[string]string
    Implementations []Implementation // higher-level runtimes offered here; empty in ADR-0021
}

type Implementation struct {
    Name             string // for example "gvisor"
    RuntimeClassName string // "nebari-gvisor", or a provider-managed or operator-owned class
    Level            string
    Release          string // for example "release-20261012.0"
    PropertySet      string // qualified property-set version (table above)
    Prerequisites    []string
}
```

Packs still receive only concrete values: the resolved entry, copied by the operator (or by pack codegen) into Helm values.

### Evidence from the higher levels

Before the contract was fixed, the higher levels were exercised on clusters deployed with NIC, using test-only installers that ADR-0021 does not adopt. Raw output from these runs is not committed; this table and the summaries under `tests/sandbox-probe/` are the record. Run-by-run detail is in "ADR-0023: probe evidence in full" (§20.9).

| Run | Result | Informed |
|---|---|---|
| gVisor `release-20261012.0` behind a `RuntimeClass` on EKS 1.34 AL2023, x86_64 (2026-10-19, 2026-10-27) and arm64 (2026-10-27) | Non-root and root pods ran; Landlock returned `ENOSYS`; the pod's `RuntimeDefault` was ignored (`Seccomp: 0`) | The acceptance policy; rule (d); property sets per implementation |
| gVisor on Hetzner k3s, Ubuntu 24.04, x86_64 (2026-10-25, 2026-10-27) | As on EKS; k3s enforced NetworkPolicy for gVisor pods as for runc pods | As above |
| gVisor with home directories on NIC's `efs-sc` (EKS, 2026-10-19) | Not writable: each EFS access point owns its directory as its own UID with mode 700, and gVisor checks permissions itself; access points using the pod's UID and GID worked under both runtimes | Rule (b): qualification covers storage; `workspaceStorageClass` in the mapping |
| A deliberately failed gVisor install (EKS and Hetzner, 2026-10-25) | Pods sent to the node stayed in `ContainerCreating` rather than run unsandboxed, but `status.runtimeHandlers` still listed `runsc` | Rule (a); `runtimeHandlers` is not evidence of a working runtime |
| Kata 4.2.0 (QEMU) on EKS 1.34 through EC2 nested virtualisation, `m8i-flex.large`, x86_64 (2026-10-27) | The probe passed inside the guest at Landlock ABI 7; the guest reported `seccomp_mode` 0, so the declared `RuntimeDefault` was not applied | Rule (d); capabilities differ between implementations |
| Bubblewrap in a non-root pod on EKS 1.34 AL2023, x86_64 (2026-10-19), and on Hetzner (2026-10-25) | On EKS it worked only with `seccompProfile` unset (the EKS kubelet default) and failed under `RuntimeDefault`; on Hetzner AppArmor blocked it | `in-pod-namespaces` stays reserved |
| Node self-labelling on EKS 1.34 (2026-10-26) | With only its own credentials, a node rewrote its own node-group label, and the change survived a kubelet restart; it could not change taints or set labels under `node-restriction.kubernetes.io/` | Placement-label guidance |
| NetworkPolicy on EKS 1.34 (2026-10-19, 2026-10-27) | Not enforced in NIC's EKS clusters by default; once enabled in the VPC CNI, default deny held against root under gVisor and Kata, except towards the pod's own node | Profiles left out until [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691); `default-deny-off-pod-egress` names the own-node gap |

## 20.7 Lifecycle

*`process-self-restriction` installs nothing and does not use this phase (ADR-0021); it applies to capabilities with cluster components.* Capabilities that need cluster components are installed in a **post-bootstrap phase**, not inside the provider's `Deploy()`:

1. Provider `Deploy()`: node groups, node images, node labels and taints, and any boot-time node settings.
2. Foundational services bootstrap (ArgoCD and the foundational applications).
3. **Wait for the dependencies to be ready** (for example cert-manager).
4. Install the capability's components and its versioned profiles.
5. Verify (§20.10).
6. Publish the mapping entries, with their implementation release and property-set version.

Today, conditional software ([ADR-0006](../../adr/0006-conditional-foundational-software-helm.md)) is installed inside the provider's `Deploy()`, before ArgoCD and cert-manager exist, and foundational-service failures are reported as warnings rather than failing the deploy. A capability with components therefore needs either a post-bootstrap lifecycle hook in `pkg/nic` or an amendment to ADR-0006. Independently of ADR-0010's fail-closed hardened mode, a capability the operator requires (or opts into on a node group) that fails steps 3-5 makes `nic deploy` exit non-zero.

## 20.8 Delivery: `process-self-restriction`

ADR-0021 delivers a **qualified description of the default runtime's host prerequisite (Landlock), plus an optional, read-only diagnostic preflight**. It is not an enforced sandbox. NIC reports an incompatible cluster but does not block `nic deploy`; enforcement is the pack's startup check. An operator option that makes a requirement fail the deploy can be added later without changing the mapping.

1. **No opt-in, no relaxation, no components, no configuration.** No profiles, no operator, no admission exception and no node preparation. Steps 3-4 of the lifecycle are empty. A cluster-wide minimum-ABI setting was considered and dropped: one number ignores the runtime (gVisor has no Landlock), cannot judge node groups with no nodes or images nobody has probed, and duplicates the pack's own startup check, which is where the guarantee is enforced.
2. **Qualified expectations.** Each provider reports, per node group and from config alone, the expectation the qualification record (below) gives for that group's configuration: `qualified` with an ABI for a configuration inside a record's extrapolation range, `unsupported` where the kernel line is known to be below ABI 3, and `unknown` otherwise. Not every default node group on a supported Kubernetes version qualifies: AWS below 1.33 (kernel 6.1, ABI 2) and AKS below 1.35 (Ubuntu 22.04, kernel 5.15, ABI 1) are unsupported; AKS from 1.35, AWS AMI types other than `AL2023_x86_64_STANDARD` (including ARM, NVIDIA and Bottlerocket), images an operator pins, `existing` and kind are unknown. NIC does **not** change node images on its own; moving a group to a qualifying image is an operator change through the provider's own config.
3. **Reporting and the preflight.** `nic outputs` reads the nodes afresh each time it runs and shows, per node group, the qualified expectation and the host-kernel baseline, labelled "default runtime only" and with the time of the read; nodes the provider's `NodeGroupOf` cannot place are listed as `unassigned`, and groups with no nodes are `not checked`. `nic deploy` prints the same report once the nodes are up. The baseline maps each node's `node.status.nodeInfo.kernelVersion` to the Landlock ABI that kernel version introduced upstream: 5.13 ABI 1, 5.19 ABI 2, 6.2 ABI 3, 6.7 ABI 4, 6.10 ABI 5, 6.12 ABI 6, 6.15 ABI 7. It never warns or fails, is not stored, and is never read as a qualification, because three things defeat it: distribution backports (a lower version with a newer ABI), Landlock built in but not enabled at boot (`EOPNOTSUPP`), and container-runtime seccomp profiles that predate the Landlock system calls and deny them. Nodes added later (autoscaling, replacement) are seen only by the next read. The `default` entry's state follows from the per-group expectations (§20.6). NIC labels no node groups for this delivery; the per-group report is diagnostic.
4. **Probe and requalification.** The probe ([`tests/sandbox-probe/`](../../../tests/sandbox-probe/README.md)) is the qualified consumer of `process-self-restriction` and the evidence behind each record entry. NIC maintainers run it on a fresh node of each configuration before it is recorded, following the probe's [requalification procedure](../../../tests/sandbox-probe/README.md#requalification), and again whenever a node leaves a record's extrapolation range (below). It is not run on users' clusters. A non-root pod with every capability dropped and `RuntimeDefault` applies a Landlock ruleset and confirms a denied write and truncation fail, reports the highest ABI, at ABI 4 confirms a disallowed `connect` and `bind` fail, and records `/sys/kernel/security/lsm`. Each denial has a positive control on the same node, so an unrelated failure cannot pass as confinement. The probe reports three separate verdicts: `landlock_fs`; `landlock_tcp`, evaluated at ABI 4 or newer, where the record advertises TCP confinement, and failing if a forbidden `connect` or `bind` succeeded or the network check errored; and `seccomp_user_notification` (two stacked filters, listener transfer, `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`). Its `process_self_restriction` verdict needs `landlock_fs` to pass and `landlock_tcp` not to fail, and does not depend on seccomp notification. In qualification mode the probe exits non-zero when a property being qualified fails; `--diagnostic` prints the same result and always exits 0, and is not a gate.
5. **Reference launcher.** The example below is committed with its unit and end-to-end tests under [`tests/sandbox-probe/recipe/`](../../../tests/sandbox-probe/recipe/). It is a reference consumer, tested on local VMs and containers and in CI, awaiting provider qualification: it has not been run on the qualified EKS or Hetzner configurations, whose qualification rests on the probe. The code is an example, not part of the contract.
6. **Documentation.** A pack-developer page (copy the `default` values, do not mount the service-account token, check the Landlock ABI at startup, refuse sandboxed work rather than fall back, treat the work directory as untrusted input, the example below) and an operator page (the qualification record, what `nic outputs` reports and what each state means).

### Qualification record

The record lists what has been qualified, not every image: unknown combinations stay unknown. Probe results (node names redacted) are under [`tests/sandbox-probe/`](../../../tests/sandbox-probe/README.md#evidence-table).

| Provider, image variant, architecture | Tested image release | Kernel | Container runtime | Pod settings | Probe revision | ABI | Date | Extrapolation range |
|---|---|---|---|---|---|---|---|---|
| `aws`, EKS `AL2023_x86_64_STANDARD`, x86_64 (`m6i.large`), Kubernetes 1.34 | AMI release 2023.12.20261012 | 6.12.111-136.204.amzn2023 | containerd 2.3.5 | `pod.yaml` (UID 65532, no capabilities, read-only root, `RuntimeDefault`; also unset) | probe 0.1.0 | 6 | 2026-10-19 | `AL2023_x86_64_STANDARD` on x86_64, 6.12 kernel line (Kubernetes 1.33–1.35), containerd 2.3 |
| `hetzner`, hetzner-k3s Ubuntu 24.04, x86_64 | Ubuntu 24.04.4 LTS | 6.8.0-138-generic | containerd 2.2.7-k3s1 | As above | probe 0.1.0 | 4 | 2026-10-25 | Ubuntu 24.04 on x86_64, GA kernel line (6.8), containerd 2.2 (k3s) |

**Extrapolation range.** An entry extends only to nodes with the same image variant and architecture, the same kernel line and the same container runtime minor version; within it, a new image or kernel revision keeps the expectation. Anything else is unknown until re-probed, including a new kernel line, a runtime minor upgrade, a changed default seccomp profile and a changed boot-time LSM list. The recorded results were taken with probe 0.1.0; their verdict fields were recomputed from the recorded raw fields by probe 0.2.0 (`--rederive`), which is deterministic and needs no rerun.

Unsupported, from the kernel line: AWS AL2023 on 6.1 (Kubernetes 1.31–1.32, ABI 2); AKS Ubuntu 22.04 (5.15, ABI 1). Everything else is unknown until probed, including AL2023 on 6.18 (Kubernetes 1.36–1.37), every arm64 image, GPU images, Bottlerocket, AKS on Ubuntu 24.04 or Azure Linux, `existing` and kind. (kind on a 6.8 Colima VM, 2026-10-15, passed the probe at ABI 4; that is a local observation, not a qualification, since kind's kernel is the host's.)

### Example: confining a command

This is a **reference launcher** for the default runtime: a reference consumer of `process-self-restriction`, tested on local VMs and containers and in CI, awaiting qualification on provider nodes. It is not a library NIC ships and not part of the contract. It runs non-root under Pod Security `restricted` with no added capability. The optional seccomp user-notification mediation mentioned at the end is a capability demonstration in the probe, not part of this launcher.

The agent never confines itself. It starts a **helper**, its own binary re-executed through `/proc/self/exe` with `os/exec`, passing the policy and the command as arguments, a minimal explicit environment (`PATH`, `HOME` and `TMPDIR` set to the work directory, `LANG`) and only standard input, output and error. The helper checks the policy against the kernel's Landlock ABI and, if the kernel cannot enforce all of it, refuses before executing anything. Otherwise it restricts itself and executes the command, which inherits the restriction and cannot lift it:

- **The policy states what it requires.** Its TCP mode is `proxy-port` (connect to one port, no `bind`), `deny` (no TCP `connect` or `bind`) or `unrestricted` (filesystem only). The first two need ABI 4, the third ABI 3. There is no default: a policy with no mode, an unknown field or a port in the wrong mode is refused.
- **Landlock** through [go-landlock](https://github.com/landlock-lsm/go-landlock) (v0.11.0), in two stacked domains. The first is strict: the filesystem rights of ABI 3 (every creation and removal right, `REFER` and `TRUNCATE`) and, unless TCP is unrestricted, TCP `connect` and `bind` from ABI 4; go-landlock fails rather than drop any of them. The second, from ABI 5, is best effort with the same grants and adds what newer kernels have: `IOCTL_DEV` (ABI 5), signal and abstract-socket scoping (ABI 6), pathname Unix-socket `connect` (ABI 9) and, unless TCP is unrestricted, UDP (ABI 10). Access must pass every domain, so the best-effort domain can only take access away and never weakens the strict one. The grants: everything beneath the work directory, including moves and links within it (`REFER`; without it, legitimate moves inside the workspace fail) and connecting to sockets there; read and execute beneath listed system paths; read and write on listed files such as `/dev/null`; and, with `proxy-port`, TCP `connect` to that port. The library also sets `no_new_privs`.
- **Reads are restricted** to the work directory and the listed paths (for example `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc`, `/proc`), so files elsewhere, including a mounted service-account token, cannot be read. The pack should still not mount the token, and must not put credentials in the listed paths or the work directory.
- **Optional non-Unix socket restriction** (`unixSocketsOnly`) adds a seccomp filter, built with raw `x/sys/unix` calls because go-landlock does not cover seccomp, under which `socket()` succeeds only for `AF_UNIX`. It is an allowlist, so `AF_VSOCK`, `AF_ALG`, `AF_PACKET`, `AF_NETLINK` and any other family fail with `EPERM` as well as `AF_INET` and `AF_INET6`. It also refuses `io_uring` and foreign or x32 system calls. It works from ABI 3, so with `tcp: unrestricted` it denies IP networking where TCP rules are unavailable.
- **Descriptors** other than 0, 1 and 2 are marked close-on-exec with `close_range` before `execve`, so a descriptor the agent leaked without `O_CLOEXEC` does not reach the command.

```go
// Policy is what a confined command may do. Every field is stated; nothing
// is inferred from what the kernel happens to support.
type Policy struct {
	WorkDir   string   `json:"workDir"`   // read, write, create, remove, move and link beneath it
	ReadOnly  []string `json:"readOnly"`  // read and execute beneath, e.g. /usr, /etc, /proc
	ReadWrite []string `json:"readWrite"` // read and write, e.g. /dev/null
	// TCP is "proxy-port" (connect to ProxyPort only, no bind), "deny" (no
	// connect or bind) or "unrestricted" (Landlock leaves TCP alone). The first
	// two need Landlock ABI 4; the command is refused on older kernels.
	TCP       string `json:"tcp"`
	ProxyPort uint16 `json:"proxyPort,omitempty"` // with "proxy-port" only
	// UnixSocketsOnly adds a seccomp filter under which socket() succeeds only
	// for AF_UNIX: no IP, packet, netlink, vsock or other sockets.
	UnixSocketsOnly bool `json:"unixSocketsOnly,omitempty"`
}

const (
	confineArg      = "__confine"
	TCPProxyPort    = "proxy-port"
	TCPDeny         = "deny"
	TCPUnrestricted = "unrestricted"
)

// Agent side: run argv under p in a fresh helper (this binary, re-executed),
// with a minimal environment and only stdin, stdout and stderr.
func confinedCommand(p Policy, argv ...string) (*exec.Cmd, error) {
	pj, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/exe", append([]string{confineArg, string(pj)}, argv...)...)
	cmd.Dir = p.WorkDir
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + p.WorkDir,
		"TMPDIR=" + p.WorkDir, "LANG=C.UTF-8"}
	return cmd, nil
}

// Helper side, first thing in main:
//
//	if len(os.Args) > 2 && os.Args[1] == confineArg {
//		err := confineAndExec(os.Args[2], os.Args[3:]) // returns only on failure
//		fmt.Fprintln(os.Stderr, "confine:", err)
//		os.Exit(126)
//	}
func confineAndExec(policyJSON string, argv []string) error {
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader([]byte(policyJSON)))
	decoder.DisallowUnknownFields() // a misspelt or retired field must not be ignored
	if err := decoder.Decode(&p); err != nil || len(argv) == 0 {
		return errors.Join(errors.New("bad policy or empty command"), err)
	}
	abi := landlockABI()
	if err := p.check(abi); err != nil {
		return err // refuse rather than run the command with less than the policy says
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	runtime.LockOSThread() // the seccomp filter applies to this thread, which then execs
	if err := applyLandlock(p, abi); err != nil {
		return err
	}
	if p.UnixSocketsOnly {
		if err := allowOnlyUnixSockets(); err != nil {
			return err
		}
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err // inherited descriptors must not reach the command
	}
	return unix.Exec(path, argv, os.Environ())
}

// check refuses a policy the running kernel cannot enforce in full.
func (p Policy) check(abi int) error {
	switch {
	case p.WorkDir == "":
		return errors.New("policy has no workDir")
	case p.TCP != TCPProxyPort && p.TCP != TCPDeny && p.TCP != TCPUnrestricted:
		return fmt.Errorf("policy tcp must be %q, %q or %q", TCPProxyPort, TCPDeny, TCPUnrestricted)
	case (p.TCP == TCPProxyPort) != (p.ProxyPort != 0):
		return errors.New("policy proxyPort is required with tcp proxy-port and invalid otherwise")
	case abi < 3:
		return fmt.Errorf("Landlock ABI 3 or newer is required, have %d", abi)
	case p.TCP != TCPUnrestricted && abi < 4:
		return fmt.Errorf("tcp %q needs Landlock ABI 4 or newer, have %d", p.TCP, abi)
	}
	return nil
}

// landlockABI returns the kernel's Landlock ABI, or 0 if Landlock is absent
// (ENOSYS) or not enabled at boot (EOPNOTSUPP). It is a variable so that a
// test can stand in for an older kernel.
var landlockABI = func() int {
	abi, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return abi
}

// applyLandlock grants everything beneath the work directory, including moves
// and links within it (REFER) and connecting to Unix sockets there; read and
// execute beneath p.ReadOnly; read and write on p.ReadWrite; and, with
// "proxy-port", TCP connect to p.ProxyPort. It also sets no_new_privs.
//
// It restricts twice, and each restriction adds a stacked Landlock domain
// that can only take access away. The first is strict: the filesystem rights
// of ABI 3 and, unless TCP is unrestricted, TCP connect and bind of ABI 4; it
// fails rather than do less. The second, from ABI 5, is best effort with the
// same grants and adds whatever newer rights the kernel has: device ioctls
// (ABI 5), signals and abstract Unix sockets outside the sandbox (ABI 6),
// pathname Unix sockets outside the work directory (ABI 9) and, unless TCP
// is unrestricted, UDP (ABI 10).
func applyLandlock(p Policy, abi int) error {
	rules := []landlock.Rule{
		landlock.RWDirs(p.WorkDir).WithRefer().WithResolveUnix(),
		landlock.RODirs(p.ReadOnly...).IgnoreIfMissing(),
		landlock.RWFiles(p.ReadWrite...).IgnoreIfMissing(),
	}
	if p.TCP == TCPProxyPort {
		rules = append(rules, landlock.ConnectTCP(p.ProxyPort))
	}
	required, extra := landlock.V4, landlock.V11
	if p.TCP == TCPUnrestricted {
		required, extra.HandledAccessNet = landlock.V3, 0
	}
	if err := required.Restrict(rules...); err != nil {
		return err
	}
	if abi < 5 {
		return nil // nothing newer to add
	}
	return extra.BestEffort().Restrict(rules...)
}

// allowOnlyUnixSockets installs a seccomp filter under which socket() fails
// with EPERM for every address family except AF_UNIX. It also refuses
// io_uring, which can create sockets without calling socket(), and any
// syscall from a foreign or x32 ABI.
func allowOnlyUnixSockets() error {
	arch := map[string]uint32{"amd64": unix.AUDIT_ARCH_X86_64, "arm64": unix.AUDIT_ARCH_AARCH64}[runtime.GOARCH]
	const (
		ld, jeq, jge, ret = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_RET | unix.BPF_K
		deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	)
	filter := []unix.SockFilter{
		{Code: ld, K: 4}, // seccomp_data.arch
		{Code: jeq, Jt: 1, K: arch},
		{Code: ret, K: deny},
		{Code: ld, K: 0},                  // seccomp_data.nr
		{Code: jge, Jt: 5, K: 0x40000000}, // x32
		{Code: jeq, Jt: 4, K: unix.SYS_IO_URING_SETUP},
		{Code: jeq, Jf: 2, K: unix.SYS_SOCKET},
		{Code: ld, K: 16}, // low 32 bits of args[0], the address family
		{Code: jeq, Jf: 1, K: unix.AF_UNIX},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ret, K: deny},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
}
```

A pack runs it with, for example, `Policy{WorkDir: work, ReadOnly: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc"}, ReadWrite: []string{"/dev/null"}, TCP: TCPProxyPort, ProxyPort: 8080}`.

**What is tested.** On 2026-10-28, as a non-root user. `recipe/test.sh` runs every case through the helper and as an unconfined control (which must succeed, so a denial is not an unrelated failure), with the agent holding a canary secret in its environment and a leaked writable descriptor. Rows are `PASS`, `LIMIT` (reachable as documented for that ABI: a known gap, not confinement), `SKIP` (the container's own seccomp profile already denies it, so the launcher's denial cannot be told apart) or `FAIL`. The unit tests check every policy refusal, and run the helper with the ABI it sees capped at 3, 2 or 0 to show that a policy the kernel cannot enforce stops the command before it executes, against a positive control that does execute.

| Environment | Kernel, Landlock ABI | Launcher end to end | Unit tests | Probe |
|---|---|---|---|---|
| Lima VM, Ubuntu 24.04, aarch64, UID 501 | 6.8.0-134-generic, 4 | 49 pass, 8 limit, 0 fail | Pass | All four verdicts pass |
| The same VM, container (`nerdctl run --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges`, `python:3.12-slim`, containerd's default seccomp profile, a stand-in service-account token mounted) | 6.8.0-134-generic, 4 | 47 pass, 8 limit, 3 skip, 0 fail | Pass | All pass (`seccomp_mode` 2) |
| Lima VM, Ubuntu 25.04, aarch64, UID 501 | 6.14.0-37-generic, 6 | 53 pass, 4 limit, 0 fail | Pass | All pass |
| The same VM, container as above | 6.14.0-37-generic, 6 | 51 pass, 4 limit, 3 skip, 0 fail | Pass | All pass |
| Lima VM, Ubuntu 24.04, x86_64 (emulated), UID 501 | 6.8.0-134-generic, 4 | 49 pass, 8 limit, 0 fail | Pass | All pass |
| The same VM, container as above | 6.8.0-134-generic, 4 | 47 pass, 8 limit, 3 skip, 0 fail | Pass | All pass |
| Lima VM, Ubuntu 22.04, aarch64, UID 501 | 5.15.0-185-generic, 1 | Every policy refused before executing (6 of 6 refusal rows); confinement unsupported, reported as such | Pass (positive control skipped) | `landlock_fs` fails, exit 1 |
| The CI job's steps (Go 1.26.9) in the x86_64 VM above | 6.8.0-134-generic, 4 | `NIC_RECIPE_E2E=1 go test ./recipe/` passed (49 pass, 8 limit) | `go vet`, `go build`, `go test` pass | Not run |
| CI job "Sandbox probe", GitHub-hosted `ubuntu-24.04` runner, x86_64, UID 1001 | 7.0.0-1017-azure, 8 | 53 pass, 4 limit, 0 fail | Pass | Not run |

| Case | ABI 4 | ABI 6 |
|---|---|---|
| A `proxy-port` or `deny` policy below ABI 4, any policy below ABI 3, a policy with no TCP mode, an unknown field or a port in the wrong mode | Refused before executing | Refused before executing |
| Write, `mkdir`, symlink and move between directories inside the work directory | Allowed | Allowed |
| Create, append, truncate, remove, `mkdir`, symlink (planting, for example `~/.gitconfig`), `rmdir`, `mkfifo`, bind a Unix socket, or move a file out, outside the work directory | Denied | Denied |
| Grandchild of the command writes outside | Denied | Denied |
| Write to `/dev/null`; read under the listed paths | Allowed | Allowed |
| Read a file outside the listed paths (the agent's home, `/var`, the stand-in token) | Denied | Denied |
| Read the agent's environment through `/proc/<pid>/environ` | Denied | Denied |
| Agent's canary in the command's environment; write through the leaked descriptor | Absent; denied | Absent; denied |
| `proxy-port`: TCP `connect` to the proxy port, also at another address | Allowed | Allowed |
| `proxy-port`: TCP `connect` to another port; TCP `bind` | Denied | Denied |
| `deny`: TCP `connect` to any port; TCP `bind` | Denied | Denied |
| `unrestricted`: TCP `connect` to any port, UDP send; a write outside is still denied | Allowed; denied | Allowed; denied |
| UDP send under `proxy-port` | Limit (not covered below ABI 10) | Limit |
| `chmod` a file outside (metadata) | Limit (not covered) | Limit |
| Connect to a pathname Unix socket outside the work directory, in every mode including non-Unix socket restriction | Limit (not covered below ABI 9) | Limit |
| Connect to an abstract Unix socket, or signal the agent or another process, outside the sandbox | Limit (not covered below ABI 6) | Denied |
| Non-Unix socket restriction: `socket()` for `AF_INET`, `AF_INET6`, `AF_NETLINK`, `AF_PACKET`, `AF_ALG`, `AF_VSOCK`, and `io_uring_setup` | `EPERM` from the filter, where the control gets the kernel's own answer (`EINVAL` for an invalid socket type, `EFAULT`); in containers `AF_ALG`, `AF_VSOCK` and `io_uring` skip | As at ABI 4 |
| Non-Unix socket restriction: `AF_UNIX` reaches the kernel; TCP to the proxy port, UDP, IPv6 and netlink sockets in real use | Reaches it; denied | Reaches it; denied |
| Non-Unix socket restriction: Unix socket to a proxy in the work directory; ordinary commands | Allowed | Allowed |

The CI job runs on every pull request to `main`; on a runner below ABI 3 its end-to-end step would be skipped with a warning, never reported as passed. At ABI 8 the ABI 6 column applies. Not tested: kernels at ABI 3, 5, 7 or 9 and above (ABI 3 refusal is covered by the capped-ABI unit test), and a Kubernetes pod or a provider node; the probe covers the Kubernetes pod settings, and the launcher awaits provider qualification.

**Limits.** Landlock does not cover metadata changes (`chmod`, `chown`, timestamps), descriptors already open when the restriction is applied (hence `close_range`), or anything the agent passes in on purpose: sandboxing a whole agent protects its surroundings from the agent, not credentials deliberately given to the agent from prompt-injected decisions. Port rules check the port, not the address, so a `proxy-port` command may reach any host on the proxy port; below ABI 10 they do not cover UDP. Below ABI 9 the command can connect to pathname Unix sockets outside the work directory that it can name, and below ABI 6 to abstract sockets and signal processes outside the sandbox. Non-Unix socket restriction does not change that, so a Unix-socket proxy is the only network route only where no other Unix service is reachable from the command: a deployment precondition the pack must ensure (for example, the agent's own sockets and process run as a separate user or outside the pod), or else a separate execution environment. Landlock does not stop kernel exploits (§20.11).

**The workspace is untrusted input.** Files a confined command writes inside the work directory can be executed later by the unconfined agent or its tools: a `.git/config` with `core.fsmonitor` or hooks runs on the agent's next `git status`, an `.envrc` on entering the directory with direnv, a `conftest.py` on the next `pytest`. Landlock confines the command, not what the agent later does with its output. The agent must treat the workspace as untrusted input: run tools there through the launcher too, or with hardened invocations (for example `git -c core.fsmonitor= -c core.hooksPath=/dev/null`, and no automatic environment loading).

**Optionally, mediate system calls.** A pack that hands the command descriptors (for example a connection to a proxy) can install, before `execve`, a second seccomp filter that returns `SECCOMP_RET_USER_NOTIF` for chosen system calls and pass the listener to a supervisor that answers with `SECCOMP_IOCTL_NOTIF_ADDFD` and `SECCOMP_ADDFD_FLAG_SEND`. That is `seccomp-user-notification`, reserved and demonstrated only by the probe; it must not be used as a check-then-continue policy (§20.11).

## 20.9 Future work: delivery of `in-pod-namespaces` (Phase 2)

This section holds the detail behind [ADR-0022](../../adr/0022-in-pod-namespaces-capability.md), an exploratory sketch that defines `in-pod-namespaces` and its qualified configurations but has **no supported delivery route yet**; ADR-0021 delivers only `process-self-restriction`. ADR-0022's intended first route is bubblewrap inside a gVisor implementation of `mediated-kernel` (§20.12), which needs none of this section's node machinery. The unfiltered AL2023 behaviour is recorded as evidence below, not as a setting. The gates and steps that follow design the **filtered implementation** (a NIC-owned seccomp profile on dedicated node groups), which ADR-0022 defers because of its maintenance cost; they are kept for reference in case a pack ever needs the capability where gVisor cannot run. An earlier draft adapted them for AWS by writing the profile and setting `seccompDefault` at node boot, without the Security Profiles Operator, post-bootstrap phase or readiness barrier; that variant is in "ADR-0022: the filtered implementation in full" below.

Phase 2 ships only when all of its **release gates** are met:

- **Gate A, AppArmor mechanism.** The Security Profiles Operator (v1.1.1) can distribute seccomp profiles, but its `AppArmorProfile` API offers only abstract executable, filesystem, network, capability and ptrace rules: it cannot express a `userns` grant, scoped `mount` rules, or raw policy. Until a maintained mechanism can express the required AppArmor policy (upstream SPO support, or another maintained loader), Phase 2 is offered **only on node groups without AppArmor** (for example AWS AL2023). A NIC-owned privileged AppArmor loader would be substantial additional scope and needs its own decision.
- **Gate B, Hetzner autoscaling.** hetzner-k3s v2.4.6 applies per-pool pre-k3s commands to initially created workers, but its autoscaler cloud-init uses the global settings instead of pool overrides. Until that is fixed upstream (and NIC pins the fixed version) or another verified preparation mechanism exists, NIC rejects autoscaling on Hetzner pools that request `in-pod-namespaces`. The gate is closed only by testing a node the autoscaler created.
- **Gate C, versioned profiles.** The seccomp profile exists as a reviewed, immutable artifact (item 5 of §20.9), with adversarial tests passing.
- **Gate D, qualified consumer.** The pinned bubblewrap invocation passes the primitive tests, and one real pack passes the consumer acceptance test (§20.10).

When the gates are met:

1. **Opt-in per node group** through a per-node-group `sandbox` block.
2. **Dedicated placement.** `in-pod-namespaces` node groups are **tainted by default** (`sandbox.nebari.dev/in-pod-namespaces=true:NoSchedule`), following the AWS GPU precedent, which taints GPU node groups rather than only labelling them. A taint is a placement control, not authorization, so admission restricts which namespaces may carry the matching toleration (§20.11, item 2). Pods already running on a node group when it is converted are drained as part of the change. Without the taint and the admission rule, the ADR makes no claim that foundational workloads are kept off these nodes.
3. **Node preparation (layer 1)**, only where needed: on Hetzner, per-pool pre-k3s commands that lift Ubuntu's restriction (preferably a scoped AppArmor `userns` grant rather than the global sysctl) once Gate A allows AppArmor nodes; elsewhere, labels and taints only, unless verification shows otherwise. The kubelet runs with `seccompDefault: true` on these node groups (§20.11, item 1).
4. **Readiness barrier.** New nodes in these node groups register with a startup taint, `sandbox.nebari.dev/in-pod-namespaces-unverified:NoSchedule`, which is removed only once the node has its profiles installed and passes the per-node probe. This covers autoscaled and replacement nodes, which a deploy-time probe does not. The barrier holds only with these invariants:
   - **Consumers tolerate the dedication taint, never the unverified taint.** Only trusted installer, probe and system workloads (the profile operator's daemon, the verifier) tolerate the unverified taint.
   - **Admission rejects wildcard tolerations** (an empty key with `operator: Exists`) and tolerations of the unverified taint from untrusted namespaces, and rejects untrusted direct node assignment (`spec.nodeName`) that bypasses the scheduler.
   - **Each supported autoscaler recognises the unverified taint as a startup taint.** A taint is not a startup taint just because of its name: Cluster Autoscaler only treats its own prefix, or keys passed with `--startup-taint`, that way, and otherwise a scale-from-zero node group can look permanently unsuitable for waiting pods. NIC's AWS autoscaler configuration sets no such flag today, so NIC must configure it, and scale-from-zero is tested per provider.
   - **The bootstrap components have capacity outside the gated pool,** so the verifier and profile installer can always run before any gated node is ready.
5. **Profiles.** NIC owns a complete seccomp policy, not a delta: a `Localhost` profile **replaces** `RuntimeDefault` rather than extending it, and the operator's base-profile mechanism references another stored profile, not the node runtime's generated default. NIC therefore maintains the full allowlist, per architecture, and tracks runtime default changes. The profile:
   - is immutable and **versioned in its name** (`nebari-sandbox-v1`, then `-v2`); a change is a new version, and pods opt into a version explicitly;
   - blocks netfilter configuration by filtering `socket()` on its arguments (netlink netfilter and raw packet sockets), together with the relevant legacy socket options, with stated assumptions about inherited descriptors and compatibility syscall ABIs;
   - makes `clone3` fail with `ENOSYS` so programs fall back to `clone`: seccomp cannot inspect `clone3`'s flags, which are passed in a structure in memory rather than in registers, so namespace flags can only be filtered on `clone` and `unshare`;
   - is installed through the Security Profiles Operator, pinned by digest, with its daemon restricted to these node groups by node affinity and tolerations.

   Rollout semantics differ by mechanism and are documented: a new seccomp version affects only processes started with it, so old versions stay installed until every declared consumer has migrated or the operator explicitly retires the version. Current pod count is not a retirement signal: a Deployment scaled to zero, a CronJob or a KubeSpawner configuration can launch the old version later. Newly added nodes receive every still-supported version, not only the newest; AppArmor policy replacement can change already-running processes, so AppArmor profiles (once Gate A allows them) are never replaced in place.
6. **Qualified invocation.** The primitive is qualified with one pinned bubblewrap version and a fixed invocation of the form `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --ro-bind / / --ro-bind /proc /proc --dev /dev --tmpfs /tmp --die-with-parent --new-session -- <command>` (exact flags fixed in the implementation), with no pid namespace and no fresh procfs.

### Qualified configurations and profile contents (ADR-0022)

ADR-0022 summarises these; the full detail is recorded here.

- **The capability test** proves only that the namespaces can be created: `unshare --user --map-current-user --net -- bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-pid --ro-bind / / --ro-bind /proc /proc --dev /dev --die-with-parent -- true`. It exposes the whole container read-only and is not a sandbox policy.
- **The qualified consumer configuration** is what packs start from and what the acceptance test runs against. It binds only what a command needs and hides everything else, in the form `unshare --user --map-current-user --net -- bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-pid --clearenv --setenv PATH /usr/bin:/bin --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --ro-bind /etc/ssl /etc/ssl --tmpfs <home> --bind <workdir> <workdir> --ro-bind /proc /proc --dev /dev --tmpfs /tmp --die-with-parent --new-session -- <command>` (exact flags fixed in the implementation). Order matters: bubblewrap applies mounts in sequence, so `<home>` must be masked before `<workdir>` is bound when the work directory is inside the home directory; the reverse order hides the work directory (found by the 2026-10-17 probe). `/lib64` is needed on x86, where the dynamic loader lives; without it every command fails with `execvp ...: No such file or directory` (found by the 2026-10-19 EKS probe). The network namespace is created by `unshare` (util-linux) before bubblewrap runs, rather than by bubblewrap's `--unshare-net`, because bubblewrap's own loopback setup fails under gVisor ([gVisor #13438](https://github.com/google/gvisor/issues/13438)); the `unshare`-first form worked on both runc (EKS AL2023) and gVisor, so packs use one form everywhere and need not detect the runtime. `--unshare-pid` with the container's `/proc` bound read-only also worked on both and stops sandboxed commands signalling the agent; under gVisor only, packs may replace `--ro-bind /proc /proc` with `--proc /proc` for a fresh procfs that also hides other processes' command lines (a normal container refuses that mount). The agent's home directory, configuration, mounted secrets, service-account token paths and socket directories are not bound, and `--clearenv` stops credentials in environment variables from passing through.
- **The qualified networked configuration** is the same, except that instead of no network at all, the sandboxed command reaches the network only through a proxy the pack runs outside the sandbox: the pack binds the proxy's Unix socket into the sandbox (for example `--bind <proxy-socket-dir> <proxy-socket-dir>`) and points the command's `HTTP_PROXY`/`HTTPS_PROXY` at a small in-sandbox forwarder to that socket. The sandbox still has its own network namespace with only a loopback interface, so nothing else is reachable, including the cloud instance metadata service. The proxy decides which destinations are allowed and can inject credentials so they never enter the sandbox.

The qualified configurations are secure starting points: packs extend them with the specific paths their tools need (for example a virtualenv, `/usr/local` or a toolchain directory), never with `/` or the home directory, and the acceptance test runs against the extended version.

**The seccomp profile (filtered implementation, deferred).** Under the filtered implementation (ADR-0022's Option 4), NIC would own a complete `Localhost` profile, `nebari-sandbox-v1` (a `Localhost` profile replaces `RuntimeDefault` rather than extending it, so NIC maintains the full allowlist per architecture). It permits the namespace syscalls, makes `clone3` fail with `ENOSYS` (seccomp cannot inspect its flags), and blocks netfilter configuration by filtering `socket()` on its arguments while allowing what bubblewrap needs to bring up a loopback interface. It keeps denying the families that widen the kernel surface reachable from a user namespace: `bpf`, the `io_uring` calls, `keyctl`/`add_key`/`request_key`, `userfaultfd`, `perf_event_open`, kernel-module and `kexec` calls, and `open_by_handle_at`. Seccomp cannot filter which filesystem type a `mount` inside a user namespace uses, so bugs in, for example, overlayfs mounted from user namespaces (CVE-2023-0386) are covered only by kernel patching. A change is a new version (`-v2`) shipped alongside the old ones; because profiles are written at boot, a new version reaches nodes through a node-group rolling update, which replaces nodes one at a time and evicts the sandboxing pods on each, ending users' running sessions. That is acceptable for routine changes, which should be rare. If a profile fix ever has to land faster than a rolling update allows, the planned mechanism is a minimal in-node writer that only copies new profile versions into place, added by amending this ADR. Old versions stay until declared consumers have migrated or the operator retires them.

### ADR-0022: admission policy and alternatives in full

ADR-0022 summarises these; the full text is recorded here.

**Admission policy (filtered implementation).** When a node group enables the capability, the provider installs a small chart containing a ValidatingAdmissionPolicy the way providers already install conditional charts (for example the GPU operator), following [ADR-0006](../../adr/0006-conditional-foundational-software-helm.md)'s provider-driven approach and moving to its shared interface (#349) once that exists; in hardened mode, ADR-0010's admission policy does the same job. Only namespaces labelled for the capability may reference `nebari-sandbox-v*` or tolerate the dedication taint, and only cluster administrators may set that namespace label, so a namespace owner cannot grant it to themselves. In workload namespaces, wildcard tolerations (an empty key with `operator: Exists`) and direct node assignment (`spec.nodeName`) onto these nodes are rejected unless the namespace is labelled; `kube-system` and NIC's foundational namespaces are exempt, because system DaemonSets such as the VPC CNI, kube-proxy, CSI drivers and monitoring agents rely on wildcard tolerations to run on every node. Pack namespaces are normally created by ArgoCD from the GitOps repository, so ArgoCD's identity is among those allowed to set the label: anyone who can write to that repository can grant the capability, which is consistent with ADR-0010's position that repository write is equivalent to cluster administration.

**Alternatives.**

- **Where a filtered profile could come from.** No Kubernetes runtime ships a default profile that allows namespace creation. containerd's default allows `mount`, `unshare` and namespace `clone` only when the container has `CAP_SYS_ADMIN`. Podman's default profile ([`containers/common`](https://github.com/podman-container-tools/container-libs/blob/main/common/pkg/seccomp/seccomp.json), about 1,100 lines of JSON) allows `clone`, `mount`, `pivot_root`, `setns`, `umount2` and `unshare` unconditionally, but CRI-O, which builds on it, removes `clone`, `clone3` and `unshare` for Kubernetes, citing the risk of unprivileged containers creating namespaces. The filtered implementation therefore has three sources for its profile:
  - **NIC writes it** (the design below): full control, including the `clone3` and netfilter restrictions, at the cost of owning a complete allowlist per architecture.
  - **NIC pins Podman's profile:** NIC bundles and tracks an upstream file instead of writing one, but inherits a profile designed for Podman's threat model that CRI-O judged too permissive for Kubernetes, without the netfilter block; any delta NIC adds brings ownership back.
  - **Packs supply profiles through the Security Profiles Operator:** a pack ships a `SeccompProfile` resource and SPO writes it to nodes. NIC installs SPO instead of writing profiles, but the admission policy must then restrict which namespaces may load and use profiles (a custom profile can allow more than `RuntimeDefault`, and Pod Security accepts any `Localhost` profile), each pack's profile needs review, and profiles reach new nodes after they join, so pods can race them (they fail safe). A single shared profile owned by the Pack Specification is a middle ground.
- **Option 6 with a pod user namespace (`pod-user-namespaces`):** with `hostUsers: false`, the pod's `CAP_SYS_ADMIN` applies only inside its own user namespace, and containerd's default profile allows the namespace calls when that capability is present, so containerd keeps owning the filter. It needs an admission exception (Pod Security rejects added capabilities), grants the capability to the whole container, needs containerd 2.x and a kernel with idmapped mounts (not yet confirmed on NIC's EKS images), and does not lift AppArmor's `mount` denial on Ubuntu nodes.
- **Option 5 (the existing pod under gVisor, at the `mediated-kernel` level):** the pod stays as it is, and gVisor intercepts its syscalls in a user-space kernel, so a host-kernel exploit from the pod is far harder. It needs no unprivileged user namespaces, no NIC-owned seccomp allowlist and no AppArmor work, and its default mode needs no hardware virtualisation, so it could reach Hetzner Cloud and AKS sooner. Its costs: installing gVisor and a `RuntimeClass` per provider, compatibility gaps and I/O overhead for some workloads, limited GPU support, and checking that the pack's stack (for example JupyterLab and its kernels) runs under it. Above all, it protects the **host from the pod**, not the **pod's credentials from the agent's commands**, because everything in the pod shares gVisor's kernel. It is the right next capability where kernel-exploit risk matters, and it composes with this one: ADR-0021's composition rules allow namespace tools inside a `user-space-kernel` pod, subject to probing.
- **Option 7 (separate, credential-free gVisor pod per session):** this does meet the threat model: the commands run where the agent's credentials are not, behind a user-space kernel, with no user namespaces on the host. Its costs are a pod start per session, sharing the workspace between the agent's pod and the sandbox pod (which needs shared storage or copying), giving the pack permission to create pods, and re-architecting packs around it; it also needs the same gVisor installation as Option 5. It is a strong candidate once `user-space-kernel` exists, and the [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project could provide its request layer. It is not chosen first because it depends on that capability and on a larger change to how packs work.

### ADR-0022 evidence: bubblewrap on the host kernel without a filter

An earlier draft of ADR-0022 made this its first implementation; ADR-0022 now records it as an observation only. **It is not a supported NIC setting**: NIC neither publishes nor checks it, because doing so would make running with no syscall filter an endorsed configuration and turn any future `seccompDefault` hardening into a breaking change.

- **Observed on AL2023 (EKS 1.34 x86, 2026-10-19):** with `seccompProfile` unset and the kubelet's `seccompDefault` off (the EKS default), the capability test and both qualified configurations worked and hid environment, home-directory, Secret and service-account-token canaries, the agent's socket and the network. The same pod with `RuntimeDefault` failed. The run also found that the configurations need `/lib64` on x86.
- **Not working on Hetzner or AKS Ubuntu:** AppArmor's user-namespace restriction and the default container profile block it (Hetzner observed 2026-10-25: `Failed to make / slave: Permission denied`).
- **Fragile even where it works.** `seccompProfile: RuntimeDefault` is a common chart default and scanner recommendation, and in a JupyterLab-based pack the user's pod is generated by JupyterHub from configuration the extension author may not control; either blocks bubblewrap, whose error ("No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces") points at the wrong cause.
- **Checks that were designed and dropped with it:** a per-node `nic deploy` check reading `seccompDefault` through `/api/v1/nodes/<node>/proxy/configz` and requiring an AL2023 `osImage`, a provider-reported "expected to allow" flag for `nic validate`, and a published setting "leave `seccompProfile` unset".

**Inside gVisor (the intended first route).** The same qualified configurations, with the network namespace created by `unshare` first, worked under gVisor on a local Ubuntu 24.04 VM (2026-10-17), EKS AL2023 x86 and arm64, and Hetzner Ubuntu 24.04 (2026-10-25), with a pid namespace and a fresh `/proc` showing only the sandbox's processes; Landlock was absent and the pod's seccomp profile ignored. Run-by-run results are recorded with the gVisor evidence in this section.

### ADR-0022: the filtered implementation in full

This is ADR-0022's deferred alternative (Option 4), recorded from an earlier draft and not being pursued; ADR-0022's intended first route is bubblewrap inside gVisor. Were it built, the published seccomp setting for the capability would be a `Localhost` profile and the deploy check would confirm the profile is installed.

**Design.**

1. **Dedicated node groups.** Because bubblewrap runs inside the pack's pod, the pod hosting the agent must itself run on an `in-pod-namespaces` node group, opted in through a per-node-group `sandbox: { capabilities: [in-pod-namespaces] }` block. "Dedicated" means opted in, not necessarily new: an operator can opt in the existing user node group, provided foundational workloads stay off it. Opting in a shared group affects every pod on it: each needs the dedication taint's toleration, so its namespace must be labelled for the capability, and each moves from no filter to `RuntimeDefault` under `seccompDefault`, so it must be tested there. The provider taints the node group `sandbox.nebari.dev/in-pod-namespaces=true:NoSchedule`, following the AWS GPU precedent, and NIC labels its nodes `nebari.dev.node-restriction.kubernetes.io/sandbox-in-pod-namespaces` through the API after registration (ADR-0021: placement labels are never writable by nodes, and kubelets cannot set this prefix). Adding the capability to an existing node group is a node-group replacement. A GPU node group with the capability needs its GPU image qualified separately.
2. **Boot-time node configuration.** The node's bootstrap writes the profile files into the kubelet's seccomp directory and sets `seccompDefault: true` before the kubelet starts, so replacement and autoscaled nodes are ready when they join, with no installer and no readiness barrier.
3. **A versioned profile**, `nebari-sandbox-v1`, as described above.
4. **Admission**, as described above.
5. **Deploy-time check.** `nic deploy` checks live nodes against the node group's prediction from an image table of qualified images (kernel version and OS image from `node.status.nodeInfo`), reads each sandbox node's configz to confirm `seccompDefault` is on, and reports results in `nic outputs`. A node missing the profile file fails safe: pods that reference it do not start there.
6. **Pack settings.** Sandboxing pods carry the node selector and toleration, reference the published profile (`seccompProfile: Localhost`, plus an `appArmorProfile` reference on AppArmor nodes once Hetzner is supported), and run in a labelled namespace. The profile applies to the whole container that references it, so a pack can keep the agent in its own container.

**Concrete work.**

- **NIC's EKS module (`terraform-aws-eks-cluster`):** per-node-group bootstrap configuration (a nodeadm `NodeConfig` setting kubelet `seccompDefault`, plus cloud-init writing the profile files), and node-group labels and taints. Today the module uses its pre-nodeadm hook only for the extra CA bundle.
- **NIC's AWS provider:** plumbing for the `sandbox` block, the image table and profile versions. NIC's EKS node groups already require IMDSv2 with a hop limit of 1 (observed 2026-10-19), so pods cannot reach the instance metadata service and the node's IAM credentials; this must be kept on sandbox node groups (later also enforceable with NetworkPolicy once [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) lands).
- **Cluster autoscaler:** confirm scale-from-zero works for tainted, labelled sandbox node groups.
- **System DaemonSets:** `seccompDefault: true` and the metadata-service hop limit also apply to the VPC CNI, kube-proxy, CSI drivers and monitoring agents on these nodes; each must be tested under `RuntimeDefault` and with hop limit 1 (some components, such as the EBS CSI node plugin depending on its configuration, look up instance metadata), with any needed exceptions documented.
- **Pack workloads:** the pack's main workload must be tested under `nebari-sandbox-v1` itself, since the profile covers the whole container.
- **Admission policy, profile files and the image table** in NIC's repository, reviewed as security policy.

**Verification.**

- **Per node image, by hand:** before an image enters the table, a probe confirms the capability test and both qualified consumer configurations work with the profile, a pod without the profile on the same node cannot create a user namespace, netfilter and raw-socket creation fail inside a new user namespace, and Unix sockets on the container's filesystem are not reachable from the qualified configurations.
- **At deploy:** the consistency check described above.
- **Consumer acceptance, before the first delivery:** a consumer must show, with the capability in use, that credential canaries in the agent's environment, files and mounted secrets are unreadable by sandboxed commands, inherited descriptors are closed or allowed, networking is denied or limited to the pack's proxy, the instance metadata service is unreachable, its pod settings are correct, and it refuses unsandboxed fallback. Until an upstream pack adopts the capability, a small reference consumer in NIC's user-journey tests fulfils this.

### ADR-0023: mechanisms in full

ADR-0023 states these as requirements; the mechanisms are recorded here. Each is a design target, not yet implemented or tested as NIC code. Earlier drafts preserved running sessions across upgrades, had failed nodes retire themselves, and then upgraded nodes in place; review showed none could be made reliable with the tools available (see "Rejected after review" below). The design rests on two rules: **a node's runtime never changes after it joins**, and **no pod is placed on a node that only the node itself has vouched for** (ADR-0021's placement-label rule, adopted in the 2026-10-28 revision).

**Artifact and trust.** NIC publishes one OCI image per gVisor release and architecture containing the extracted `runsc`, `containerd-shim-runsc-v1` and `gvisor-bin/` helpers and a per-file SHA-256 list. Shipping extracted binaries removes the boot step's dependency on `bzip2`, which Hetzner's image lacks. Trust is checked in stages: NIC's image build verifies gVisor's published checksum of the release archive before extracting it; the node hashes the **fetched manifest** and compares it with the digest NIC pinned before trusting any layer descriptor in it (fetching a URL that contains a digest is not itself verification); it then verifies the layer against the manifest, and each installed file against the per-file list. Each stage caught its tampering case in a local probe (2026-10-27, below). NIC publishes to a public registry; operators with private registries mirror the image and point NIC's configuration at the mirror.

**Release layout.** Each node installs exactly one release, once, at boot. The runtime handler names that release's directory directly; there is no `current` link, no switching and no rollback on the node, so every sandbox on a node runs the release in its label.

**Boot-step dependency order (per provider).**

1. Trust: on clusters with a `trust_bundle`, the node's OS trust store is installed first (NIC's existing pre-bootstrap hook on AWS), so a TLS-inspecting proxy does not break the fetch.
2. Credentials: on AWS, a registry login from the node role, passed to `ctr` explicitly together with any mirror host, since `ctr` does not read the kubelet's credential providers or the CRI plugin's registry configuration. On Hetzner, an anonymous token for a public registry or the mirror's credentials, used by `curl` against the registry API before k3s exists.
3. Fetch and verify the manifest and layer by digest, with a bounded timeout and a fixed number of retries.
4. Install into `/opt/nic/gvisor/<release>/` (binaries and `gvisor-bin/` together, since `runsc` finds its helpers beside itself), written under a temporary name and renamed into place once every file matches the per-file list.
5. Register the runtime handler, pointing at that directory (nodeadm containerd configuration merge on AWS; k3s's `config-v3.toml.tmpl` with `{{ template "base" . }}` on Hetzner). runsc's own options go through the handler's `TypeUrl` and `ConfigPath`; the runsc shim silently ignores `BinaryName`.
6. Write a marker file recording the installed release. The outcome is decided by this marker, never by shell error handling (`set -e` is ignored inside `( … ) || …`, which in the probe logged success after a failed pull).
7. After containerd, the kubelet and the CNI are ready (on EKS the first check on every good node failed with `cni plugin not initialized` when it waited only for the kubelet), a node service runs the **end-to-end check**: it starts a test pod sandbox and container **through the CRI** with runtime handler `runsc` (`crictl runp --runtime runsc`, then `crictl create` and `start`; `k3s crictl` on Hetzner), as a non-root user with every capability dropped and the published seccomp setting, and checks that it reports gVisor's kernel (matching `gvisor` in the release string, not a version: one release reports `4.19.0-gvisor`) and passes ADR-0022's capability test. This resolves the CRI plugin's `runtimes.runsc` entry and its options as the kubelet does. `ctr run --runtime io.containerd.runsc.v1` was rejected: it names the shim directly, so a missing or broken handler entry passes it while pods fail (observed locally on 2026-10-27 for a removed entry, a `runtime_type` typo and a shim configuration naming a missing binary, each of which failed the CRI check), and under runsc it cannot write to standard output through non-terminal pipes (on EKS it failed even with a good entry); `runsc do` tests even less. The check retries a bounded number of times and waits for the test container to exit rather than for a fixed time: on EKS a fixed wait failed 20–40% of good runs, and with both changes 20 of 20 passed.
8. Using the node's own credentials, the service records only failure: the label `sandbox.nebari.dev/gvisor` set to `failed` and a Kubernetes event; on success it writes an informational `sandbox.nebari.dev/gvisor-release` label that nothing routes on. On Hetzner the boot and node steps run as cluster-wide commands that act only on nodes whose name matches an opted-in pool exactly (static nodes are named `<cluster>-pool-<pool>-worker<N>` and autoscaled ones `<cluster>-<pool>-<hex>`, so a pool `sandbox` does not match `sandboxauto`). This depends on hetzner-k3s's node-naming convention, which is why the hetzner-k3s version is validated (below), and because hetzner-k3s per-pool commands do not reach autoscaled nodes. On k3s the node service is ordered after `k3s-agent` and runs at every k3s start. Control-plane groups cannot opt in, so none of this runs on them.
9. **Placement.** A small NIC-owned component in the cluster, whose only write permission is patching nodes (RBAC cannot narrow that to labels, so the component is pinned by digest and runs on system nodes), sets `nebari.dev.node-restriction.kubernetes.io/sandbox-gvisor: "true"` on a node once (a) the provider's records show the node belongs to an opted-in group, through a trustworthy node-to-instance binding (on AWS the instance's Auto Scaling group, with the instance identity confirmed from the EC2 API rather than taken from the node's own `spec.providerID` alone; on Hetzner the server's pool in the Hetzner API), never the node's own labels, and (b) a check pod pinned to the node with the published settings reports gVisor's kernel. It removes the label when the node reports `sandbox.nebari.dev/gvisor: failed`. The kubelet cannot set or change labels under this prefix, even at registration, so neither a failed node nor a rogue one can attract gVisor pods through its own credentials. This depends on the Node authorizer and NodeRestriction, verified per provider with a negative test using a kubelet identity, and does not cover a compromised node that already carries the label (ADR-0021's placement guidance).

**Why routing uses a label nodes cannot write.** Earlier drafts routed on `sandbox.nebari.dev/user-space-kernel` set to `"true"` on every node of an opted-in group through the provider's node-group labels, with a failed node relabelling itself `"false"`. That worked with both providers' plumbing and autoscaler templates, but the label was writable by the node: any compromised node could set it, and on Hetzner, where the metadata service exposed the k3s join token, a rogue machine could register as a node of an opted-in pool and attract every sandbox pod. On k3s it also showed `"true"` for about 3 s after each agent restart, because k3s re-applies its command-line labels at every start. A label under `node-restriction.kubernetes.io/` closes all three: nodes cannot write it and k3s does not re-apply it. Two other alternatives were rejected earlier and stay rejected. A selector naming the pinned release strands pods: the `RuntimeClass` admission plugin copies the selector into each pod when it is created. A failure taint cannot be set by the node: node-restriction admission does not let a node modify its own taints (observed on EKS, 2026-10-26).

**Limits.** The label is removed only after the node reports failure, so a gVisor pod scheduled between a k3s restart (or a runtime fault) and the removal fails to start and must be recreated; it never runs unsandboxed. If the node service itself fails, the node keeps its label and gVisor pods sent there fail to start. The labeller is a single point of placement: while it is down, new nodes are not labelled and gVisor pods wait. Scale-from-zero needs the label in the autoscaler's template although no kubelet sets it: on AWS through the Auto Scaling group's `k8s.io/cluster-autoscaler/node-template/label/...` tags; on Hetzner, where hetzner-k3s builds templates from pool labels (passed to the kubelet, which would refuse this prefix) or a live node, it is not yet qualified, so opted-in pools keep a minimum of one node.

**Failed nodes and scaling.** The install retries with backoff for a bounded period (30 minutes proposed); on success it clears its failure label, the labeller (re)applies the placement label after its own check, so transient failures (a registry blip) heal on the same node. If it still fails, the node keeps its failure label, never receives the placement label, emits an event and **remains in service for its other workloads**: a failure of an optional runtime never takes a node down. NIC does not retire failed nodes. The cluster autoscaler records a scale-up as successful once the node registers and reports Ready, so nothing a node does afterwards (powering off, stopping its kubelet) turns it into a failed scale-up that triggers backoff; powering off would also take the node's other workloads with it, on AWS the Auto Scaling group would replace a stopped instance immediately, on Hetzner a stopped server is still billed, and enough unready nodes would make the autoscaler pause scale-ups for the whole cluster. The consequence is accepted and stated: during a persistent failure (for example a registry outage), a pending gVisor pod can grow an opted-in group to its maximum with nodes that serve other workloads but no gVisor pods, so operators set modest maximums on opted-in groups. Automatic replacement and stopping scale-up for a failing group need a component running in the cluster, which is future work. Observed 2026-10-27: on EKS a pending gVisor pod grew a failing group from 0 to its maximum of 2 and then stopped; on Hetzner the group stayed at one node, because the autoscaler built its template from the live, failed node.

**Deploy-time verification.** When a mapping entry resolves to gVisor, `nic deploy` runs a short-lived smoke pod on every labelled node of every opted-in group (bounded by group size), from an image NIC publishes alongside the gVisor artifact, with the published `runtimeClassName`, the published pod settings and a pin to that node. It must report gVisor's kernel (the kernel release inside differs from the node's `kernelVersion` and names gVisor, which a VM guest would not) and, when `in-pod-namespaces` is also required, pass ADR-0022's capability test. Like every check here it is a diagnostic, not attestation. This exercises admission, `RuntimeClass` scheduling and the pod's security context, which the node-side check cannot. A failure fails the deploy. Groups at zero nodes are reported as unverified until they scale up. **Verification-only mode.** On `existing` clusters, and kind clusters whose nodes the operator prepared, NIC owns neither the node groups nor the runtime (`pkg/providers/cluster/existing` treats infrastructure as externally owned). The operator names the `RuntimeClass` and its level in the sandbox configuration, and NIC publishes that exact name in the mapping entry; NIC checks that it exists, runs the smoke pod on every node it can schedule to, and never creates, changes or deletes it. The opted-in-group and toolchain checks do not apply.

**Upgrades.** ADR-0023 no longer depends on a particular rollout mechanism; it states lifecycle invariants (unverified nodes never run gVisor pods; a broken runtime never causes unsandboxed fallback; semantics changes are explicit; security updates have a path; interrupted operations have documented recovery). The first operating model meets them with the providers' own node replacement: on AWS a release change updates the group's launch template and the managed node group replaces nodes; on Hetzner, where gVisor runs only on autoscaled pools, new nodes boot the new release and the operator drains and deletes the old ones. New nodes receive gVisor pods only once labelled, so a broken release leaves pods Pending rather than on broken nodes; what it costs is capacity and per-session sandboxes on drained nodes, which end. Pods without a controller (per-session sandboxes, interactive servers started by a hub) must be recreatable by their pack; that is the pack's acceptance test. A blue/green mechanism that keeps capacity and verifies a whole new group before moving work (sketched in [ADR-0024](../../adr/0024-immutable-node-pool-rollouts.md), [§21](21-node-pool-rollouts.md)) is one candidate if sessions or capacity must survive upgrades; its inputs from this design would be the gVisor release and artifact digest, the installer version and the containerd handler configuration.

**Toolchain qualification.** The support matrix names exact versions: CPU architecture, node OS family, containerd, and on Hetzner the hetzner-k3s release and the k3s release. NIC accepts a hetzner-k3s binary from `NIC_HETZNER_K3S_PATH` or `PATH` without checking its version today (`pkg/providers/cluster/hetzner/resolve.go`), and resolves a short Kubernetes version to the latest matching k3s release at deploy time (`pkg/providers/cluster/hetzner/k3s.go`). When the capability is required, `nic validate` and `nic deploy` resolve both before creating nodes and fail if either is outside the matrix, so an unchanged config cannot silently move to an unqualified installer or k3s release that breaks pool-name matching or the containerd template.

**Ownership and lifecycle.** NIC creates and updates the `RuntimeClass` `nebari-gvisor` (handler `runsc`, labelled `sandbox.nebari.dev/level: mediated-kernel`), the node services and the labeller, marking them as NIC-managed. It refuses to adopt a `RuntimeClass` of that name it did not create. Requiring, provisioning and retiring are separate. Mapping entries only gate resolution; dropping it uninstalls nothing. Provisioning follows the opted-in groups. NIC never deletes the `RuntimeClass` on its own, because packs may still name it, and deleting it would make replacement pods fail admission. With no group opted in, the `RuntimeClass` stays (its pods remain Pending with a scheduling reason) and `nic deploy` warns. Retiring it is an explicit operator action, deferred until packs declare what they consume. None of this applies in verification-only mode. A failure to create or update any required sandbox resource fails the deploy, unlike the warning-only handling of some foundational installs in `pkg/nic/deploy.go`.

**Diagnosing a stuck gVisor pod.** A gVisor pod Pending with an unmatched node selector usually means no node carries the placement label yet: the labeller has not verified one, or every node failed. A pod in `ContainerCreating` usually means a failed install on a node that has not yet reported it. The operator checks the node's labels (`nebari.dev.node-restriction.kubernetes.io/sandbox-gvisor`, `sandbox.nebari.dev/gvisor`, `…-release`), the labeller's events, the install marker and boot-step log on the node (`/var/lib/nic/gvisor/marker` and `/var/log/nic-gvisor-install.log` in the proposed layout), the pod's events (`failed to resolve runtime path` points at the handler), and gVisor's own logs, enabled per node through the runtime handler's options when needed. `nic outputs` lists failed and unlabelled nodes.

**Delivery alternatives considered.** Downloading from gVisor's release bucket at each boot needs no NIC artifact, but makes every boot depend on an external site, which proxies and restricted egress break, and the release format has already changed once. A NIC-controlled copy in an S3 bucket created with the cluster works on AWS only. Custom node images with gVisor baked in remove the download at boot but need a node-image pipeline per provider. A privileged DaemonSet installer is easy to ship but is a privileged component in the cluster that restarts containerd on running nodes and races new nodes joining unless a startup taint holds them back.

**Rejected after review.**

- *A canary promoted on Ready or on the node's own label:* does not exercise the path consumers use.
- *An in-place swap that keeps running sessions:* could not be made crash-consistent or account for which release each running sandbox uses.
- *In-place upgrades with draining,* through the system-upgrade-controller on Hetzner (per-release directories, an atomic `current` switch, a quiescence check, one attempt per node recorded before the drain): each review found a failure the protocol did not cover. In v0.18.0 the controller keeps a node with failing jobs in its applying list ahead of other candidates, so a failed node holds the only slot of a `concurrency: 1` plan indefinitely, and a running job whose node leaves the plan's selection is deleted midway, so a selector-based retry limit kills upgrades. Rollback needed the same quiescence check as the forward switch, and `runsc list` is a snapshot, not a barrier against new sandboxes. Recovery after a killed job needs the API it may have lost. Replacing node groups removes all of these.
- *A managed node group update limited to one node at a time on AWS, after a temporary canary group:* rejected while placement followed a node-written label, because the update could replace healthy nodes with Ready but broken ones that still attracted pods. With placement only after cluster-side verification, the provider's own update is the first operating model ("Upgrades" above); it can still drain working nodes faster than new ones are verified, which costs capacity, not safety.
- *Routing on a node-written group label:* see "Why routing uses a label nodes cannot write".
- *Replacing nodes one by one (drain and delete, letting the autoscaler recreate them):* gives no point at which a new node is verified before the next is removed, and on AWS cannot be gated per node.

**Verification checklist.** Before a provider, architecture, node OS family and toolchain are listed, and on every gVisor or k3s upgrade, the probe (sandbox probe brief, Part C) runs with NIC's implementation and covers:

- bubblewrap's qualified configurations and a fresh `/proc` inside gVisor, canaries hidden, no network from inside the sandbox, Landlock reported absent, `RuntimeDefault` ignored;
- the node-side end-to-end check failing for each cause it should catch (missing helpers, a removed or broken CRI `runtimes.runsc` entry, a wrong security context);
- Kubernetes volume updates and NetworkPolicy enforcement for gVisor pods;
- PVC-backed homes on each supported storage backend (FSx for OpenZFS, EBS, and whatever Hetzner uses for homes), including with `dedicated: true`;
- scale-from-zero alongside other pool labels, and a live autoscaled node under exact pool matching on Hetzner;
- a deliberately failed install: the node reports failure, is never labelled for placement (or loses the label), keeps serving other workloads and receives no gVisor pods, including across k3s agent restarts; with a persistent failure, the group grows no further than its maximum;
- a node outside any opted-in group (for example one registered by hand with the join token) never labelled by the labeller, and a node trying to set the placement label itself refused;
- the deploy-time smoke pods on every node of every opted-in group, and groups at zero reported as unverified;
- a release change through each provider's node replacement with gVisor pods created continuously: none lands on an unlabelled node, a deliberately broken release leaves them Pending, reverting it recovers, and the pack's acceptance test (recreating its controller-less pods, with a PVC-backed workspace) passes on the new nodes;
- dropping the mapping entry leaving the `RuntimeClass` in place, and an `existing` cluster with an operator-installed `RuntimeClass` verified without being changed and its name published;
- an unqualified hetzner-k3s binary or k3s release rejected before nodes are created;
- pods under memory limits with the configured `RuntimeClass` overhead, at realistic sizes, and JupyterLab timings.

**Support matrix.** `InfraSettings.Sandbox` reports qualification per provider, CPU architecture, node OS family and container runtime version (today: AWS AL2023 x86 and arm64 with containerd 2.x; Hetzner Ubuntu 24.04 x86, autoscaled pools only, with the k3s versions whose `config-v3.toml.tmpl` format the install targets, re-probed on each k3s upgrade), and `nic validate` rejects opted-in groups outside it.

### ADR-0023: probe evidence in full

#### Evidence summary

Longhorn and in-place upgrade results below are kept as a record; NIC is phasing Longhorn out, and ADR-0023 now upgrades by replacing node groups rather than in place.

Probe runs (gVisor `release-20261012.0`, non-root pods with every capability dropped) on a local Ubuntu 24.04 VM, EKS 1.34 AL2023 x86 (with EFS, and with FSx for OpenZFS from [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705)) and Hetzner Ubuntu 24.04 x86 with k3s, using test-only installers:

| Claim | Result |
|---|---|
| Bubblewrap's qualified configurations run inside gVisor and hide canaries, the agent's socket, the network and `169.254.169.254` | Holds on all three; the final configuration (with a required fresh `/proc`) ran on Hetzner, the earlier variant on the VM and EKS. Bubblewrap's own `--unshare-net` fails ([gVisor #13438](https://github.com/google/gvisor/issues/13438)), which the qualified configurations avoid |
| A fresh `/proc` and pid namespace work inside gVisor | Holds: only the sandbox's processes are visible and the agent cannot be signalled |
| Tool-execution sandbox pods work as root under gVisor (EKS, 2026-10-27) | Holds: commands over SSH and files over SFTP from a separate agent pod, PVC-backed workspace; `NET_RAW` removed even when requested; without `NET_ADMIN` no route or address changes; host-side NetworkPolicy, once enforced, held against root (§22) |
| Boot-time installation on opted-in pools, including autoscaled-from-zero nodes | Holds on Hetzner (pre-k3s command) and AWS (node bootstrap pulling from ECR) for fresh nodes; upgrading existing nodes not tested |
| A failed install never runs a pod unsandboxed | Holds on EKS, Hetzner and locally (a pod sent to a failed node stays in `ContainerCreating`); a failed node labels itself `"false"` and keeps running other pods; `status.runtimeHandlers` still lists `runsc`, so it cannot detect failure |
| Storage with real ownership works | FSx for OpenZFS (via `fsGroup`), EBS gp3, Hetzner Cloud Volumes and Longhorn volumes work, including on tainted groups; EFS access points as NIC configures them fail |
| File watching across pods (local VM, 2026-10-27) | Polling only: a process in a gVisor pod gets inotify events only for changes made in its own sandbox; changes from other pods, of any runtime and on NFS or local storage, are seen only by polling. Changes made in gVisor do reach runc pods' inotify |
| Tooling and integration | pixi, shared memory, Dask, file watching within one sandbox, `debugpy`, C builds, SQLite WAL, sandboxed Chromium, NetworkPolicy, volume updates and `dedicated` routing work; attaching a debugger to an unrelated process is refused |
| Cost | Metadata-heavy work on network homes 1.4–1.8× slower; JupyterLab startup 0.8–1.6 s slower; idle overhead about 18 MiB per pod; under a 1 GiB limit a JupyterLab kernel reached 32–48 MiB less than under runc, more than recovered by a 64 MiB `RuntimeClass` overhead |
| arm64 (EKS Graviton, 2026-10-27) | Holds: install, node check and ADR-0022's qualified configuration inside gVisor as on x86 |
| Composition | Landlock unavailable inside gVisor; pod seccomp profiles ignored without `--oci-seccomp` |
| A node can record its install result itself (EKS spike, 2026-10-26) | With only its own credentials, a node could change its own labels, including overwriting its node-group label, and the change survived a kubelet restart; it could not modify taints (`not allowed to modify taints`), touch other nodes, or use reserved prefixes |
| On k3s, a node's own label change is durable (Hetzner, 2026-10-27) | No: the node could set its label to `"false"`, but a k3s agent restart put it back to `"true"`, because k3s re-applies its command-line labels at every start; self-tainting was refused, as on EKS |
| gVisor can be upgraded in place (local k3s and Hetzner, 2026-10-27) | Holds through hetzner-k3s's system-upgrade-controller: the node moved between releases in about 15 s; a pod started on the old release kept running, accepted `kubectl exec` and deleted cleanly; new pods ran on the new release; an upgrade to a missing release left the node working on its current one, while the controller kept retrying |
| Memory under a tight limit (local k3s and Hetzner, 2026-10-27) | Under a 512 MiB limit, an allocator was killed at 480 MiB under gVisor against 496 MiB under runc (about 3% less); writing and reading back 1.5 GiB of files completed under both; both kill the whole container |

Not yet tested: NIC's own implementation (including the `curl`-based image fetch on Hetzner and re-asserting the label at every k3s start), rolling upgrades on AWS, a live autoscaled node under exact pool matching, GPUs (`nvproxy`), arm64.

The run-by-run detail follows.

#### Local probe (2026-10-17)

On an Ubuntu 24.04 VM (kernel 6.8, arm64; the OS and kernel Hetzner uses) with Docker and gVisor `release-20261012.0`, non-root and with every capability dropped (2026-10-17; raw output not committed):

- Bubblewrap's qualified configurations from ADR-0022 work inside gVisor and hide environment, home-directory and service-account canaries, sockets outside the bound paths, and the network (including `169.254.169.254`), with one workaround: bubblewrap's own `--unshare-net` fails because gVisor pre-configures the new namespace's loopback ([gVisor #13438](https://github.com/google/gvisor/issues/13438), open; [bubblewrap #745](https://github.com/containers/bubblewrap/issues/745), open). Creating the network namespace first with `unshare --user --map-current-user --net` and running bubblewrap without `--unshare-net` works.
- A sandbox can have its own pid namespace and a fresh `/proc`, which a normal container cannot. That closes the two limits ADR-0022 states: sandboxed commands can no longer signal the agent or read other processes' command lines.
- Landlock is not available inside gVisor (`ENOSYS`).
- gVisor ignores the pod's seccomp profile unless configured with `--oci-seccomp`; with it, `RuntimeDefault` blocks bubblewrap.
- JupyterLab startup and notebook execution ran with little overhead (about 0.1–0.25 s). Metadata-heavy work on an NFS-backed home directory was 1.5–2.3× slower than without gVisor, on top of network latency that already made it slow; large sequential I/O was unaffected.

#### EKS probe (2026-10-19)

On an EKS 1.34 cluster deployed with NIC (AL2023 x86, kernel 6.12, containerd 2.3.5; 2026-10-19), with gVisor `release-20261012.0` installed on one node group behind a `RuntimeClass`:

- Every bubblewrap result above held, including the `--unshare-net` failure and its workaround, the fresh `/proc`, `RuntimeDefault` being ignored, and Landlock's absence.
- The node's `status.runtimeHandlers` listed `runsc` once containerd was configured. (The 2026-10-25 run showed this is not proof of a working install; see below.)
- With NetworkPolicy enforcement turned on in the VPC CNI (it is off in NIC's EKS clusters today, see #691), default-deny egress blocked gVisor pods exactly as it blocked runc pods, and an allow rule restored only the allowed destination.
- Secret and ConfigMap updates reached gVisor pods within the kubelet's sync period (about 45 s in this run).
- The instance metadata service was unreachable from gVisor pods, because NIC's EKS node groups require IMDSv2 with a hop limit of 1.
- With home directories on EFS, metadata-heavy work was 1.5–1.8× slower under gVisor than under runc (for example `pip install` 192 s against 132 s), on top of EFS latency that already dominated; JupyterLab started about 0.7 s slower.
- **EFS access points broke gVisor pods.** With NIC's `efs-sc` storage class, each volume's access point owns its directory as its own UID (50000 and up) with mode 700. A runc pod running as UID 1000 can write there, because the kernel's NFS client leaves the decision to EFS, which maps every request to the access point's UID. gVisor checks permissions itself against the owner and refuses. A storage class whose access points use the pod's UID and GID worked under both runtimes.
- The gVisor release ships as one archive per architecture; `runsc` needs the `gvisor-bin/` helper binaries from it (including `gvisor_sentry`) installed beside it.

#### EKS: tool-execution sandbox under gVisor (2026-10-27, second run)

EKS 1.34 deployed with NIC from `main`; a probe `gv` group (m6i.large, gVisor `release-20261012.0` installed at boot, tainted); `RuntimeClass` overhead 64 MiB. Raw output is not committed; the network-policy and admission results from the same run are in §22, and the Kata results in §23.

- **Pattern:** an Alpine sandbox pod running sshd and sftp-server as root, `automountServiceAccountToken: false`, no Secrets (the authorised key in a ConfigMap), a 2 GiB gp3 workspace PVC; an agent pod in another namespace held the private key.
- **Tool calls:** `ssh` ran commands as UID 0 (kernel `4.19.0-gvisor`); `sftp` wrote and read `/workspace/note.txt` and a later command edited it.
- **Reach before any policy:** no service-account token; an IMDSv2 token request failed (hop limit 1) and IMDSv1 answered 401; the Pod Identity agent answered 400; the API server and the node's kubelet answered 401; the node's port 22 and direct internet were reachable, which is why ADR-0025's host-side policy is required.
- **Root's control of its own network:** with default capabilities, route, address and MTU changes were refused; gVisor removed `NET_RAW` even when added (raw sockets failed) and its iptables did not initialise; with `NET_ADMIN` root could change routes, MTU and addresses inside the sandbox; writing `/etc/resolv.conf` worked. None of these bypassed the enforced policy.

#### EKS: node check, failures, storage, memory and arm64 (2026-10-27)

EKS 1.34 in us-east-1 deployed with NIC from `main`, AL2023 x86 (`m6i.large`) and arm64 (`m7g.large`) groups, gVisor installed at boot by a probe launch template. Raw output is not committed.

- **CRI node check:** passed 10 of 10 on x86 and arm64; failed with the CRI `runtimes.runsc` entry removed (`no runtime for "runsc"`) and passed once restored. It needs the CNI ready, bounded retries and a wait for the container to exit (above). `ctr run --runtime io.containerd.runsc.v1` failed with or without the entry.
- **Failed install:** a wrong pinned digest was rejected on each of three attempts; the node labelled itself `"false"` about 40 s after boot, before it was Ready; a runc pod ran there; a pending gVisor pod grew the group from 0 to its maximum of 2, where the autoscaler stopped.
- **Group taints and fixed size (ADR-0024):** a taint added through NIC's module was an in-place change that reached the existing node; `update-nodegroup-config` added and removed taints on the existing node within 60 s. A 1/1/1 group was never scaled ("max size reached"), and a replacement for a terminated instance registered with the group's taint.
- **Artifact trust against ECR:** manifest against the pinned digest, layer against the manifest and files against the list, each catching its tampering case.
- **Storage:** EBS gp3 and FSx for OpenZFS homes on a tainted group, written by UID 1000 with `fsGroup` 1000; setgid inheritance works; EBS throughput matched runc.
- **File watching:** as locally, a gVisor pod got no inotify events for changes from other pods, even on the same node; polling saw them after 2–60 s on NFS.
- **Memory:** with a 1 GiB limit a JupyterLab kernel reached 736 MiB under runc, 704 MiB under gVisor and 768 MiB under gVisor with a 64 MiB overhead; gVisor's memory is charged to the pod's cgroup, so the overhead raises the effective limit. An out-of-memory kill restarted the whole container, server included, under both runtimes.
- **arm64:** the aarch64 artifact verified and installed, the node check passed, and ADR-0022's qualified configuration behaved as on x86 (Landlock `ENOSYS`).
- **Module:** custom per-group launch templates must keep NIC's node and VPC-endpoint security groups; without them `nodeadm` could not reach the EC2 API and nodes never joined.

#### Hetzner: pool lifecycle, failures, storage and memory (2026-10-27)

hetzner-k3s v2.4.6 driven directly (NIC lacks pool labels and boot commands), Ubuntu 24.04 x86, k3s v1.34. Raw output is not committed.

- **Taints (ADR-0024):** changing a pool's taint and re-running `create` restarts the k3s agent with the new flag, but the existing node keeps its old taint: k3s applies taints only at registration. Taints added or removed through the API survive agent restarts. New nodes register with the configured taint.
- **Fixed size:** hetzner-k3s rejects min = max. With min 1 and max 2 the autoscaler stopped at 2 and built its template from a live node; a server deleted through the API was replaced in about 100 s with the configured taint.
- **Pools:** adding a pool by re-running `create` works and updates the autoscaler's arguments (the install script re-runs on every static node, restarting k3s only where its flags changed); removing a pool from the configuration leaves its servers and nodes, which draining, deleting the node and deleting the server through the APIs retire.
- **k3s upgrades:** the label `plan.upgrade.cattle.io/k3s-agent=disabled` excluded a pool from the upgrade, but there is one cluster-wide `k3s_version` and the next `create` reinstalled it on every static node, the excluded pool included. hetzner-k3s's upgrade hung on k3s 1.34 until its plan selector was patched (see Related issues in ADR-0023).
- **Node check and failures:** the CRI check passed in about 6 s and failed with the handler entry removed (the node labelled itself `"false"`, then healed). A failed node stayed `"false"` across three agent restarts and a reboot, showing `"true"` for 2.9–3.0 s after each start. A failed autoscaled pool stayed at one node; its triggering pod stayed in `ContainerCreating`.
- **Scale-from-zero:** an autoscaled gVisor pool with an ordinary label scaled from zero, matched exactly by pool name (`sandboxauto`, not `sandbox`).
- **Artifact trust with `curl`:** each stage rejected its tampering case, and a wrong pin was refused.
- **Storage:** a Hetzner Cloud Volume on a tainted pool was writable from a gVisor pod as UID 1000 with `fsGroup` (the CSI node plugin runs on tainted nodes); setgid works.
- **Memory:** with a 1 GiB limit a JupyterLab kernel reached 848 MiB under runc, 800 MiB under gVisor and 864 MiB with a 64 MiB overhead; in all three the whole pod was `OOMKilled`, server included.
- **Capacity:** the project's limit of 20 shared vCPUs blocked scale-ups, which matters for a second generation during a rollout.

#### Local VM: CRI node check, file watching and artifact trust (2026-10-27)

Colima VM (aarch64, Ubuntu 24.04, k3s), gVisor `release-20261012.0`. Raw output is not committed.

- **CRI node check:** with a good handler entry, `crictl runp --runtime runsc` then `create` and `start`, non-root with every capability dropped, reported gVisor's kernel and passed the capability test. With the entry removed (`no runtime for "runsc" is configured`), a `runtime_type` typo (`failed to resolve runtime path`) or the shim's configuration naming a missing binary (`OCI runtime create failed: fork/exec`), the CRI check failed while `ctr run --runtime io.containerd.runsc.v1` passed in all three. A runc control with `RuntimeDefault` failed the capability test, as it should.
- **File watching across pods:** a watcher (inotify, plus listing and `stat` every 0.5 s) in one pod and a writer in another, over NFS and local storage. A gVisor watcher received inotify events only for changes from its own sandbox; changes from other pods, runc or gVisor, were seen only by polling, within the polling interval. A runc watcher saw changes made from gVisor pods through inotify.
- **Artifact trust:** against a local registry, the genuine artifact was accepted; a tag moved to another build and a mirror serving a different manifest at the pinned-digest URL were rejected on the manifest digest, a substituted layer on the layer digest, a file modified after listing by the per-file check, and an extra file as unlisted. Registry credentials, a TLS-inspecting proxy and x86 were not covered.

#### k3s, in-place upgrade and memory (2026-10-27)

On a local k3s cluster (`v1.34.12+k3s1`, arm64, in the Colima VM) and a Hetzner cluster deployed with NIC on the same k3s version, with gVisor installed at boot only on the exactly matched `sandbox` pool:

- **In-place upgrade:** a system-upgrade-controller plan (v0.18.0, as hetzner-k3s installs) upgraded the node from gVisor `20261005.0` to `20261019.0` in about 15 seconds. A gVisor pod started before the upgrade stayed Running, accepted `kubectl exec`, and its processes still used the previous `runsc` (shown as deleted) and the moved-aside `gvisor-bin.prev-*/gvisor_sentry`; it deleted cleanly in 1–2 seconds with no leftover processes. New pods ran on the new release. A plan for a release that does not exist left the node on its current release and new pods working, while the controller kept retrying the job.
- **Self-relabelling on k3s (Hetzner agent node):** with its own credentials (`system:node:<name>`), the node set its label to `"false"`, which held for 30 seconds; after `systemctl restart k3s-agent` the label was `"true"` again. Self-tainting was refused (`not allowed to modify taints`). The local run produced no output, most likely because restarting the single-node k3s server also ended the test pod.
- **Memory (512 MiB limit, same node):** an allocator in 16 MiB steps was OOM-killed at 496 MiB under runc and 480 MiB under gVisor, identically on both clusters; writing and reading back 1.5 GiB of files completed under both runtimes; both terminated the whole container.
- **Pool matching:** gVisor was installed on `nic-probe-hz3-pool-sandbox-worker1` and not on the `general` node, and only that node listed `runsc` in `status.runtimeHandlers`.

Scripts and output are not committed; this summary is the record.

#### EKS node self-labelling spike (2026-10-26)

On an EKS 1.34 AL2023 cluster deployed with NIC, a script run on one node as that node (using only `/var/lib/kubelet/kubeconfig`, identity `system:node:<name>`):

- could add and remove its own label `sandbox.nebari.dev/user-space-kernel-release`;
- could overwrite its own node-group label `sandbox.nebari.dev/user-space-kernel` from `"true"` to `"false"` and back, and the change held for 90 seconds and survived `systemctl restart kubelet`;
- could **not** modify its own taints (`node "…" is not allowed to modify taints`);
- could not read or modify the other node, and could not set a label under the reserved `node-restriction.kubernetes.io/` prefix.

Scripts and output are not committed; this summary is the record.

#### Hetzner and EKS-with-FSx probe (2026-10-25)

On a Hetzner cluster deployed with NIC (Ubuntu 24.04, kernel 6.8, k3s with containerd 2.2) and an EKS 1.34 cluster with FSx for OpenZFS from [#705](https://github.com/nebari-dev/nebari-infrastructure-core/pull/705) (2026-10-25):

- **Bubblewrap inside gVisor works on Hetzner** with ADR-0022's single qualified configuration: canaries, the agent's socket, the network and the metadata address hidden, signalling blocked, and a fresh `/proc` showing only the sandbox's processes. On the same nodes, bubblewrap outside gVisor failed at AppArmor, as ADR-0022 predicts.
- **Installation at boot works on both providers.** On Hetzner, a cluster-wide pre-k3s command that acted only on nodes of opted-in pools installed gVisor and the k3s containerd template, including on a node the autoscaler created from zero (pod pending to running in under two minutes); pool labels routed the pod. Hetzner's image lacks `bzip2`, which the release archive needs. On AWS, a node group's bootstrap (a nodeadm `NodeConfig` adding the runtime handler, plus a script) pulled gVisor as an image from ECR with `ctr` and installed it.
- **A failed install is fail-safe but not visible to `runtimeHandlers`.** With a bad image tag, the node still joined; a gVisor pod sent there stayed in `ContainerCreating` (`failed to resolve runtime path`) rather than running unsandboxed. But the node still listed `runsc` in `status.runtimeHandlers`, which reflects containerd's configuration, not the installed binary. The probe's own install script also logged success after the failure, because shell error handling (`set -e`) is ignored inside a `( … ) || …` construct.
- **k3s reports `status.runtimeHandlers`**, with `runsc` listed only on nodes where it was configured.
- **Storage:** FSx for OpenZFS homes (owned through the pod's `fsGroup`) and Longhorn shared and single-writer volumes were writable from gVisor pods, with setgid directories passing their group on, as the ownership analysis predicted. Longhorn shared volumes needed the NFS client installed on the node first (see "Findings for NIC beyond sandboxing").
- **Compatibility:** under gVisor, pixi environments (about 1.5–2× slower to build on local disk), Python shared memory, a local Dask cluster, file watching within one pod, `debugpy`, C-extension builds, SQLite in WAL mode on the shared home, and headless Chromium with its own sandbox all worked. Attaching `gdb` to an unrelated running process was refused (gVisor reports `ptrace_scope` 1, as Ubuntu does); launching a program under `gdb` worked.
- **Performance (median of three):** with an FSx home, `pip install` into a fresh environment took 65 s under gVisor against 46 s under runc, and 5,000 small-file operations 40 s against 24 s; with a Longhorn shared home on Hetzner, 141 s against 100 s and 84 s against 49 s. JupyterLab startup was 1–1.6 s slower; large sequential I/O was unchanged.
- **Overhead:** an idle gVisor pod used about 18 MiB more memory than the same pod under runc.
- **`dedicated: true`:** with the node group tainted and the `RuntimeClass` carrying the toleration, gVisor pods landed on it, an ordinary pod pinned there stayed pending, and system DaemonSets kept running.
- **NetworkPolicy:** hetzner-k3s enforced it for gVisor pods as for runc pods.

## 20.10 Verification

- **Per node group, then per node.** For `process-self-restriction`, NIC reports each node's kernel baseline when `nic outputs` runs, for diagnosis only, and the probe runs only in maintainers' requalification runs unless automating it is adopted (§20.8). Where probes are used, they run on each node group that should provide a capability, placed with that capability's own selectors and tolerations. For Phase 2, the per-node probe also gates the readiness barrier.
- **Primitive tests, in both directions.** For `process-self-restriction`: the probe's Landlock cases and the reference launcher's unit and end-to-end tests in §20.8, each denial with a positive control. For `in-pod-namespaces` inside gVisor: the capability test and qualified configurations succeed with the published settings. Filtered implementation (deferred): the qualified invocation succeeds with the profile; a pod without the profile on the same node cannot create a user namespace; netfilter and raw-socket creation fail from inside a new user namespace.
- **Consumer acceptance test (Gate D).** Separately from the primitive, one real pack must show, with the capability in use:
  - credential canaries placed in the agent's environment, files and mounted secrets are not readable by sandboxed commands;
  - inherited file and socket descriptors are closed or explicitly allowed;
  - networking is denied (or limited to the intended proxy);
  - the pack's generated worker-pod settings carry the expected profile, selectors and tolerations;
  - when the capability is absent, the pack refuses sandboxed work rather than falling back to running unsandboxed.

  This matters because node support alone changes nothing in a pack that, for example, passes credentials in environment variables or launches browsers with `--no-sandbox`.
- **Scheduled re-verification.** Probes also run on a schedule, following the pattern proposed in [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683); a failing node is reported (the readiness record and quarantine in §20.6 are deferred).
- The NetworkPolicy enforcement check proposed in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) uses the same positive/negative pattern, and the two should share their harness.

## 20.11 Security considerations

`in-pod-namespaces` has three possible delivery settings, and the `seccompDefault` items below must not be read across them. **Inside gVisor** (ADR-0022's intended route) gVisor implements the namespaces and applies its own filter, so neither the host's user-namespace settings nor `seccompDefault` matter. **Unfiltered on AL2023** works only because `seccompDefault` is off and the pod sets no profile; it is recorded as evidence (§20.9), not supported, and nothing below applies to it. **The deferred filtered implementation** permits user namespaces on dedicated host nodes and therefore turns `seccompDefault` **on** there (item 1), so that pods without the NIC profile get `RuntimeDefault` and cannot create namespaces. Items 1–6 apply only to that filtered implementation; `process-self-restriction` relaxes nothing.

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`. Today, by contrast, pods without a seccomp profile run with no syscall filter at all (confirmed on AWS), and packs that want isolation reach for root, privileged pods or `Unconfined` profiles; a sanctioned, narrower path improves on that. `in-pod-namespaces` on the host kernel adds real risk, bounded only if:

1. **Seccomp is on by default on `in-pod-namespaces` nodes.** Once a node permits unprivileged user namespaces, any pod there without a seccomp filter can create them, not only pods that reference the profile. These node groups run the kubelet with `seccompDefault: true`.
2. **Admission controls who may use the profile and the nodes.** Only namespaces explicitly labelled for the capability may reference `nebari-sandbox-v*` profiles or tolerate the `in-pod-namespaces` dedication taint (never the unverified taint; see the readiness-barrier invariants): through the hardened-mode admission policy (#480) in hardened mode, and a ValidatingAdmissionPolicy shipped with the capability in standard mode.
3. **The profile operator's API is locked down.** Only NIC and cluster administrators may create or modify `SeccompProfile` or `AppArmorProfile` resources; the operator's images are pinned by digest.
4. **The netfilter block is concrete and tested** (item 5 of §20.9).
5. **Kernels on `in-pod-namespaces` node groups are patched promptly**, on a defined cadence with a named owner.
6. **Readiness is re-verified** at node start (readiness barrier) and on a schedule.
7. **Pack-facing documentation states the threat model precisely.** Both capabilities share the host kernel and are not protection against kernel exploits or hostile multi-tenant code. Code an agent executes should be classified by what an adversary can influence (prompt injection, compromised dependencies), not by who owns the pod: a single-tenant deployment does not make that code trusted. These capabilities are appropriate where a kernel exploit from that code is an acceptable risk; where it is not, use `user-space-kernel` or `vm-boundary`. Packs using seccomp user notification must not rely on a check-then-continue supervisor as their policy mechanism. With the container's `/proc` reused, sandboxed commands can still see the command lines of other processes in the pod, which can contain credentials, and they inherit whatever environment and descriptors the launcher passes; a fresh user namespace does not by itself let them read another process's environment or follow its `/proc/<pid>/root`, since the kernel's ptrace access checks still apply.

## 20.12 Composition and privilege tiers for later capabilities

**Composition.** Which in-pod capabilities are available at a level is recorded as properties of each implementation (§20.6), and validation uses them; this paragraph records how those properties came about. In-pod namespace tools can also run *inside* a `user-space-kernel` or `vm-boundary` workload, where they may obtain namespaces through privileges the outer boundary contains (root, `CAP_SYS_ADMIN`), with no node-level change. On the default runtime the only accepted route is the unprivileged one: `CAP_SYS_ADMIN` on a default-runtime pod is never an accepted way to obtain `in-pod-namespaces`. `process-self-restriction` depends on the kernel the workload actually sees: inside a stronger runtime that is the runtime's kernel, not the node's. gVisor (`release-20261012.0`) does not implement Landlock (`landlock_create_ruleset` returns `ENOSYS`), so `process-self-restriction` does not combine with a gVisor-backed `user-space-kernel`. Conversely, under gVisor a non-root process with no capabilities can create user, mount, IPC, UTS and pid namespaces and mount a fresh procfs, with no node-level change; bubblewrap's own network-namespace setup fails there ([gVisor #13438](https://github.com/google/gvisor/issues/13438)) unless the network namespace is created first (probe, 2026-10-17). Every combination a pack relies on is probed before it is advertised; for example, NetworkPolicy enforcement is checked separately under each stronger runtime, and where a capability's workloads bypass the pod network entirely (for example VMs networked by a host-level process), NetworkPolicy does not apply and that capability's ADR must state how egress is enforced.

**Privilege tiers.** Later capabilities may need more privilege than these two. Each tier is admitted in hardened mode only on the stated terms, and each later capability's ADR must justify its tier against restricted-compatible alternatives, which exist for capable sandbox systems:

| Tier | Example | Terms |
|---|---|---|
| Restricted-compatible | `process-self-restriction` | Nothing needed |
| Capability node agents, non-privileged | Host-management agents that need specific capabilities or host paths but not `privileged: true` (for example a seccomp-only profile installer) | One general exception, pinned to a namespace and to the capability's node groups; enforceable Localhost profiles, never `Unconfined` |
| Capability node agents, privileged | Runtime installers and other agents that need `privileged: true` | Treated as **host-trusted** exceptions: for privileged containers, Kubernetes runs seccomp unconfined and ignores AppArmor profiles, so a Localhost profile field confines nothing. Pinned to a namespace, an image digest and the capability's node groups, and justified in the capability's ADR |
| Relaxed workload pods | Worker pods that run a user-space kernel or a VMM themselves, needing added capabilities and relaxed seccomp/AppArmor | Dedicated namespace, exact privileges, confined node groups, set by the capability's ADR; Localhost profiles rather than `Unconfined` |
| Node-owning systems | Engines that run privileged in host namespaces, mount the host filesystem, or run as root directly on the host | A dedicated, tainted node group treated as a separate trust zone: no other workloads, admission only there and in the system's namespace, no NIC node preparation for other capabilities |

Scale limits are part of a capability's definition: where a provider's system runs on a single node in its open-source form, the capability's ADR says so and packs must not assume horizontal scale.

## 20.13 Related work

**NetworkPolicy enforcement (platform).**

- [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) Enforce NetworkPolicy on every cluster provider (open). Records per-provider state: Azure's AKS module sets no `network_policy`; Hetzner's k3s should enforce but is untested; kind is unchecked; `existing` needs a documented requirement and a readiness check. Proposes a user-journey enforcement check.
- [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) Enforce NetworkPolicy on the VPC CNI addon, with an opt-in strict mode (open, blocked on the storage strategy in [#586](https://github.com/nebari-dev/nebari-infrastructure-core/pull/586)). Includes trial results from a NIC-built EKS cluster, including the strict-mode requirement that every NIC namespace ships a NetworkPolicy.

**Multi-tenancy (the main driver of the above).**

- [#674](https://github.com/nebari-dev/nebari-infrastructure-core/pull/674) Multi-tenancy design doc (open; being split into a platform layer and a deployment-specific guide). Treats NetworkPolicy enforcement as precondition 1.
- [#676](https://github.com/nebari-dev/nebari-infrastructure-core/issues/676) Cluster preconditions for a tenant, and [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683) scheduled isolation checks. The scheduled-check idea applies equally to the sandbox probe.

**Packs already building isolation (rows 4 and 2-3 consumers).**

- An existing Nebari pack runs workers as separate pods with no ServiceAccount token, created only by a least-privilege controller (row 4). Its egress and controller work remain unfinished, so it is a precedent rather than a finished reference. Its plan to restrict worker egress notes that a NetworkPolicy cannot allow a hostname, so model traffic goes through an in-cluster egress gateway; the same constraint applies to Landlock (row 2), which restricts by port, not host.
- [nebi#445](https://github.com/nebari-dev/nebi/issues/445) and [nebi#513](https://github.com/nebari-dev/nebi/issues/513) Untrusted environment builds run in a shared worker with database credentials; proposal to run each job in its own pod (row 4). Proposed, not yet implemented.
- [nebari-operator#197](https://github.com/nebari-dev/nebari-operator/issues/197) A shared NetworkPolicy helper for packs.

**Pack contract.**

- The [Nebari Pack Specification](https://github.com/nebari-dev/nebari-operator/blob/main/docs/pack-specification.md) (section 6, Security baseline) requires a hardened `securityContext` at GA and says packs SHOULD ship a NetworkPolicy. It says nothing about seccomp today. If it later requires `RuntimeDefault`, packs that currently run sandboxing tools with no syscall filter (see "Why it can appear to work today") stop working, so the `sandbox.*` contract here should be referenced from that section.

## 20.14 Future work deferred from ADR-0021

When ADR-0021 was narrowed to `process-self-restriction`, the following consequences and open questions, which apply to `in-pod-namespaces` (§20.9) and later capabilities, moved here. They are inputs to those capabilities' own ADRs.

**Consequences of delivering `in-pod-namespaces`:**

- It depends on external work (an AppArmor mechanism, a hetzner-k3s fix) and may be limited to non-AppArmor node groups for some time.
- NIC owns a complete seccomp policy per architecture and must track runtime default changes.
- It needs a new post-bootstrap lifecycle phase in `pkg/nic`, or an ADR-0006 amendment.
- Enabling user namespaces on dedicated node groups widens the kernel attack surface there.

**Open questions:**

- Gate A: upstream AppArmor support in the Security Profiles Operator, another maintained loader, or AppArmor nodes deferred indefinitely?
- Post-bootstrap lifecycle hook in `pkg/nic`, or an amendment to ADR-0006?
- Where the readiness barrier's taint removal runs (a small NIC-owned controller, or the probe DaemonSet itself), and what RBAC it needs to patch nodes.
- Is per-node-group opt-in the right granularity for AKS and `existing`, where NIC does not own node groups in the same way?
- Should `in-pod-namespaces` ever cover pods that run sandboxes for several users or sessions? With single-ID user namespaces every session maps to the pod's own host UID, so files are not separated between sessions; separating them needs a distinct real UID per session, which needs root and belongs inside a stronger boundary.

## 20.15 Guidance for later capability ADRs

These decision drivers were part of ADR-0021 when it also covered `in-pod-namespaces`. They no longer bear on the capability ADR-0021 delivers, but apply to the ADRs that will deliver later capabilities:

- **Off by default and narrowly scoped.** Relaxations that later capabilities need, such as unprivileged user namespaces, widen the kernel attack surface (e.g. CVE-2024-1086 was reachable via `CAP_NET_ADMIN` in a user namespace), so they are confined to dedicated node groups.
- **Prefer community-maintained mechanisms** over NIC-owned node agents, where they can express the required policy.

## 20.16 Alternatives considered in detail

ADR-0021 summarises Options 2, 3, 6 and 7; their full assessment is recorded here.

### Option 2: Node-group labels from an image table

An earlier draft of ADR-0021 advertised `process-self-restriction` with node-group labels rather than only reporting an expectation per node group:

1. **Image table.** NIC kept a table mapping each node image it provisions to the Landlock ABI it provides. An image entered the table only after a manual probe run on it confirmed the capability under the exact pod settings; images not in the table were not advertised.
2. **Placement at node-group creation.** The provider predicted the capability from the node group's image when creating the group, reported it in `InfraSettings.Sandbox`, and applied `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi` as node-group labels (the same mechanism as GPU groups), so replacement and autoscaled nodes carried them from the start. Where node groups differed in ABI, each level got its own placement, and packs that needed ABI 4 selected it. NIC's Hetzner provider needed node-pool label support added. For `existing` and kind clusters NIC labelled nothing; operators could label nodes themselves at their own risk.
3. **Consistency check and readiness record.** During `nic deploy`, NIC compared each node's kernel version and OS image (`node.status.nodeInfo`) with its group's prediction and recorded mismatches (for example a manually upgraded node) in a read-only readiness record shown by `nic outputs`, reporting but not relabelling.

- **Pros:** steers pods away from non-qualifying node groups in mixed clusters; per-placement ABI guarantees.
- **Cons:** steering matters only in mixed clusters, and packs check Landlock at startup anyway; a table to keep current, label plumbing in every provider and a readiness record for that benefit. The `default` mapping entry renders a placement from NIC-set node-group labels where a provider has them (§20.6), which covers the mixed-cluster case without a separate table.

It can be added later, without changing the capability's name or guarantee, if mixed clusters become common.

### Option 3: Node Feature Discovery

Node Feature Discovery, a Kubernetes SIG project, runs a DaemonSet that reads each node's kernel version and configuration, and a controller that turns those facts into node labels through `NodeFeatureRule` resources. It would label nodes automatically, including images NIC does not know, `existing` clusters and kind. It was discarded because it adds a DaemonSet, a controller with permission to patch nodes, and CRDs for something NIC can do with a version comparison: the node images NIC provisions are known in advance and change rarely. Like the kernel check, it reads kernel configuration rather than confirming Landlock is active at boot. It remains an option if clusters NIC does not provision become important.

### Option 6: Stronger-isolation runtime only (gVisor or Kata)

Provide only a `RuntimeClass` backed by gVisor or Kata, e.g. through `kubernetes-sigs/agent-sandbox`.

- **Pros:** much stronger boundary; a kernel exploit in the workload does not directly yield the node.
- **Cons:** provider-specific runtime installation (nested virtualisation or bare metal for Kata), memory and I/O overhead, compatibility gaps.

Kept as implementations of the `mediated-kernel` and `hardware-virtualised` levels (§20.6).

### Option 7: Adopt a full sandbox platform (e.g. Agent Substrate)

Install a complete agent-sandbox platform as NIC's sandboxing answer and have packs run untrusted work on it. Agent Substrate is the leading example (v0.6.0, released 2026-10-22; pre-1.0 with no compatibility guarantees; documented for GKE and kind only): a control plane that runs up to 1,000 "actors" in each worker pod, isolates each under gVisor or a Kata guest on Cloud Hypervisor that the worker downloads, verifies and starts itself rather than through a `RuntimeClass`, suspends and resumes them from snapshots in object storage, and brokers egress with credential injection through a shared gateway.

- **Pros:** a much stronger boundary than rows 2 and 3, appropriate for attacker-influenced or multi-tenant code; egress policy, credential injection, suspend/resume and density come built in rather than being assembled by each pack; an ecosystem is forming around it.
- **Cons:**
  - A different isolation unit: many actors share a worker pod, so NIC's pod-level guarantees (network policy, admission) cannot separate actors; that is the platform's job, and its isolation between actors on one node is still a roadmap item. (The earlier objection that it replaces the pod model no longer separates it from NIC's own direction, which also runs untrusted work in separate sandbox pods.)
  - Not qualified or supported by NIC: Agent Substrate needs Kubernetes 1.36 or later with beta pod-certificate APIs (`PodCertificateRequest`, `ClusterTrustBundle`) that managed services do not let you enable (realistically 1.37), enforced NetworkPolicy ([#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) is blocked), changes to GKE-specific node paths, and KVM-capable nodes for its microVM class (not Hetzner Cloud; its gVisor class needs none).
  - A weaker pod-level posture: its worker pods are no longer `privileged`, but run as root with 13 added capabilities (including `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`), seccomp and AppArmor unconfined, and `/dev/kvm` and `/dev/net/tun` for microVMs; its node agent mounts host paths. ADR-0010's hardened mode would have to admit that by exception, whereas `process-self-restriction` runs under Pod Security `restricted`.
  - A large operational footprint: API server, controller, router, egress gateway, node agent, an identity (OIDC) server, a pod-certificate signer, embedded OpenFGA, PostgreSQL and object storage.

Not chosen as the starting point. Because actors are not pods with published settings and the platform runs its own runtime binaries, it cannot provide a level through NIC's mapping; where it can run, it is separately trusted infrastructure on dedicated node groups, close to host root, not an implementation of a level. If packs converge on such a platform, the future `in-pod-namespaces` work can be deprioritised; `process-self-restriction` remains useful either way.

## 20.17 Links

- [ADR-0003: Software Pack Codegen](../../adr/0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](../../adr/0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](../../adr/0010-high-security-mode.md)
- [ADR-0017: User Journey Tests](../../adr/0017-user-journey-tests-for-foundational-software.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [go-landlock](https://github.com/landlock-lsm/go-landlock)
- [Sandbox probe and reference launcher](../../../tests/sandbox-probe/README.md)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
