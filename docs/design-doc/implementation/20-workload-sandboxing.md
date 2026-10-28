# Workload Sandboxing

## 20.1 Scope

This document holds the implementation design behind [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](../../adr/0021-gradual-workload-sandboxing-for-software-packs.md). The ADR records the decision: a tool-neutral contract on three axes (boundary level, in-pod capability, profile), a published mapping of concrete values packs copy, and rules for later additions, delivering a qualified description of `process-self-restriction` (Landlock on the default runtime) with a read-only diagnostic report. This document records the detail that implements and justifies it: the sandboxing spectrum, provider findings, the full contract, delivery, evidence from probes of the higher levels, verification, security considerations and related work. Where the two disagree, the ADR is authoritative for the decision and this document is updated to match.

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
| `aws` (AL2023) | OK (observed, 2026-10-19) | Blocked under `RuntimeDefault`; profile needed | n/a (no AppArmor) | Depends on AMI kernel/containerd *(unverified)* |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | Blocked by the AppArmor sysctl | Blocked under `RuntimeDefault`; profile needed | Profile needed | Example config pins Kubernetes 1.32 |
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
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; the ABI is part of each qualification). | The reference consumer (§20.8): one combined filesystem and TCP ruleset, then `execve` of a command | **Described (ADR-0021)**: qualified per configuration; enforcement is the consumer's |
| `seccomp-user-notification` | The same process can install nested seccomp filters with user notification, including `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`. User notification is a mechanism for emulating syscalls or injecting descriptors, not a policy check: a supervisor that inspects arguments and then lets the call continue can race with changes to that memory, as the Linux manual warns. | The probe's notification path (two stacked filters, listener transfer, descriptor injection) | Reserved. Probed separately because a container runtime or default-profile change can break it independently of the kernel |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed. | One pinned bubblewrap version with a fixed, tested invocation | Reserved; needs its own ADR |

**Profiles.** A profile is a composition of **atomic guarantees**, each of which the cluster enforces around a pod and can check from outside it, for example:

| Atomic guarantee | Enforced by | What it does not cover |
|---|---|---|
| `no-service-account-token` | Admission: `automountServiceAccountToken: false` and no projected token volume | Tokens copied into images, files or environment values |
| `no-secret-references` | Admission: no `secretKeyRef`, `secretRef` or Secret volumes | Literal values in the pod spec, ConfigMaps, images, data |
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

NIC publishes a mapping from requirement name to concrete values. In ADR-0021 it is computed from config and shown by `nic outputs`; there is no automatic resolution, and `default` is the only entry. The operator copies the values into the pack's Helm values until pack codegen ([ADR-0003](../../adr/0003-software-pack-codegen.md)); packs copy them into pod specs, volume claims and Agent Sandbox `SandboxTemplate`s, which take an exact `runtimeClassName`. Packs never look anything up in the cluster and nothing selects a `RuntimeClass` by label.

```yaml
# nic outputs -o yaml (sandbox section; illustrative)
sandbox:
  observedAt: 2026-10-28T10:00:00Z        # fresh read of the nodes; nothing is stored
  requirements:
    default:
      level: shared-kernel
      capabilities: [process-self-restriction]
      runtimeClassName: ""                 # the cluster's normal runtime
      placement: {}                        # empty: no node group is known not to qualify
      securityContext:
        seccompProfile: {type: RuntimeDefault}
      workspaceStorageClass:
        name: gp2                          # InfraSettings.StorageClass: the cluster's normal class
        notes: ""                          # access mode and ownership notes
      profile: {}                          # reserved
      implementation: {}                   # release and property-set version; empty for the default runtime
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

`placement` for `default` is empty when no node group is known not to qualify. Where some are `unsupported`, it is a node selector for the others, using a label NIC itself sets on node groups through provider config; a provider that cannot set node-group labels leaves it empty and `nic outputs` names the groups that do not qualify. `unknown` groups are not excluded, since excluding them would make most clusters unschedulable; the pack's startup check covers them. Storage portability is part of the entry: a later entry names a storage class known to work with its runtime (the tested gVisor configuration could not write to EFS access points as NIC configures them), not a promise that any storage works.

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
    Placement   map[string]string // a label NIC sets on this group via provider config; nil if none
}

type Expectation struct {
    State       string // "qualified", "unsupported" or "unknown"
    LandlockABI int    // when qualified or unsupported; 0 when unknown
    Record      string // qualification record entry, when qualified
}

// Computed by pkg/nic from InfraSettings and config; shown by nic outputs.
type Requirement struct {
    Level                 string
    Capabilities          []string
    RuntimeClassName      string
    Placement             Placement // nodeSelector, affinity, tolerations
    SecurityContext       *corev1.PodSecurityContext
    WorkspaceStorageClass StorageClassRef
    Profile               map[string]string // reserved
    Implementation        Implementation    // release and property-set version; reserved
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

### Evidence from the higher levels

Before the contract was fixed, the higher levels were exercised on clusters deployed with NIC, using test-only installers that ADR-0021 does not adopt. Raw output from these runs is not committed; this table and the summaries under `tests/sandbox-probe/` are the record.

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
5. Verify (§20.9).
6. Publish the mapping entries, with their implementation release and property-set version.

Today, conditional software ([ADR-0006](../../adr/0006-conditional-foundational-software-helm.md)) is installed inside the provider's `Deploy()`, before ArgoCD and cert-manager exist, and foundational-service failures are reported as warnings rather than failing the deploy. A capability with components therefore needs either a post-bootstrap lifecycle hook in `pkg/nic` or an amendment to ADR-0006. Independently of ADR-0010's fail-closed hardened mode, a capability the operator requires (or opts into on a node group) that fails steps 3-5 makes `nic deploy` exit non-zero.

## 20.8 Delivery: `process-self-restriction`

ADR-0021 delivers a **qualified description of the default runtime's host prerequisite (Landlock), plus an optional, read-only diagnostic preflight**. It is not an enforced sandbox.

1. **No opt-in, no relaxation, no components, no configuration.** No profiles, no operator, no admission exception and no node preparation. Steps 3-4 of the lifecycle are empty. A cluster-wide minimum-ABI setting was considered and dropped: one number ignores the runtime (gVisor has no Landlock), cannot judge node groups with no nodes or images nobody has probed, and duplicates the pack's own startup check, which is where the guarantee is enforced.
2. **Qualified expectations.** Each provider reports, per node group and from config alone, the expectation the qualification record (below) gives for that group's configuration: `qualified` with an ABI for a configuration inside a record's extrapolation range, `unsupported` where the kernel line is known to be below ABI 3, and `unknown` otherwise. Not every default node group on a supported Kubernetes version qualifies: AWS below 1.33 (kernel 6.1, ABI 2) and AKS below 1.35 (Ubuntu 22.04, kernel 5.15, ABI 1) are unsupported; AKS from 1.35, AWS AMI types other than `AL2023_x86_64_STANDARD` (including ARM, NVIDIA and Bottlerocket), images an operator pins, `existing` and kind are unknown. NIC does **not** change node images on its own; moving a group to a qualifying image is an operator change through the provider's own config.
3. **Reporting and the preflight.** `nic outputs` reads the nodes afresh each time it runs and shows, per node group, the qualified expectation and the host-kernel baseline, labelled "default runtime only" and with the time of the read; nodes the provider's `NodeGroupOf` cannot place are listed as `unassigned`, and groups with no nodes are `not checked`. `nic deploy` prints the same report once the nodes are up. The baseline maps each node's `node.status.nodeInfo.kernelVersion` to the Landlock ABI that kernel version introduced upstream: 5.13 ABI 1, 5.19 ABI 2, 6.2 ABI 3, 6.7 ABI 4, 6.10 ABI 5, 6.12 ABI 6, 6.15 ABI 7. It never warns or fails, is not stored, and is never read as a qualification, because three things defeat it: distribution backports (a lower version with a newer ABI), Landlock built in but not enabled at boot (`EOPNOTSUPP`), and container-runtime seccomp profiles that predate the Landlock system calls and deny them. Nodes added later (autoscaling, replacement) are seen only by the next read.
4. **Probe and requalification.** The probe ([`tests/sandbox-probe/`](../../../tests/sandbox-probe/README.md)) is the evidence behind each record entry. NIC maintainers run it through the release checklist on a fresh node of each configuration before it is recorded, and again on any **requalification trigger**: a new node-image revision line or kernel line; changed kernel configuration or boot options (for example the LSM list); a container runtime upgrade or a change to its default seccomp profile; a new architecture; or storage becoming part of a promise. It is not run on users' clusters. A non-root pod with every capability dropped and `RuntimeDefault` applies a Landlock ruleset and confirms a denied write and truncation fail, reports the highest ABI, at ABI 4 confirms a disallowed `connect` and `bind` fail, and records `/sys/kernel/security/lsm`. Each denial has a positive control on the same node, so an unrelated failure cannot pass as confinement. The same run checks `seccomp-user-notification` (two stacked filters, listener transfer, `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`) and reports it separately.
5. **Reference consumer.** The example below is committed with its end-to-end test under [`tests/sandbox-probe/recipe/`](../../../tests/sandbox-probe/recipe/). It is the qualified consumer of `process-self-restriction`; the code is an example, not part of the contract.
6. **Documentation.** A pack-developer page (copy the `default` values, do not mount the service-account token, check the Landlock ABI at startup, refuse sandboxed work rather than fall back, the example below) and an operator page (the qualification record, what `nic outputs` reports and what each state means).

### Qualification record

The record lists what has been qualified, not every image: unknown combinations stay unknown. Probe results (node names redacted) are under [`tests/sandbox-probe/`](../../../tests/sandbox-probe/README.md#evidence-table).

| Provider, image variant, architecture | Tested image release | Kernel | Container runtime | Pod settings | Probe revision | ABI | Date | Extrapolation range |
|---|---|---|---|---|---|---|---|---|
| `aws`, EKS `AL2023_x86_64_STANDARD`, x86_64 (`m6i.large`), Kubernetes 1.34 | AMI release 2023.12.20261012 | 6.12.111-136.204.amzn2023 | containerd 2.3.5 | `pod.yaml` (UID 65532, no capabilities, read-only root, `RuntimeDefault`; also unset) | probe 0.1.0 | 6 | 2026-10-19 | Same variant and architecture on the 6.12 kernel line (Kubernetes 1.33–1.35) |
| `hetzner`, hetzner-k3s Ubuntu 24.04, x86_64 | Ubuntu 24.04.4 LTS | 6.8.0-138-generic | containerd 2.2.7-k3s1 | As above | probe 0.1.0 | 4 | 2026-10-25 | Ubuntu 24.04 GA kernel line (6.8) on x86_64 |

Unsupported, from the kernel line: AWS AL2023 on 6.1 (Kubernetes 1.31–1.32, ABI 2); AKS Ubuntu 22.04 (5.15, ABI 1). Everything else is unknown until probed, including AL2023 on 6.18 (Kubernetes 1.36–1.37), every arm64 image, GPU images, Bottlerocket, AKS on Ubuntu 24.04 or Azure Linux, `existing` and kind. (kind on a 6.8 Colima VM, 2026-10-15, passed the probe at ABI 4; that is a local observation, not a qualification, since kind's kernel is the host's.)

### Example: confining a command

This is the reference consumer: a **tested reference launcher** for the default runtime, not a library NIC ships and not part of the contract. It runs non-root under Pod Security `restricted` with no added capability. Everything shown in the code below was tested end to end (below); the optional seccomp user-notification mediation mentioned at the end is a capability demonstration in the probe, not part of this launcher.

The agent never confines itself. It starts a **helper**, its own binary re-executed through `/proc/self/exe` with `os/exec`, passing the policy and the command as arguments, a minimal explicit environment (`PATH`, `HOME` and `TMPDIR` set to the work directory, `LANG`) and only standard input, output and error. The helper refuses below Landlock ABI 3, then restricts itself and executes the command, which inherits the restriction and cannot lift it:

- **Landlock** through [go-landlock](https://github.com/landlock-lsm/go-landlock) (v0.11.0), in best-effort mode on its newest ABI, so every right the running kernel knows is handled, including all creation and removal rights (`MAKE_DIR`, `MAKE_SYM`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_CHAR`, `MAKE_BLOCK`, `REMOVE_DIR`), `REFER` at ABI 2, `TRUNCATE` at ABI 3 and `IOCTL_DEV` at ABI 5, and, on newer kernels, pathname Unix-socket connection (ABI 9) and UDP (ABI 10). It grants everything beneath the work directory, including moves and links within it (`REFER`; without it, legitimate moves inside the workspace fail) and connecting to sockets there; read and execute beneath listed system paths; read and write on listed files such as `/dev/null`; and at ABI 4 TCP `connect` to one proxy port only and no `bind`. At ABI 6 the command cannot signal, or reach abstract Unix sockets of, processes outside the sandbox. Best effort silently does less on older kernels, which is why the helper checks the ABI first. The library also sets `no_new_privs`.
- **Reads are restricted** to the work directory and the listed paths (for example `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/etc`, `/proc`), so files elsewhere, including a mounted service-account token, cannot be read. The pack should still not mount the token, and must not put credentials in the listed paths or the work directory.
- **Optional strict mode** adds a seccomp filter, built with raw `x/sys/unix` calls because go-landlock does not cover seccomp, that makes `socket()` fail for `AF_INET`, `AF_INET6`, `AF_PACKET` and `AF_NETLINK` while leaving `AF_UNIX` for a proxy socket in the work directory, and refuses `io_uring` and foreign or x32 system calls.
- **Descriptors** other than 0, 1 and 2 are marked close-on-exec with `close_range` before `execve`, so a descriptor the agent leaked without `O_CLOEXEC` does not reach the command.

```go
// Policy is what a confined command may do.
type Policy struct {
	WorkDir   string   // read, write, create, remove, move and link beneath it
	ReadOnly  []string // read and execute beneath, e.g. /usr, /etc, /proc
	ReadWrite []string // read and write, e.g. /dev/null
	ProxyPort uint16   // ABI 4+: the only TCP port connect may use; 0 for none
	NoInet    bool     // seccomp: no IP, packet or netlink sockets at all
}

const confineArg = "__confine"

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
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil || len(argv) == 0 {
		return errors.Join(errors.New("bad policy or empty command"), err)
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	if landlockABI() < 3 { // best effort would silently do less: refuse instead
		return errors.New("Landlock ABI 3 or newer is required")
	}
	runtime.LockOSThread() // the seccomp filter applies to this thread, which then execs
	if err := applyLandlock(p); err != nil {
		return err
	}
	if p.NoInet {
		if err := denyInetSockets(); err != nil {
			return err
		}
	}
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return err // inherited descriptors must not reach the command
	}
	return unix.Exec(path, argv, os.Environ())
}

// landlockABI returns the kernel's Landlock ABI, or 0 if Landlock is absent
// (ENOSYS) or not enabled at boot (EOPNOTSUPP).
func landlockABI() int {
	abi, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return abi
}

// applyLandlock handles every right go-landlock knows (V11), degrading to what the
// running kernel supports, and grants: everything beneath the work directory,
// including moves and links within it (REFER) and connecting to Unix sockets
// there; read and execute beneath p.ReadOnly; read and write on p.ReadWrite;
// and, at ABI 4+, TCP connect to p.ProxyPort only. At ABI 6+ the command may
// not signal, or reach abstract Unix sockets of, processes outside the sandbox.
// It also sets no_new_privs.
func applyLandlock(p Policy) error {
	rules := []landlock.Rule{
		landlock.RWDirs(p.WorkDir).WithRefer().WithResolveUnix(),
		landlock.RODirs(p.ReadOnly...).IgnoreIfMissing(),
		landlock.RWFiles(p.ReadWrite...).IgnoreIfMissing(),
	}
	if p.ProxyPort != 0 {
		rules = append(rules, landlock.ConnectTCP(p.ProxyPort))
	}
	return landlock.V11.BestEffort().Restrict(rules...)
}

// denyInetSockets installs a seccomp filter that makes socket() fail with
// EPERM for AF_INET, AF_INET6, AF_PACKET and AF_NETLINK (AF_UNIX stays
// available, for example for a proxy socket in the work directory). It also
// refuses io_uring, which can create sockets without calling socket(), and
// any syscall from a foreign or x32 ABI.
func denyInetSockets() error {
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
		{Code: ld, K: 0}, // seccomp_data.nr
		{Code: jge, Jt: 8, K: 0x40000000}, // x32
		{Code: jeq, Jt: 7, K: unix.SYS_IO_URING_SETUP},
		{Code: jeq, Jf: 5, K: unix.SYS_SOCKET},
		{Code: ld, K: 16}, // low 32 bits of args[0], the address family
		{Code: jeq, Jt: 4, K: unix.AF_INET},
		{Code: jeq, Jt: 3, K: unix.AF_INET6},
		{Code: jeq, Jt: 2, K: unix.AF_PACKET},
		{Code: jeq, Jt: 1, K: unix.AF_NETLINK},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ret, K: deny},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
}
```

A pack runs it with, for example, `Policy{WorkDir: work, ReadOnly: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc"}, ReadWrite: []string{"/dev/null"}, ProxyPort: 8080}`.

**What is tested.** On 2026-10-28, `tests/sandbox-probe/recipe/test.sh` ran every case through the helper and as an unconfined control (which must succeed, so a denial is not an unrelated failure), as a non-root user, with the agent holding a canary secret in its environment and a leaked writable descriptor. Environments: Lima VMs on Apple silicon (aarch64), Ubuntu 24.04 (kernel 6.8.0-134-generic, Landlock ABI 4) and Ubuntu 25.04 (6.14.0-37-generic, ABI 6), each directly as UID 501 and inside a container (`nerdctl run --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges`, `python:3.12-slim`, containerd's default seccomp profile, a stand-in service-account token mounted). Results: 35 of 35 cases passed on each VM and 36 of 36 in each container.

| Case | ABI 4 | ABI 6 |
|---|---|---|
| Write, `mkdir`, symlink and move between directories inside the work directory | Allowed | Allowed |
| Create, append, truncate, remove, `mkdir`, symlink (planting, for example `~/.gitconfig`), `rmdir`, `mkfifo`, bind a Unix socket, or move a file out, outside the work directory | Denied | Denied |
| Grandchild of the command writes outside | Denied | Denied |
| Write to `/dev/null`; read under the listed paths | Allowed | Allowed |
| Read a file outside the listed paths (the agent's home, `/var`, the stand-in token) | Denied | Denied |
| Read the agent's environment through `/proc/<pid>/environ` | Denied | Denied |
| Agent's canary in the command's environment; write through the leaked descriptor | Absent; denied | Absent; denied |
| TCP `connect` to the proxy port, also at another address | Allowed | Allowed |
| TCP `connect` to another port; TCP `bind` | Denied | Denied |
| UDP send; connect to a pathname Unix socket outside the work directory | Allowed (not covered below ABI 10 and 9) | Allowed (as at ABI 4) |
| `chmod` a file outside (metadata) | Allowed (not covered) | Allowed (not covered) |
| Connect to an abstract Unix socket, or signal the agent or another process, outside the sandbox | Allowed (not covered below ABI 6) | Denied |
| Strict mode: TCP to the proxy port, UDP, IPv6 and netlink sockets | Denied | Denied |
| Strict mode: Unix socket to a proxy in the work directory; ordinary commands | Allowed | Allowed |

Not tested: kernels at ABI 3, 5 or 7 and above, x86_64 (the binary builds for it), and a Kubernetes pod; the probe covers the Kubernetes pod settings.

**Limits.** Landlock does not cover metadata changes (`chmod`, `chown`, timestamps), descriptors already open when the restriction is applied (hence `close_range`), or anything the agent passes in on purpose: sandboxing a whole agent protects its surroundings from the agent, not credentials deliberately given to the agent from prompt-injected decisions. Port rules check the port, not the address, so without strict mode a command may reach any host on the proxy port; below ABI 10 they do not cover UDP, and below ABI 9 pathname Unix sockets the command can name stay reachable, so keep such sockets out of its view. Without ABI 6, keep the agent's abstract sockets and process out of reach by other means (for example a separate user). Strict mode leaves pathname Unix sockets, so the only network route is whatever proxy listens on one. Landlock does not stop kernel exploits (§20.10).

**Optionally, mediate system calls.** A pack that hands the command descriptors (for example a connection to a proxy) can install, before `execve`, a second seccomp filter that returns `SECCOMP_RET_USER_NOTIF` for chosen system calls and pass the listener to a supervisor that answers with `SECCOMP_IOCTL_NOTIF_ADDFD` and `SECCOMP_ADDFD_FLAG_SEND`. That is `seccomp-user-notification`, reserved and demonstrated only by the probe; it must not be used as a check-then-continue policy (§20.10).

## 20.9 Verification

- **Per node group, then per node.** For `process-self-restriction`, NIC reports each node's kernel baseline when `nic outputs` runs, for diagnosis only, and the probe runs only in maintainers' release testing unless automating it is adopted (§20.8). Where probes are used, they run on each node group that should provide a capability, placed with that capability's own selectors and tolerations.
- **Primitive tests, in both directions.** For `process-self-restriction`: the probe's Landlock cases and the reference consumer's end-to-end test in §20.8, each denial with a positive control. A later capability states its own, including a negative case on the same node.
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

- An existing Nebari pack runs workers as separate pods with no ServiceAccount token, created only by a least-privilege controller (row 4). Its egress and controller work remain unfinished, so it is a precedent rather than a finished reference. Its plan to restrict worker egress notes that a NetworkPolicy cannot allow a hostname, so model traffic goes through an in-cluster egress gateway; the same constraint applies to Landlock (row 2), which restricts by port, not host.
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
  - Not qualified or supported by NIC: Agent Substrate needs Kubernetes 1.36 or later with beta pod-certificate APIs (`PodCertificateRequest`, `ClusterTrustBundle`) that managed services do not let you enable (realistically 1.37), enforced NetworkPolicy ([#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) is blocked), changes to GKE-specific node paths, and KVM-capable nodes for its microVM class (not Hetzner Cloud; its gVisor class needs none).
  - A weaker pod-level posture: its worker pods are no longer `privileged`, but run as root with 13 added capabilities (including `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`), seccomp and AppArmor unconfined, and `/dev/kvm` and `/dev/net/tun` for microVMs; its node agent mounts host paths. ADR-0010's hardened mode would have to admit that by exception, whereas `process-self-restriction` runs under Pod Security `restricted`.
  - A large operational footprint: API server, controller, router, egress gateway, node agent, an identity (OIDC) server, a pod-certificate signer, embedded OpenFGA, PostgreSQL and object storage.

Not chosen as the starting point. Because actors are not pods with published settings and the platform runs its own runtime binaries, it cannot provide a level through NIC's mapping; where it can run, it is separately trusted infrastructure on dedicated node groups, close to host root, not an implementation of a level. If packs converge on such a platform, the future `in-pod-namespaces` work can be deprioritised; `process-self-restriction` remains useful either way.

### Option 6: Node Feature Discovery

Node Feature Discovery, a Kubernetes SIG project, runs a DaemonSet that reads each node's kernel version and configuration, and a controller that turns those facts into node labels through `NodeFeatureRule` resources. It would label nodes automatically, including images NIC does not know, `existing` clusters and kind. It was discarded because it adds a DaemonSet, a controller with permission to patch nodes, and CRDs for something NIC can do with a version comparison: the node images NIC provisions are known in advance and change rarely. Like the kernel check, it reads kernel configuration rather than confirming Landlock is active at boot. It remains an option if clusters NIC does not provision become important.

### Option 7: Node-group labels from an image table

An earlier draft of ADR-0021 advertised `process-self-restriction` with node-group labels rather than only reporting an expectation per node group:

1. **Image table.** NIC kept a table mapping each node image it provisions to the Landlock ABI it provides. An image entered the table only after a manual probe run on it confirmed the capability under the exact pod settings; images not in the table were not advertised.
2. **Placement at node-group creation.** The provider predicted the capability from the node group's image when creating the group, reported it in `InfraSettings.Sandbox`, and applied `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi` as node-group labels (the same mechanism as GPU groups), so replacement and autoscaled nodes carried them from the start. Where node groups differed in ABI, each level got its own placement, and packs that needed ABI 4 selected it. NIC's Hetzner provider needed node-pool label support added. For `existing` and kind clusters NIC labelled nothing; operators could label nodes themselves at their own risk.
3. **Consistency check and readiness record.** During `nic deploy`, NIC compared each node's kernel version and OS image (`node.status.nodeInfo`) with its group's prediction and recorded mismatches (for example a manually upgraded node) in a read-only readiness record shown by `nic outputs`, reporting but not relabelling.

- **Pros:** steers pods away from non-qualifying node groups in mixed clusters; per-placement ABI guarantees.
- **Cons:** steering matters only in mixed clusters, and packs check Landlock at startup anyway; a table to keep current, label plumbing in every provider and a readiness record for that benefit. The `default` mapping entry renders a placement from NIC-set node-group labels where a provider has them (§20.6), which covers the mixed-cluster case without a separate table.

It can be added later, without changing the capability's name or guarantee, if mixed clusters become common.

## 20.13 Links

- [ADR-0003: Software Pack Codegen](../../adr/0003-software-pack-codegen.md)
- [ADR-0006: Conditional Foundational Software](../../adr/0006-conditional-foundational-software-helm.md)
- [ADR-0010: High-Security Mode](../../adr/0010-high-security-mode.md)
- [ADR-0017: User Journey Tests](../../adr/0017-user-journey-tests-for-foundational-software.md)
- [bubblewrap](https://github.com/containers/bubblewrap)
- [Landlock](https://docs.kernel.org/security/landlock.html)
- [go-landlock](https://github.com/landlock-lsm/go-landlock)
- [Sandbox probe and reference consumer](../../../tests/sandbox-probe/README.md)
- [Kubernetes v1.36: User Namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/)
- [KEP-4265: ProcMount option](https://www.kubernetes.dev/resources/keps/4265/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards)
- [Security Profiles Operator](https://sigs.k8s.io/security-profiles-operator)
- [Podman rootless requirements](https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Claude Code sandboxing: bubblewrap inside containers](https://code.claude.com/docs/en/sandboxing)
