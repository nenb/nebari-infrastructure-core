# Workload Sandboxing

## 20.1 Scope

This document holds the implementation design behind [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](../../adr/0021-gradual-workload-sandboxing-for-software-packs.md). The ADR records the decision: a tool-neutral capability contract with separate interfaces for desired configuration, observed readiness and consumer integration, delivering `process-self-restriction` ("Phase 1" below) and reserving names for later capabilities. The `in-pod-namespaces` design ("Phase 2" below) and the material on later capabilities are future work here; each needs its own ADR before delivery. This document records the detail that implements and justifies it: the sandboxing spectrum, provider findings, the full capability definitions, delivery steps and release gates, verification, security considerations, composition and privilege tiers, and related work. Where the two disagree, the ADR is authoritative for the decision and this document is updated to match.

## 20.2 The sandboxing spectrum

| # | Option | Examples | What isolates the code | Cluster changes needed | Main limits | Place in this ADR |
|---|---|---|---|---|---|---|
| 1 | Language runtime | WASM (wasmtime, WASI), V8 isolates, Deno with permission flags, Pyodide, Monty (a Python-subset interpreter written in Rust, with no filesystem, environment or network inside the sandbox; the host exposes only the functions it chooses) | The runtime: code can only do what the runtime exposes | None | Runs only code built for that runtime, or a subset of a language (no C extensions or third-party native packages); no arbitrary binaries, shells, `pip install` or `git` | Packs can do this today |
| 1b | The user's own browser | JupyterLite, Pyodide or WebContainers on the client side | The browser sandbox, on the user's machine | None; the cluster is not involved | As row 1; nothing runs on the platform | Packs can do this today |
| 2 | Process self-restriction | Landlock plus seccomp filters, including seccomp user notification to mediate selected syscalls (the approach of several agent sandboxes on Linux) | The process drops its own filesystem (and, on newer kernels, TCP) rights and installs syscall filters before running a command | Node kernel only: Landlock ABI >= 3 enabled (ABI 4 for TCP rules); nothing else. Not every provider's default node image qualifies (see §20.4) | Covers filesystem access and syscall mediation; Landlock TCP rules need a newer kernel than filesystem rules; no process-visibility isolation on its own | **`process-self-restriction`, this ADR** |
| 3 | Namespace sandbox in the pod | bubblewrap, nsjail, minijail, rootless podman/buildah | Linux namespaces inside the pod, on the shared host kernel | Yes: node prep and security profiles (the four layers below) | Shares the host kernel; extra kernel attack surface from user namespaces | **`in-pod-namespaces`, this ADR** |
| 3b | Headless browser in the pod | Chromium/Playwright running untrusted pages or scripts | Chromium's own sandbox, which also uses user namespaces | Same as row 3, otherwise it runs with `--no-sandbox` | As row 3 | Potential consumer of `in-pod-namespaces`; not qualified (Chromium's sandbox may need more than the guarantee, such as its own pid namespace) |
| 3c | System-container runtime | Sysbox, used to run `dockerd` or `systemd` inside a workspace | User namespaces plus virtualised `/proc` and `/sys`, on the shared host kernel | Yes: either a `RuntimeClass` installed on the nodes, or a privileged outer container that hosts an unprivileged inner one | Shares the host kernel; the privileged-outer-container variant is root on the node | Not delivered here. As a `RuntimeClass`, a later capability; the privileged-outer-container variant falls under the relaxed-workload or node-owning tiers (§20.12) |
| 4 | Separate locked-down pod per task | A Job or Agent Sandbox `Sandbox` with the default runtime: no service-account token, NetworkPolicy, read-only root, optionally `hostUsers: false` | Standard container isolation, on the shared host kernel | Pod security settings: none. NetworkPolicy: only takes effect where the network plugin enforces it, which is not the case on AWS or Azure as NIC deploys them today (tracked in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). `hostUsers: false` needs recent Kubernetes, containerd and kernel | Start-up latency; the pack needs RBAC to create pods; still a shared kernel | Basic form: packs can do this today. collab-hub-pack already runs workers as separate pods with no ServiceAccount token (egress restriction still in progress); Nebi has proposed the same for its builds (see Related work). Its network controls depend on #691/#675. With `hostUsers: false`: `pod-user-namespaces`, follow-up |
| 5 | User-space kernel | gVisor (`runsc`) | gVisor implements the Linux syscall interface itself; the workload never calls the host kernel directly | Yes: install the runtime and a `RuntimeClass` (built into some managed offerings, otherwise installed per provider) | I/O and syscall overhead; some applications are incompatible | `user-space-kernel`, follow-up |
| 6 | MicroVM per pod | Kata Containers, Firecracker, Cloud Hypervisor | Hardware virtualisation with a separate guest kernel | Yes: runtime install, and nodes that expose `/dev/kvm` (bare metal, or instance types with nested virtualisation) | More memory per pod, slower start; usually a dedicated KVM-capable node group | `vm-boundary`, follow-up |
| 7 | Dedicated node or cluster | Per-tenant node pools, a separate cluster, confidential VMs | A separate machine | Yes: provisioning | Cost | Out of scope |
| 8 | External sandbox service | Hosted code-execution services (several are Firecracker-based) | Someone else's infrastructure | None in the cluster; outbound network and credentials only | Data leaves the environment; vendor dependency | Packs can do this today |

Notes on egress, credentials and what each row needs from NIC are in §20.3.

## 20.3 Notes on the sandboxing spectrum

These points follow from the spectrum table in §20.2.

- **Several options need nothing from NIC** (rows 1, 1b, 4 in its basic form, and 8). This ADR is not a precondition for sandboxing in general; it addresses the band where pack developers are blocked by settings only the cluster can change. Row 2 needs no relaxation of pod security, but does depend on the node kernel, which only the cluster controls.
- **Row 1 can carry a whole agent platform, not just code snippets.** If agents write code for the runtime instead of running shell commands, and every external action goes through brokers, a language-runtime sandbox can host a full agent platform with the strongest credential posture of any row: no ambient network at all. The trade-off is giving up arbitrary binaries and shells (no `git`, `pip` or compilers), which rules it out for general coding agents.
- **Isolation strength is only part of the picture.** In every row, outbound network policy, which credentials are visible to the sandboxed code (service-account token, cloud IAM, Git tokens), resource limits (including process counts) and filesystem write access usually matter as much as the isolation tier, and so does observability: logging the process tree and network egress, so that misuse can be detected. Lifecycle is a separate dimension again (a fresh sandbox per run, a long-lived workspace, or snapshot and restore); it is outside the capability contract and is the pack's choice, with long-lived workspaces needing an explicit policy for secrets.
- **GPUs widen the attack surface.** Passing a GPU into a sandbox exposes large driver code paths through device interfaces, whatever the boundary. Where possible, keep general code execution in CPU-only sandboxes and reach model execution through a separate GPU service. A VM with cloud credentials mounted is weaker in practice than a namespace sandbox without them.
- **Egress can be enforced in four ways, and all are legitimate.** *Cluster-enforced* egress (NetworkPolicy) cannot be changed by anything inside the pod, but matches only IP addresses and ports. *In-pod* egress enforcement (a proxy or a sidecar running a DNS filter and packet rules in the pod's network namespace) can allow domain names, which NetworkPolicy cannot. A *mediating proxy outside the workload* (an egress gateway, or a dedicated proxy pod per sandbox that performs policy checks and opens approved upstream connections) can also allow domain names and keep credentials out of the workload, with NetworkPolicy denying the workload every other route. Domain-based egress therefore needs the in-pod kind or a mediating proxy. For the pod-network proxy topology described here, NetworkPolicy enforced for both ingress and egress provides the required bypass prevention; without it, the workload can bypass the proxy. Topologies that reach the proxy through a namespace with no other route, or through IPC, prevent bypass by other means. An in-pod enforcer that programs packet rules needs `NET_ADMIN`, which Pod Security Baseline does not allow: on the default runtime it falls under the relaxed-workload terms in §20.12, and the workload container itself must not hold it. Landlock network rules (ABI 4) give **TCP-port confinement** with no added privilege: the workload may not `bind`, and may `connect` only to listed ports. That is **not** proxy enforcement on its own: Landlock checks the port, not the destination address, so a workload allowed to reach a proxy on `127.0.0.1:8080` can also reach any remote host on port 8080; it does not restrict UDP; and already-connected inherited sockets stay usable. Making an in-pod proxy non-bypassable additionally needs destination and protocol enforcement (for example a network namespace with only a loopback route to the proxy, or qualified syscall mediation that enforces approved destinations, combined with protocol restrictions) and descriptor hygiene. A consumer qualified as proxy-enforcing must show that the proxy connection succeeds, the same port at another address fails, direct UDP fails, and unapproved inherited sockets are unavailable. Finally, *capability-scoped brokers* remove the network altogether: the workload has no outbound network, only typed calls to broker services that hold the credentials and scope each call to the resource the user granted. Row 1 runtimes make this easy, because they can be given no network at all, but it is not exclusive to them: a native workload can also run with no ambient network and reach a credential-holding broker only through tightly controlled pipes or other IPC. Credential posture is a property of configuration, not of the isolation tier.

- **NetworkPolicy enforcement is tracked separately and is not part of this ADR.** [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) makes enforcement a per-provider guarantee and [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) covers the AWS VPC CNI. Row 4's network controls, and sandbox systems that place a mediating proxy on the pod network, depend on that work; rows 2 and 3 do not, so the two can proceed independently.

## 20.4 Why row 2 (process self-restriction) needs NIC

Row 2 needs nothing from the pod spec: it runs non-root, with every capability dropped and the runtime's default seccomp profile, so it is compatible with Pod Security `restricted`. What it needs is node kernel support, which packs cannot change:

- **Landlock** enabled in the kernel's active security modules, at a sufficient ABI version. ABI 3 (Linux 6.2) covers filesystem access including truncation; TCP bind/connect rules need ABI 4 (Linux 6.7). ABI 3 is the floor for the capability, but **ABI 4 is the target**: TCP-port confinement (restricting which ports a process may `bind` or `connect` to) is the main agent use case, and it needs ABI 4. Landlock checks ports, not destination addresses, and does not restrict UDP, so port confinement is not by itself proxy enforcement (§20.3). Distribution backports exist, so the version number alone does not decide it: the probe does.
- **Nested seccomp filters with user notification**, including the operations that let a supervising process inject descriptors into the workload, usable under the runtime's default seccomp profile. containerd's default profile allows the `seccomp` syscall, and, on kernels from 4.8, `ptrace` and `process_vm_readv`, which some mediators use to inspect the workload.

Where the providers' default node images stand, from AMI release notes and module source (checked 2026-10-14). Whether Landlock is in each kernel's active security-module list at boot is still to be confirmed on a running node (`/sys/kernel/security/lsm`):

| Provider | Default node kernel | Landlock ABI >= 3 |
|---|---|---|
| `aws` (AL2023 EKS AMI) | Set by Kubernetes version (amazon-eks-ami v20261012): 6.1 for 1.31–1.32, 6.12 for 1.33–1.35, 6.18 for 1.36–1.37. NIC's AWS example (1.34) gets 6.12 | Yes from Kubernetes 1.33 (6.12 provides ABI 6). AL2023 enabled `CONFIG_SECURITY_LANDLOCK` in its 6.1 and 6.12 kernels in release 2023.8.20250804; boot-time activation unconfirmed |
| `hetzner` (hetzner-k3s, Ubuntu 24.04) | 6.8 | Yes (ABI 4); Landlock expected in Ubuntu's default security-module list, unconfirmed on a node |
| `azure` (AKS) | NIC's AKS module (v0.2.0) sets no `os_sku`, so AKS defaults apply: Ubuntu 22.04 (5.15) below Kubernetes 1.35, and Ubuntu 24.04 (6.8) from 1.35, to which AKS migrates node pools automatically on upgrade. NIC's Azure example (1.34) gets 22.04 | No below 1.35; expected yes (ABI 4) from 1.35. Selecting Ubuntu 24.04 earlier (`Ubuntu2404`, available from 1.32) or Azure Linux 3 needs an `os_sku` setting the module does not expose today |
| `local` (kind) | The host's kernel | Host-dependent |
| `existing` | Unknown | Detect only |

So the NIC work for row 2 is choosing qualifying node images, reporting what each node group supports, and probing it, not changing pod security.

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

The cluster advertises a **set of capabilities**, not a single level, because the options are not strictly ordered (a VM runtime is not a superset of in-pod namespaces). Capabilities name **guarantees, not mechanisms**.

| Capability | Guarantee | Qualified consumer | Phase |
|---|---|---|---|
| `process-self-restriction` | A non-root process with no added capabilities, under the runtime's default seccomp profile, can restrict itself and its descendants with Landlock (ABI 3 or newer; the observed ABI is reported) and with nested seccomp filters, including user-notification filters. User notification is a mechanism for emulating syscalls or injecting descriptors, not a security-policy check on its own: a supervisor that inspects a syscall's arguments and then lets it continue can race with changes to that memory or filesystem state, as the Linux manual warns. | A Landlock ruleset that denies a filesystem write and, at ABI 4, restricts `connect` to one port; a nested seccomp user-notification filter | **1 (this ADR)** |
| `in-pod-namespaces` | A non-root process with no added capabilities can create a user namespace that maps **only its own UID and GID**, and mount, network, IPC and UTS namespaces inside it. The container's masked `/proc` is retained (bind-mounted, not freshly mounted), so no pid namespace with a fresh procfs is guaranteed. | One pinned bubblewrap version with a fixed, tested invocation (§20.9) | **2 (this ADR, gated)** |
| `pod-user-namespaces` | Pods may set `hostUsers: false`. Permission to unmask `/proc` is a separate question: Pod Security `restricted` rejects `procMount: Unmasked` even with `hostUsers: false` as of Kubernetes 1.36. | n/a | Later ADR |
| `user-space-kernel` | Workloads that request it run behind a user-space kernel that implements the Linux syscall interface. | n/a | Later ADR |
| `vm-boundary` | Workloads that request it run behind a hardware-virtualisation boundary with their own guest kernel. | n/a | Later ADR |
| `network-policy` | NetworkPolicies are enforced for ingress and egress. | n/a | Candidate only; owned by [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) |

Tools that need more than the qualified configuration are **potential** consumers, not implied ones. Rootless container engines are the main example: normal multi-UID operation uses `newuidmap`/`newgidmap` and subordinate ID ranges, which a non-root pod with `allowPrivilegeEscalation: false` and no capabilities cannot use, and they may also need FUSE, storage drivers or cgroup delegation. Supporting them would be a separately qualified configuration.

Every capability is defined by the same items: **guarantee**, **qualified consumer**, **placement**, **cluster requirements** (node kernel or OS, boot-time node settings, Kubernetes or API-server features, all expressed through provider config), **provisioning** (what is installed, by whom, and when in the lifecycle), **verification**, and any **scale limits**. Later ADRs may add capabilities by defining these items. For capabilities backed by a `RuntimeClass`, placement uses the `RuntimeClass`'s own `scheduling` field (node selector and tolerations merged into pods by Kubernetes), so packs only set `runtimeClassName`; NIC does not duplicate that mechanism.

Composition rules and the privilege tiers available to later capabilities are in §20.12.

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

**2. Observed readiness (after bootstrap).** *For `process-self-restriction`, ADR-0021 replaces observation with a deploy-time consistency check against node metadata, and node-group labels set at creation; the probe-based observation, expiry and quarantine described here apply to capabilities that adopt probes (see §20.8 and §20.9).* NIC records what it actually verified, per capability and node group, in a read-only `nebari-sandbox-capabilities` ConfigMap in a NIC-owned namespace: verified or not, observed Landlock ABI, profile version, and when it was last verified, with an **expiry**: a record not refreshed by scheduled verification before it expires reads as unverified, so a stopped verifier cannot leave a stale success in place.

The record is **informational**: it is a snapshot that tells operators and packs what was observed, not an enforcement point. Updating it does not change Helm values a pack was installed with, does not move pods, and does not stop a running worker from accepting new commands. The enforcement contract is therefore: (a) each consumer fails closed when it establishes each sandbox, by checking the guarantee itself (for example applying its Landlock ruleset or creating its namespace and refusing to run if that fails), never by reading the record; and (b) for capabilities with a readiness barrier (Phase 2), a node that fails re-verification is **quarantined** by re-applying its unverified taint, so no new pods schedule there. Already-running tasks are left running by default and reported; eviction is an operator choice, not automatic.

**3. Consumer integration (packs).** Until pack codegen ([ADR-0003](0003-software-pack-codegen.md)) exists, packs are integrated **explicitly**: they take documented Helm values (`sandbox.capabilities.<name>.nodeSelector`, `.tolerations`, `.runtimeClassName`, the profile name and version, and the placement's guaranteed minimum Landlock ABI) set by the operator from the readiness record, and are responsible for refusing to start sandboxed work without an unsafe fallback. Declaring `requires: { sandbox: [...] }` in `nebari-integration.yaml`, with NIC refusing incompatible packs, is **future work** that depends on ADR-0003. A ConfigMap alone does not make Helm, ArgoCD or KubeSpawner consume settings or reject workloads.

## 20.7 Lifecycle

*`process-self-restriction` installs nothing and does not use this phase (ADR-0021); it applies to capabilities with cluster components.* Capabilities that need cluster components are installed in a **post-bootstrap phase**, not inside the provider's `Deploy()`:

1. Provider `Deploy()`: node groups, node images, node labels and taints, and any boot-time node settings.
2. Foundational services bootstrap (ArgoCD and the foundational applications).
3. **Wait for the dependencies to be ready** (for Phase 2, cert-manager).
4. Install the capability's components and its versioned profiles.
5. Verify (§20.10).
6. Publish the readiness record.

Today, conditional software ([ADR-0006](0006-conditional-foundational-software-helm.md)) is installed inside the provider's `Deploy()`, before ArgoCD and cert-manager exist, and foundational-service failures are reported as warnings rather than failing the deploy. This ADR therefore needs either a post-bootstrap lifecycle hook in `pkg/nic` or an amendment to ADR-0006. Independently of ADR-0010's fail-closed hardened mode, a capability in `sandbox.require` (or opted into on a node group) that fails steps 3-5 makes `nic deploy` exit non-zero.

## 20.8 Delivery, Phase 1: `process-self-restriction`

1. **No opt-in, no relaxation, no components.** No profiles, no operator, no admission exception and no node preparation are needed. Steps 3-4 of the lifecycle are empty.
2. **Qualifying node images: passive by default.** NIC discovers and advertises the capability on node groups whose current images qualify; it does **not** change node images on its own, and explicit image pins are preserved. Moving a node group to a qualifying image is an explicit, operator-requested migration through the provider's own config, as for GPU images. NIC targets Landlock ABI 4 (for example Ubuntu 24.04's 6.8 kernel, or AL2023 on a 6.12 kernel); node groups that reach only ABI 3 still qualify, with their ABI reported. On Azure, Kubernetes 1.35 and later bring Ubuntu 24.04 by default; earlier versions need NIC's AKS module to expose `os_sku`. `local` and `existing` are detect-only. A node group that cannot qualify (for example a GPU image pinned to an older kernel) is not listed as providing the capability. A node image is added to NIC's qualifying-image table only after a one-off manual probe run on it (step 5) confirms the capability under the exact pod settings.
3. **Placement, set at node-group creation.** The provider predicts the capability from the node group's image when it creates the group, reports it in `InfraSettings.Sandbox`, and applies `sandbox.nebari.dev/process-self-restriction` and `sandbox.nebari.dev/landlock-abi` as **node-group labels** (the same mechanism as GPU groups), so replacement and autoscaled nodes carry them from the start. No taint is needed: nothing on these nodes is relaxed. NIC's Hetzner provider needs node-pool label support added. For `existing` and kind clusters NIC labels nothing; operators may label nodes themselves at their own risk.
4. **Consistency check (default).** During `nic deploy`, NIC reads each node's kernel version and OS image from `node.status.nodeInfo` and compares them with its group's prediction, recording mismatches (for example a manually upgraded node) in the readiness record and showing them in `nic outputs`. It reports mismatches but does not relabel. It installs nothing in the cluster and adds no CLI command. It is an inference: between manual probe runs it cannot see changes the table does not capture, such as Landlock disabled at boot by custom kernel parameters.
5. **Probe: run by hand per node image today; automating it is an open question in ADR-0021.** The probe observes the capability directly. On each node group, a non-root pod with every capability dropped and the default seccomp profile applies a Landlock ruleset and confirms a denied write fails, reports the highest ABI available and, at ABI 4, confirms a disallowed `connect` fails, and installs a nested seccomp user-notification filter whose supervisor injects a descriptor into the child with `SECCOMP_IOCTL_NOTIF_ADDFD` (with `SECCOMP_ADDFD_FLAG_SEND`), and the child then uses that descriptor. Each denial check has a positive control on the same node (the same write or `connect` succeeds without the ruleset), so an unrelated filesystem or network failure cannot pass as successful confinement. For this capability, verification runs each time `nic deploy` or `nic verify` runs, using short-lived probe pods that are deleted afterwards; nothing stays running in the cluster. Operators who want a regular cadence run `nic verify` on a schedule from outside the cluster, and the readiness record's expiry is set to match. In-cluster scheduled re-verification and the readiness barrier apply to capabilities with installed components (§20.9).

## 20.9 Future work: delivery of `in-pod-namespaces` (Phase 2)

This section is the detailed design behind [ADR-0022](../../adr/0022-in-pod-namespaces-capability.md), which proposes delivering `in-pod-namespaces`, first on node groups without AppArmor; ADR-0021 delivers only `process-self-restriction`. ADR-0022 changes this design for its first delivery (AWS): the seccomp profile is written at node boot and the kubelet's `seccompDefault` is set in node bootstrap, so the Security Profiles Operator, the post-bootstrap phase and the readiness barrier below are not used there; Gate C and Gate D still apply. The operator-based design and readiness barrier below are kept for providers without a node bootstrap hook in NIC (AKS), and Gates A and B describe what extends the capability to AppArmor nodes and autoscaled Hetzner pools, where ADR-0022 proposes loading a NIC-owned AppArmor profile at boot instead of through the operator.

Phase 2 ships only when all of its **release gates** are met:

- **Gate A, AppArmor mechanism.** The Security Profiles Operator (v1.1.1) can distribute seccomp profiles, but its `AppArmorProfile` API offers only abstract executable, filesystem, network, capability and ptrace rules: it cannot express a `userns` grant, scoped `mount` rules, or raw policy. Until a maintained mechanism can express the required AppArmor policy (upstream SPO support, or another maintained loader), Phase 2 is offered **only on node groups without AppArmor** (for example AWS AL2023). A NIC-owned privileged AppArmor loader would be substantial additional scope and needs its own decision.
- **Gate B, Hetzner autoscaling.** hetzner-k3s v2.4.6 applies per-pool pre-k3s commands to initially created workers, but its autoscaler cloud-init uses the global settings instead of pool overrides. Until that is fixed upstream (and NIC pins the fixed version) or another verified preparation mechanism exists, NIC rejects autoscaling on Hetzner pools that request `in-pod-namespaces`. The gate is closed only by testing a node the autoscaler created.
- **Gate C, versioned profiles.** The seccomp profile exists as a reviewed, immutable artifact (item 5 of §20.9), with adversarial tests passing.
- **Gate D, qualified consumer.** The pinned bubblewrap invocation passes the primitive tests, and one real pack passes the consumer acceptance test (§20.10).

When the gates are met:

1. **Opt-in per node group** through the `sandbox` block above.
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

- **The capability test** proves only that the namespaces can be created: `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --ro-bind / / --ro-bind /proc /proc --dev /dev --die-with-parent -- true`. It exposes the whole container read-only and is not a sandbox policy.
- **The qualified consumer configuration** is what packs start from and what the acceptance test runs against. It binds only what a command needs and hides everything else, in the form `bwrap --unshare-user --unshare-ipc --unshare-uts --unshare-net --clearenv --setenv PATH /usr/bin:/bin --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --ro-bind /etc/ssl /etc/ssl --bind <workdir> <workdir> --ro-bind /proc /proc --dev /dev --tmpfs /tmp --tmpfs <home> --die-with-parent --new-session -- <command>` (exact flags fixed in the implementation). The agent's home directory, configuration, mounted secrets, service-account token paths and socket directories are not bound, and `--clearenv` stops credentials in environment variables from passing through.
- **The qualified networked configuration** is the same, except that instead of no network at all, the sandboxed command reaches the network only through a proxy the pack runs outside the sandbox: the pack binds the proxy's Unix socket into the sandbox (for example `--bind <proxy-socket-dir> <proxy-socket-dir>`) and points the command's `HTTP_PROXY`/`HTTPS_PROXY` at a small in-sandbox forwarder to that socket. The sandbox still has its own network namespace with only a loopback interface, so nothing else is reachable, including the cloud instance metadata service. The proxy decides which destinations are allowed and can inject credentials so they never enter the sandbox.

The qualified configurations are secure starting points: packs extend them with the specific paths their tools need (for example a virtualenv, `/usr/local` or a toolchain directory), never with `/` or the home directory, and the acceptance test runs against the extended version.

**The seccomp profile.** NIC owns a complete `Localhost` profile, `nebari-sandbox-v1` (a `Localhost` profile replaces `RuntimeDefault` rather than extending it, so NIC maintains the full allowlist per architecture). It permits the namespace syscalls, makes `clone3` fail with `ENOSYS` (seccomp cannot inspect its flags), and blocks netfilter configuration by filtering `socket()` on its arguments while allowing what bubblewrap needs to bring up a loopback interface. It keeps denying the families that widen the kernel surface reachable from a user namespace: `bpf`, the `io_uring` calls, `keyctl`/`add_key`/`request_key`, `userfaultfd`, `perf_event_open`, kernel-module and `kexec` calls, and `open_by_handle_at`. Seccomp cannot filter which filesystem type a `mount` inside a user namespace uses, so bugs in, for example, overlayfs mounted from user namespaces (CVE-2023-0386) are covered only by kernel patching. A change is a new version (`-v2`) shipped alongside the old ones; because profiles are written at boot, a new version reaches nodes through a node-group rolling update, which replaces nodes one at a time and evicts the sandboxing pods on each, ending users' running sessions. That is acceptable for routine changes, which should be rare. If a profile fix ever has to land faster than a rolling update allows, the planned mechanism is a minimal in-node writer that only copies new profile versions into place, added by amending this ADR. Old versions stay until declared consumers have migrated or the operator retires them.

### ADR-0022: admission policy and alternatives in full

ADR-0022 summarises these; the full text is recorded here.

**Admission policy.** When a node group enables the capability, the provider installs a small chart containing a ValidatingAdmissionPolicy the way providers already install conditional charts (for example the GPU operator), following [ADR-0006](0006-conditional-foundational-software-helm.md)'s provider-driven approach and moving to its shared interface (#349) once that exists; in hardened mode, ADR-0010's admission policy does the same job. Only namespaces labelled for the capability may reference `nebari-sandbox-v*` or tolerate the dedication taint, and only cluster administrators may set that namespace label, so a namespace owner cannot grant it to themselves. In workload namespaces, wildcard tolerations (an empty key with `operator: Exists`) and direct node assignment (`spec.nodeName`) onto these nodes are rejected unless the namespace is labelled; `kube-system` and NIC's foundational namespaces are exempt, because system DaemonSets such as the VPC CNI, kube-proxy, CSI drivers and monitoring agents rely on wildcard tolerations to run on every node. Pack namespaces are normally created by ArgoCD from the GitOps repository, so ArgoCD's identity is among those allowed to set the label: anyone who can write to that repository can grant the capability, which is consistent with ADR-0010's position that repository write is equivalent to cluster administration.

**Alternatives.**

- **Option 4 (`runtimeClassName: gvisor` on the existing pod):** the pod stays as it is, and gVisor intercepts its syscalls in a user-space kernel, so a host-kernel exploit from the pod is far harder. It needs no unprivileged user namespaces, no NIC-owned seccomp allowlist and no AppArmor work, and its default mode needs no hardware virtualisation, so it could reach Hetzner Cloud and AKS sooner. Its costs: installing gVisor and a `RuntimeClass` per provider, compatibility gaps and I/O overhead for some workloads, limited GPU support, and checking that the pack's stack (for example JupyterLab and its kernels) runs under it. Above all, it protects the **host from the pod**, not the **pod's credentials from the agent's commands**, because everything in the pod shares gVisor's kernel. It is the right next capability where kernel-exploit risk matters, and it composes with this one: ADR-0021's composition rules allow namespace tools inside a `user-space-kernel` pod, subject to probing.
- **Option 6 (separate, credential-free gVisor pod per session):** this does meet the threat model: the commands run where the agent's credentials are not, behind a user-space kernel, with no user namespaces on the host. Its costs are a pod start per session, sharing the workspace between the agent's pod and the sandbox pod (which needs shared storage or copying), giving the pack permission to create pods, and re-architecting packs around it; it also needs the same gVisor installation as Option 4. It is a strong candidate once `user-space-kernel` exists, and the [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) project could provide its request layer. It is not chosen first because it depends on that capability and on a larger change to how packs work.

## 20.10 Verification

- **Per node group, then per node.** For `process-self-restriction`, detection is by node metadata unless the optional probe (§20.8) is adopted. Where probes are used, they run on each node group that should provide a capability, placed with that capability's own selectors and tolerations. For Phase 2, the per-node probe also gates the readiness barrier.
- **Primitive tests, in both directions.** For `process-self-restriction`: Landlock and seccomp cases above. For `in-pod-namespaces`: the qualified invocation succeeds with the profile; a pod without the profile on the same node cannot create a user namespace; netfilter and raw-socket creation fail from inside a new user namespace.
- **Consumer acceptance test (Gate D).** Separately from the primitive, one real pack (the Pi pack is the first candidate) must show, with the capability in use:
  - credential canaries placed in the agent's environment, files and mounted secrets are not readable by sandboxed commands;
  - inherited file and socket descriptors are closed or explicitly allowed;
  - networking is denied (or limited to the intended proxy);
  - the pack's generated worker-pod settings carry the expected profile, selectors and tolerations;
  - when the capability is absent, the pack refuses sandboxed work rather than falling back to running unsandboxed.

  This matters because node support alone changes nothing in a pack that, for example, passes credentials in environment variables or launches browsers with `--no-sandbox`.
- **Scheduled re-verification.** Probes also run on a schedule, following the pattern proposed in [#683](https://github.com/nebari-dev/nebari-infrastructure-core/issues/683); the readiness record and its expiry are refreshed; a failing node is reported and, for Phase 2, quarantined (see §20.6, Observed readiness).
- The NetworkPolicy enforcement check proposed in [#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691) uses the same positive/negative pattern, and the two should share their harness.

## 20.11 Security considerations

Items 1-4 below concern the future `in-pod-namespaces` capability (§20.9); `process-self-restriction` relaxes nothing.

`process-self-restriction` relaxes nothing and runs under Pod Security `restricted`. Today, by contrast, pods without a seccomp profile run with no syscall filter at all (confirmed on AWS), and packs that want isolation reach for root, privileged pods or `Unconfined` profiles; a sanctioned, narrower path improves on that. `in-pod-namespaces` adds real risk, bounded only if:

1. **Seccomp is on by default on `in-pod-namespaces` nodes.** Once a node permits unprivileged user namespaces, any pod there without a seccomp filter can create them, not only pods that reference the profile. These node groups run the kubelet with `seccompDefault: true`.
2. **Admission controls who may use the profile and the nodes.** Only namespaces explicitly labelled for the capability may reference `nebari-sandbox-v*` profiles or tolerate the `in-pod-namespaces` dedication taint (never the unverified taint; see the readiness-barrier invariants): through the hardened-mode admission policy (#480) in hardened mode, and a ValidatingAdmissionPolicy shipped with the capability in standard mode.
3. **The profile operator's API is locked down.** Only NIC and cluster administrators may create or modify `SeccompProfile` or `AppArmorProfile` resources; the operator's images are pinned by digest.
4. **The netfilter block is concrete and tested** (item 5 of §20.9).
5. **Kernels on `in-pod-namespaces` node groups are patched promptly**, on a defined cadence with a named owner.
6. **Readiness is re-verified** at node start (readiness barrier) and on a schedule.
7. **Pack-facing documentation states the threat model precisely.** Both capabilities share the host kernel and are not protection against kernel exploits or hostile multi-tenant code. Code an agent executes should be classified by what an adversary can influence (prompt injection, compromised dependencies), not by who owns the pod: a single-tenant deployment does not make that code trusted. These capabilities are appropriate where a kernel exploit from that code is an acceptable risk; where it is not, use `user-space-kernel` or `vm-boundary`. Packs using seccomp user notification must not rely on a check-then-continue supervisor as their policy mechanism. With the container's `/proc` reused, sandboxed commands can still see the command lines of other processes in the pod, which can contain credentials, and they inherit whatever environment and descriptors the launcher passes; a fresh user namespace does not by itself let them read another process's environment or follow its `/proc/<pid>/root`, since the kernel's ptrace access checks still apply.

## 20.12 Composition and privilege tiers for later capabilities

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

## 20.13 Related work

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

ADR-0021 summarises Options 4 and 5; their full assessment is recorded here.

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

## 20.17 Links

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
