# 22. Untrusted-Execution Pods

Mechanisms for [ADR-0025](../../adr/0025-untrusted-execution-pods.md). Each is a design target, not yet implemented or tested as NIC code. Probe results are in 22.10; claims marked "to be verified" have not been probed.

## 22.1 The pattern

An agent runs in a trusted pod that holds its model and integration credentials. Its tool calls run in a separate sandbox pod, usually one per session, reached over SSH (with a per-session key and a host key pinned in advance) or `kubectl exec`. The sandbox pod holds the workspace and no real credentials; outbound HTTP goes through the pack's proxy, which checks the destination and injects credentials outside the sandbox. NIC's role is everything around the sandbox pod: runtime, placement, admission and enforced network rules.

## 22.2 Namespace profile

For each namespace in `sandbox.untrusted_execution.namespaces`, NIC creates (or, in verification-only mode, checks):

| Object | Purpose |
|---|---|
| Namespace label `sandbox.nebari.dev/untrusted-execution: "true"` | Selects the admission policies and the profile's probes |
| Pod Security labels `enforce: baseline` | Root allowed; host namespaces, privileged and host paths refused |
| NetworkPolicy `nic-default-deny` (`podSelector: {}`, `policyTypes: [Ingress, Egress]`) | Default deny in both directions |
| `ValidatingAdmissionPolicy` `nic-untrusted-execution-pods` | Pod rules (22.3) |
| `ValidatingAdmissionPolicy` `nic-untrusted-execution-netpol` | NetworkPolicy rules (22.4) |
| Default ServiceAccount with `automountServiceAccountToken: false` | Belt and braces; the admission policy is the guarantee |
| `LimitRange` `nic-sandbox-defaults` and `ResourceQuota` `nic-sandbox-quota` | Default and maximum CPU, memory and ephemeral storage per container; namespace totals (22.11) |

Cluster-wide, once per cluster that uses the profile:

| Object | Purpose |
|---|---|
| `ValidatingAdmissionPolicy` `nic-sandbox-pool-tolerations` | Allows a toleration for a sandbox pool's taint (explicit, or a blanket `operator: Exists`) only for pods using a sandbox level's `RuntimeClass`; `kube-system` and NIC's node-level DaemonSets exempt. A taint alone let a runc pod that added the toleration run on a gVisor node (22.10) |
| On AWS, the `vpc-cni` add-on's `configuration_values`: `enableNetworkPolicy: "true"` and `env.NETWORK_POLICY_ENFORCING_MODE: strict` | Enforcement with no window at pod start; NIC's EKS module sets neither today, and a later `nic deploy` leaves hand-set values in place without guaranteeing them |
| A host-side rule on sandbox node groups, written at boot, dropping traffic from pod addresses to the node's own addresses | The CNI's policy does not cover a pod's traffic to its own node (22.10); the mechanism (an nftables rule in the node's boot steps on AWS and k3s) is to be qualified, including that the kubelet's and CNI's own traffic to pods is unaffected |

NIC owns these objects, labels them as NIC-managed, and fails the deploy if it cannot create or update them, as for ADR-0023's resources. Removing a namespace from the list stops NIC managing it but deletes nothing.

A platform's worker namespace (22.9) gets the same objects, with Pod Security `privileged` (the envelope policy, not Pod Security, is the limit there), an extra `ValidatingAdmissionPolicy` `nic-platform-envelope-<name>` and its binding, and a taint `sandbox.nebari.dev/platform=<name>:NoSchedule` on the platform's node groups.

## 22.3 Pod admission rules

Rejected in an untrusted-execution namespace:

- no `runtimeClassName`, or one that is not the published class of the profile's boundary level or a stronger one;
- any ephemeral container (the policy matches `pods` and `pods/ephemeralcontainers`; matching only `pods` let an ephemeral container read a Secret into a running sandbox pod, 22.10);
- `automountServiceAccountToken` not explicitly `false` (pod or ServiceAccount), or a projected service-account token volume;
- Secret volumes, projected Secrets, `env.valueFrom.secretKeyRef` or `envFrom.secretRef`, except Secrets labelled `sandbox.nebari.dev/session-capability: "true"`;
- `hostPath` volumes, `hostNetwork`, `hostPID`, `hostIPC`, `privileged: true`, added capabilities beyond the container runtime's defaults.

The runtime class applies to the whole pod, so trusted helpers (the agent, a proxy) must never be containers in a sandbox pod: under a VM runtime they would share its VM, and under any runtime its network rules.

Allowed: running as UID 0, the runtime's default capabilities, writable root file systems, `emptyDir`, PVCs, ConfigMaps (for public material such as authorized keys).

## 22.4 NetworkPolicy admission rules

NetworkPolicies other than NIC's own in these namespaces may only:

- allow egress to pods selected by `podSelector` and `namespaceSelector` (for example the pack's proxy namespace), and to the cluster DNS service if the pack declares it;
- allow ingress from pods selected the same way (the agent's pods, for SSH or exec traffic).

Rejected: any `ipBlock` (egress or ingress), and empty selectors that would match every namespace. Because NetworkPolicies are additive, this is what prevents a pack's allow-all from undoing the default deny.

## 22.5 Enforcement per provider

| Provider | Enforcement | Status |
|---|---|---|
| AWS | VPC CNI network policy agent (`enableNetworkPolicy` and strict mode on the add-on, #675) | Off in NIC today. Once enabled, default deny held against root under gVisor and Kata for every external and cluster destination tried, including the metadata service, Pod Identity, the API server and other nodes; **not** for the pod's own node, which needs the host-side rule (22.10) |
| Hetzner | k3s's embedded policy controller (kube-router) with flannel | Enforced for gVisor pods (2026-10-25). Metadata service (including the join-token issue) and node-local traffic: to be verified |
| Azure | Cilium dataplane (#691) | Not configured by NIC's AKS module today |
| `existing`, kind | Operator's CNI | Verification only |

`InfraSettings.Sandbox` reports whether the provider enforces NetworkPolicy, and `nic validate` rejects the profile where it does not. The deploy probe (22.6) is the evidence; configuration is never taken as proof.

**Start-up window.** In the VPC CNI's default `standard` mode, each new pod could connect directly for its first 1.0–1.4 s before its policy applied. In `strict` mode no direct connection succeeded, and the pod's allowed routes (the proxy, DNS) opened 1.4–1.8 s after start. NIC uses strict mode, and packs' sandboxes retry their first connections rather than failing. The window on k3s is to be measured.

## 22.6 Deploy-time probe

For each namespace and each listed runtime, `nic deploy` starts a short-lived root pod from an image NIC publishes, plus a NIC test target in a separate namespace with a label the probe's own NetworkPolicy allows. The probe must observe:

1. external egress (an IP and a hostname) fails;
2. the allowed test target is reachable and a second, non-allowed target is not;
3. `169.254.169.254` (and the provider's other metadata addresses) is unreachable;
4. the node's own addresses on the kubelet port and a NodePort are unreachable;
5. the Kubernetes API service address is unreachable;
6. no service-account token exists at the usual path;
7. the pod's boundary level holds (ADR-0021: the kernel release inside differs from the node's, and for `hardware-virtualised` the pod sees a hypervisor);
8. in strict mode, a connection attempted in the pod's first second fails rather than succeeds.

It also submits, with server-side dry run, a pod without a runtime class, a pod mounting a Secret, an ephemeral container, a runc pod tolerating a sandbox pool's taint and a NetworkPolicy with an external `ipBlock`, each of which must be rejected. Any failure fails the deploy; the probe objects are deleted afterwards.

## 22.7 Verification checklist

Per provider, before it is listed as supporting the profile:

- every step of the deploy probe, under gVisor and (where supported) the VM runtime, with the probe running as root;
- an SSH session from an agent pod in another namespace to a sandbox pod, allowed by the pack's ingress policy, and refused from a pod without the label;
- a sandbox pod's HTTP traffic through a proxy in another namespace succeeding, and the same request sent directly failing;
- the admission rules against each rejected pattern in 22.3 and 22.4, and a labelled session-capability Secret accepted;
- a tool-execution workload as root under each runtime: SSH commands and SFTP to a PVC-backed workspace (observed on EKS under gVisor and Kata, 22.10); package installs, compilers and Git (to be verified);
- node-local reachability tests repeated after a node replacement and a CNI upgrade;
- for each sandbox-platform envelope: a worker pod within it admitted, each field exceeded by one step rejected, a non-platform pod on the platform's nodes rejected, and the network probe passing from a pod holding `NET_ADMIN` that tries to change its own routes and nftables rules.

## 22.8 Rejected alternatives

- **Trusting NetworkPolicy objects without enforcement checks:** a policy nothing enforces is accepted and does nothing (EKS today).
- **Pod Security `restricted` for sandbox namespaces:** forbids root, which tool execution needs; the runtime is the boundary instead.
- **In-pod network restrictions for sandboxes:** root inside the pod can undo them.
- **A NIC-owned request layer or egress gateway:** see ADR-0025, options 4 and 5.
- **Admitting sandbox platforms by loosening the sandbox-pod rules:** any loosening applies to every pod in the namespace; the envelope applies only to declared service accounts on dedicated nodes.
- **Running a platform's workers under NIC's gVisor `RuntimeClass`:** the workers start `runsc` or a VMM themselves, which a gVisor pod cannot do; nesting is unsupported by the platform and would double the runtime.

## 22.9 Sandbox platforms

Facts are from Agent Substrate v0.6.0 (released 2026-10-22; repository created 2026-05; tags v0.2.0 to v0.6.0 in five months), read from its source and documentation, and from Agent Sandbox v1.0.8 (2026-10-22). Both projects move quickly; the envelope below must be re-read for each release.

### Two shapes

| | Agent Sandbox (kubernetes-sigs) | Agent Substrate |
|---|---|---|
| Unit of isolation | A pod (`Sandbox`, `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; API `v1beta1` from v1.0) | An actor inside a worker pod; up to 1,000 per worker |
| Runtime | `RuntimeClass` (gVisor, Kata) installed by the cluster | `runsc`, or Kata guest kernel on Cloud Hypervisor, started by the worker from binaries fetched through a `SandboxConfig` and checked by SHA-256; no `RuntimeClass` |
| Worker privileges | None beyond the pod's own | Root; adds `NET_ADMIN`, `SYS_ADMIN`, `SYS_CHROOT`, `SYS_PTRACE`, `SETUID`, `SETGID`, `SETPCAP`, `DAC_OVERRIDE`, `FOWNER`, `CHOWN`, `MKNOD`, `NET_RAW`, `SETFCAP` (microVM adds `FSETID`, `DAC_READ_SEARCH`); seccomp and AppArmor `Unconfined`; host path `/var/lib/ate`; microVM also `/dev/net/tun` and `/dev/kvm` as a device-plugin resource. Not `privileged` (it was before) |
| Node agent | None | `atelet` DaemonSet: root with `DAC_OVERRIDE`; host paths `/var/lib/ate`, `/var/lib/kubelet/plugins`, `/var/lib/kubelet/device-plugins`, `/dev`, and GKE's kubelet credential-provider paths (`/home/kubernetes/bin`, `/etc/srv/kubernetes/cri_auth_config.yaml`) |
| Network | Ordinary pod networking and NetworkPolicy | Per-actor private network namespace and veth programmed by the worker; link-local blocked; filtered DNS relay; shared `atenet-router` ingress and `atenet-egress` gateway that injects credentials (fail closed); NetworkPolicy at the worker-pool boundary and for its own namespaces |
| State | Pod storage (PVCs) | Memory and file-system snapshots in object storage (GCS, S3 plugin), state in PostgreSQL |
| Kubernetes | Ordinary | Latest stable and previous minor; `PodCertificateRequest` and `ClusterTrustBundle` APIs (beta on 1.36, enabled only at cluster creation; served by default on GKE 1.37) |
| Documented environments | Any cluster with the runtime | GKE and kind |
| Maturity | v1.x | Pre-1.0, "no guarantees about backward compatibility"; CNCF Sandbox application open |

Its own security table marks per-actor network isolation, zero ambient credentials and fail-closed egress as met, and node blast-radius containment, the delete guarantee and atespace network policy as in progress; a second security boundary between co-located actors is a roadmap goal.

### Fit with ADR-0021 to ADR-0026

- **ADR-0021's contract.** Actors are not pods with published settings, so NIC cannot verify a platform's boundary level. The platform may claim one, which NIC records and shows as claimed, not verified. Packs built on it depend on the platform's own API.
- **ADR-0023 (gVisor).** Not used: the platform's pools must not opt in, or a second `runsc` would sit unused on every node. A pod-per-sandbox design (a pack's pods, or Agent Sandbox) is what ADR-0023's tool-execution consumer is for.
- **ADR-0024 (immutable pools).** Fits: workers are a Deployment, and suspended actors resume on any worker in the pool with room, so sessions could survive a rollout that would end a pod-per-sandbox session. Whether draining a node suspends its active actors cleanly (its node agent has drain settings, `--drain-timeout=5m` by default) is to be verified. The platform's own runtime upgrades are its business; snapshots record the runtime they were taken on.
- **ADR-0025 (this ADR).** The sandbox-pod admission rules reject every worker pod (no runtime class, added capabilities, unconfined profiles, host paths), hence the second profile. NetworkPolicy enforcement, dedicated tainted pools (it already tolerates its own `ate.dev/sandboxClass` taint and supports a separate control-plane pool) and blocked metadata are prerequisites it shares with sandbox pods.
- **ADR-0026 (VM boundary).** Its microVM class needs `/dev/kvm` but not NIC's Kata install, so ADR-0026 should offer KVM-capable node groups without installing Kata. Hetzner Cloud has no KVM, so only the gVisor class could run there.

### Division of responsibility

| Property | Sandbox-pod profile | Sandbox-platform profile |
|---|---|---|
| Runtime boundary around untrusted code | NIC (ADR-0023, ADR-0026), checked by the probe | Platform |
| Isolation between sandboxes | Pod boundary, NIC | Platform |
| Network default deny at the pod or pool boundary | NIC | NIC |
| Egress destinations and credential injection | Pack's proxy, forced by NIC's rules | Platform's gateway, forced by NIC's rules at the pool boundary |
| Metadata and node-local endpoints | NIC | NIC (pool boundary); platform for actors |
| Privileges | Root inside the runtime only | Declared envelope, enforced by NIC |
| Node placement | Dedicated pools, NIC | Dedicated pools, NIC |
| Snapshots, state store, control plane | n/a | Platform |

### The privilege envelope

An envelope lists the service accounts allowed to use it, capabilities to add, profiles that may be `Unconfined` (seccomp, AppArmor), host paths with their types, extended resources (for example a KVM device), and whether `runAsUser: 0` is allowed. The policy is generated from it as CEL rules; any field not listed is rejected, and `privileged`, `hostNetwork`, `hostPID` and `hostIPC` are never allowed. For Agent Substrate v0.6.0 the worker envelope is the worker row above and the node-agent envelope is the `atelet` row, after its GKE-specific credential-provider paths are made configurable. Envelopes are declared by whoever installs the platform and reported by `nic outputs`; publishing qualified envelopes per platform release is an open question in ADR-0025.

### What has to change before Agent Substrate runs on NIC

- NetworkPolicy enforcement on the provider (#691, #675).
- The pod-certificate APIs: EKS and k3s support for enabling them at the required versions is to be verified; the platform ships a signer controller but needs the API types served.
- Configurable kubelet credential-provider paths in `atelet` (its manifest notes they are GKE's and that other distributions differ).
- Object storage (S3 through its plugin on AWS) and PostgreSQL.
- For the microVM class, KVM-capable node groups (ADR-0026, without NIC's Kata install).

### Sources

- Agent Substrate repository and README: <https://github.com/agent-substrate/substrate> (v0.6.0, 2026-10-22); `docs/architecture.md`, `docs/security.md`, `docs/threat-model.md`, `docs/roadmap.md`; worker pod spec in `cmd/atecontroller/internal/controllers/workerpool_apply.go`; node agent in `manifests/ate-install/atelet.yaml`.
- kagent's Agent Substrate architecture page: <https://kagent.dev/docs/kagent/1.x/about/architecture/agent-substrate/>.
- CNCF Sandbox application: <https://github.com/cncf/sandbox/issues/523>.
- Agent Sandbox: <https://github.com/kubernetes-sigs/agent-sandbox> (v1.0.8, 2026-10-22) and <https://agent-sandbox.sigs.k8s.io/docs/>.

## 22.10 Probe results

### EKS, 2026-10-27

EKS 1.34 in us-east-1 deployed with NIC from `main`; probe groups `gv` (m6i.large, gVisor) and `kata` (m8i-flex.large, Kata 4.2.0), both tainted as dedicated. Raw output in `tests/sandbox-probe/session5-results/aws/` (`t2-*`, `t3a-*`, `t3b-*`, `t3c-*`).

- **Sandbox pods:** Alpine with sshd and sftp-server as root, `automountServiceAccountToken: false`, no Secrets (the authorised key in a ConfigMap), a gp3 workspace PVC, reached over SSH and SFTP from an agent pod in another namespace, under gVisor and Kata. Before any policy: no token file; IMDSv2 refused (hop limit 1) and IMDSv1 401; Pod Identity 400; API server and the node's kubelet 401; the node's port 22 and the internet reachable.
- **Enforcement off by default:** NIC's EKS module (v0.7.0) installs `vpc-cni` without `configuration_values`; a deny-all policy had no effect although the node agent and the PolicyEndpoint CRD were present. Re-running `nic deploy` (no changes) left hand-set add-on values in place.
- **Enforced default deny** (`enableNetworkPolicy`), namespace policies allowing egress only to a proxy pod on 8888 and to CoreDNS, and ingress only SSH from the agent namespace; under gVisor and Kata, with and without `NET_ADMIN`: proxy, cluster DNS and SSH worked; direct HTTP and HTTPS, other proxy ports, the metadata service, Pod Identity, the API server, other nodes' kubelets, DNS to 8.8.8.8 (also with `resolv.conf` rewritten), raw UDP, IPv6, raw ICMP, a spoofed source address, an added host route and an iptables DNAT redirect were all blocked.
- **Own node:** the kubelet (10250), port 22 and 10256 on the pod's own node stayed reachable in standard and strict mode.
- **Start-up window:** 1.0–1.4 s of direct egress per new pod in standard mode (six runs, both runtimes); none within 30 s in strict mode, where allowed routes opened after 1.4–1.8 s.
- **Admission:** a `ValidatingAdmissionPolicy` bound to sandbox namespaces passed all eleven cases (missing runtime class, token automount, Secret, projected token and hostPath volumes, host namespaces, Secrets in the environment, compliant pods admitted, other namespaces unaffected) once it matched `pods/ephemeralcontainers` and forbade ephemeral containers.
- **Dedicated pools:** sandbox pods landed only on their groups through their `RuntimeClass`es, but a runc pod that added the toleration ran on the gVisor node; the cluster-wide toleration policy (22.2) rejected it and still admitted sandbox pods.

## 22.11 Resource limits, tenancy and observability

**Resource limits.** Untrusted code's cheapest attack is on cost: mining, fork bombs, runaway builds and disk filling.

| Limit | Mechanism | Set by |
|---|---|---|
| Processes per pod | kubelet `podPidsLimit`, node-level: on EKS in the sandbox group's `nodeadm` `NodeConfig` (`kubelet.config.podPidsLimit`); on k3s through the pool's kubelet arguments (`--kubelet-arg=pod-max-pids=<n>`). Proposed default 4096 | NIC, on sandbox node groups; applies to every pod on them, which on dedicated pools are sandboxes and node agents |
| CPU, memory, ephemeral storage per container | `LimitRange` defaults and maxima in each namespace; the admission policy rejects containers above the maxima | NIC sets defaults; packs size pods within them |
| Namespace totals | `ResourceQuota` (CPU, memory, ephemeral storage, pods, PVCs and requested storage) | NIC, from operator values |
| Lifetime | Admission requires `activeDeadlineSeconds` no longer than the configured maximum (proposed 24 h) | Packs set it; NIC enforces the maximum |

Ephemeral-storage limits evict a pod that fills its node's disk; PVC-backed workspaces are bounded by their requested size and the quota. Values belong in the stored spec of the sandbox node groups where they are node-level (ADR-0024), so changing the process cap is a rollout. To be verified: that the process cap applies inside gVisor and Kata pods as on runc (gVisor's sandbox and Kata's VM processes are counted in the pod's cgroup on the host, but the limit seen by code inside may differ).

**Workspace rule.** In the tool-execution pattern the sandbox writes the shared workspace and the trusted agent pod reads it. Content written by untrusted code can attack the trusted side without any escape: Git hooks and configuration (`core.fsmonitor`, `core.hooksPath`), `.envrc`, shell start-up files, editor and language-server configuration, build files a trusted tool might run, and files the agent parses into prompts. Packs run Git with hooks disabled and safe configuration on the trusted side, never source or execute workspace files there, and treat parsed content as untrusted input. NIC cannot see this boundary, so it is a pack obligation, stated in ADR-0025.

**Tenancy.** Dedicated pools keep sandboxes away from foundational services but not from each other. A runtime escape or a side channel (cache timing, shared CPU resources) between sandboxes on one node is not addressed by the profile; the operator's answer is a `hardware-virtualised` floor (ADR-0021, ADR-0026) and, where needed, separate pools per group of users. Confidential computing (protecting the guest from the operator, for example Confidential Containers on SEV-SNP or TDX) and in-process tool sandboxes (WebAssembly, V8 isolates) are outside the profile.

**Observability (deferred).** The first delivery records no audit trail beyond the pack's proxy. Where it plugs in later: denied-traffic logging from the network policy agent (the VPC CNI's policy-event logs on AWS, kube-router's on k3s), set alongside strict-mode enforcement; gVisor's runtime monitoring, which streams process and system-call events, and Kata's runtime events, set in the runtime configuration that ADR-0024 pins per generation; and sandbox pod lifecycle events. Denial logging is a "should" for the first delivery, because without it operators debug default-deny blind.

