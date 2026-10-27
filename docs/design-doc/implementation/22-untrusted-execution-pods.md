# 22. Untrusted-Execution Pods

Mechanisms for [ADR-0025](../../adr/0025-untrusted-execution-pods.md). Each is a design target, not yet implemented or tested as NIC code. Claims marked "to be verified" are being probed.

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

NIC owns these objects, labels them as NIC-managed, and fails the deploy if it cannot create or update them, as for ADR-0023's resources. Removing a namespace from the list stops NIC managing it but deletes nothing.

A platform's worker namespace (22.9) gets the same objects, with Pod Security `privileged` (the envelope policy, not Pod Security, is the limit there), an extra `ValidatingAdmissionPolicy` `nic-platform-envelope-<name>` and its binding, and a taint `sandbox.nebari.dev/platform=<name>:NoSchedule` on the platform's node groups.

## 22.3 Pod admission rules

Rejected in an untrusted-execution namespace:

- no `runtimeClassName`, or one not in `runtime_classes`;
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
| AWS | VPC CNI network policy agent (`enableNetworkPolicy` on the add-on, #675) | Off in NIC today; default deny enforced for gVisor and runc pods once enabled (2026-10-19). Metadata service and node-local traffic: to be verified |
| Hetzner | k3s's embedded policy controller (kube-router) with flannel | Enforced for gVisor pods (2026-10-25). Metadata service (including the join-token issue) and node-local traffic: to be verified |
| Azure | Cilium dataplane (#691) | Not configured by NIC's AKS module today |
| `existing`, kind | Operator's CNI | Verification only |

`InfraSettings.Sandbox` reports whether the provider enforces NetworkPolicy, and `nic validate` rejects the profile where it does not. The deploy probe (22.6) is the evidence; configuration is never taken as proof.

## 22.6 Deploy-time probe

For each namespace and each listed runtime, `nic deploy` starts a short-lived root pod from an image NIC publishes, plus a NIC test target in a separate namespace with a label the probe's own NetworkPolicy allows. The probe must observe:

1. external egress (an IP and a hostname) fails;
2. the allowed test target is reachable and a second, non-allowed target is not;
3. `169.254.169.254` (and the provider's other metadata addresses) is unreachable;
4. the node's own addresses on the kubelet port and a NodePort are unreachable;
5. the Kubernetes API service address is unreachable;
6. no service-account token exists at the usual path;
7. the runtime is the expected one (gVisor's or the VM's kernel, not the host's).

It also submits, with server-side dry run, a pod without a runtime class, a pod mounting a Secret and a NetworkPolicy with an external `ipBlock`, each of which must be rejected. Any failure fails the deploy; the probe objects are deleted afterwards.

## 22.7 Verification checklist

Per provider, before it is listed as supporting the profile:

- every step of the deploy probe, under gVisor and (where supported) the VM runtime, with the probe running as root;
- an SSH session from an agent pod in another namespace to a sandbox pod, allowed by the pack's ingress policy, and refused from a pod without the label;
- a sandbox pod's HTTP traffic through a proxy in another namespace succeeding, and the same request sent directly failing;
- the admission rules against each rejected pattern in 22.3 and 22.4, and a labelled session-capability Secret accepted;
- a tool-execution workload as root under gVisor: package installs, compilers, Git, writing to a PVC-backed workspace (to be verified);
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

- **ADR-0021's contract.** Actors are not pods with published settings, so a platform cannot be checked as providing `user-space-kernel` or `vm-boundary` in NIC's sense. Packs built on it depend on the platform's own API.
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
