# 22. Untrusted-Execution Pods

Mechanisms for [ADR-0025](../../adr/0025-untrusted-execution-pods.md). Each is a design target, not yet implemented or tested as NIC code. Probe results are in 22.10; claims marked "to be verified" have not been probed.

## 22.1 The pattern

An agent runs in its own pod that holds its model and integration credentials; that pod reads model output and tool results, so it is exposed to prompt injection and trusted only to hold credentials. Its tool calls run in a separate sandbox pod, usually one per session, reached over SSH (with a per-session key and a host key pinned in advance) or `kubectl exec`. The sandbox pod holds the workspace and no real credentials; outbound HTTP goes through the pack's proxy, which checks the destination and injects credentials outside the sandbox, so the proxy's policy decides what authority the sandbox has. NIC's role is everything around the sandbox pod: runtime, placement, admission and enforced network rules.

## 22.2 Namespace profile

For each namespace in `sandbox.untrusted_execution.namespaces`, NIC creates (or, in verification-only mode, checks):

| Object | Purpose |
|---|---|
| Namespace label `sandbox.nebari.dev/untrusted-execution: "true"` | Selects the admission policies and the profile's probes |
| Pod Security labels `enforce: baseline` (`restricted` when the profile's level is `shared-kernel`) | Root allowed above `shared-kernel`; host namespaces, privileged and host paths refused |
| NetworkPolicy `nic-default-deny` (`podSelector: {}`, `policyTypes: [Ingress, Egress]`) | Default deny in both directions |
| `ValidatingAdmissionPolicy` `nic-untrusted-execution-pods` | Pod and PVC rules (22.3), on create and update |
| `ValidatingAdmissionPolicy` `nic-untrusted-execution-netpol` | NetworkPolicy rules (22.4) |
| Default ServiceAccount with `automountServiceAccountToken: false` | Belt and braces; the admission policy is the guarantee |
| `LimitRange` `nic-sandbox-defaults` and `ResourceQuota` `nic-sandbox-quota` | Default and maximum CPU, memory and ephemeral storage per container; namespace totals (22.11) |
| In a credential namespace only: `Role` `nic-credential-controller` and a `RoleBinding` to the ServiceAccount named in `credential_controllers` | Grants creating, reading and deleting Secrets, pods and the workload objects that create pods (Jobs, Deployments, Agent Sandbox's resources) to that controller alone; NIC binds no other role in the namespace (22.3) |

Cluster-wide, once per cluster that uses the profile:

| Object | Purpose |
|---|---|
| `ValidatingAdmissionPolicy` `nic-sandbox-pool-tolerations` | On create and update, allows a toleration for a sandbox pool's taint (explicit, or a blanket `operator: Exists`) only for pods whose `runtimeClassName` is on the approved list below; `kube-system` and NIC's node-level DaemonSets exempt. A taint alone let a runc pod that added the toleration run on a gVisor node (22.10) |
| Parameter object `nic-approved-runtime-classes`, read by the pod and toleration policies through `paramRef` | The NIC-generated list of `RuntimeClass` names ADR-0021's acceptance policy allows for the profile's level. A `ValidatingAdmissionPolicy` cannot dereference a class's labels, so admission checks names, never the `sandbox.nebari.dev/level` label. NIC updates the list fail-closed (a class leaves the list before NIC changes or removes it) and lists only classes whose ownership is controlled: NIC's own, or provider-managed and operator-owned classes the operator names |
| On AWS, the `vpc-cni` add-on's `configuration_values`: `enableNetworkPolicy: "true"` and `env.NETWORK_POLICY_ENFORCING_MODE: strict` | Enforcement with no window at pod start; NIC's EKS module sets neither today, and a later `nic deploy` leaves hand-set values in place without guaranteeing them. Strict mode is cluster-wide: every new pod is denied all traffic until a policy selects it, so NIC must first ship a NetworkPolicy for every namespace it manages (foundational services and packs), as the #675 trial found |
| Pod Security `enforce: restricted` on each namespace in `peer_namespaces` | Trusted pods that mount a sandbox's workspace run with `allowPrivilegeEscalation: false`, so setuid files planted by root in a sandbox on `no_root_squash` storage give them nothing |
| A host-side rule on sandbox node groups, written at boot, dropping traffic from pod addresses to the node's own addresses | The CNI's policy does not cover a pod's traffic to its own node (22.10); the mechanism (an nftables rule in the node's boot steps on AWS and k3s) is to be qualified, including that the kubelet's and CNI's own traffic to pods is unaffected |

NIC owns these objects, labels them as NIC-managed, and fails the deploy if it cannot create or update them, as for ADR-0023's resources. Removing a namespace from the list stops NIC managing it but deletes nothing.

## 22.3 Pod admission rules

Rejected in an untrusted-execution namespace, on create and update:

- no `runtimeClassName` (above `shared-kernel`), or one not on `nic-approved-runtime-classes`;
- any ephemeral container (the policy matches `pods` and `pods/ephemeralcontainers`; matching only `pods` let an ephemeral container read a Secret into a running sandbox pod, 22.10);
- `automountServiceAccountToken` not explicitly `false` (pod or ServiceAccount), or a projected service-account token volume;
- Secret volumes, projected Secrets, `env.valueFrom.secretKeyRef` or `envFrom.secretRef`, except in a credential namespace (below), where a projected service-account token is still rejected;
- inline `csi` volumes: a CSI driver can request the pod's service-account token or fetch secrets for the pod regardless of `automountServiceAccountToken`;
- `hostPath` volumes, `hostNetwork`, `hostPID`, `hostIPC`, `privileged: true`, added capabilities beyond the container runtime's defaults, device resources, `procMount: Unmasked`, unsafe sysctls;
- on update, any added toleration (Kubernetes lets a pod's tolerations grow after creation, which would otherwise bypass the pool rule);
- at `shared-kernel`, anything Pod Security `restricted` rejects, including running as root;
- for a bare pod, or a pod whose controlling owner reference names a Job, no `activeDeadlineSeconds` or one above `max_pod_lifetime` (Job pods set it in the pod template). Pods whose controlling owner is any other kind are exempt (22.11). The exemption keys on the owner reference, which whoever creates the pod sets, so it guards against a pack forgetting a deadline, not against a pack evading it; the pack's controller is trusted.

PersistentVolumeClaims in these namespaces may not set `spec.volumeName`: binding a claim to an existing PersistentVolume by name could hand a sandbox another workload's data.

The runtime class applies to the whole pod, so trusted helpers (the agent, a proxy) must never be containers in a sandbox pod: under a VM runtime they would share its VM, and under any runtime its network rules.

Allowed: running as UID 0 above `shared-kernel`, the runtime's default capabilities, writable root file systems, `emptyDir`, PVCs, ConfigMaps.

**Per-pod credentials in a credential namespace.** Controllers that create sandbox pods legitimately deliver a short-lived credential per pod: a run token the pod uses to call a broker, or to authenticate to its controller. Ambient credentials stay prohibited everywhere: service-account tokens (automounted or projected), host paths, and Secrets shared across pods or namespaces. A pod may mount a Secret only in a namespace listed in `credential_controllers`, which names the one ServiceAccount allowed to create Secrets and pods there.

- **What carries the guarantee.** Admission cannot tell who created a Secret that a pod refers to, nor whether another pod uses it, so the guarantee rests on the namespace's RBAC. NIC sets that RBAC up (22.2) rather than auditing every binding in the cluster, because it already creates and owns these namespaces and a setup is simpler and deterministic. RBAC is additive: cluster-wide grants (cluster administrators, or a ClusterRole a pack binds to all namespaces) are outside it, and whether `nic deploy` should report them is an open question in ADR-0025.
- **Trust model.** The controller is trusted; the code inside its pods is not. The controller must scope each Secret to one pod or run (for example one Secret per pod, deleted with it through an owner reference), keep it short-lived, and never place the platform's or other workloads' credentials in the namespace. Packs should prefer brokering, a proxy outside the pod that adds credentials, wherever they can: a credential inside the sandbox can be read and exfiltrated through any route the sandbox has.
- **Everything else is unchanged.** Default-deny networking, the remaining admission rules and the lifetime rule apply in credential namespaces as in any other.

**Session material without a labelled exception.** An earlier draft admitted Secrets labelled as session capabilities (an SSH host key, an authorised key); since a pack can label any Secret it creates, that was an open door, and it stays removed. Outside a credential namespace, session material is delivered without Secrets: public material (an authorised key, a CA certificate) through ConfigMaps; private material generated inside the sandbox at start (an SSH host key, whose public half the pack reads back through a channel it already trusts, such as the pod's log through the API) or sent over the session channel after it opens. In a credential namespace, the controller may instead deliver it as a per-pod Secret.

## 22.4 NetworkPolicy admission rules

NetworkPolicies other than NIC's own in these namespaces may only:

- allow egress to pods in a namespace listed in `peer_namespaces`, selected by `kubernetes.io/metadata.name` (which only the API server sets), so a pack cannot extend the list by labelling a namespace;
- allow ingress from pods selected the same way (the agent's pods, for SSH);
- allow egress to the cluster DNS service on port 53, only when `allow_dns` is set.

Rejected: any `ipBlock` (egress or ingress), selectors that match namespaces by any other label, and empty selectors that would match every namespace. Because NetworkPolicies are additive, this is what prevents a pack's allow-all from undoing the default deny. DNS is denied by default because a sandbox using an explicit proxy needs none and queries are an exfiltration channel.

Request layers are subject to the same rules. Agent Sandbox v1.0.8's managed networking creates, for each sandbox, an egress NetworkPolicy that allows public egress through an `ipBlock`, which this policy rejects. Integrating it therefore needs explicit network-policy handling: either a custom policy that is qualified against these rules, or `networkPolicyManagement: Unmanaged`, with the pack supplying policies that pass admission.

## 22.5 Enforcement per provider

| Provider | Enforcement | Status |
|---|---|---|
| AWS | VPC CNI network policy agent (`enableNetworkPolicy` and strict mode on the add-on, #675) | Off in NIC today. Once enabled, default deny held against root under gVisor and Kata for every external and cluster destination tried, including the metadata service, Pod Identity, the API server and other nodes; **not** for the pod's own node, which needs the host-side rule (22.10) |
| Hetzner | k3s's embedded policy controller (kube-router) with flannel | Enforced for gVisor pods (2026-10-25). Metadata service (including the join-token issue) and node-local traffic: to be verified |
| Azure | Cilium dataplane (#691) | Not configured by NIC's AKS module today |
| `existing`, kind | Operator's CNI | Verification only |

`InfraSettings.Sandbox` reports whether the provider enforces NetworkPolicy, and `nic validate` rejects the profile where it does not. The deploy probe (22.6) is the evidence; configuration is never taken as proof.

**Start-up window.** In the VPC CNI's default `standard` mode, each new pod could connect directly for its first 1.0–1.4 s before its policy applied. In `strict` mode no direct connection succeeded, and the pod's allowed routes (the proxy, DNS) opened 1.4–1.8 s after start. NIC uses strict mode, and packs' sandboxes retry their first connections rather than failing. The window on k3s is to be measured, and the profile is not offered on Hetzner until it has been: provider qualification is a delivery gate, as is a working rule for own-node traffic.

## 22.6 Deploy-time probe

For each namespace and each listed runtime, `nic deploy` starts a short-lived root pod from an image NIC publishes, plus a NIC test target in a separate namespace with a label the probe's own NetworkPolicy allows. The probe must observe:

1. external egress (an IP and a hostname) fails, and so does DNS when `allow_dns` is not set;
2. a test target in a peer namespace is reachable and a target in a namespace outside `peer_namespaces` is not, even when a policy selects it by label;
3. `169.254.169.254` (and the provider's other metadata addresses) is unreachable;
4. the node's own addresses on the kubelet port and a NodePort are unreachable;
5. the Kubernetes API service address is unreachable;
6. no service-account token exists at the usual path;
7. the pod's boundary level shows (ADR-0021's diagnostic: above `shared-kernel` the kernel release inside differs from the node's, with evidence specific to the implementation);
8. in strict mode, a connection attempted in the pod's first second fails rather than succeeds.

It also submits, with server-side dry run, a pod without a qualifying runtime class, a pod mounting a Secret outside a credential namespace, a pod with a projected service-account token inside one, a bare pod without `activeDeadlineSeconds` and one above the maximum, a pod with an inline CSI volume, an ephemeral container, an update adding a toleration, a runc pod tolerating a sandbox pool's taint, a PVC naming an existing PersistentVolume, a NetworkPolicy with an external `ipBlock` and one selecting a namespace by label, each of which must be rejected, and a pod owned by a Deployment's ReplicaSet with no deadline, which must be admitted. In each credential namespace it checks with `SubjectAccessReview`s that the declared controller can create Secrets and pods there and that the namespace's default ServiceAccount and those of the peer namespaces cannot. The probe is a diagnostic of the path it exercised, not attestation. Any failure fails the deploy; the probe objects are deleted afterwards.

## 22.7 Verification checklist

Per provider, before it is listed as supporting the profile:

- every step of the deploy probe, under gVisor and (where supported) the VM runtime, with the probe running as root;
- an SSH session from an agent pod in another namespace to a sandbox pod, allowed by the pack's ingress policy, and refused from a pod without the label;
- a sandbox pod's HTTP traffic through a proxy in another namespace succeeding, and the same request sent directly failing;
- the admission rules against each rejected pattern in 22.3 and 22.4, on create and on update;
- session material delivered as in 22.3 (a host key generated in the sandbox and pinned by the agent);
- in a credential namespace, a per-pod Secret created by the declared controller mounted by its pod, and Secret creation by any other ServiceAccount in the namespace or a peer namespace refused (to be verified);
- the lifetime rule: a bare pod and a Job pod above the maximum rejected, and an Agent Sandbox warm pool and a Deployment-owned pod admitted and recreated normally (to be verified);
- a tool-execution workload as root under each runtime: SSH commands and SFTP to a PVC-backed workspace (observed on EKS under gVisor and Kata, 22.10); package installs, compilers and Git (to be verified);
- node-local reachability tests repeated after a node replacement and a CNI upgrade;
- the start-up window measured on each provider, and strict mode enabled on EKS without breaking any NIC namespace;
- a pod in a peer namespace with `allowPrivilegeEscalation: true` rejected.

## 22.8 Rejected alternatives

- **Trusting NetworkPolicy objects without enforcement checks:** a policy nothing enforces is accepted and does nothing (EKS today).
- **Pod Security `restricted` for sandbox namespaces:** forbids root, which tool execution needs; the runtime is the boundary instead.
- **In-pod network restrictions for sandboxes:** root inside the pod can undo them.
- **A NIC-owned request layer or egress gateway:** see ADR-0025, options 4 and 5.
- **Admitting sandbox platforms by loosening the sandbox-pod rules:** any loosening applies to every pod in the namespace.
- **A sandbox-platform profile with a declared privilege envelope and a claimed boundary level** (an earlier draft): dropped after review. NIC cannot verify a platform's isolation, so a claimed level adds a name without a guarantee, and the envelope's privileges place the platform close to host root; see 22.9.
- **An exception for labelled session Secrets:** packs can label their own Secrets; see 22.3. Per-pod Secrets are allowed only where namespace RBAC confines who creates them.
- **Auditing every RBAC binding instead of setting up the namespace's own:** more work for NIC for a guarantee that still excludes cluster administrators; see 22.3.
- **A lifetime cap on every pod:** controllers recreate the pods they own and warm pools keep pods alive by design, so a cap on them either fails or churns; it applies to bare and Job pods only (22.11).

## 22.9 Future integration: sandbox platforms

Background for ADR-0025's "Future integration" note; nothing here is part of the profile. Facts are from Agent Substrate v0.6.0 (released 2026-10-22; repository created 2026-05; tags v0.2.0 to v0.6.0 in five months), read from its source and documentation, and from Agent Sandbox v1.0.8 (2026-10-22). Both projects move quickly; the envelope below must be re-read for each release.

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

### Where it would fit

An earlier draft gave platforms a second profile: dedicated pools, an exact privilege envelope for workers and the node agent, and a boundary level the platform claimed and NIC recorded as unverified. Review dropped it. Actors are not pods with published settings, so NIC cannot check the isolation between them or the runtime the worker starts; the worker and node-agent privileges above (root, `SYS_ADMIN`, unconfined profiles, host paths) put the platform close to host root on its nodes; and a claimed level is a name without a guarantee. Such a platform is separately trusted infrastructure. If one runs on a NIC provider, its integration is its own decision; the useful parts NIC already has are dedicated, tainted pools, enforced NetworkPolicy at the pool boundary and unreachable metadata, and KVM-capable node groups without NIC's Kata install for a microVM class. Agent Sandbox, by contrast, creates ordinary pods and is a consumer of this profile: it should be qualified with an unmodified `SandboxTemplate`, checking that its controller-owned pods and warm pools fall under the lifetime exemption (22.11), how it delivers any per-pod credential (a credential namespace, 22.3), and whether its templates create `ipBlock` policies, which the profile rejects.

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

EKS 1.34 in us-east-1 deployed with NIC from `main`; probe groups `gv` (m6i.large, gVisor) and `kata` (m8i-flex.large, Kata 4.2.0), both tainted as dedicated. Raw output is not committed; this summary is the record. The admission policy used in this run named the approved runtime classes in a fixed list; it did not read level labels.

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
| Lifetime | Bare pods and Job pods: admission requires `activeDeadlineSeconds` no longer than the configured maximum (proposed 24 h). Pods owned by another controller (Deployments, StatefulSets, Agent Sandbox's controllers) are exempt, since such controllers recreate pods and warm pools keep them alive by design | Packs set the deadline and NIC enforces the maximum; for controller-owned pods the pack's controller enforces lifetime and idle clean-up itself and states it in its trust model, which NIC's pack documentation requires |

Ephemeral-storage limits evict a pod that fills its node's disk; PVC-backed workspaces are bounded by their requested size and the quota. Node-level values are part of what the sandbox node groups boot with, so changing the process cap replaces nodes. To be verified: that the process cap applies inside gVisor and Kata pods as on runc (gVisor's sandbox and Kata's VM processes are counted in the pod's cgroup on the host, but the limit seen by code inside may differ).

**Workspace rule.** In the tool-execution pattern the sandbox writes the shared workspace and the agent's pod reads it, so content written by untrusted code can attack the agent's side without any escape. NIC cannot see this boundary; it is a pack obligation stated in ADR-0025, and 22.12 gives the cases and acceptance tests for coding agents.

**Tenancy.** Dedicated pools keep sandboxes away from foundational services but not from each other. A runtime escape or a side channel (cache timing, shared CPU resources) between sandboxes on one node is not addressed by the profile, and no boundary level addresses side channels: they need separate nodes, so the operator's answer is separate pools per group of users. A VM floor does not change this: on nested virtualisation the VMM and its file-sharing daemon run on the node, so a VM escape lands where a gVisor escape would. Confidential computing (protecting the guest from the operator, for example Confidential Containers on SEV-SNP or TDX) and in-process tool sandboxes (WebAssembly, V8 isolates) are outside the profile.

**Observability (deferred).** The first delivery records no audit trail beyond the pack's proxy. Where it plugs in later: denied-traffic logging from the network policy agent (the VPC CNI's policy-event logs on AWS, kube-router's on k3s), set alongside strict-mode enforcement; gVisor's runtime monitoring, which streams process and system-call events, and Kata's runtime events, set in the runtime configuration the sandbox node groups boot with; and sandbox pod lifecycle events. Denial logging is a "should" for the first delivery, because without it operators debug default-deny blind.

## 22.12 Consumer guide: coding agents

ADR-0025's profile is generic; this guide covers what a coding agent's pack must do on its own side, with the acceptance test for each item. The agent's pod is the component exposed to prompt injection and holds the credentials, so these are the routes by which a sandbox can act through it.

| Risk | What the pack does | Acceptance test |
|---|---|---|
| Git hooks and configuration written by the sandbox (`.git/hooks`, `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, filters, `include` directives) | Runs Git on the agent's side with hooks disabled (`core.hooksPath=/dev/null`), `safe.directory` scoped, and repository configuration ignored or allowlisted, or runs Git only inside the sandbox | A hook and an `fsmonitor` command planted by the sandbox do not run when the agent commits or checks status |
| `.envrc`, shell start-up files, editor and language-server configuration, build files (`Makefile`, `package.json` scripts, `pyproject.toml` build backends) | Never sources, executes or loads them on the agent's side; tools that would run them run in the sandbox | A planted `.envrc`, `.bashrc` and language-server configuration produce no execution on the agent's side |
| Files the agent parses into prompts | Treats them as untrusted input: size limits, no automatic following of links or includes, provenance marked in the prompt | An oversized file and a file with instructions addressed to the agent are handled without acting on them |
| The SSH session to the sandbox | Pins the sandbox's host key per session; disables agent forwarding, X11 and port forwarding; uses an explicit client configuration (`ssh -F <pack config>`) so nothing in the workspace or `~/.ssh` changes it; `ProxyCommand` and `LocalCommand` unset; no SFTP paths outside the workspace | A changed host key aborts the session; forwarding requests from the sandbox side are refused |
| The credential-injecting proxy | Allows only the destinations and methods the session needs, scopes injected credentials to them, logs every request, and never returns credentials in responses | A request to an unlisted host and one that tries to read the injected header back both fail |
| Shared storage with root in the sandbox | Mounts the workspace in the agent's pod with `nosuid` semantics (the peer namespace's `restricted` profile gives `allowPrivilegeEscalation: false`) and never executes files from it | A setuid binary planted by root in the sandbox gains no privilege when run on the agent's side |

