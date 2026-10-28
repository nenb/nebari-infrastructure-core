# ADR-0025: Guarantees for Untrusted-Execution Pods

## Status

Proposed (DRAFT, exploratory): a feasibility sketch that fits [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md)'s interface; not proposed for acceptance yet. Depends only on ADR-0021, of whose interface this profile is the third axis, independent of any runtime implementation; [ADR-0023](0023-user-space-kernel-capability.md) (gVisor) and [ADR-0026](0026-vm-boundary-capability.md) (Kata) sketch implementations of higher levels it can require. It names its minimum level through the requirement sets the sketches propose adding to ADR-0021's contract ([§20.6](../design-doc/implementation/20-workload-sandboxing.md#proposed-additions-requirement-sets-and-a-requirement-mapping)); ADR-0021 itself adopts only `sandbox.minLandlockABI`. Requires NetworkPolicy enforcement on every provider that offers it ([#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691), with [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) for the AWS VPC CNI). Revised 2026-10-28 after review: a trust model; ambient credential delivery prohibited, with per-pod Secrets only in namespaces whose RBAC lets one declared controller create them; the lifetime cap limited to bare and Job pods; more admission rules; egress only to operator-declared namespaces and DNS denied by default; the strict-mode prerequisite; exec and shared-storage risks; provider qualification as a delivery gate; the sandbox-platform profile and claimed levels dropped. Mechanisms, the verification checklist and a consumer guide are in the [design doc](../design-doc/implementation/22-untrusted-execution-pods.md).

## Date

2026-10-28

## Context

The strongest design for ADR-0021's threat model keeps an agent's credentials and the code it runs in different places: **an agent running its tool calls in a separate sandbox pod**. The agent runs in its own pod with its model and integration credentials. That pod is trusted only in the sense that it holds credentials: it reads model output and tool results, so it is the component exposed to prompt injection. Each tool call (a shell command, a file read or write) runs in a separate, usually per-session pod that holds no credentials, reached over SSH or `kubectl exec`. Code that takes over the sandbox pod finds nothing to steal there; to get further it must escape the runtime boundary, get past the network rules around the pod, or attack the agent through what it writes.

That design is only as good as what surrounds the sandbox pod, and today NIC promises none of it:

- **The network.** A sandbox that may reach the internet directly can exfiltrate the workspace and bypass the pack's credential-injecting proxy. Neither gVisor nor Kata isolates a pod's network, and NIC's EKS clusters do not enforce NetworkPolicy at all: the VPC CNI's enforcement is off unless enabled, and NIC's EKS module neither sets nor exposes it (observed 2026-10-19 and 2026-10-27; #675). A policy nothing enforces is accepted by the API server and does nothing.
- **Credentials.** Kubernetes mounts a service-account token into every pod unless told not to, and nothing stops a pack's pod spec mounting a Secret, a host path or a CSI volume into a sandbox.
- **Root.** Tools run by agents routinely need root (package installs, system libraries). On the host kernel that is a real escalation risk; behind a stronger boundary level it is far less of one, but only if no root sandbox pod can run on the default runtime.
- **Placement.** Sandbox pods that share nodes with foundational services put Keycloak and ArgoCD one runtime escape away.

Packs can try to get each of these right themselves, but several are platform properties no pack can enforce from a namespace: whether policies are enforced, whether the metadata service is reachable, which runtime a pod may use. Here **the pod is the sandbox**: a pack's own pods, or pods from a request layer such as Agent Sandbox. Systems that run many sandboxes inside their own worker pods are a different shape (see "Future integration").

## Decision Drivers

- **Platform guarantees, not pack diligence.** What NIC promises holds whatever a pack's pod spec says.
- **Enforced from outside the pod.** Nothing inside the sandbox, including root, can loosen it.
- **Verified, not configured.** Every guarantee is checked by a real probe, never inferred from settings; a passing probe is a diagnostic, not attestation.
- **No ambient credentials.** Kubernetes' mechanisms for handing a pod shared or platform credentials are closed in these namespaces; a credential for one pod is allowed only where RBAC confines who can create it.
- **Independent of the runtime.** The profile is a separate axis from the boundary level: it works at any level, and root inside is allowed only above `shared-kernel`.
- **Leave the agent design to packs.** NIC provides the substrate: no request layer, proxy or session protocol of its own.

## Considered Options

1. Do nothing: each pack secures its own sandbox pods.
2. Documentation only: publish guidance for packs.
3. A NIC-guaranteed **untrusted-execution profile** on namespaces: enforced default-deny networking, admission rules, a minimum boundary level and dedicated pools, verified at deploy.
4. Option 3 plus a NIC-owned request layer (for example the Agent Sandbox controller) that creates sandbox pods for packs.
5. Option 3 plus NIC-owned domain-based egress (an egress gateway or FQDN policies) instead of each pack's proxy.

## Decision Outcome

Chosen option: "Option 3", because the properties packs cannot provide themselves (enforced network rules, admission, runtime and placement) are exactly the ones a namespace profile can guarantee, while request layers, protocols and proxies differ between agent designs and belong to packs.

### What the operator configures

```yaml
sandbox:
  requirements:
    - name: tool-sandboxes
      boundary: mediated-kernel        # a proposed requirement set (§20.6), resolved per provider
  untrusted_execution:
    namespaces: [agent-sandboxes]      # NIC creates, labels and guards these
    requirement: tool-sandboxes        # minimum level for every pod in them
    peer_namespaces: [agents, proxy]   # the only namespaces packs may open routes to or from
    allow_dns: false                   # the default
    credential_controllers:            # optional: per-pod Secrets allowed here, created only by this ServiceAccount
      agent-sandboxes: agents/sandbox-controller
    limits:                            # resource limits (§22.11); NIC defaults if omitted
      max_pids_per_pod: 4096
      max_pod_lifetime: 24h            # bare and Job pods
```

The profile can ship at `requirement` level `shared-kernel`, before any runtime installer exists: sandbox pods then run non-root under Pod Security `restricted`, with every other guarantee unchanged. Above `shared-kernel`, node groups serving the runtime must be opted in with `dedicated: true`; NIC rejects the profile otherwise.

### What NIC guarantees for sandbox pods

1. **Default-deny networking, enforced from outside the pod.** NIC installs a default-deny policy for ingress and egress in each untrusted-execution namespace. A pack opens routes by adding NetworkPolicies, which an admission policy restricts to pods in `peer_namespaces` (selected by namespace name, so a pack cannot add a namespace by labelling it); `ipBlock` rules and empty selectors are rejected. DNS is denied unless `allow_dns` is set, since sandboxes using an explicit proxy need none and DNS is an exfiltration channel; when set, only the cluster DNS service is allowed.
2. **Metadata and node-local endpoints unreachable.** The cloud metadata service, the node's own addresses (kubelet and node ports) and the Kubernetes API are not reachable from sandbox pods. On EKS, enforced default-deny blocked all of them except **the pod's own node** (2026-10-27), so NIC adds a host-side rule on sandbox node groups that drops traffic from pod addresses to the node's own addresses.
3. **No ambient credentials.** An admission policy matching `pods` and `pods/ephemeralcontainers`, on both create and update, rejects in these namespaces: ephemeral containers; service-account tokens (automounted or projected); Secrets by volume, projected volume or environment, except in a credential namespace (below); host paths (including `/dev`); inline CSI volumes (a CSI driver can mint the pod's token or fetch secrets regardless of automount); device resources; host networking, PID or IPC; an unmasked `/proc`; unsafe sysctls; and tolerations added on update. PVCs in these namespaces may not name an existing PersistentVolume (`spec.volumeName`). There is still no exception for self-labelled "session" Secrets, since a pack could label any Secret itself.

   **Per-pod credentials in a credential namespace.** A controller that creates sandbox pods may legitimately give each one a short-lived credential of its own, such as a run token the pod uses to call a broker or to authenticate to its controller. The operator names that controller for a dedicated namespace (`credential_controllers`), and only there may pods mount Secrets. Admission cannot tell who created a Secret a pod refers to, so the guarantee rests on the namespace's RBAC, which NIC sets up rather than audits, as the simpler of the two: only the named controller's ServiceAccount is granted creating Secrets, and pods or the workload objects that create them, so the namespace never holds the platform's or other workloads' Secrets. The controller is trusted and the code in its pods is not: each credential must be scoped to one pod or run and short-lived, and packs should prefer brokering, a proxy outside the pod that adds credentials, wherever they can (§22.3).
4. **A minimum boundary level.** Pods must use a `RuntimeClass` whose `sandbox.nebari.dev/level` label is at or above the profile's level (ADR-0021's ordering rule: a stronger level satisfies policy). Above `shared-kernel`, root and the default capabilities are allowed and the namespaces use Pod Security `baseline`; at `shared-kernel`, `restricted`.
5. **Dedicated pools, by default.** Sandbox runtimes run only on opted-in, dedicated groups. A taint alone does not dedicate a pool: a runc pod that added the toleration itself ran on a gVisor node (2026-10-27). A cluster-wide admission policy, on create and update, allows the dedicated taint's toleration only for pods using a sandbox class, with `kube-system` and NIC's node-level DaemonSets exempt.
6. **Resource limits.** NIC sets a per-pod process cap on sandbox node groups, and in each namespace a `LimitRange` and a `ResourceQuota`. Admission requires bare pods and Job pods to set a maximum lifetime (`activeDeadlineSeconds`) no longer than the configured limit. Pods owned by another controller (a Deployment, a StatefulSet, Agent Sandbox's controllers) are exempt, since such controllers recreate pods and warm pools keep them alive by design; the pack's controller then enforces lifetime and idle clean-up itself and says so in its trust model.
7. **Peer namespaces enforce Pod Security `restricted`.** On shared storage exported with `no_root_squash`, root in a sandbox can plant setuid files that a trusted pod might execute; `restricted` requires `allowPrivilegeEscalation: false`, under which setuid bits are ignored. Workspace volumes must present real ownership, and storage that keeps data on nodes is not used.
8. **Verification at `nic validate` and `nic deploy`.** `nic validate` rejects the profile where the provider cannot enforce NetworkPolicy, the requirement set cannot be met, or no dedicated opted-in group exists. `nic deploy` runs a probe pod (as root above `shared-kernel`) under each class the namespaces admit and fails unless external egress, DNS (when not allowed), the metadata service, the node's addresses and the Kubernetes API are unreachable, a test target in a peer namespace is reachable and one elsewhere is not, and no token is present; it dry-runs each rejected pattern above.

### Prerequisites and delivery gates

- **NetworkPolicy enforcement in a mode with no start-up window.** On EKS that is the VPC CNI's `enableNetworkPolicy` with `NETWORK_POLICY_ENFORCING_MODE=strict`, because in the default mode each new pod had 1.0–1.4 s of open egress (observed 2026-10-27). **Strict mode is cluster-wide:** every new pod in the cluster is denied all traffic until a policy selects it, so every NIC namespace (foundational services and packs) needs its own NetworkPolicy before NIC enables it.
- **Provider qualification is a delivery gate.** The profile is offered on a provider only once its qualification passes there, including the start-up window (unmeasured on k3s) and own-node traffic (the host-side rule, not yet built).

**Per provider:** AWS uses the VPC CNI in strict mode (#675); default-deny held against root under gVisor and Kata except for the pod's own node. Hetzner uses k3s's network policy controller, observed enforcing for gVisor pods (2026-10-25); the start-up window, node-local and metadata reachability are unmeasured. Azure needs the Cilium dataplane (#691), unsupported until NIC's AKS module enables it. `existing` and kind: verification only.

### Risks the pack must address

- **`kubectl exec` on a shared sandbox namespace.** RBAC for `pods/exec` is per namespace, so an agent allowed to exec into its sandbox can exec into every other user's. Packs either use one sandbox namespace per user, or give agents no exec RBAC and reach sandboxes over SSH with per-session keys and pinned host keys, as in the probe.
- **The workspace is untrusted input.** The sandbox writes it and the agent's pod reads it; content written by untrusted code can attack the agent without any escape. The consumer guide in §22.12 lists the cases for coding agents and their acceptance tests.
- **The proxy is the real boundary for egress.** NIC blocks direct access; a credential-injecting proxy gives the sandbox the *authority* of the credentials it injects for whatever the proxy allows, so its policy is the pack's boundary, not NIC's.

### Trust model

- **Trusted:** the operator, NIC, the runtime implementing the profile's level, and the pack's proxy and request layer, including the controller that creates sandbox pods and any per-pod credentials. The agent's pod holds credentials but is exposed to prompt injection, so it is trusted with credentials, not with judgement.
- **A hostile workload** in a sandbox pod may run as root (above `shared-kernel`), use the runtime's whole syscall surface, write anything in its workspace, try every network route, and send anything to the agent and the proxy.
- **NIC enforces** default-deny networking with routes only to peer namespaces, unreachable metadata and node-local endpoints, no ambient credentials, credential namespaces' RBAC as NIC sets it up, the minimum level, dedicated pools and resource limits.
- **The pack enforces** its proxy's policy, how its agent treats the workspace, exec and SSH access, keeping credentials out of sandbox pods it creates other than short-lived per-pod ones, and the lifetime and idle clean-up of controller-owned sandbox pods.
- **Outside the guarantee:** runtime escapes; side channels between sandboxes on one node, which need separate nodes per group of users, not a stronger level (on nested virtualisation the VMM runs on the node, so a VM escape lands where a gVisor escape would); protecting sandboxes from the operator; isolation inside a sandbox pod; audit of what sandboxes do.

**Observability is a known gap of the first delivery.** NIC records no audit trail of what sandboxes do; the pack's proxy sees the traffic it allows. Denied-traffic logging comes from the same VPC CNI and k3s configuration NIC sets for enforcement and should be in the first delivery, since default-deny is otherwise hard to debug; runtime telemetry is a later ADR.

### Future integration

Agent Substrate and similar systems run many sandboxes inside worker pods that drive the runtime themselves, as root with added capabilities, unconfined profiles and host paths. They are separately trusted infrastructure, close to host root, not users of this profile: NIC could at most give them dedicated pools and the network boundary around those pools, and could not verify the isolation inside them. That integration needs its own decision when such a system runs on a NIC provider ([§22.9](../design-doc/implementation/22-untrusted-execution-pods.md#229-future-integration-sandbox-platforms)).

### Consequences

**Good:**
- The separate-sandbox design gets platform guarantees that hold whatever a pack's pod spec says, checked at every deploy.
- Root-needing tools work in sandboxes without weakening the host boundary, and the profile is useful at `shared-kernel` before any runtime exists.
- Packs keep their own request layer, protocol and proxy; NIC adds no agent framework.
- Enforcing NetworkPolicy fixes a gap that also matters outside sandboxing (#691).

**Bad:**
- Depends on #691 and #675 for every provider that offers the profile, on strict mode's cluster-wide policy work on EKS, and on a host-side rule for node-local traffic that NIC does not have yet.
- NetworkPolicy matches addresses and ports, not domain names, so domain allowlists live in the pack's proxy.
- Dedicated pools cost capacity, and sandboxes of different users can still share a node.
- Admission rules can break packs that assumed a service-account token or shared Secrets.
- Per-pod credentials and the lifetime of controller-owned pods rest on the pack's controller, not on admission.
- New verification work on every deploy.

## Options Detail

- **Option 1 (do nothing):** no work, but enforcement, admission and placement are outside any pack's reach, and on EKS today a pack's policies would silently do nothing.
- **Option 2 (documentation):** cheap, but promises nothing NIC checks.
- **Option 3 (chosen):** guarantees the platform properties at the namespace level, with a probe at every deploy.
- **Option 4 (NIC-owned request layer):** convenient, but agent designs differ, and a pack can install Agent Sandbox inside these namespaces itself.
- **Option 5 (NIC-owned domain egress):** domain-based rules and central audit, but a large component that duplicates the proxy packs already run for credential injection. A later ADR if several packs need the same egress.

## Open Questions

- How should own-node traffic be blocked: the proposed host-side rule, or network segmentation (dedicated subnets and security groups on AWS, firewalls on Hetzner) if it can cover a pod's traffic to its own node?
- Should NIC create one sandbox namespace per user itself, to remove the shared-exec risk?
- Should the profile also forbid ingress except from labelled agent pods, or leave ingress within peer namespaces to packs?
- Should `nic deploy` also report cluster-wide grants (a ClusterRoleBinding a pack adds) that let identities other than the declared controller create Secrets or pods in a credential namespace? NIC's setup covers only the namespace's own bindings.

## Links

- [ADR-0021: Workload Sandboxing Capability Contract for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0023: User-Space Kernel Sandboxes with gVisor](0023-user-space-kernel-capability.md)
- [ADR-0026: VM Boundary with Kata Containers](0026-vm-boundary-capability.md)
- [Design doc: Untrusted-Execution Pods](../design-doc/implementation/22-untrusted-execution-pods.md)
- [#691: Enforce NetworkPolicy on every cluster provider](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691)
- [#675: Enforce NetworkPolicy on the VPC CNI addon](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Luis Cardoso, "Sandboxes for AI" (2026)](https://www.luiscardoso.dev/blog/sandboxes-for-ai)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
- [Agent Substrate](https://github.com/agent-substrate/substrate)
