# ADR-0025: Guarantees for Untrusted-Execution Pods

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md)'s capability contract, [ADR-0023](0023-user-space-kernel-capability.md) (gVisor) and [ADR-0024](0024-immutable-node-pool-rollouts.md) (immutable pools); [ADR-0026](0026-vm-boundary-capability.md) adds a VM runtime. Depends on NetworkPolicy enforcement on every provider ([#691](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691), with [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675) for the AWS VPC CNI). Mechanisms and the verification checklist are in the [design doc](../design-doc/implementation/22-untrusted-execution-pods.md).

## Date

2026-10-28

## Context

The strongest design for ADR-0021's threat model keeps an agent's credentials and the code it runs in different places: **an agent running its tool calls in a separate sandbox pod**. The agent runs in a trusted pod with its model and integration credentials. Each tool call (a shell command, a file read or write) runs in a separate, usually per-session pod that holds no credentials, reached over SSH or `kubectl exec`. The agent's pod can be anything: a coding agent, a chat assistant, a scheduled job, a notebook server. Even code that takes over the sandbox pod completely finds nothing to steal there; to get further it must escape the runtime boundary or the network rules around the pod.

That design is only as good as what surrounds the sandbox pod, and today NIC promises none of it:

- **The network.** A sandbox that may reach the internet directly can exfiltrate the workspace and bypass the pack's credential-injecting proxy. ADR-0023 deliberately relies on no NetworkPolicy, and NIC's EKS clusters do not enforce NetworkPolicy at all: the VPC CNI's enforcement is off unless enabled (observed in the 2026-10-19 probe; [#675](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)). A policy nothing enforces is accepted by the API server and does nothing.
- **Credentials.** Kubernetes mounts a service-account token into every pod unless told not to, and nothing stops a pack's pod spec mounting a Secret or a host path into a sandbox.
- **Root.** Tools run by agents routinely need root (package installs, system libraries). Inside a pod on the host kernel that is a real escalation risk; behind gVisor or a VM it is ordinary, but only if no sandbox pod can run on the default runtime.
- **Placement.** Sandbox pods that share nodes with foundational services put Keycloak and ArgoCD one runtime escape away.

Packs can try to get each of these right themselves, but several are platform properties no pack can enforce from a namespace: whether policies are enforced, whether the metadata service is reachable, which runtime a pod may use.

## Decision Drivers

- **Platform guarantees, not pack diligence.** What NIC promises holds whatever a pack's pod spec says.
- **Enforced from outside the pod.** Nothing inside the sandbox, including root, can loosen it.
- **Verified, not configured.** Every guarantee is checked by a real probe, never inferred from settings.
- **No credentials in the sandbox by default.**
- **Root inside is allowed**, because the boundary is the runtime and the network rules, not in-pod restrictions.
- **Leave the agent design to packs.** NIC provides the substrate: no request layer, proxy or session protocol of its own.

## Considered Options

1. Do nothing: each pack secures its own sandbox pods.
2. Documentation only: publish guidance for packs.
3. A NIC-guaranteed **untrusted-execution namespace profile**: enforced default-deny networking, admission rules, required sandbox runtimes and dedicated pools, verified at deploy.
4. Option 3 plus a NIC-owned request layer (for example the Agent Sandbox controller) that creates sandbox pods for packs.
5. Option 3 plus NIC-owned domain-based egress (an egress gateway or FQDN policies) instead of each pack's proxy.

## Decision Outcome

Chosen option: "Option 3", because the properties packs cannot provide themselves (enforced network rules, admission, runtime and placement) are exactly the ones a namespace profile can guarantee, while request layers, protocols and proxies differ between agent designs and belong to packs.

### What the operator configures

```yaml
sandbox:
  require:
    - capability: user-space-kernel
  untrusted_execution:
    namespaces: [agent-sandboxes]      # NIC creates, labels and guards these
    runtime_classes: [gvisor]          # sandbox pods must use one of these
```

Node groups serving these runtimes must be opted in with `dedicated: true` (ADR-0023), which keeps other workloads off them; NIC rejects the profile otherwise.

### What NIC guarantees in those namespaces

1. **Default-deny networking, enforced from outside the pod.** NIC installs a default-deny policy for ingress and egress in each untrusted-execution namespace. A pack opens routes by adding NetworkPolicies, which an admission policy restricts to in-cluster destinations selected by label (typically the pack's proxy in another namespace) and the ingress its agent needs (SSH or exec); policies that allow `ipBlock` destinations outside the cluster are rejected. Credential-injecting egress is therefore **the pack's own proxy**; NIC's part is the enforced rules that leave the proxy as the only way out. NetworkPolicy enforcement itself is a per-provider guarantee from #691; this ADR requires it on any cluster that uses the profile.
2. **Metadata and node-local endpoints unreachable.** The cloud metadata service, the node's own addresses (kubelet and node ports) and the Kubernetes API are not reachable from sandbox pods. Default-deny egress is expected to cover them, but on some CNIs traffic to the local node bypasses policy, so each is checked separately (to be verified per provider); on AWS NIC's node groups also require IMDSv2 with a hop limit of 1.
3. **No credentials by default.** An admission policy (a `ValidatingAdmissionPolicy`) in these namespaces rejects pods that mount a service-account token, a Secret (by volume, projected volume or environment), a host path, or use host networking, PID or IPC. One exception: Secrets labelled as session-scoped sandbox capabilities (for example an SSH host key or authorized key), which grant nothing outside the sandbox.
4. **A sandbox runtime is mandatory; root inside is allowed.** The same policy rejects pods without a `runtimeClassName` from `runtime_classes`, and privileged containers. Root and the default capabilities are allowed, and the namespaces use Pod Security `baseline`, not `restricted`: the boundary is the runtime (ADR-0023's gVisor, ADR-0026's VM) and the network rules, so no sandbox pod can run as root on the host kernel.
5. **Dedicated, immutable pools.** Sandbox runtimes run only on opted-in, dedicated groups, which are immutable pools under ADR-0024, so foundational services never share a node with sandbox pods.
6. **Workspace storage with real ownership.** Volumes sandbox pods write to present real ownership (ADR-0023's storage prerequisite), so root or a mapped user can work in them; storage that keeps data on nodes is not used.
7. **Verification at `nic validate` and `nic deploy`.** `nic validate` rejects the profile where the provider cannot enforce NetworkPolicy, has no qualified sandbox runtime, or has no dedicated opted-in group. `nic deploy` runs a root probe pod under each listed runtime in each namespace and fails unless: external egress fails; a NIC test target allowed by label is reachable and a non-allowed one is not; the metadata service, the node's addresses and the Kubernetes API are unreachable; no service-account token is present; and the admission policy rejects a pod without a sandbox runtime, a pod mounting a Secret and a policy allowing an external `ipBlock`.

**Per provider (to be verified unless noted):**

- **AWS:** the VPC CNI's network policy enforcement, enabled by NIC (#675); enforcement of default-deny for gVisor and runc pods was observed once enabled (2026-10-19). Whether it blocks the metadata service and node-local addresses is to be verified.
- **Hetzner:** k3s's built-in network policy controller; observed enforcing for gVisor pods (2026-10-25). Node-local and metadata reachability (including the join-token issue) to be verified.
- **Azure:** the Cilium dataplane (#691); unsupported until NIC's AKS module enables it.
- **`existing` and kind:** verification only, as in ADR-0023: NIC checks and probes the profile but does not configure the CNI.

### What a pack does

It creates its sandbox pods in an untrusted-execution namespace with a listed `runtimeClassName`, opens only the routes it needs (to its proxy, and from its agent's pod for SSH or exec), and keeps every real credential in its trusted pods. The pack's own startup check remains the final guard.

### Consequences

**Good:**
- The separate-sandbox design gets platform guarantees that hold whatever a pack's pod spec says, verified at every deploy.
- Root-needing tools work in sandboxes without weakening the host boundary.
- Packs keep their own request layer, protocol and proxy; NIC adds no agent framework.
- Enforcing NetworkPolicy fixes a gap that also matters outside sandboxing (#691).

**Bad:**
- Depends on #691 and #675 landing for every provider that offers the profile.
- NetworkPolicy matches addresses and ports, not domain names, so domain allowlists live in the pack's proxy.
- Dedicated pools cost capacity.
- Admission rules can break packs that assumed a service-account token or mounted Secrets; such packs must change.
- New verification work on every deploy, and per-provider uncertainty about node-local traffic until probed.

## Options Detail

- **Option 1 (do nothing):** no work, but enforcement, admission and placement are outside any pack's reach, and on EKS today a pack's policies would silently do nothing.
- **Option 2 (documentation):** cheap, but promises nothing NIC checks.
- **Option 3 (chosen):** guarantees the platform properties at the namespace level, with a probe at every deploy.
- **Option 4 (NIC-owned request layer):** convenient for packs that want it, but agent designs differ (SSH, exec, pre-started pools), and Agent Sandbox can be installed by a pack inside these namespaces without NIC owning it.
- **Option 5 (NIC-owned domain egress):** domain-based rules and central audit, but a large component (a gateway or an FQDN-capable CNI on every provider) that duplicates the proxy packs already run for credential injection. A later ADR if several packs need the same egress.

## Open Questions

- Should DNS be allowed by default? Sandbox pods using an explicit proxy need none, and DNS is an exfiltration channel.
- Should the profile also forbid ingress except from labelled agent pods, or leave ingress entirely to packs?
- How do packs declare the Secrets that count as session-scoped capabilities, and should NIC limit their number or size?
- Should the profile be a capability under ADR-0021's contract (for example `untrusted-execution`), so packs can require it in `sandbox.require`?
- Does `kubectl exec` from the agent's pod need extra restriction, since it needs RBAC on the sandbox namespace?

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0023: User-Space Kernel Sandboxes with gVisor](0023-user-space-kernel-capability.md)
- [ADR-0024: Immutable Node-Pool Rollouts](0024-immutable-node-pool-rollouts.md)
- [ADR-0026: VM Boundary with Kata Containers](0026-vm-boundary-capability.md)
- [Design doc: Untrusted-Execution Pods](../design-doc/implementation/22-untrusted-execution-pods.md)
- [#691: Enforce NetworkPolicy on every cluster provider](https://github.com/nebari-dev/nebari-infrastructure-core/issues/691)
- [#675: Enforce NetworkPolicy on the VPC CNI addon](https://github.com/nebari-dev/nebari-infrastructure-core/issues/675)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/)
