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

Sandboxes come in two shapes. In one, **the pod is the sandbox**: a pack's own pods, or pods from a request layer such as Agent Sandbox, which selects gVisor or Kata through `RuntimeClass`. In the other, **a sandbox platform** runs many sandboxes inside worker pods and drives the runtime itself: Agent Substrate (v0.6.0, pre-1.0) runs up to 1,000 gVisor or Kata/Cloud Hypervisor "actors" per worker pod, and its workers run on the host kernel as root with thirteen added capabilities, seccomp and AppArmor unconfined, host paths and no `RuntimeClass`. Rules for the first shape reject the second; rules loosened for the second undo the first ([§22.9](../design-doc/implementation/22-untrusted-execution-pods.md#229-sandbox-platforms)).

## Decision Drivers

- **Platform guarantees, not pack diligence.** What NIC promises holds whatever a pack's pod spec says.
- **Enforced from outside the pod.** Nothing inside the sandbox, including root, can loosen it.
- **Verified, not configured.** Every guarantee is checked by a real probe, never inferred from settings.
- **No credentials in the sandbox by default.**
- **Root inside is allowed**, because the boundary is the runtime and the network rules, not in-pod restrictions.
- **Leave the agent design to packs.** NIC provides the substrate: no request layer, proxy or session protocol of its own.
- **Guarantee at the boundary NIC can see.** NIC's rules and probes act on pods, namespaces and nodes; isolation inside a pod belongs to whoever runs it.

## Considered Options

1. Do nothing: each pack secures its own sandbox pods.
2. Documentation only: publish guidance for packs.
3. NIC-guaranteed **untrusted-execution profiles**: enforced default-deny networking, admission rules and dedicated pools, verified at deploy, with one profile for sandbox pods (a sandbox runtime required, root allowed) and one for sandbox-platform workers (a declared privilege envelope on dedicated pools, the platform owning isolation inside its pods).
4. Option 3 plus a NIC-owned request layer (for example the Agent Sandbox controller) that creates sandbox pods for packs.
5. Option 3 plus NIC-owned domain-based egress (an egress gateway or FQDN policies) instead of each pack's proxy.
6. Sandbox pods only, with platforms admitted by per-pack exceptions decided case by case.
7. A sandbox platform as a system-provided capability under ADR-0021, providing `user-space-kernel` or `vm-boundary` through its own API.

## Decision Outcome

Chosen option: "Option 3", because the properties packs cannot provide themselves (enforced network rules, admission, runtime and placement) are exactly the ones a namespace profile can guarantee, while request layers, protocols and proxies differ between agent designs and belong to packs. Two profiles keep each shape's rules strict: sandbox pods never get host privileges, and a platform gets exactly the privileges it declares, only on nodes nothing else uses.

### What the operator configures

```yaml
sandbox:
  require:
    - capability: user-space-kernel
  untrusted_execution:
    namespaces: [agent-sandboxes]      # sandbox-pod profile: NIC creates, labels and guards these
    runtime_classes: [gvisor]          # sandbox pods must use one of these
    platforms:                         # sandbox-platform profile (optional; envelope in §22.9)
      - name: substrate
        namespace: ate-workers
        node_groups: [actors]          # dedicated; not opted in to NIC's runtimes
        privileges: {...}              # the exact envelope its workers may use
```

Node groups serving sandbox runtimes must be opted in with `dedicated: true` (ADR-0023), and platform groups must be dedicated too, which keeps other workloads off them; NIC rejects either profile otherwise.

### What NIC guarantees for sandbox pods

1. **Default-deny networking, enforced from outside the pod.** NIC installs a default-deny policy for ingress and egress in each untrusted-execution namespace. A pack opens routes by adding NetworkPolicies, which an admission policy restricts to in-cluster destinations selected by label (typically the pack's proxy in another namespace) and the ingress its agent needs (SSH or exec); policies that allow `ipBlock` destinations outside the cluster are rejected. Credential-injecting egress is therefore **the pack's own proxy**; NIC's part is the enforced rules that leave the proxy as the only way out. NetworkPolicy enforcement itself is a per-provider guarantee from #691; this ADR requires it on any cluster that uses the profile.
2. **Metadata and node-local endpoints unreachable.** The cloud metadata service, the node's own addresses (kubelet and node ports) and the Kubernetes API are not reachable from sandbox pods. Default-deny egress is expected to cover them, but on some CNIs traffic to the local node bypasses policy, so each is checked separately (to be verified per provider); on AWS NIC's node groups also require IMDSv2 with a hop limit of 1.
3. **No credentials by default.** An admission policy (a `ValidatingAdmissionPolicy`) in these namespaces rejects pods that mount a service-account token, a Secret (by volume, projected volume or environment), a host path, or use host networking, PID or IPC. One exception: Secrets labelled as session-scoped sandbox capabilities (for example an SSH host key or authorized key), which grant nothing outside the sandbox.
4. **A sandbox runtime is mandatory; root inside is allowed.** The same policy rejects pods without a `runtimeClassName` from `runtime_classes`, and privileged containers. Root and the default capabilities are allowed, and the namespaces use Pod Security `baseline`, not `restricted`: the boundary is the runtime (ADR-0023's gVisor, ADR-0026's VM) and the network rules, so no sandbox pod can run as root on the host kernel.
5. **Dedicated, immutable pools.** Sandbox runtimes run only on opted-in, dedicated groups, which are immutable pools under ADR-0024, so foundational services never share a node with sandbox pods.
6. **Workspace storage with real ownership.** Volumes sandbox pods write to present real ownership (ADR-0023's storage prerequisite), so root or a mapped user can work in them; storage that keeps data on nodes is not used.
7. **Verification at `nic validate` and `nic deploy`.** `nic validate` rejects the profile where the provider cannot enforce NetworkPolicy, has no qualified sandbox runtime, or has no dedicated opted-in group. `nic deploy` runs a root probe pod under each listed runtime in each namespace and fails unless: external egress fails; a NIC test target allowed by label is reachable and a non-allowed one is not; the metadata service, the node's addresses and the Kubernetes API are unreachable; no service-account token is present; and the admission policy rejects a pod without a sandbox runtime, a pod mounting a Secret and a policy allowing an external `ipBlock`.

### What NIC guarantees for sandbox-platform workers

NIC guarantees the boundary around the platform's pool; the platform guarantees everything inside its pods.

1. **Dedicated, immutable pools** (ADR-0024) that only the platform's workers, its node agent and NIC's node-level DaemonSets may use, enforced by a taint and an admission policy; never shared with sandbox pods or another platform, and not opted in to NIC's runtimes.
2. **An exact privilege envelope.** In the worker namespace, pods are admitted only under a declared service account and within the declared capabilities, unconfined profiles, host paths and device resources; `privileged` and host networking, PID and IPC are always refused, and any other pod gets the sandbox-pod rules. The platform's node agent and control plane get their own envelopes, and `nic outputs` lists every envelope in force.
3. **Default-deny networking and unreachable metadata and node-local endpoints**, as for sandbox pods, with routes only to the platform's own namespaces by selector. The CNI enforces them outside the pod's network namespace, so the workers' `NET_ADMIN` cannot lift them (to be verified per provider).
4. **API gating and verification.** `nic validate` rejects a platform whose declared APIs the cluster does not serve; `nic deploy` runs the network probe on the platform's nodes and confirms by dry run that pods beyond the envelope, under other service accounts, or of other workloads on the platform's nodes are rejected.

**Not promised for platforms:** isolation between sandboxes inside a worker pod, the platform's runtime binaries (ADR-0023's and ADR-0026's checks do not apply), per-sandbox egress and credentials, snapshot confidentiality, or the platform's control plane. A runtime escape inside a worker lands in a container holding the envelope's privileges on a dedicated node; operators accept that by declaring the envelope.

**Per provider (to be verified unless noted):**

- **AWS:** the VPC CNI's network policy enforcement, enabled by NIC (#675); enforcement of default-deny for gVisor and runc pods was observed once enabled (2026-10-19). Whether it blocks the metadata service and node-local addresses is to be verified.
- **Hetzner:** k3s's built-in network policy controller; observed enforcing for gVisor pods (2026-10-25). Node-local and metadata reachability (including the join-token issue) to be verified.
- **Azure:** the Cilium dataplane (#691); unsupported until NIC's AKS module enables it.
- **`existing` and kind:** verification only, as in ADR-0023: NIC checks and probes the profile but does not configure the CNI.

### What a pack does

It creates its sandbox pods in an untrusted-execution namespace with a listed `runtimeClassName`, opens only the routes it needs (to its proxy, and from its agent's pod for SSH or exec), and keeps every real credential in its trusted pods. The pack's own startup check remains the final guard. A pack built on a sandbox platform instead depends on that platform's installation and declares no privileges of its own; the platform's installer, not the pack, declares the envelope.

### Consequences

**Good:**
- The separate-sandbox design gets platform guarantees that hold whatever a pack's pod spec says, verified at every deploy.
- Root-needing tools work in sandboxes without weakening the host boundary.
- Packs keep their own request layer, protocol and proxy; NIC adds no agent framework.
- Sandbox platforms can run on NIC without weakening the sandbox-pod profile, with explicit, visible privileges; platforms that suspend and resume sandboxes can carry sessions across ADR-0024 rollouts.
- Enforcing NetworkPolicy fixes a gap that also matters outside sandboxing (#691).

**Bad:**
- Depends on #691 and #675 landing for every provider that offers the profile.
- NetworkPolicy matches addresses and ports, not domain names, so domain allowlists live in the pack's proxy.
- Dedicated pools cost capacity.
- Admission rules can break packs that assumed a service-account token or mounted Secrets; such packs must change.
- New verification work on every deploy, and per-provider uncertainty about node-local traffic until probed.
- A platform's runtime and node agent join the trusted computing base on its nodes; NIC bounds where, but cannot check them.
- Agent Substrate does not run on NIC's providers today (GKE and kind only, GKE-specific node paths, pod-certificate APIs NIC's clusters do not serve). The platform profile is specified now so the rules need no redesign, and delivered when a platform qualifies on a NIC provider.

## Options Detail

- **Option 1 (do nothing):** no work, but enforcement, admission and placement are outside any pack's reach, and on EKS today a pack's policies would silently do nothing.
- **Option 2 (documentation):** cheap, but promises nothing NIC checks.
- **Option 3 (chosen):** guarantees the platform properties at the namespace level, with a probe at every deploy.
- **Option 4 (NIC-owned request layer):** convenient for packs that want it, but agent designs differ (SSH, exec, pre-started pools), and Agent Sandbox can be installed by a pack inside these namespaces without NIC owning it.
- **Option 6 (case-by-case exceptions):** no new profile, but each exception loosens the sandbox-pod rules with no shared limits, pool rules or probes.
- **Option 7 (system-provided capability):** a platform's sandboxes are not pods with published settings and NIC cannot check the runtime it downloads, so the guarantee would be the platform's, not NIC's. Revisit if NIC ever installs and qualifies a platform itself.
- **Option 5 (NIC-owned domain egress):** domain-based rules and central audit, but a large component (a gateway or an FQDN-capable CNI on every provider) that duplicates the proxy packs already run for credential injection. A later ADR if several packs need the same egress.

## Open Questions

- Should DNS be allowed by default? Sandbox pods using an explicit proxy need none, and DNS is an exfiltration channel.
- Should the profile also forbid ingress except from labelled agent pods, or leave ingress entirely to packs?
- How do packs declare the Secrets that count as session-scoped capabilities, and should NIC limit their number or size?
- Should the profile be a capability under ADR-0021's contract (for example `untrusted-execution`), so packs can require it in `sandbox.require`?
- Does `kubectl exec` from the agent's pod need extra restriction, since it needs RBAC on the sandbox namespace?
- Should privilege envelopes be operator-declared (as proposed) or NIC-published per platform version, given that pre-1.0 platforms change their privileges between releases?
- ADR-0026 should offer KVM-capable node groups without NIC's Kata install, for platforms that bring their own VMM.
- Can EKS and k3s serve the pod-certificate APIs a platform needs, and at which Kubernetes versions?

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
- [Agent Substrate](https://github.com/agent-substrate/substrate)
