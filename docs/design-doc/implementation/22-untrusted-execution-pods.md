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
- node-local reachability tests repeated after a node replacement and a CNI upgrade.

## 22.8 Rejected alternatives

- **Trusting NetworkPolicy objects without enforcement checks:** a policy nothing enforces is accepted and does nothing (EKS today).
- **Pod Security `restricted` for sandbox namespaces:** forbids root, which tool execution needs; the runtime is the boundary instead.
- **In-pod network restrictions for sandboxes:** root inside the pod can undo them.
- **A NIC-owned request layer or egress gateway:** see ADR-0025, options 4 and 5.
