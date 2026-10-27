# ADR-0026: VM-Boundary Sandboxes (`vm-boundary`) with Kata Containers

## Status

Proposed (DRAFT). Builds on [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md), which reserves the name `vm-boundary`; reuses [ADR-0023](0023-user-space-kernel-capability.md)'s installation, checks and routing, [ADR-0024](0024-immutable-node-pool-rollouts.md)'s rollouts and [ADR-0025](0025-untrusted-execution-pods.md)'s guarantees for untrusted-execution pods. This ADR cannot be accepted before them. Mechanisms and the verification checklist are in the [design doc](../design-doc/implementation/23-vm-boundary.md).

## Date

2026-10-28

## Context

ADR-0023 puts pods behind gVisor, a user-space kernel. That is a strong boundary, but an escape from gVisor reaches the host kernel directly. For the primary pattern of ADR-0023 and ADR-0025, an agent running its tool calls in a separate sandbox pod, some threat models want the sandbox behind **hardware virtualisation with its own guest kernel**, so that an escape must break the hypervisor as well.

[Kata Containers](https://katacontainers.io/) runs each pod inside a lightweight VM and is selected with a `RuntimeClass`, like gVisor. It needs hardware virtualisation inside the node, which narrows where it can run:

- **AWS.** Regular EC2 instances have not exposed virtualisation extensions, so Kata has meant bare-metal instances, which are large and scale coarsely. AWS is reported to support nested virtualisation on selected virtual instance families, enabled through the launch template's CPU options (`NestedVirtualization`); which families, regions and EKS node images qualify is **to be verified**.
- **Azure (AKS).** Pod Sandboxing is a built-in Kata-based runtime on node pools that opt in (Azure Linux nodes; to be verified against NIC's AKS module).
- **Hetzner Cloud.** No nested virtualisation, and software emulation is too slow for tool workloads. The alternative there is a whole cloud VM per sandbox, created outside Kubernetes, which is not a node-level capability and is out of scope here.

Because a VM pod is still a pod, everything else carries over: ADR-0021's contract, ADR-0023's boot-time install, node check, routing and smoke pods, ADR-0024's immutable pools and ADR-0025's network and admission guarantees.

## Decision Drivers

- **A boundary with its own kernel** for workloads whose threat model needs one.
- **Same contract as `user-space-kernel`.** Packs switch runtime class, not architecture.
- **Use the provider's own mechanism where one exists** (AKS), and install at boot elsewhere (ADR-0023's driver).
- **Elastic, not bare metal, where possible.**
- **Promise only what is verified**, per instance family and node image.

## Considered Options

1. Do nothing: gVisor is the strongest boundary NIC offers.
2. Kata on AWS nested-virtualisation node groups (bare metal as fallback) and AKS Pod Sandboxing, as a `vm-boundary` capability.
3. Kata on bare metal only.
4. Kata with Firecracker as the VMM.
5. A cloud VM per sandbox outside Kubernetes.

## Decision Outcome

Chosen option: "Option 2", because it delivers a guest-kernel boundary through the same capability contract and runtime-class mechanism as ADR-0023, on elastic node groups where the provider allows it, and uses AKS's maintained implementation rather than a NIC-owned one there.

### The capability

**`vm-boundary`:** a pod that sets the `runtimeClassName` NIC publishes for this capability runs inside its own virtual machine with its own guest kernel, isolated from the host by hardware virtualisation. The guarantee names no product; Kata Containers is its first implementation. The qualified consumer is ADR-0023's primary pattern: a tool-execution sandbox pod under ADR-0025's profile, root allowed inside. Every container in a VM pod shares its VM, so trusted containers (an agent, a proxy) must never be placed in the sandbox pod.

### What the operator configures

```yaml
cluster:
  aws:
    node_groups:
      sandbox:
        instance: <a nested-virtualisation family>   # or a bare-metal family
        nested_virtualization: true                   # launch template CPU option
        sandbox:
          capabilities: [vm-boundary]
          dedicated: true                             # required for vm-boundary
```

`dedicated: true` is required: VM pods run on nodes that run nothing else of the platform.

### What NIC does

1. **`nic validate`** checks the provider, instance family (nested virtualisation or bare metal), node image, architecture and the resolved Kata release against the support matrix, as ADR-0023 does. Hetzner is rejected with a message naming the alternative; AKS requires a node pool with Pod Sandboxing.
2. **AWS: installation at boot on opted-in groups.** The node group's launch template enables nested virtualisation (not needed on bare metal); a boot step installs NIC's published Kata artifact (runtime, shim, guest kernel and image, and the VMM), verified like ADR-0023's, and registers a containerd handler `kata`. The node checks that `/dev/kvm` exists before installing.
3. **AKS: the built-in runtime.** NIC opts the node pool into Pod Sandboxing through its AKS module and publishes AKS's runtime class rather than installing anything.
4. **Node check and routing** as in ADR-0023: a test pod sandbox through the CRI with the VM handler, which must report a guest kernel different from the host's and pass the checks the qualified consumer needs; the node labels itself; a `RuntimeClass` (`kata`, with a measured memory `overhead`) selects the group label `sandbox.nebari.dev/vm-boundary: "true"` and tolerates the dedicated taint.
5. **`nic deploy` smoke pods** on every node of every opted-in group, plus ADR-0025's probe under the VM runtime when the untrusted-execution profile lists it.
6. **Upgrades** through ADR-0024: the Kata release, VMM, guest kernel and launch-template CPU options are part of each generation's spec.

**Prerequisites.**

- **AWS.** Per-group launch templates with nested virtualisation in NIC's EKS module (keeping NIC's security groups, as ADR-0024 requires), a supported instance family and EKS node image with KVM modules, and NIC's Kata artifact.
- **AKS.** Pod Sandboxing in NIC's AKS module, and ADR-0025's NetworkPolicy enforcement (#691).
- **Storage.** Volumes reach the guest through Kata's shared file system or as block devices; ownership and performance on the supported storage classes are to be verified.

### Combining capabilities

| The pack wants | Requirement | Result |
|---|---|---|
| Tool-execution sandbox in a VM | `vm-boundary`, with ADR-0025's profile | Root inside the VM, network isolated from outside |
| Landlock or bubblewrap inside the VM | `process-self-restriction` or `in-pod-namespaces` `within: vm-boundary` | Possible in principle, since the guest is a real Linux kernel; to be verified |
| gVisor and a VM | — | Not supported: one runtime per pod |

### Security

- **Stronger than gVisor, still not absolute.** An escape must break the guest kernel and the VMM; on nested virtualisation the host is itself a VM. Treat code an agent executes as attacker-influenced, as ADR-0021 does.
- **Sidecars share the VM.** Any container in the pod is inside the boundary with the untrusted code.
- **Network.** The VM changes nothing about egress: ADR-0025's enforced rules apply outside the VM.
- **Supply chain.** NIC pins one Kata release, VMM and guest kernel per NIC release and treats their security releases like its own.

### Consequences

**Good:**
- A guest-kernel boundary for packs whose threat model needs it, through the same contract and runtime-class switch as gVisor.
- Elastic VM sandboxes on AWS if nested virtualisation qualifies, and AKS support through Azure's maintained runtime.
- Unlike gVisor, a real Linux guest kernel, so tools that gVisor does not implement are expected to work.

**Bad:**
- Not available on Hetzner Cloud.
- Larger memory overhead and slower pod start than gVisor (to be measured).
- On AWS, a narrower set of instance families, possibly regions, and node-image requirements; bare metal costs more and scales coarsely.
- NIC owns another runtime artifact and its re-qualification on Kata, VMM, kernel and node-image changes.

## Options Detail

- **Option 1 (do nothing):** no work, but no guest-kernel boundary for packs that need one.
- **Option 2 (chosen):** elastic where nested virtualisation qualifies, built in on AKS.
- **Option 3 (bare metal only):** predictable KVM, but a high idle cost and coarse scaling; kept as the AWS fallback.
- **Option 4 (Firecracker):** a minimal VMM, but Kata's Firecracker mode needs a block-device snapshotter and supports fewer volume types; a later variant.
- **Option 5 (a cloud VM per sandbox):** works on Hetzner, but is a provisioning system outside Kubernetes rather than a node capability; a pack or a separate ADR could provide it.

## Open Questions

- Which AWS instance families, regions and EKS node images support nested virtualisation with Kata, and how does performance compare with bare metal?
- Which VMM should the AWS artifact use (QEMU, Cloud Hypervisor)?
- What `RuntimeClass` overhead covers the guest kernel and VMM at realistic sandbox sizes?
- Should `vm-boundary` be required to use ADR-0025's profile, given its primary consumer?
- Should Hetzner dedicated servers, which expose virtualisation, be supported?

## Links

- [ADR-0021: Gradual Workload Sandboxing Capability for Software Packs](0021-gradual-workload-sandboxing-for-software-packs.md)
- [ADR-0023: User-Space Kernel Sandboxes with gVisor](0023-user-space-kernel-capability.md)
- [ADR-0024: Immutable Node-Pool Rollouts](0024-immutable-node-pool-rollouts.md)
- [ADR-0025: Guarantees for Untrusted-Execution Pods](0025-untrusted-execution-pods.md)
- [Design doc: VM Boundary](../design-doc/implementation/23-vm-boundary.md)
- [Kata Containers](https://katacontainers.io/)
- [Amazon EC2 nested virtualisation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html)
- [AKS Pod Sandboxing](https://learn.microsoft.com/azure/aks/use-pod-sandboxing)
