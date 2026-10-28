# ADR-0026: VM-Boundary Sandboxes (`vm-boundary`) with Kata Containers

## Status

Proposed (DRAFT, exploratory): a feasibility sketch that fits [ADR-0021](0021-gradual-workload-sandboxing-for-software-packs.md)'s interface; not proposed for acceptance yet, and paused until a consumer needs it and AKS has been probed. Depends only on ADR-0021, whose `hardware-virtualised` boundary level it implements with Kata (the `vm-boundary` family). It mirrors mechanisms sketched in [ADR-0023](0023-user-space-kernel-capability.md) and can be required by [ADR-0025](0025-untrusted-execution-pods.md)'s profile, but depends on neither; [ADR-0024](0024-immutable-node-pool-rollouts.md) is not assumed to apply unchanged. Mechanisms and the verification checklist are in the [design doc](../design-doc/implementation/23-vm-boundary.md).

## Date

2026-10-28

## Context

ADR-0023 puts pods behind gVisor, a user-space kernel. That is a strong boundary, but an escape from gVisor reaches the host kernel directly. For the primary pattern of ADR-0023 and ADR-0025, an agent running its tool calls in a separate sandbox pod, some threat models want the sandbox behind **hardware virtualisation with its own guest kernel**, so that an escape must break the hypervisor as well.

[Kata Containers](https://katacontainers.io/) runs each pod inside a lightweight VM and is selected with a `RuntimeClass`, like gVisor. It needs hardware virtualisation inside the node, which narrows where it can run:

- **AWS.** Kata used to mean bare-metal instances, which are large and scale coarsely. Regular instances of 7th- and 8th-generation Intel families (c7i, m7i, r7i, c8i, m8i, r8i and variants, from `.large`; 166 types in us-east-1) now support nested virtualisation through one launch-template CPU option (`CpuOptions.NestedVirtualization`). Observed 2026-10-27: an EKS managed node group of m8i-flex.large on AL2023 joined with `/dev/kvm` and the KVM modules, and Kata 4.2.0 ran on it.
- **Azure (AKS).** Pod Sandboxing is a built-in Kata-based runtime on node pools that opt in (Azure Linux nodes), with its own VMM and guest. It is a separate implementation from Kata installed on AWS, owned and upgraded by the provider, and has not been probed.
- **Hetzner Cloud.** No nested virtualisation, and software emulation is too slow for tool workloads. The alternative there is a whole cloud VM per sandbox, created outside Kubernetes, which is not a node-level capability and is out of scope here.

Because a VM pod is still a pod, it fits ADR-0021's interface and can reuse the mechanisms sketched for gVisor (boot-time install, a node-side failure signal, placement on a label nodes cannot write, smoke pods) and ADR-0025's profile, without depending on them.

## Decision Drivers

- **A boundary with its own kernel** for workloads whose threat model needs one.
- **Same interface as gVisor.** Packs read their settings from the requirement mapping, so a set that resolves to Kata needs no pack change.
- **Use the provider's own mechanism where one exists** (AKS), and install at boot elsewhere (ADR-0023's driver).
- **Elastic, not bare metal, where possible.**
- **Promise only what is verified**, per instance family and node image.

## Considered Options

1. Do nothing: gVisor is the strongest boundary NIC offers.
2. Kata on AWS nested-virtualisation node groups (bare metal as fallback) and AKS Pod Sandboxing, as an implementation of the `hardware-virtualised` level.
3. Kata on bare metal only.
4. Kata with Firecracker as the VMM.
5. A cloud VM per sandbox outside Kubernetes.

## Decision Outcome

Chosen option: "Option 2", because it delivers a guest-kernel boundary through the same capability contract and runtime-class mechanism as ADR-0023, on elastic node groups where the provider allows it, and uses AKS's maintained implementation rather than a NIC-owned one there.

### The implementation

**`vm-boundary`** is an implementation family of ADR-0021's **`hardware-virtualised`** level: a pod that sets the level's published `RuntimeClass` runs inside its own virtual machine with its own guest kernel, isolated from the host by hardware virtualisation. Kata Containers is its first implementation. Under ADR-0021's ordering rule, a stronger level satisfies an operator's `mediated-kernel` policy, but satisfies a requirement set only where Kata has every property the set needs. ADR-0021 builds no choice between two qualifying implementations, so offering gVisor and Kata for the same set on one provider needs that choice decided first.

**Two implementations, qualified separately.** Kata installed by NIC on AWS (QEMU) and AKS Pod Sandboxing (a different VMM and guest, managed by Azure) are separate implementations of the level. Properties established for one are not carried over to the other; the table below is for AWS only, and AKS has none until it is probed.

**Properties of Kata on AWS** (Kata 4.2.0 with QEMU on EKS AL2023, 2026-10-27):

| Property | Kata |
|---|---|
| `process-self-restriction` (Landlock inside) | Yes (guest kernel 6.18, Landlock ABI 7; ADR-0021's probe passed) |
| `in-pod-namespaces` | Not yet probed |
| Pod's `seccompProfile` applied | No in the tested configuration (`seccomp_mode` 0 inside the guest) |
| Root inside | Contained by the VM; with `NET_ADMIN`, root can change routes and iptables inside the guest, which does not bypass ADR-0025's host-side policy |
| Usable memory under a limit | Less than the limit: at 1 GiB the guest saw about 947 MiB and a process was killed after 880 MiB (runc 1,008) |
| Start time | About 5.8 s against about 4.3 s for gVisor and runc |
| Host memory per idle VM | About 255–285 MiB |

The qualified consumer is ADR-0023's primary pattern: a tool-execution sandbox pod under ADR-0025's profile, root allowed inside. Every container in a VM pod shares its VM, so trusted containers (an agent, a proxy) must never be placed in the sandbox pod.

### What the operator configures

```yaml
cluster:
  aws:
    node_groups:
      sandbox:
        instance: <a nested-virtualisation family>   # or a bare-metal family
        nested_virtualization: true                   # launch template CPU option
        sandbox:
          runtime: kata                               # the implementation this group offers
          dedicated: true                             # required for this runtime
```

`dedicated: true` is required: VM pods run on nodes that run nothing else of the platform.

### What NIC does

1. **`nic validate`** checks the provider, instance family (nested virtualisation or bare metal), node image, architecture and the pinned Kata release against the support matrix. Hetzner is rejected with a message naming the alternative; AKS requires a node pool with Pod Sandboxing.
2. **AWS: installation at boot on opted-in groups.** The node group's launch template enables nested virtualisation on a supported family (not needed on bare metal) and keeps NIC's node and VPC-endpoint security groups; a boot step installs NIC's published Kata artifact (runtime, shim, guest kernel and image, and the VMM), verified like ADR-0023's, and registers a containerd handler `kata`. The node checks that `/dev/kvm` exists before installing.
3. **AKS: the built-in runtime.** NIC opts the node pool into Pod Sandboxing through its AKS module and publishes Azure's runtime class in the requirement mapping rather than installing anything. Azure owns that runtime's installation and version; NIC declares and observes it (ADR-0021's declaration and observation layers) without implying it controls either.
4. **Node check and placement**, mirroring ADR-0023's sketch: a test pod sandbox through the CRI with the `kata` handler must show **Kata-specific evidence**: the kernel release inside matches the pinned Kata guest kernel, and the VM's firmware (DMI) identifies NIC's VMM rather than the EC2 instance. A different kernel plus the CPU's hypervisor flag is not enough, since EC2 nodes already show the flag and a gVisor pod there would pass. The node only reports failure itself (`sandbox.nebari.dev/kata: failed`); a cluster-side component sets the placement label `node-restriction.kubernetes.io/nebari-sandbox-kata` after verifying the node. NIC creates `RuntimeClass` `nebari-kata`, labelled `sandbox.nebari.dev/level: hardware-virtualised`, with a memory `overhead` set from measurement, selecting that label and tolerating the dedicated taint (the class kata-deploy creates has no toleration for a custom taint).
5. **`nic deploy` smoke pods** on every labelled node of every opted-in group, with the same Kata-specific evidence, plus ADR-0025's probe under the VM runtime when that profile admits it. They are diagnostics, not attestation.
6. **Upgrades** meet the lifecycle invariants stated in ADR-0023 (unverified nodes get no pods, no unsandboxed fallback, explicit semantics changes, a path for security updates, documented recovery): a change to the Kata release, VMM, guest kernel or CPU options replaces nodes. On AKS the provider owns the runtime's lifecycle.

**Prerequisites.**

- **AWS.** Per-group launch templates with nested virtualisation in NIC's EKS module (keeping NIC's node and VPC-endpoint security groups, without which nodes never join), a supported instance family and EKS node image with KVM modules, and NIC's Kata artifact.
- **AKS.** Pod Sandboxing in NIC's AKS module, and ADR-0025's NetworkPolicy enforcement (#691).
- **Storage.** Volumes reach the guest through Kata's shared file system or as block devices. An EBS gp3 workspace worked for a root sandbox under Kata on EKS (2026-10-27); `fsGroup` ownership and FSx for OpenZFS are to be verified.

### Combining with in-pod capabilities

Validation uses the properties above: Kata on AWS has `process-self-restriction` (Landlock ABI 7 in the guest), so it can satisfy a set that needs Landlock at `mediated-kernel` or above where gVisor cannot; `in-pod-namespaces` is not yet probed and is not offered until it is. Nothing is inferred for AKS. One runtime applies per pod, so gVisor and a VM never combine.

### Security

- **A different boundary, not an absolute one.** An escape must break the guest kernel and then the VMM. On nested virtualisation QEMU and virtiofsd run as processes on the node, so an escape from them lands on the node, where a gVisor escape would. A VM floor does not answer tenancy or side channels: cache side channels need separate nodes. Treat code an agent executes as attacker-influenced, as ADR-0021 does.
- **Sidecars share the VM.** Any container in the pod is inside the boundary with the untrusted code.
- **Network.** The VM changes nothing about egress: ADR-0025's enforced rules apply outside the VM, and held against root with `NET_ADMIN` inside it on EKS.
- **Declared seccomp is not enforced in the guest** in the tested configuration, as with gVisor; documentation for hardened mode says so.
- **Supply chain.** NIC pins one Kata release, VMM and guest kernel per NIC release and treats their security releases like its own.

### Trust model

- **Trusted:** the operator, NIC, the pinned Kata release, VMM and guest kernel (on AKS, Azure's runtime), the labeller, and the provider's node image.
- **A hostile workload** may run as root in the guest and use the VMM's virtual devices.
- **NIC enforces** placement only on verified nodes and that pods naming the class never run on another runtime; network rules come from ADR-0025's profile where used.
- **The pack enforces** keeping trusted containers out of the VM pod and credentials out of the sandbox.
- **Outside the guarantee:** VMM and host escapes, side channels between pods on one node, and the guest's declared seccomp settings.

### Consequences

**Good:**
- A guest-kernel boundary for packs whose threat model needs it, through the same interface as gVisor.
- Elastic VM sandboxes on AWS on regular nested-virtualisation instances (no bare metal needed), and AKS support through Azure's maintained runtime.
- Unlike gVisor, a real Linux guest kernel, so tools that gVisor does not implement are expected to work.

**Bad:**
- Not available on Hetzner Cloud.
- Slower pod start than gVisor (about 1.5 s), about 255–285 MiB of host memory per VM, and less usable memory in the guest than the pod's limit.
- On AWS, Intel 7th- and 8th-generation families only; bare metal costs more and scales coarsely.
- NIC owns another runtime artifact and its re-qualification on Kata, VMM, kernel and node-image changes.
- The guest kernel is a second kernel, besides the host's, that NIC must track and patch.

## Options Detail

- **Option 1 (do nothing):** no work, but no guest-kernel boundary for packs that need one.
- **Option 2 (chosen):** elastic where nested virtualisation qualifies, built in on AKS.
- **Option 3 (bare metal only):** predictable KVM, but a high idle cost and coarse scaling; kept as the AWS fallback.
- **Option 4 (Firecracker):** a minimal VMM, but Kata's Firecracker mode needs a block-device snapshotter and supports fewer volume types; a later variant.
- **Option 5 (a cloud VM per sandbox):** works on Hetzner, but is a provisioning system outside Kubernetes rather than a node capability; a pack or a separate ADR could provide it.

## Open Questions

- How does Kata on nested virtualisation perform against bare metal, and in which other regions are the families available?
- The artifact uses QEMU, the VMM tested. Should a smaller VMM (Firecracker or Cloud Hypervisor) replace it later? That would change how volumes reach the guest.
- What `RuntimeClass` overhead and limit sizing should be published, given that the guest sees less memory than the limit (the chart's default overhead is 320 MiB)?
- Which properties does AKS Pod Sandboxing have on NIC's AKS module, and what Kata-specific evidence does its guest offer?
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
