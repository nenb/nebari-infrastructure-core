# 23. VM Boundary

Mechanisms for [ADR-0026](../../adr/0026-vm-boundary-capability.md). Each is a design target, not yet implemented or tested as NIC code; claims marked "to be verified" are being probed.

## 23.1 Where it runs

| Provider | Mechanism | Status |
|---|---|---|
| AWS, nested virtualisation | Managed node group with a custom launch template setting `CpuOptions.NestedVirtualization=enabled` on a supported family; Kata installed at boot | To be verified: supported families and regions, `/dev/kvm` on the EKS node image, Kata start and performance |
| AWS, bare metal | A `.metal` family; Kata installed at boot | Fallback; no launch-template CPU option needed |
| AKS | Pod Sandboxing on an Azure Linux node pool; Azure's runtime class | To be verified against NIC's AKS module |
| Hetzner Cloud | None (no nested virtualisation) | Unsupported; a cloud VM per sandbox outside Kubernetes is the alternative |
| `existing`, kind | Operator's runtime | Verification only, as in ADR-0023 |

## 23.2 AWS installation

Follows ADR-0023's boot sequence (§20, "Boot-step dependency order"), with these differences:

1. Before installing, the boot step checks that `/dev/kvm` exists and is usable; if not, the node labels itself `"false"` with reason `no-kvm`.
2. NIC's artifact contains the Kata runtime and shim (`containerd-shim-kata-v2`), the guest kernel and guest image, and the VMM, with a per-file list, verified as ADR-0023's is.
3. The containerd handler `kata` uses `runtime_type = "io.containerd.kata.v2"`, with the Kata configuration in the release directory.
4. The node check runs a test pod sandbox through the CRI with handler `kata` and checks that `uname -r` inside differs from the host's, that it runs as root inside, and that it can write to an `emptyDir`.

The launch template's CPU option, the instance family and the Kata, VMM and guest-kernel versions are part of the generation spec (ADR-0024), so changing any of them is a rollout.

## 23.3 AKS

NIC's AKS module creates a node pool with Pod Sandboxing enabled (the node pool's workload runtime, on Azure Linux; field names to be verified) and NIC publishes Azure's runtime class name, as in ADR-0023's verification-only mode for the class itself. NIC still labels the pool, runs the node and deploy checks, and applies ADR-0025's profile, which on AKS requires the Cilium dataplane (#691).

## 23.4 Memory, start time and storage

- **Overhead.** The guest kernel, agent and VMM add memory per pod; the `RuntimeClass` `overhead` is set from measurement at realistic sandbox sizes (to be measured), as ADR-0023 did for gVisor.
- **Start time.** A VM pod starts more slowly than a gVisor pod (to be measured); per-session sandbox designs may need pre-started pools, which are the pack's concern.
- **Volumes.** File-system volumes reach the guest through Kata's shared file system (virtio-fs); block volumes can be passed as devices. Ownership, `fsGroup` and performance on EBS, FSx for OpenZFS and Azure disks are to be verified.

## 23.5 Verification checklist

Per instance family, node image and Kata release:

- `/dev/kvm` present and the node check passing on fresh and autoscaled nodes, including scale-from-zero;
- a node without virtualisation (wrong family) labelling itself `"false"` with `no-kvm`, and gVisor-style failure handling otherwise;
- guest kernel differing from the host's; root inside the VM; package installs, compilers and Git as root;
- ADR-0025's deploy probe under the VM runtime;
- PVC-backed workspaces on each supported storage class with real ownership;
- memory under a limit with the configured overhead, and pod start time;
- `process-self-restriction` and `in-pod-namespaces` within `vm-boundary`;
- an ADR-0024 rollout changing the Kata release.

## 23.6 Rejected alternatives

- **kata-deploy (a privileged DaemonSet installer):** the same objections as ADR-0023's option 4: a privileged in-cluster component that restarts containerd on running nodes.
- **Software-emulated VMs (QEMU without KVM):** keeps a VM boundary but is too slow for compilation-heavy tool work.
- **Trusted sidecars in the sandbox pod:** under Kata they share the untrusted code's VM.
