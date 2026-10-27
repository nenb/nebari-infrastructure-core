# 23. VM Boundary

Mechanisms for [ADR-0026](../../adr/0026-vm-boundary-capability.md). Each is a design target, not yet implemented or tested as NIC code. Probe results are in 23.7; claims marked "to be verified" have not been probed.

## 23.1 Where it runs

| Provider | Mechanism | Status |
|---|---|---|
| AWS, nested virtualisation | Managed node group with a custom launch template setting `CpuOptions.NestedVirtualization=enabled` on a supported family; Kata installed at boot | Observed (23.7): 7th- and 8th-generation Intel families from `.large` (166 types in us-east-1, listed by `describe-instance-types` filtered on `processor-info.supported-features=nested-virtualization`); `/dev/kvm` on the AL2023 EKS node; Kata 4.2.0 runs. Other regions and performance against bare metal to be verified |
| AWS, bare metal | A `.metal` family; Kata installed at boot | Fallback; no launch-template CPU option needed |
| AKS | Pod Sandboxing on an Azure Linux node pool; Azure's runtime class | To be verified against NIC's AKS module |
| Hetzner Cloud | None (no nested virtualisation) | Unsupported; a cloud VM per sandbox outside Kubernetes is the alternative |
| `existing`, kind | Operator's runtime | Verification only, as in ADR-0023 |

## 23.2 AWS installation

Follows ADR-0023's boot sequence (§20, "Boot-step dependency order"), with these differences:

1. Before installing, the boot step checks that `/dev/kvm` exists and is usable; if not, the node labels itself `"false"` with reason `no-kvm`.
2. NIC's artifact contains the Kata runtime and shim (`containerd-shim-kata-v2`), the guest kernel and guest image, and the VMM, with a per-file list, verified as ADR-0023's is.
3. The containerd handler `kata` uses `runtime_type = "io.containerd.kata.v2"`, with the Kata configuration in the release directory.
4. The node check runs a test pod sandbox through the CRI with handler `kata` and checks that `uname -r` inside differs from the host's, that the guest sees a hypervisor (the CPU's hypervisor flag), that it runs as root inside, and that it can write to an `emptyDir`.
5. NIC creates the level's `RuntimeClass` itself, with a node selector and a toleration for the dedicated taint; the class kata-deploy creates (`kata-qemu-runtime-rs`, overhead 320Mi/250m) has a node selector but no toleration for a custom taint.

The launch template's CPU option, the instance family and the Kata, VMM and guest-kernel versions are part of the generation spec (ADR-0024), so changing any of them is a rollout.

## 23.3 AKS

NIC's AKS module creates a node pool with Pod Sandboxing enabled (the node pool's workload runtime, on Azure Linux; field names to be verified) and NIC publishes Azure's runtime class name, as in ADR-0023's verification-only mode for the class itself. NIC still labels the pool, runs the node and deploy checks, and applies ADR-0025's profile, which on AKS requires the Cilium dataplane (#691).

## 23.4 Memory, start time and storage

- **Overhead.** An idle VM costs about 255–285 MiB of host memory, and a container holding 512 MiB raised its VM to about 780 MiB. Kata's overhead is charged on the host, not given to the guest: at a 1 GiB limit the guest saw about 947 MiB and an allocating process was killed after 880 MiB (runc 1,008 MiB, gVisor 1,056 MiB with its 64 MiB overhead). Packs size limits for the guest they need, and the published overhead covers the host's share.
- **Start time.** About 5.8 s from create to Ready against about 4.3 s for gVisor and runc (image cached, three runs each); per-session designs may need pre-started pools, which are the pack's concern.
- **Volumes.** File-system volumes reach the guest through Kata's shared file system (virtio-fs); block volumes can be passed as devices. An EBS gp3 workspace worked for a root sandbox (23.7); `fsGroup` ownership and FSx for OpenZFS and Azure disks are to be verified.

## 23.5 Verification checklist

Per instance family, node image and Kata release:

- `/dev/kvm` present and the node check passing on fresh and autoscaled nodes, including scale-from-zero;
- a node without virtualisation (wrong family) labelling itself `"false"` with `no-kvm`, and gVisor-style failure handling otherwise;
- guest kernel differing from the host's; root inside the VM; package installs, compilers and Git as root;
- ADR-0025's deploy probe under the VM runtime;
- PVC-backed workspaces on each supported storage class with real ownership;
- memory under a limit with the configured overhead, and pod start time;
- `process-self-restriction` inside the guest (observed: Landlock ABI 7, ADR-0021's probe passed) and `in-pod-namespaces` (not yet probed);
- an ADR-0024 rollout changing the Kata release.

## 23.6 Rejected alternatives

- **kata-deploy (a privileged DaemonSet installer):** the same objections as ADR-0023's option 4: a privileged in-cluster component that restarts containerd on running nodes.
- **Software-emulated VMs (QEMU without KVM):** keeps a VM boundary but is too slow for compilation-heavy tool work.
- **Trusted sidecars in the sandbox pod:** under Kata they share the untrusted code's VM.

## 23.7 Probe results

### EKS, 2026-10-27

us-east-1, EKS 1.34 deployed with NIC from `main`. Raw output in `tests/sandbox-probe/session5-results/aws/` (`t1-*`, `nested-virt-*`). Kata was installed with the kata-deploy chart for the probe only; 23.6 rejects it for NIC.

- **Nested virtualisation:** the EC2 API exposes `CpuOptions.NestedVirtualization` on `run-instances` and launch templates. A c8i-flex.large with it enabled (AL2023, kernel 6.18) had the `vmx` flag, `kvm_intel` and `/dev/kvm`; `KVM_GET_API_VERSION` returned 12 and `KVM_CREATE_VM` and `KVM_CREATE_VCPU` succeeded. The same type without it had neither. The CLI help names only 8th-generation types, but `describe-instance-types` lists 166 types across c7i, c7i-flex, m7i, m7i-flex, r7i, r7iz, c8i, c8i-flex, c8id, m8i, m8i-flex, m8id, r8i, r8i-flex, r8id, i7i, i7ie and x8i.
- **EKS node group:** an m8i-flex.large managed node group with a custom launch template (the CPU option plus NIC's security groups) joined normally; the AL2023 EKS node (kernel 6.12) had `kvm_intel` and `/dev/kvm`.
- **Kata 4.2.0** (QEMU `qemu-runtime-rs` shim only) installed in 80 s; guest kernel 6.18.35.
- **ADR-0021's probe inside Kata** (UID 65532, all capabilities dropped, read-only root, `RuntimeDefault`): Part A passed with Landlock ABI 7 and the full seccomp user-notification path, but the guest reported `seccomp_mode` 0, so the declared `RuntimeDefault` was not applied.
- **Tool-execution sandbox:** as root over SSH and SFTP with an EBS workspace, as under gVisor (§22.10); with `NET_ADMIN`, root could add routes and iptables rules inside the guest, none of which bypassed the enforced NetworkPolicy.
- **Memory and start time:** as in 23.4.
