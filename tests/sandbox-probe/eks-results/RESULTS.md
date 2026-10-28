# EKS probe results (Parts A, B, C) — 2026-10-19

Cluster deployed with NIC (with a placeholder repository, which stops the deploy after
infrastructure), destroyed with `nic destroy` afterwards. us-east-1, Kubernetes 1.34, two `m6i.large`
node groups (`user`: untouched, Parts A and B; `sandbox`: gVisor installed, Part C).

## Node facts

| Fact | Value |
|---|---|
| OS image (`nodeInfo.osImage`) | `Amazon Linux 2023.12.20261012` |
| Kernel | `6.12.111-136.204.amzn2023.x86_64` |
| Container runtime | containerd 2.3.5, config `version = 3`, no drop-in imports |
| Kubelet `seccompDefault` (configz) | `false` |
| Active LSMs | `lockdown,capability,landlock,yama,safesetid,selinux,bpf,ima` (no AppArmor) |
| SELinux | permissive |
| `user.max_user_namespaces` | 30811 |
| `status.runtimeHandlers` | reported: `""`, `runc` (features `recursiveReadOnlyMounts`, `userNamespaces`); `runsc` appears after gVisor install |
| IMDS | IMDSv2 required, hop limit 1 on NIC's launch templates; unreachable from pods (runc and gVisor) |
| NetworkPolicy | not enforced by default (`--enable-network-policy=false`) |

## Part A (`process-self-restriction` probe)

`pass` under both `RuntimeDefault` (seccomp mode 2) and no profile (mode 0): Landlock enabled at **ABI 6**,
filesystem write and truncate denials with controls, TCP connect/bind denials with controls, UDP unaffected,
full seccomp user-notification path including `SECCOMP_ADDFD_FLAG_SEND`. Raw: `partA-eks134-*.json` (node name redacted).

## Part B (bubblewrap in a non-root pod)

Pod: non-root UID 1000, all capabilities dropped, `allowPrivilegeEscalation: false`, seccomp unset.

- Capability test passes, including bubblewrap's own `--unshare-net`.
- **Bug found:** the qualified configurations failed on x86 (`execvp sh: No such file or directory`) because
  the dynamic loader is in `/lib64`; adding `--symlink usr/lib64 /lib64` fixes it.
- With the fix: work dir writable; env, home, Secret and service-account-token canaries hidden; agent socket
  unreachable; no network (DNS, IP, IMDS fail; only `lo`); proxy socket works.
- Signalling: possible without a pid namespace; `--unshare-pid` with the container's `/proc` works on runc and
  prevents it. A fresh procfs fails (`Can't mount proc ... Operation not permitted`).
- Negative control with `RuntimeDefault`: `bwrap: No permissions to create new namespace, likely because the
  kernel does not allow non-privileged user namespaces.` (misleading: the cause is seccomp).

Raw output for Parts B and C is not committed; this summary is the record.

## Part C (gVisor, test-only install)

Test-only install by a privileged DaemonSet: gVisor `release-20261012.0` ships as
`gvisor.tar.bz2`; `runsc` needs its `gvisor-bin/` helpers (including `gvisor_sentry`) installed beside it.
Runtime handler added to containerd's v3 config under
`plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc`, `runtime_type = "io.containerd.runsc.v1"`.

- Bubblewrap: `--unshare-net` fails (gVisor #13438 still present); with the network namespace created first by
  `unshare`, all qualified-configuration checks pass as in Part B; `--unshare-pid --proc /proc` works (only
  sandbox PIDs visible, agent not signallable).
- `RuntimeDefault` is ignored (`Seccomp: 0`); Landlock returns `ENOSYS`.
- Secret and ConfigMap updates reach gVisor pods (about 45 s vs about 18 s for runc in this run).
- NetworkPolicy (after enabling it in the VPC CNI add-on): default-deny egress blocks gVisor and runc pods
  alike; an allow rule for one destination restores only that destination.
- **EFS:** with NIC's `efs-sc` (access points with their own UID 50000+ and mode 700), the home directory is
  **not writable** from a gVisor pod (gVisor checks permissions itself), while runc works. A storage class
  whose access points use the pod's UID (`uid: "1000"`, `gid: "1000"`) works under both.

Timings (median of 3, seconds; same node):

| Task | local runc | local gVisor | EFS runc | EFS gVisor |
|---|---|---|---|---|
| JupyterLab startup | 1.61 | 2.39 | 1.61 | 2.34 |
| Kernel start + cell | 0.96 | 1.11 | 1.12 | 1.32 |
| venv + `pip install` pandas, requests, rich | 10.3 | 14.3 | 132 | 192 |
| `import pandas` | 0.27 | 0.48 | 0.86 | 0.93 |
| `git clone` / `git status` | 0.04 / 0.02 | 0.18 / 0.04 | 3.2 / 0.23 | 4.9 / 0.26 |
| 5,000 small files | 0.24 | 1.03 | 85 | 155 |
| 256 MB write + read | 2.05 | 2.04 | 3.8 | 2.7 |


## Not tested

Cluster-autoscaler scale-from-zero with gVisor, node bootstrap install, GPUs (`nvproxy`), arm64 nodes,
Hetzner, AKS.
