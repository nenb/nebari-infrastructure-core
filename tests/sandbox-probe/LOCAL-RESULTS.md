# Local probe results

Date: 2026-10-15

These are local-development observations, not evidence for any managed cloud
provider. The cluster was created by NIC from `examples/local-config.yaml` on
macOS using Colima's Linux VM and the bundled kind provider.

## Environment

- Cluster: kind v1.36.1, one control-plane node
- Node image: Debian 13 (`kindest/node:v1.36.1`)
- Host/guest kernel visible to pods: `6.8.0-117-generic` (`arm64`)
- Active VM security modules: `lockdown,capability,landlock,yama,apparmor`
- kind node-container security options: `seccomp=unconfined`,
  `apparmor=unconfined`, `label=disable`
- Kubelet `seccompDefault`: `false`

## Probe results

| Seccomp setting | Observed mode / filter count | Landlock | Filesystem | TCP/UDP | Seccomp notification | Verdict |
|---|---|---|---|---|---|---|
| `RuntimeDefault` | `2 / 1` | enabled, ABI 4 | controls pass; denied write and truncate return `EACCES` | controls and allowed connect pass; denied connect and bind return `EACCES`; UDP succeeds and is received | both filters, listener transfer, notification, `ADDFD|SEND`, and marker read pass | pass |
| omitted | `0 / 0` | enabled, ABI 4 | same | same | same | pass |

Raw results:

- `results/kind-colima-runtime-default.json`
- `results/kind-colima-unset.json`

A separate direct-Docker smoke test under the equivalent user, capability,
no-new-privileges, read-only-root, and seccomp settings produced the same
results before the Kubernetes run.

## Optional context checks

An ordinary busybox pod had AppArmor attribute `unconfined`. This confirms the
kind node container and an ordinary pod were both AppArmor-unconfined in this
specific Colima environment; it does not establish behavior on a native Linux
kind host.

Bubblewrap 0.8.0 was tested in a pod with no seccomp profile, non-root UID/GID
65532, all capabilities dropped, and privilege escalation disabled:

- The requested reduced command with `--unshare-user --unshare-net` failed
  while configuring loopback: `Failed RTM_NEWADDR: Operation not permitted`.
- Removing `--unshare-net` still failed while setting the UID map:
  `Permission denied`.
- The node reported `kernel.apparmor_restrict_unprivileged_userns = 1` and
  `user.max_user_namespaces = 7657`.
- The fresh-`/proc` variant also failed, but at the earlier network/UID-map
  stage, so this run did not independently reach and test the masked-`/proc`
  failure.

This is a local surprise worth retaining: an AppArmor-unconfined kind node
container did not make bubblewrap's reduced mode work when the underlying
Linux VM retained its AppArmor unprivileged-user-namespace restriction.

## ADR/design-doc claims

1. **EKS kernel lines:** not tested locally.
2. **Landlock active on AL2023 and Ubuntu 24.04 provider nodes:** provider
   claims not tested. Landlock was active at ABI 4 on the local Linux 6.8 VM.
3. **AKS OS/kernel transition:** not tested locally.
4. **Landlock and nested seccomp notification under `RuntimeDefault`:**
   confirmed for this kind/Colima environment, including descriptor injection
   with `SECCOMP_ADDFD_FLAG_SEND`.
5. **No-profile pods have no filter and `seccompDefault` is off:** confirmed
   for this kind cluster (`Seccomp: 0`, `Seccomp_filters: 0`,
   `seccompDefault=false`); EKS, Hetzner, and AKS remain untested.
6. **Provider-specific bubblewrap predictions:** not tested. The reduced mode
   failed locally for the reasons above.
7. **kind/AppArmor behavior:** kind's node container and the sampled ordinary
   pod were both AppArmor-unconfined here. Native Linux hosts remain untested.
