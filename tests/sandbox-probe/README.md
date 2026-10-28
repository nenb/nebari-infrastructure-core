# Process self-restriction probe

This directory contains the evidence probe for ADR-0021's
`process-self-restriction` capability. It reports exactly one JSON object on
stdout. Landlock and seccomp restrictions are installed in re-executed child
processes because both mechanisms are irreversible and inherited.

## Checks

The probe records:

- kernel, architecture, node, `Seccomp`, `Seccomp_filters`, and `NoNewPrivs`;
- the highest available Landlock ABI;
- positive controls and restricted filesystem writes/truncation;
- at ABI 4+, positive controls and restricted TCP connect/bind behavior, plus
  the expected lack of UDP confinement;
- two nested seccomp filters, listener descriptor transfer, user-notification
  receipt, `SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`, and a
  marker read from the injected descriptor.

A verdict passes only when Landlock is enabled at ABI 3+, all filesystem
controls and denials behave as expected, and every seccomp notification step
succeeds. TCP checks are reported at ABI 4+ but are not part of the ABI 3
minimum verdict.

## Build

The probe is its own Go module (`go.mod` in this directory), so its direct
dependency on `golang.org/x/sys` does not change the repository's `go.mod`.
Unit tests: `cd tests/sandbox-probe && go test ./...`.

Images are built from the repository root:

```bash
docker build -f tests/sandbox-probe/Dockerfile -t psr-probe:dev .

# Registry image for both cloud-node architectures:
docker buildx build --platform linux/amd64,linux/arm64 \
  -f tests/sandbox-probe/Dockerfile \
  -t REGISTRY/psr-probe:TAG --push .
```

The final image is `scratch`, contains one static binary, and runs as UID/GID
65532.

For a direct container-runtime smoke test using the same relevant settings:

```bash
docker run --rm \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev \
  -e NODE_NAME=container-runtime \
  psr-probe:dev | jq .
```

## Run on Kubernetes

`pod.yaml` is the exact restricted pod contract: non-root UID/GID 65532, all
capabilities dropped, privilege escalation disabled, read-only root,
`RuntimeDefault`, no service-account token, and only an `emptyDir` at `/tmp`.
The wrapper changes only the image, node selector, and (for the required
comparison run) the pod-level seccomp profile.

```bash
# Every node group: use that group's real identifying label.
tests/sandbox-probe/run.sh \
  --image REGISTRY/psr-probe:TAG \
  --selector eks.amazonaws.com/nodegroup=user \
  --output tests/sandbox-probe/results/eks-1.34-user-runtime-default.json

# Secondary comparison only: no pod-level seccomp profile.
tests/sandbox-probe/run.sh \
  --image REGISTRY/psr-probe:TAG \
  --selector eks.amazonaws.com/nodegroup=user \
  --seccomp unset \
  --output tests/sandbox-probe/results/eks-1.34-user-unset.json

# Pin a run to one node when sampling each node in a group.
tests/sandbox-probe/run.sh --image REGISTRY/psr-probe:TAG --node NODE_NAME
```

The wrapper requires `kubectl` and `jq`. It deletes and recreates only a pod
named `psr-probe` in the selected namespace.

For a local kind image, load the image into the kind node before running the
wrapper. When using NIC's local provider, the cluster name comes from the
local provider configuration.

## Evidence table

Store probe JSON under `results/` (node names redacted) and add one row per
node group and seccomp mode.

| Cluster | Node group | Kernel | `seccomp_mode` (RuntimeDefault / unset) | Landlock status and ABI | FS checks | Net checks | Seccomp notify path | Verdict | Notes |
|---|---|---|---|---|---|---|---|---|---|
| kind on Colima (macOS), 2026-10-15 | control-plane | 6.8.0-117-generic (arm64) | 2 / 0 | enabled, ABI 4 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `seccompDefault=false`; `results/kind-colima-*.json`, `LOCAL-RESULTS.md` |
| EKS 1.34, AL2023 standard AMI (x86_64, `m6i.large`), 2026-10-19 | user | 6.12.111-136.204.amzn2023.x86_64 | 2 / 0 | enabled, ABI 6 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `eks-results/` |
| Hetzner, hetzner-k3s Ubuntu 24.04 (x86_64), 2026-10-25 | general | 6.8.0-138-generic | 2 / 0 | enabled, ABI 4 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `results/hetzner-ubuntu-24.04-*.json` |
| EKS arm64, Bottlerocket, GPU AMIs | | | | | | | | | Not probed |
| AKS | | | | | | | | | Not probed |

Optional context checks (kubelet `seccompDefault`, node LSM list, bubblewrap,
and kind/AppArmor) are recorded in the result write-ups rather than folded
into the capability verdict. Raw output from exploratory runs of other
sandboxing options is not committed; their summaries are in the design doc
(§20.6, "Evidence from the higher levels").

## Reference consumer

`recipe/` is the executable reference consumer for `process-self-restriction`,
the example in §20.8 of the design doc ("Example: confining a command").
`recipe/confine_linux.go` is the code from the design doc, verbatim (it uses
[go-landlock](https://github.com/landlock-lsm/go-landlock) for Landlock and raw
`x/sys/unix` calls for the optional seccomp filter); `recipe/main.go` wraps it
as an agent that sets a canary secret in its environment and leaks a
descriptor, plus an unconfined control mode; `recipe/test.sh` runs each case
confined and as a control, as a non-root user, on a Linux host with Python 3.

```bash
cd tests/sandbox-probe
NIC_RECIPE_E2E=1 go test ./recipe        # Linux only; builds and runs test.sh
# or, for a VM or container without Go:
GOOS=linux go build -o recipe-test ./recipe && ./recipe/test.sh ./recipe-test
```

Results are recorded in §20.8 ("What is tested").
