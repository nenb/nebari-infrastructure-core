# Process self-restriction probe

This directory contains the evidence probe for ADR-0021's
`process-self-restriction` capability, and its qualified consumer: a
configuration is qualified when this probe passes on it. It reports exactly
one JSON object on stdout. Landlock and seccomp restrictions are installed in
re-executed child processes because both mechanisms are irreversible and
inherited.

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

## Verdicts and exit status

`verdicts` holds separate results, each computed from the raw fields alone:

| Verdict | Passes when |
|---|---|
| `landlock_fs` | Landlock is enabled at ABI 3+, the filesystem check ran without error, its positive controls succeeded, and the denied write and truncation failed with `EACCES` |
| `landlock_tcp` | At ABI 4+, where the qualification record advertises TCP confinement: the network check ran without error, its positive controls succeeded, the allowed `connect` succeeded, and the forbidden `connect` and `bind` failed with `EACCES`. A forbidden operation that succeeded, a check error or a check that never ran fails it. `not_applicable` below ABI 4 |
| `seccomp_user_notification` | Every step of the notification path succeeded. This is the separate, reserved capability |
| `process_self_restriction` | `landlock_fs` passes and `landlock_tcp` does not fail. It does not depend on seccomp notification |

Run with no flags, the probe is the qualification command: it exits 1 if a
property being qualified did not pass. `--qualify` names the properties
(default `process-self-restriction`; also `seccomp-user-notification`,
comma-separated). `--diagnostic` prints the same JSON and always exits 0; it is
**not** a qualification gate. On a non-Linux system every verdict fails.

`--rederive` reads a recorded result on stdin and recomputes its verdicts from
the raw fields, recording the probe version that did so in
`verdicts_derived_by`. The committed results were taken with probe 0.1.0,
whose single `capability_verdict` also required seccomp notification; their
verdicts were recomputed this way by probe 0.2.0, deterministically and with no
rerun. Their raw fields are unchanged.

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
  psr-probe:dev | jq .verdicts
```

## Run on Kubernetes

`pod.yaml` is the exact restricted pod contract: non-root UID/GID 65532, all
capabilities dropped, privilege escalation disabled, read-only root,
`RuntimeDefault`, no service-account token, and only an `emptyDir` at `/tmp`.
The wrapper changes only the image, node selector, probe arguments
(`--qualify`, `--diagnostic`) and (for the comparison run) the pod-level
seccomp profile. The pod ends `Failed` when qualification fails; the wrapper
still saves the result and then exits 1.

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

| Cluster | Node group | Kernel | `seccomp_mode` (RuntimeDefault / unset) | Landlock status and ABI | `landlock_fs` | `landlock_tcp` | `seccomp_user_notification` | `process_self_restriction` | Notes |
|---|---|---|---|---|---|---|---|---|---|
| kind on Colima (macOS), 2026-10-15 | control-plane | 6.8.0-117-generic (arm64) | 2 / 0 | enabled, ABI 4 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `seccompDefault=false`; `results/kind-colima-*.json`, `LOCAL-RESULTS.md`; local observation, not a qualification |
| EKS 1.34, AL2023 standard AMI (x86_64, `m6i.large`), 2026-10-19 | user | 6.12.111-136.204.amzn2023.x86_64 | 2 / 0 | enabled, ABI 6 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `eks-results/` |
| Hetzner, hetzner-k3s Ubuntu 24.04 (x86_64), 2026-10-25 | general | 6.8.0-138-generic | 2 / 0 | enabled, ABI 4 | pass / pass | pass / pass; UDP remained usable | pass / pass | pass / pass | `results/hetzner-ubuntu-24.04-*.json` |
| EKS arm64, Bottlerocket, GPU AMIs | | | | | | | | | Not probed |
| AKS | | | | | | | | | Not probed |

Verdicts in this table were recomputed from the recorded raw fields
(`--rederive`, see above). Optional context checks (kubelet `seccompDefault`,
node LSM list, bubblewrap, and kind/AppArmor) are recorded in the result
write-ups rather than folded into a verdict. Raw output from exploratory runs of other
sandboxing options is not committed; their summaries are in the design doc
(§20.6, "Evidence from the higher levels").

## Requalification

This is the procedure for the qualification record in §20.8 of the design doc.

1. **When.** Before recording a new configuration, and whenever a node leaves
   an entry's extrapolation range: a different image variant or architecture,
   a new kernel line, a new container runtime minor version, a changed default
   seccomp profile or a changed boot-time LSM list. Within the range (same
   image variant and architecture, kernel line and runtime minor version) an
   entry still holds; anything outside it is unknown until probed.
2. **Where.** A fresh node of that configuration in a cluster deployed with
   NIC, one run per node group, using the group's own selector.
3. **How.** Build the image for the node's architecture, then run
   `run.sh --selector ...` with `RuntimeDefault` (the default) and, as a
   comparison, `--seccomp unset`. Both must exit 0 for
   `process-self-restriction`; add `--qualify
   process-self-restriction,seccomp-user-notification` only when qualifying the
   reserved capability.
4. **Record.** Commit the JSON (node names redacted) under `results/`, add a
   row to the evidence table above, and update the qualification record in
   §20.8 and ADR-0021 with the image release, kernel, container runtime,
   probe version, ABI, date and extrapolation range.

A failed run is not recorded as a qualification; the configuration stays
unknown, or becomes unsupported when the kernel line is known to be below
ABI 3.

## Reference launcher

`recipe/` is a reference consumer of `process-self-restriction`, tested on
local VMs and containers and in CI, awaiting provider qualification; it is the
example in §20.8 of the design doc ("Example: confining a command").
`recipe/confine_linux.go` is the code from the design doc, verbatim (it uses
[go-landlock](https://github.com/landlock-lsm/go-landlock) for Landlock and raw
`x/sys/unix` calls for the optional seccomp filter); `recipe/main.go` wraps it
as an agent that sets a canary secret in its environment and leaks a
descriptor, plus an unconfined control mode; `recipe/test.sh` runs each case
confined and as a control, as a non-root user, on a Linux host with Python 3.
Rows report `PASS`, `LIMIT` (reachable as documented for that ABI: a known
gap, not confinement), `SKIP` (already denied outside the sandbox, so the
launcher's own denial cannot be shown) or `FAIL`. `recipe/confine_linux_test.go`
has the unit tests, including a helper run with a simulated older ABI that
must refuse before executing anything.

```bash
cd tests/sandbox-probe
go test ./...                            # unit tests; the end-to-end test skips
NIC_RECIPE_E2E=1 go test -v ./recipe     # Linux only; builds and runs test.sh
# or, for a VM or container without Go:
GOOS=linux go build -o recipe-test ./recipe && ./recipe/test.sh ./recipe-test
```

Below Landlock ABI 3 only the refusal rows run; `test.sh` exits 3 and the Go
test reports a skip, never a pass. CI runs the unit and end-to-end tests on
`ubuntu-24.04` (job "Sandbox probe" in `.github/workflows/ci.yml`). Results
are recorded in §20.8 ("What is tested").
