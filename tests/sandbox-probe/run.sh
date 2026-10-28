#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image="psr-probe:dev"
namespace="default"
seccomp="runtime-default"
output=""
timeout="2m"
selectors='{}'
probe_args='[]'

usage() {
  cat <<'EOF'
Usage: run.sh [options]

Options:
  --image IMAGE             Probe image (default: psr-probe:dev)
  --namespace NAMESPACE     Kubernetes namespace (default: default)
  --selector KEY=VALUE      Node selector; repeat for multiple labels
  --node NODE               Select one node by kubernetes.io/hostname
  --seccomp MODE            runtime-default or unset (default: runtime-default)
  --output FILE             Save the raw JSON result
  --timeout DURATION        Time to wait for the probe, e.g. 90s or 2m (default: 2m)
  --qualify LIST            Properties to qualify (default: process-self-restriction;
                            also seccomp-user-notification). Exit status is
                            non-zero if any of them fails.
  --diagnostic              Diagnostic run, NOT a qualification gate: save and
                            print the result, exit 0 whatever the verdicts
  -h, --help                Show this help
EOF
}

while (($#)); do
  case "$1" in
    --image) image=${2:?missing image}; shift 2 ;;
    --namespace) namespace=${2:?missing namespace}; shift 2 ;;
    --selector)
      selector=${2:?missing selector}
      key=${selector%%=*}
      value=${selector#*=}
      if [[ "$key" == "$selector" || -z "$key" || -z "$value" ]]; then
        echo "invalid selector: $selector (want KEY=VALUE)" >&2
        exit 2
      fi
      selectors=$(jq -c --arg key "$key" --arg value "$value" '. + {($key): $value}' <<<"$selectors")
      shift 2
      ;;
    --node)
      selectors=$(jq -c --arg value "${2:?missing node}" '. + {"kubernetes.io/hostname": $value}' <<<"$selectors")
      shift 2
      ;;
    --seccomp) seccomp=${2:?missing seccomp mode}; shift 2 ;;
    --output) output=${2:?missing output file}; shift 2 ;;
    --timeout) timeout=${2:?missing timeout}; shift 2 ;;
    --qualify)
      probe_args=$(jq -c --arg value "${2:?missing properties}" '. + ["--qualify", $value]' <<<"$probe_args")
      shift 2
      ;;
    --diagnostic) probe_args=$(jq -c '. + ["--diagnostic"]' <<<"$probe_args"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$seccomp" != "runtime-default" && "$seccomp" != "unset" ]]; then
  echo "--seccomp must be runtime-default or unset" >&2
  exit 2
fi
for command in kubectl jq; do
  if ! command -v "$command" >/dev/null; then
    echo "$command is required" >&2
    exit 1
  fi
done

kubectl delete pod psr-probe --namespace "$namespace" --ignore-not-found --wait=true >/dev/null
pod=$(kubectl create --dry-run=client -f "$script_dir/pod.yaml" -o json)
pod=$(jq -c --arg image "$image" --argjson selectors "$selectors" --argjson args "$probe_args" \
  '.spec.containers[0].image = $image | .spec.nodeSelector = $selectors | .spec.containers[0].args = $args' <<<"$pod")
if [[ "$seccomp" == "unset" ]]; then
  pod=$(jq -c 'del(.spec.securityContext.seccompProfile)' <<<"$pod")
fi
kubectl apply --namespace "$namespace" -f - <<<"$pod" >/dev/null

case "$timeout" in
  *m) wait_seconds=$(( ${timeout%m} * 60 )) ;;
  *s) wait_seconds=${timeout%s} ;;
  *) wait_seconds=$timeout ;;
esac
if [[ ! "$wait_seconds" =~ ^[0-9]+$ ]]; then
  echo "invalid --timeout: $timeout (want e.g. 90s or 2m)" >&2
  exit 2
fi
# The probe exits non-zero when a qualified property fails, so the pod ends in
# Failed as well as Succeeded; both carry a result.
phase=""
for (( waited = 0; waited < wait_seconds; waited += 2 )); do
  phase=$(kubectl get pod psr-probe --namespace "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [[ "$phase" == Succeeded || "$phase" == Failed ]] && break
  sleep 2
done
if [[ "$phase" != Succeeded && "$phase" != Failed ]]; then
  echo "probe did not finish (phase: ${phase:-unknown})" >&2
  kubectl logs psr-probe --namespace "$namespace" >&2 || true
  kubectl describe pod psr-probe --namespace "$namespace" >&2 || true
  exit 1
fi

result=$(kubectl logs psr-probe --namespace "$namespace")
if ! jq -e 'type == "object" and has("verdicts")' >/dev/null <<<"$result"; then
  echo "probe output is not a result object: $result" >&2
  exit 1
fi
if [[ -n "$output" ]]; then
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$result" >"$output"
fi
printf '%s\n' "$result"
if [[ "$phase" == Failed ]]; then
  echo "qualification failed: $(jq -c .verdicts <<<"$result")" >&2
  exit 1
fi
