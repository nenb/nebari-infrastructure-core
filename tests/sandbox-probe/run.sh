#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image="psr-probe:dev"
namespace="default"
seccomp="runtime-default"
output=""
timeout="2m"
selectors='{}'

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
  --timeout DURATION        kubectl wait timeout (default: 2m)
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
pod=$(jq -c --arg image "$image" --argjson selectors "$selectors" \
  '.spec.containers[0].image = $image | .spec.nodeSelector = $selectors' <<<"$pod")
if [[ "$seccomp" == "unset" ]]; then
  pod=$(jq -c 'del(.spec.securityContext.seccompProfile)' <<<"$pod")
fi
kubectl apply --namespace "$namespace" -f - <<<"$pod" >/dev/null

if ! kubectl wait --namespace "$namespace" \
  --for=jsonpath='{.status.phase}'=Succeeded \
  "pod/psr-probe" --timeout="$timeout" >/dev/null; then
  phase=$(kubectl get pod psr-probe --namespace "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  echo "probe did not succeed (phase: ${phase:-unknown})" >&2
  kubectl logs psr-probe --namespace "$namespace" >&2 || true
  kubectl describe pod psr-probe --namespace "$namespace" >&2 || true
  exit 1
fi

result=$(kubectl logs psr-probe --namespace "$namespace")
if ! jq -e 'type == "object" and has("capability_verdict")' >/dev/null <<<"$result"; then
  echo "probe output is not a result object: $result" >&2
  exit 1
fi
if [[ -n "$output" ]]; then
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$result" >"$output"
fi
printf '%s\n' "$result"
