#!/usr/bin/env bash
# Owned EHH package-compromise lab: disposable three-node etcd + real KVM.
# Requires an existing prepared Ubuntu 24.04 x86_64/KVM setup.
# Invoke as an ordinary operator with Docker access; sudo is used only
# by the existing Firecracker runner. Never point this at production etcd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${EHH_ISOLATION_PYTHON:-/var/tmp/event-horizon-isolation-venv/bin/python}"
IMAGE="${EHH_LAB_ETCD_IMAGE:-quay.io/coreos/etcd:v3.6.0}"
ADAPTIVE_STEPS=0
ISOLATED_AUTHORITY=0
EFFECT_CRASH=0
BRIDGED_AUTHORITY=0
BRIDGED_RECIPIENT=0
if [[ "${1:-}" == "--isolated-authority" && $# == 1 ]]; then
  ISOLATED_AUTHORITY=1
  shift
fi
if [[ "${1:-}" == "--bridged-authority" && $# == 1 ]]; then
  BRIDGED_AUTHORITY=1
  shift
fi
if [[ "${1:-}" == "--bridged-recipient" && $# == 1 ]]; then
  BRIDGED_RECIPIENT=1
  shift
fi
if [[ "${1:-}" == "--effect-crash" && $# == 1 ]]; then
  EFFECT_CRASH=1
  shift
fi
if (( $# > 2 )); then
  echo "Usage: bash scripts/run_package_etcd_lab.sh [--isolated-authority | --bridged-authority | --bridged-recipient | --effect-crash | --adaptive-steps 1..4]" >&2
  exit 2
fi
if (( $# > 0 )); then
  if [[ "$1" != "--adaptive-steps" || $# -ne 2 || ! "$2" =~ ^[1-4]$ ]]; then
    echo "Only --adaptive-steps 1..4 is supported" >&2
    exit 2
  fi
  ADAPTIVE_STEPS="$2"
fi

for tool in docker git sudo python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing required command: $tool" >&2; exit 1; }
done
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "Requires an owned Linux x86_64 host" >&2
  exit 1
fi
if [[ ! -x "$PY" ]]; then
  echo "Missing prepared isolation Python: $PY; follow docs/LINUX_ISOLATION.md" >&2
  exit 1
fi
if (( EFFECT_CRASH == 0 )) && [[ ! -e /dev/kvm ]]; then
  echo "/dev/kvm is missing; KVM must be configured before this lab" >&2
  exit 1
fi
if (( EFFECT_CRASH == 0 )) && [[ ! -f firecracker/build/isolation/manifest.json ]]; then
  echo "Missing verified Firecracker build; run python3 scripts/prepare_linux_isolation.py first" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not accessible. Start Docker or enable your Docker Desktop WSL integration." >&2
  exit 1
fi
if [[ "$ADAPTIVE_STEPS" != 0 ]]; then
  if [[ -z "${EH_ADVERSARY_BASE_URL:-}" || -z "${EH_ADVERSARY_MODEL:-}" ]]; then
    echo "Adaptive mode requires EH_ADVERSARY_BASE_URL and EH_ADVERSARY_MODEL in operator environment" >&2
    exit 2
  fi
fi

# Never attach our ephemeral lab to an unrelated service. We do not stop
# existing services, change Docker daemon settings or install software.
python3 - <<'PY'
import socket
for port in (2379, 3379, 4379):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise SystemExit(f"TCP 127.0.0.1:{port} is occupied: {exc}; no changes made")
print("PASS: dedicated etcd loopback ports are available")
PY

TAG="$(date -u +%Y%m%d%H%M%S)-$$"
NETWORK="ehh-owned-pkg-$TAG"
declare -a CONTAINERS=()
CREATED_NETWORK=0
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  for id in "${CONTAINERS[@]}"; do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  if (( CREATED_NETWORK )); then
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
  fi
  if (( result != 0 )); then
    echo "Lab exited with an error; any partial report remains labeled INCOMPLETE." >&2
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker network create "$NETWORK" >/dev/null
CREATED_NETWORK=1
CLUSTER=""
for i in 1 2 3; do
  name="$NETWORK-$i"
  if [[ -n "$CLUSTER" ]]; then CLUSTER+=","; fi
  CLUSTER+="$name=http://$name:2380"
done

for i in 1 2 3; do
  port=$(( 1379 + 1000 * i ))
  name="$NETWORK-$i"
  id="$(docker run --rm -d --name "$name" --network "$NETWORK" \
    -p "127.0.0.1:${port}:2379" \
    "$IMAGE" /usr/local/bin/etcd \
    --name "$name" --data-dir /etcd-data \
    --listen-client-urls http://0.0.0.0:2379 \
    --advertise-client-urls "http://$name:2379" \
    --listen-peer-urls http://0.0.0.0:2380 \
    --initial-advertise-peer-urls "http://$name:2380" \
    --initial-cluster "$CLUSTER" --initial-cluster-state new \
    --initial-cluster-token "$NETWORK")"
  CONTAINERS+=("$id")
done

# The ID comes from the actual running cluster's linearizable API.
# Require all three endpoints to agree; do not use a fixture constant.
CLUSTER_ID="$("$PY" - <<'PY'
import time
from tests.test_etcd_live import cluster_id
addresses = [
    "http://127.0.0.1:2379",
    "http://127.0.0.1:3379",
    "http://127.0.0.1:4379",
]
for retry in range(90):
    try:
        ids = [cluster_id(address) for address in addresses]
        if len(set(ids)) == 1 and ids[0].isdecimal() and int(ids[0]) > 0:
            print(ids[0])
            break
    except Exception:
        pass
    time.sleep(1)
else:
    raise SystemExit("disposable three-node etcd cluster did not become healthy")
PY
)"
echo "PASS: three disposable etcd nodes agree on cluster $CLUSTER_ID"

mkdir -p artifacts/reports
RUN_NAME="package-etcd-$(date -u +%Y%m%dT%H%M%SZ)-$$"
if (( ADAPTIVE_STEPS > 0 )); then RUN_NAME+="-adaptive"; fi
if (( ISOLATED_AUTHORITY > 0 )); then RUN_NAME+="-isolated-authority"; fi
if (( BRIDGED_AUTHORITY > 0 )); then RUN_NAME+="-bridged-authority"; fi
if (( BRIDGED_RECIPIENT > 0 )); then RUN_NAME+="-bridged-recipient"; fi
if (( EFFECT_CRASH > 0 )); then RUN_NAME="effect-crash-$(date -u +%Y%m%dT%H%M%SZ)-$"; fi
REPORT="artifacts/reports/${RUN_NAME}.json"
echo "Source revision: $(git rev-parse HEAD)"
echo "Report: $REPORT"

# Never preserve arbitrary environment variables or credentials under sudo.
# Crash campaign deliberately exercises host processes, not Firecracker/KVM.
if (( EFFECT_CRASH > 0 )); then
  "$PY" scripts/run_effect_crash_campaign.py \
    --backend etcd --etcd-endpoint http://127.0.0.1:2379 \
    --etcd-cluster-id "$CLUSTER_ID" --report "$REPORT"
elif (( BRIDGED_RECIPIENT > 0 )); then
  sudo "$PY" scripts/run_integrated_authority.py --bridged-recipient \
    --etcd-endpoint http://127.0.0.1:2379 --etcd-cluster-id "$CLUSTER_ID" \
    --etcd-containers "${CONTAINERS[@]}" --report "$REPORT"
elif (( BRIDGED_AUTHORITY > 0 )); then
  sudo "$PY" scripts/run_integrated_authority.py --bridged-gateway \
    --etcd-endpoint http://127.0.0.1:2379 --etcd-cluster-id "$CLUSTER_ID" \
    --etcd-containers "${CONTAINERS[@]}" --report "$REPORT"
elif (( ISOLATED_AUTHORITY > 0 )); then
  sudo "$PY" scripts/run_integrated_authority.py \
    --etcd-endpoint http://127.0.0.1:2379 --etcd-cluster-id "$CLUSTER_ID" \
    --etcd-containers "${CONTAINERS[@]}" --report "$REPORT"
elif (( ADAPTIVE_STEPS > 0 )); then
  sudo --preserve-env=EH_ADVERSARY_BASE_URL,EH_ADVERSARY_MODEL,EH_ADVERSARY_API_KEY \
    "$PY" scripts/run_package_isolation.py \
    --etcd-endpoint http://127.0.0.1:2379 \
    --etcd-cluster-id "$CLUSTER_ID" --adaptive-steps "$ADAPTIVE_STEPS" \
    --report "$REPORT"
else
  sudo "$PY" scripts/run_package_isolation.py \
    --etcd-endpoint http://127.0.0.1:2379 \
    --etcd-cluster-id "$CLUSTER_ID" --report "$REPORT"
fi
if (( EFFECT_CRASH > 0 )); then
  "$PY" scripts/verify_effect_crash_campaign.py "$REPORT"
else
  "$PY" scripts/verify_package_isolation.py "$REPORT"
fi
(
  cd "$(dirname "$REPORT")"
  if (( ISOLATED_AUTHORITY == 0 && BRIDGED_AUTHORITY == 0 && BRIDGED_RECIPIENT == 0 && EFFECT_CRASH == 0 )); then
    sha256sum "$(basename "$REPORT")" > "$(basename "$REPORT").sha256"
  fi
  sha256sum -c "$(basename "$REPORT").sha256"
)
echo "PASS: original report preserved at $REPORT"
echo "Checksum: $REPORT.sha256"
echo "DO NOT edit the JSON; publication and independent provenance verification are separate steps."
if (( EFFECT_CRASH > 0 )); then
  echo "IMPORTANT: real gateway SIGKILL and etcd only; Firecracker/KVM and independent witness NOT exercised."
fi
