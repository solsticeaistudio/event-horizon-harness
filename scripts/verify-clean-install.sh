#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/event-horizon-clean.XXXXXX")"
CHECKOUT="$TEMPORARY_ROOT/repository"
VIRTUAL_ENVIRONMENT="$TEMPORARY_ROOT/venv"

cleanup() {
  case "$TEMPORARY_ROOT" in
    "${TMPDIR:-/tmp}"/event-horizon-clean.*) rm -rf -- "$TEMPORARY_ROOT" ;;
    *) echo "refusing to remove unexpected temporary path: $TEMPORARY_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT

git clone --quiet --no-local "$REPOSITORY_ROOT" "$CHECKOUT"
cd "$CHECKOUT"
npm ci
python -m venv "$VIRTUAL_ENVIRONMENT"
export PATH="$VIRTUAL_ENVIRONMENT/bin:$PATH"
python -m pip install --disable-pip-version-check -e ".[test]"
npm run build
npm test
npm run demo
python scripts/verify_capability_vectors.py
python scripts/verify_certificate.py examples/reference-run/containment-certificate.json --trusted-key examples/reference-run/certificate-signer-public.pem
python scripts/check_repository_policy.py
