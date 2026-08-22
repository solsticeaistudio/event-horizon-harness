#!/usr/bin/env python3
"""Generate a build provenance manifest for an Event Horizon build.

Binds source commit, trust architecture version, dependency lock digests, and
test-suite entry points into one signed-off (hash-chained) JSON artifact. This
is a lightweight provenance record — not a claim of full SLSA compliance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_SCHEMA = "event-horizon.build-provenance.v1"
TRUST_ARCHITECTURE_VERSION = "0.6"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        value = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        value = "unavailable"
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=REPOSITORY_ROOT / "artifacts" / "build-provenance.json",
    )
    parser.add_argument("--python-tests", default="tests (unittest discover)")
    parser.add_argument("--typescript-tests", default="attestation/tests/*.test.mjs")
    args = parser.parse_args(argv)

    lock_path = REPOSITORY_ROOT / "package-lock.json"
    pyproject = REPOSITORY_ROOT / "pyproject.toml"
    manifest = {
        "schema": PROVENANCE_SCHEMA,
        "trust_architecture_version": TRUST_ARCHITECTURE_VERSION,
        "source_commit": _git_commit(),
        "dependency_locks": {
            "npm_lock_sha256": _sha256_file(lock_path) if lock_path.exists() else None,
            "pyproject_sha256": _sha256_file(pyproject) if pyproject.exists() else None,
        },
        "test_entry_points": {
            "python": args.python_tests,
            "typescript": args.typescript_tests,
            "canonicalization_vectors": "scripts/verify_canonicalization_vectors.py",
            "remote_replay_interop": "scripts/verify_remote_replay_interop.py",
        },
        "notes": [
            "Lightweight provenance record; not SLSA-compliant attestation.",
            "Dependency hashes cover the lock manifests, not vendored artifacts.",
        ],
    }
    payload = {
        key: value
        for key, value in manifest.items()
        if key != "signature"
    }
    manifest["manifest_digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"build provenance: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
