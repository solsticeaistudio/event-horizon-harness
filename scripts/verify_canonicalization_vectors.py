from __future__ import annotations

import argparse
import json
import math
import subprocess
from pathlib import Path
from typing import Any

from event_horizon.canonical import canonical_bytes, digest, strict_json_loads


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTORS = (
    REPOSITORY_ROOT / "test-vectors" / "canonicalization" / "adversarial.json"
)
NODE_RUNNER = REPOSITORY_ROOT / "scripts" / "verify_canonicalization_vectors.mjs"


def _construct(specification: dict[str, Any]) -> Any:
    kind = specification["kind"]
    if kind == "literal":
        return specification["value"]
    if kind == "repeat-string":
        return specification["text"] * specification["count"]
    if kind == "array":
        return [0] * specification["count"]
    if kind == "object":
        return {f"key-{index:03d}": index for index in range(specification["count"])}
    if kind == "nested-array":
        value: Any = 0
        for _ in range(specification["levels"]):
            value = [value]
        return value
    if kind == "float":
        return float(specification["value"])
    if kind == "non-finite":
        return {
            "Infinity": math.inf,
            "-Infinity": -math.inf,
            "NaN": math.nan,
        }[specification["value"]]
    if kind == "integer":
        return int(specification["value"])
    if kind == "cycle":
        value = []
        value.append(value)
        return value
    if kind == "strict-canonical-json":
        return strict_json_loads(specification["value"], require_canonical=True)
    raise ValueError(f"unknown vector construction: {kind}")


def evaluate_vectors(path: Path = DEFAULT_VECTORS) -> dict[str, dict[str, Any]]:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    results: dict[str, dict[str, Any]] = {}
    for vector in fixture["vectors"]:
        try:
            value = _construct(vector["construction"])
            encoded = canonical_bytes(value)
            result = {
                "accepted": True,
                "canonical": encoded.decode("utf-8"),
                "digest": digest(value),
            }
        except (TypeError, ValueError):
            result = {"accepted": False, "canonical": None, "digest": None}
        expected = vector["expected"] == "ACCEPT"
        if result["accepted"] is not expected:
            raise AssertionError(
                f"Python {vector['name']} expected {vector['expected']} but observed "
                f"{'ACCEPT' if result['accepted'] else 'REJECT'}"
            )
        results[vector["name"]] = result
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Python/TypeScript canonicalization parity")
    parser.add_argument("vectors", nargs="?", type=Path, default=DEFAULT_VECTORS)
    args = parser.parse_args(argv)
    python_results = evaluate_vectors(args.vectors)
    completed = subprocess.run(
        ["node", str(NODE_RUNNER), str(args.vectors), "--json"],
        cwd=REPOSITORY_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stdout, end="")
        print(completed.stderr, end="")
        return completed.returncode
    node_results = json.loads(completed.stdout)
    fixture = json.loads(args.vectors.read_text(encoding="utf-8"))
    for vector in fixture["vectors"]:
        name = vector["name"]
        python_result = python_results[name]
        node_result = node_results[name]
        if python_result["accepted"] != node_result["accepted"]:
            raise AssertionError(f"acceptance mismatch for {name}")
        if python_result["accepted"] and vector.get("compare_encoding", True):
            if python_result["canonical"] != node_result["canonical"]:
                raise AssertionError(f"canonical representation mismatch for {name}")
            if python_result["digest"] != node_result["digest"]:
                raise AssertionError(f"canonical digest mismatch for {name}")
    print(f"canonicalization interoperability: VERIFIED ({len(python_results)} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
