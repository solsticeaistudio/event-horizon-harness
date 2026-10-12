"""Repository policy: external GitHub Actions use immutable commit SHAs.

Scans workflow YAML text, including reusable workflow references and local
actions. Fails closed on dynamic expressions in uses fields. Relative
in-repository actions are allowed; docker actions must pin a digest.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(.*?)\s*$")
SHA = re.compile(r"^[a-fA-F0-9]{40}$")
DIGEST = re.compile(r"^sha256:[a-fA-F0-9]{64}$")


def check_workflows(root: Path) -> list[str]:
    workflows = sorted(set(root.glob("*.yml")) | set(root.glob("*.yaml")))
    if not workflows:
        return [f"{root}: no workflow files found"]
    errors: list[str] = []
    for path in workflows:
        for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USES.match(raw)
            if not match:
                continue
            value = match.group(1).split(" #", 1)[0].strip().strip("'\"")
            if "$" + "{{" in value:
                errors.append(f"{path}:{i}: dynamic action reference forbidden")
                continue
            if value.startswith("./"):
                continue
            if value.startswith("docker://"):
                if "@sha256:" not in value or not DIGEST.fullmatch(value.rsplit("@", 1)[-1]):
                    errors.append(f"{path}:{i}: Docker action must use immutable SHA-256 digest")
                continue
            if "@" not in value or not SHA.fullmatch(value.rsplit("@", 1)[-1]):
                errors.append(f"{path}:{i}: external GitHub Action not pinned to full 40-character SHA")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1] / ".github/workflows")
    args = parser.parse_args()
    failures = check_workflows(args.directory)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("PASS: all workflow actions pinned to immutable full-length commits/digests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
