"""Verify the signed process-harness adversarial evidence independently."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_horizon.adversarial_evidence import EvidenceVerificationError, verify_report
from event_horizon.canonical import strict_json_loads


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--pin-recorder-key", type=Path,
        help="PEM key obtained and retained by the evaluator independently",
    )
    args = parser.parse_args()
    try:
        report = strict_json_loads(args.report.read_bytes())
        pinned = (
            args.pin_recorder_key.read_text(encoding="utf-8")
            if args.pin_recorder_key is not None else None
        )
        result = verify_report(report, pinned_public_key_pem=pinned)
    except (EvidenceVerificationError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"verified": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
