"""Independent verifier for signed *software-only* distributed EHH evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_horizon.distributed_signed_evidence import (
    DistributedEvidenceError, verify_distributed_report,
)
from event_horizon.protocol import _object_without_duplicates, _reject_constant


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--pin-recorder-key", type=Path)
    args = parser.parse_args()
    try:
        record = json.loads(
            args.report.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
        json.dumps(record, allow_nan=False)
        pinned = args.pin_recorder_key.read_text(encoding="utf-8") if args.pin_recorder_key else None
        result = verify_distributed_report(record, pinned_recorder_public_key=pinned)
    except (OSError, ValueError, TypeError, KeyError, DistributedEvidenceError) as exc:
        print(json.dumps({"verified": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
