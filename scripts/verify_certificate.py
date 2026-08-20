from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from event_horizon.certificate import ContainmentCertificateBuilder


MAX_CERTIFICATE_BYTES = 1_048_576
MAX_TRUSTED_KEY_BYTES = 16_384


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _bounded_read(path: Path, maximum: int) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds {maximum} byte limit")
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(f"input exceeds {maximum} byte limit")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an Event Horizon containment certificate")
    parser.add_argument("certificate", type=Path)
    parser.add_argument(
        "--trusted-key",
        type=Path,
        help="PEM public key provisioned independently of the certificate",
    )
    parser.add_argument(
        "--trusted-key-id",
        help="independently pinned Ed25519 key ID (may be combined with --trusted-key)",
    )
    args = parser.parse_args(argv)
    if args.trusted_key is None and args.trusted_key_id is None:
        print(
            "containment certificate: INVALID "
            "(external trust anchor required: use --trusted-key and/or --trusted-key-id)"
        )
        return 2
    try:
        certificate = json.loads(
            _bounded_read(args.certificate, MAX_CERTIFICATE_BYTES).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
        trusted_key = (
            _bounded_read(args.trusted_key, MAX_TRUSTED_KEY_BYTES).decode("ascii")
            if args.trusted_key is not None
            else None
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"containment certificate: INVALID ({exc})")
        return 1
    if not isinstance(certificate, dict) or not ContainmentCertificateBuilder.verify(
        certificate,
        public_key_pem=trusted_key,
        expected_key_id=args.trusted_key_id,
    ):
        print("containment certificate: INVALID (untrusted signer, signature, or envelope mismatch)")
        return 1
    print(
        "containment certificate: VERIFIED "
        f"({certificate['algorithm']}, {certificate['key_id']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
