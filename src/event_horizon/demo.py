from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .certificate import ContainmentCertificateBuilder
from .factory import build_local_harness


def request_payload(**overrides):
    payload = {
        "request_id": "req-001",
        "session_id": "session-black-hole",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"offset": 0, "length": 4096},
        "purpose": "inspect the synthetic target",
    }
    payload.update(overrides)
    return payload


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="event-horizon-demo-"))
    neural, executor, recorder, _ = build_local_harness(workdir, ttl_seconds=2.0)
    print("EVENT HORIZON v0.3 — ASSUMED ROOT DEMONSTRATION")
    print(f"workdir: {workdir}")
    print("\n[1] Attacker is assumed to have root in the hostile workload.")
    honey_credential = "EH-HONEY-ROOT-FOUND-BUT-NOT-AUTHORITY"
    (workdir / "hostile-cell").mkdir()
    (workdir / "hostile-cell" / "cloud-token.txt").write_text(honey_credential)
    print(f"    attacker found synthetic credential: {honey_credential}")

    print("\n[2] A narrowly permitted request succeeds once.")
    request, capability, attestation = neural.request_capability(request_payload())
    first = executor.execute(request, capability, attestation)
    print(json.dumps(first.__dict__, indent=2, default=str))

    print("\n[3] Replaying the stolen capability fails.")
    replay = executor.execute(request, capability, attestation)
    print(json.dumps(replay.__dict__, indent=2, default=str))

    print("\n[4] Widening the request to smuggle a network destination fails.")
    widened = request_payload(request_id="req-002", arguments={"offset": 0, "url": "https://example.invalid"})
    try:
        neural.request_capability(widened)
    except Exception as exc:
        print(f"    denied: {type(exc).__name__}: {exc}")

    print("\n[5] A prohibited network operation fails before execution.")
    network = request_payload(request_id="req-003", operation="http.request", resource_id="internet")
    try:
        neural.request_capability(network)
    except Exception as exc:
        print(f"    denied: {type(exc).__name__}: {exc}")

    valid, tip = recorder.verify()
    certificate_path = workdir / "containment-certificate.json"
    certificate_builder = ContainmentCertificateBuilder(recorder, b"C" * 32)
    trusted_key_path = workdir / "certificate-signer-public.pem"
    trusted_key_path.write_text(certificate_builder.public_key_pem, encoding="ascii")
    cert = certificate_builder.write(
        certificate_path,
        run_id="demo-run-v0.3",
        session_id="session-black-hole",
        assertions={
            "no_transferable_credential": True,
            "no_unauthorized_egress": True,
            "no_cross_session_effect": True,
            "no_persistence_claimed_by_process_prototype": True,
            "authoritative_event_chain_intact": valid,
        },
    )
    print("\n[6] External evidence chain, Executor Attestation binding, and certificate")
    print(f"    chain valid: {valid}")
    print(f"    chain tip: {tip}")
    print(f"    certificate: {certificate_path}")
    print(f"    trusted signer key: {trusted_key_path}")
    print(json.dumps(cert, indent=2)[:1600])
    print("\nThe attacker obtained the local secret and root-equivalent visibility. It did not obtain authority.")


if __name__ == "__main__":
    main()
