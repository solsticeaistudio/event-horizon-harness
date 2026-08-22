from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .certificate import ContainmentCertificateBuilder
from .intent_canonicalizer import AuthorizationDenied
from .models import ActionRequest
from .process_harness import ProcessSeparatedHarness
from .recorder import ExternalRecorder, RecorderIntegrityError


SUMMARY_LABELS = (
    ("initial_local_access", "Initial local access:", "ASSUMED"),
    ("executor_attestation", "Executor attestation:", "VERIFIED (SIMULATOR)"),
    ("permitted_exact_operation", "Permitted exact operation:", "SUCCESS"),
    ("capability_replay", "Capability replay:", "DENIED"),
    ("argument_widening", "Argument widening:", "DENIED"),
    ("cross_executor_transfer", "Cross-executor transfer:", "DENIED"),
    ("unauthorized_network_operation", "Unauthorized network operation:", "DENIED"),
    ("evidence_tampering", "Evidence tampering:", "DETECTED"),
    ("containment_certificate", "Containment certificate:", "VERIFIED"),
)


def request_payload(request_id: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": request_id,
        "session_id": "public-demo-session",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"length": 64, "offset": 0},
        "purpose": "public synthetic containment demonstration",
    }
    payload.update(overrides)
    return payload


def _tamper_copy(source: Path, destination: Path) -> bool:
    shutil.copyfile(source, destination)
    content = bytearray(destination.read_bytes())
    marker = b'"event_type":"'
    position = content.find(marker)
    if position < 0:
        return False
    target = position + len(marker)
    content[target] = ord("X") if content[target] != ord("X") else ord("Y")
    destination.write_bytes(content)
    try:
        ExternalRecorder(destination, b"tamper-verification-view-only-key")
    except RecorderIntegrityError:
        return True
    return False


def run_demo(workdir: Path, artifacts_dir: Path) -> dict[str, Any]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    harness = ProcessSeparatedHarness(workdir, ttl_seconds=5.0).start()
    try:
        trusted_certificate_signer = harness.service_info["certificate"]
        trusted_key_path = artifacts_dir / "latest-certificate-signer-public.pem"
        trusted_key_path.write_text(
            trusted_certificate_signer["public_key_pem"],
            encoding="ascii",
        )
        root_probe = harness.root_probe()

        exact_request, exact_capability, exact_attestation = harness.request_capability(
            request_payload("public-demo-exact")
        )
        attestation_verified = (
            exact_attestation.get("valid") is True
            and exact_attestation.get("method") == "simulator"
            and exact_attestation.get("trustLevel") == "simulated"
            and exact_attestation.get("nonceContext", {}).get("sessionId") == exact_request.session_id
        )
        exact_result = harness.execute(exact_request, exact_capability, exact_attestation)
        replay_result = harness.execute(exact_request, exact_capability, exact_attestation)

        argument_request, argument_capability, argument_attestation = harness.request_capability(
            request_payload("public-demo-arguments")
        )
        widened_request = ActionRequest.from_dict({
            **argument_request.canonical_payload(),
            "arguments": {"length": 65, "offset": 0},
        })
        widened_result = harness.execute(widened_request, argument_capability, argument_attestation)

        transfer_request, transfer_capability, transfer_attestation = harness.request_capability(
            request_payload("public-demo-transfer")
        )
        other_executor = ActionRequest.from_dict({
            **transfer_request.canonical_payload(),
            "executor_id": "exec-2",
        })
        transfer_result = harness.execute(other_executor, transfer_capability, transfer_attestation)

        network_denied = False
        try:
            harness.request_capability(request_payload(
                "public-demo-network",
                operation="http.request",
                resource_id="internet",
                arguments={},
            ))
        except AuthorizationDenied:
            network_denied = True

        tampered_copy = workdir / "tampered-local-evidence.jsonl"
        tampering_detected = _tamper_copy(harness.recorder_path, tampered_copy)
        harness.record(
            "evidence.tamper-attempt",
            {"target": "local-evidence-copy", "detected": tampering_detected},
            source_id="public-demo",
        )
        recorder_status = harness.call("recorder", "verify", {})
        teardown = harness.teardown_executor()
        certificate = harness.build_certificate()
        payload = certificate["certificate"]
        certificate_status = payload.get("status")
        claims = payload.get("claims", {})
        # Evidence-completeness gates containment; an unevaluated
        # effect-mediation claim simply keeps assurance below mediated level.
        evidence_claims = {
            key: value for key, value in claims.items()
            if not (key == "effect_mediation_consistent" and value == "unknown")
        }
        containment_proven = (
            certificate_status in {"complete", "conflicted"}
            and all(value == "satisfied" for value in evidence_claims.values())
        )
        certificate_path = artifacts_dir / "latest-containment-certificate.json"
        certificate_path.write_text(json.dumps(certificate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        reloaded = json.loads(certificate_path.read_text(encoding="utf-8"))
        certificate_verified = ContainmentCertificateBuilder.verify(
            reloaded,
            public_key_pem=trusted_certificate_signer["public_key_pem"],
            expected_key_id=trusted_certificate_signer["key_id"],
        )

        results = {
            "initial_local_access": True,
            "executor_attestation": attestation_verified,
            "permitted_exact_operation": exact_result.success,
            "capability_replay": not replay_result.success,
            "argument_widening": not widened_result.success,
            "cross_executor_transfer": not transfer_result.success,
            "unauthorized_network_operation": network_denied,
            "evidence_tampering": tampering_detected,
            "containment_certificate": bool(certificate_verified and containment_proven),
        }
        summary = {
            "schema": "event-horizon.public-demo-result.v0.5",
            "mode": "process-separated synthetic harness",
            "results": results,
            "simulator_is_hardware_attestation": False,
            "certificate_status": certificate_status,
            "certificate_claims": claims,
            "teardown_verified": teardown["verified"],
            "certificate": str(certificate_path),
            "trusted_certificate_key": str(trusted_key_path),
            "certificate_key_id": certificate["key_id"],
            "event_chain_tip": recorder_status["detail"],
            "root_probe": root_probe,
        }
        (artifacts_dir / "latest-summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return summary
    finally:
        harness.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Event Horizon public containment demonstration")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--artifacts-dir", type=Path, default=Path(".demo"))
    args = parser.parse_args(argv)

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.workdir is None:
        temporary = tempfile.TemporaryDirectory(prefix="event-horizon-public-demo-")
        workdir = Path(temporary.name)
    else:
        workdir = args.workdir
    try:
        summary = run_demo(workdir, args.artifacts_dir)
    finally:
        if temporary is not None:
            temporary.cleanup()

    print("Executor Attestation simulator verification is development-only and is not hardware-backed attestation.\n")
    for key, label, success_value in SUMMARY_LABELS:
        value = success_value if summary["results"][key] else "FAILED"
        print(f"{label:<34} {value}")
    print(f"\nCertificate: {summary['certificate']}")
    print(f"Trusted signer key: {summary['trusted_certificate_key']}")
    print(
        "Verify with: python scripts/verify_certificate.py "
        ".demo/latest-containment-certificate.json "
        "--trusted-key .demo/latest-certificate-signer-public.pem"
    )
    return 0 if all(summary["results"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
