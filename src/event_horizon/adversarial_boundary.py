"""Reproducible same-host adversarial security-boundary experiment.

This is a *process-isolated synthetic* test. It does NOT run Firecracker,
obtain host-root access, or substantiate kernel or hardware containment.
Untrusted activity consists of bounded, inert capability misuse requests.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .canonical import canonical_bytes
from .intent_canonicalizer import AuthorizationDenied
from .process_harness import ProcessSeparatedHarness, ServiceUnavailable
from .protocol import ProtocolError


def _request(**overrides):
    value = {
        "request_id": "adversarial-case-1",
        "session_id": "adversarial-session",
        "agent_id": "attacker-agent",
        "operation": "object.read",
        "resource_id": "target-source",
        "executor_id": "exec-1",
        "arguments": {"offset": 0, "length": 64},
        "purpose": "synthetic adversarial safety experiment",
    }
    value.update(overrides)
    return value


def run(workdir: str | Path) -> dict:
    """Execute real seven-process harness cases and return transparent outcomes."""
    with ProcessSeparatedHarness(workdir, ttl_seconds=30.0) as harness:
        # Capture every authorized append result, including its Ed25519
        # receipt. The companion verifier runs outside the harness process.
        signed_events = []
        original_record = harness.record

        def capture_record(*args, **kwargs):
            record = original_record(*args, **kwargs)
            signed_events.append(record)
            return record

        harness.record = capture_record
        observations = {}
        request, capability, attestation = harness.request_capability(_request())
        first = harness.execute(request, capability, attestation)
        observations["valid_once"] = {
            "success": first.success, "effect_state": first.effect_state
        }

        replay = harness.execute(request, capability, attestation)
        observations["replay"] = {
            "denied": not replay.success,
            "effect_state": replay.effect_state,
            "error_class": replay.error.split(":", 1)[0] if replay.error else "",
        }

        try:
            harness.call(
                "signer",
                "issue",
                {
                    "request": _request(request_id="forged-unsigned-request"),
                    "guardian_result": {},
                    "attestation": attestation,
                },
                authorize=False,
            )
            observations["unsigned_authority"] = {"denied": False}
        except ProtocolError as exc:
            observations["unsigned_authority"] = {
                "denied": True, "code": exc.code
            }

        try:
            harness.request_capability(
                _request(request_id="out-of-policy", operation="shell.execute",
                         resource_id="host-root")
            )
            observations["out_of_policy"] = {"denied": False}
        except (AuthorizationDenied, ProtocolError):
            observations["out_of_policy"] = {"denied": True}

        probe = harness.root_probe()
        observations["executor_private_key_probe"] = {
            "no_authority_key_in_executor": not probe["private_key_material_present"],
            "no_ambient_authority_environment": (
                probe["ambient_authority_environment_hits"] == []
            ),
        }

        unavailable_request, unavailable_cap, unavailable_attestation = (
            harness.request_capability(_request(request_id="authority-outage"))
        )
        harness.stop_role("signer")
        unavailable = harness.execute(
            unavailable_request, unavailable_cap, unavailable_attestation
        )
        observations["signer_outage"] = {
            "denied": not unavailable.success,
            "effect_state": unavailable.effect_state,
        }
        harness.restart_role("signer")
        replay_after_restart = harness.execute(request, capability, attestation)
        observations["replay_after_restart"] = {
            "denied": not replay_after_restart.success
        }

        passed = (
            first.success
            and not replay.success
            and observations["unsigned_authority"]["denied"]
            and observations["out_of_policy"]["denied"]
            and observations["executor_private_key_probe"]["no_authority_key_in_executor"]
            and observations["executor_private_key_probe"]["no_ambient_authority_environment"]
            and observations["signer_outage"]["denied"]
            and observations["signer_outage"]["effect_state"] == "not-started"
            and observations["replay_after_restart"]["denied"]
        )
        for case, observed in sorted(observations.items()):
            harness.record("adversarial.observation", {
                "case": case, "result": observed,
            })
        status = harness.call("recorder", "verify", {})
        if status["valid"] is not True or status["count"] != len(signed_events):
            raise RuntimeError("adversarial recorder chain is incomplete")
        return {
            "schema": "event-horizon.adversarial-boundary-observations.v1",
            "topology": "same-host-seven-process-development",
            "scope": "synthetic bounded actions; no compromised root process",
            "hardware_isolation_tested": False,
            "etcd_backend_tested": False,
            "observable": observations,
            "pass": bool(passed),
            "evidence_path": str(harness.recorder_path),
            "signed_evidence": {
                "public_key_pem": harness.service_info["recorder"]["public_key_pem"],
                "event_count": status["count"],
                "chain_tip": status["detail"],
                "events": signed_events,
                "trust_note": (
                    "Embedded recorder key establishes internal integrity only; "
                    "pin the public key out of band to authenticate the issuer."
                ),
            },
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.workdir is None:
        with tempfile.TemporaryDirectory() as folder:
            results = run(folder)
    else:
        results = run(args.workdir)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_bytes(results) + b"\n")
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
