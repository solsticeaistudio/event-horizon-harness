"""Process-isolated signer/guardian compromise experiment (owned synthetic lab).

Launch via scripts/run_isolated_authority_lab.py. Each guardian generates its
private key AFTER its own process starts; the capability signer generates
its signing key independently, and consumes one-use challenge-bound approvals.
All external communication is canonical framed Unix-socket RPC. A root-launched
--distinct-uids run additionally enforces separate Linux UIDs, admits only the
coordinator UID through SO_PEERCRED, and isolates signer pin configuration.

This is a lab, not a production agent authority daemon: attestation is a
synthetic fixture, only one static read request can succeed, no TPM, no remote
deployment, and no claim of isolation for ordinary same-UID CI.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .broker import CapabilityBroker
from .canonical import canonical_bytes
from .component_ids import (
    EXECUTOR_ATTESTATION_GUARDIAN, REQUIRED_GUARDIANS,
    STATIC_POLICY_GUARDIAN,
)
from .models import ActionRequest, GuardianDecision
from .policy import OperationRule, StaticPolicy
from .protocol import ProtocolError, encode_frame, read_frame
from .signed_guardian_authority import (
    GuardianAuthorityError, GuardianSigningKey,
    PinnedGuardianCapabilityIssuer, PinnedGuardianVerifier,
    SignedGuardianApproval,
)
from scripts.capability_fixture_support import authority_context

MAX_REQUESTS = 80
MAX_RPC_SECONDS = 4
MAX_LINE_BYTES = 65_536


def fixture_request() -> ActionRequest:
    return ActionRequest(
        "isolated-auth-read", "isolated-auth-session", "attacker-agent",
        "object.read", "synthetic-dataset", "exec-1",
        {"offset": 0, "length": 5}, "owned signer-compromise experiment",
    )


def fixture_policy() -> StaticPolicy:
    action = fixture_request()
    return StaticPolicy(
        "fixture-policy-v1",
        operations={"object.read": OperationRule(
            frozenset({"synthetic-dataset"}), frozenset({"offset", "length"}), 4096,
        )},
        allowed_agents=frozenset({action.agent_id}),
        allowed_executors=frozenset({action.executor_id}),
    )


def response(payload: dict) -> dict:
    return {"ok": True, "result": payload}


def rpc(path: str, payload: dict) -> dict:
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("invalid owned RPC socket path")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(MAX_RPC_SECONDS)
        channel.connect(path)
        channel.sendall(encode_frame(payload))
        with channel.makefile("rb") as stream:
            answer = read_frame(stream)
    if set(answer) != {"ok", "result"} or not isinstance(answer["result"], dict):
        raise ValueError("invalid trusted RPC response")
    return answer


def wrong_uid_probe(call):
    """Only a known wrong-UID probe may classify an early disconnect.

    The caller MUST subsequently require process liveness and a successful
    authorized request via confirm_wrong_uid_rejection. No timeout/EOF or
    arbitrary transport error is swallowed.
    """
    try:
        answer = call()
    except (BrokenPipeError, ConnectionResetError):
        return "early-peer-disconnect"
    if answer != {"ok": False, "result": {"error": "denied"}}:
        raise RuntimeError("wrong UID was not explicitly rejected")
    return "structured-denial"


def confirm_wrong_uid_rejection(observation, *, alive, authorized_succeeded):
    if (observation not in {"early-peer-disconnect", "structured-denial"}
            or alive is not True or authorized_succeeded is not True):
        raise RuntimeError("peer rejection lacks subsequent healthy authorized control")
    return True


def serve(listener_fd: int, coordinator_uid: int, callback) -> None:
    """Bounded one-request sockets; SO_PEERCRED checked at connection time."""
    listener = socket.socket(fileno=listener_fd)
    listener.settimeout(0.5)
    served = 0
    while served < MAX_REQUESTS:
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        served += 1
        with conn:
            conn.settimeout(MAX_RPC_SECONDS)
            try:
                _pid, uid, _gid = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                )
                if uid != coordinator_uid:
                    raise PermissionError("client UID not authorized for authority RPC")
                with conn.makefile("rb") as source:
                    message = read_frame(source)
                if not isinstance(message, dict):
                    raise ValueError("authority request not an object")
                result = callback(message)
                conn.sendall(encode_frame(response(result)))
            except (ValueError, TypeError, KeyError, PermissionError,
                    ProtocolError, OSError, OverflowError):
                try:
                    conn.sendall(encode_frame({"ok": False, "result": {"error": "denied"}}))
                except OSError:
                    pass


def guardian_decision(identity: str, request: ActionRequest, reference_time: float) -> GuardianDecision:
    policy = fixture_policy()
    if identity == STATIC_POLICY_GUARDIAN:
        return policy.evaluate(request)
    if request.canonical_payload() != fixture_request().canonical_payload():
        return GuardianDecision(identity, False, "request outside owned fixture", request_digest=request.request_digest)
    if not policy.evaluate(request).allowed:
        return GuardianDecision(identity, False, "static fixture policy veto", request_digest=request.request_digest)
    if identity == EXECUTOR_ATTESTATION_GUARDIAN:
        context = authority_context(request, reference_time)
        return GuardianDecision(
            identity, True, "independent synthetic executor fixture",
            {
                "device_id": request.executor_id,
                "measurement": context["executor_measurement"],
                "provider_trust_state": context["trust_state"].to_dict(),
                "attestation_result": context["attestation"],
            },
            request.request_digest,
        )
    return GuardianDecision(
        identity, True, "owned static bounded fixture approval",
        request_digest=request.request_digest,
    )


def guardian_main(arguments) -> None:
    session = None
    if arguments.session_config:
        from .session_authority import SessionAuthority
        session = SessionAuthority(json.loads(Path(arguments.session_config).read_text()))
    signer = GuardianSigningKey(
        arguments.guardian, Ed25519PrivateKey.generate(),
    )
    print(json.dumps({
        "type": "guardian-ready", "identity": arguments.guardian,
        "public_key": signer.public_key_pem, "pid": os.getpid(),
        "uid": os.geteuid(),
    }), flush=True)

    def handle(message: dict) -> dict:
        if set(message) != {"method", "request", "challenge"} or message["method"] != "evaluate":
            raise ValueError("unsupported guardian method")
        request = ActionRequest.from_dict(message["request"])
        vote = signer.approve(
            (session.evaluate(signer.identity, request) if session else
             guardian_decision(signer.identity, request, arguments.reference_time)),
            challenge=message["challenge"],
            policy_digest=(session.policy if session else fixture_policy()).policy_digest,
        )
        if session:
            print(json.dumps({"audit": "guardian", "approval": vote.to_dict()}), flush=True)
        return vote.to_dict()

    serve(arguments.listener_fd, arguments.coordinator_uid, handle)


def signer_main(arguments) -> None:
    # Root-installed pinset file: only signer UID can read in the distinct-UID
    # experiment; no guardian or coordinator key is generated in supervisor.
    configuration = json.loads(Path(arguments.pins_path).read_text())
    if set(configuration) != {"public_keys", "reference_time"}:
        raise ValueError("signer config schema invalid")
    if configuration["reference_time"] != arguments.reference_time:
        raise ValueError("signer fixture clock was altered")
    session = None
    if arguments.session_config:
        from .session_authority import SessionAuthority
        session = SessionAuthority(json.loads(Path(arguments.session_config).read_text()))
    verifier = PinnedGuardianVerifier(configuration["public_keys"])
    broker = CapabilityBroker(ttl_seconds=60)
    issuer = PinnedGuardianCapabilityIssuer(
        broker=broker, static_policy=session.policy if session else fixture_policy(), verifier=verifier,
        challenge_ttl_seconds=2.0 if session else 15.0,
    )
    print(json.dumps({
        "type": "signer-ready", "public_key": broker.public_key_pem,
        "key_id": broker.key_id, "pid": os.getpid(), "uid": os.geteuid(),
    }), flush=True)

    issued_count = 0

    def handle(message: dict) -> dict:
        nonlocal issued_count
        kind = message.get("method")
        if kind == "challenge":
            if set(message) != {"method", "request"}:
                raise ValueError("unknown signer challenge fields")
            request = ActionRequest.from_dict(message["request"])
            return {"challenge": issuer.new_challenge(request)}
        if kind != "issue" or set(message) != {"method", "request", "challenge", "approvals"}:
            raise ValueError("unsupported signer method")
        request = ActionRequest.from_dict(message["request"])
        raw_approvals = message["approvals"]
        if not isinstance(raw_approvals, list) or len(raw_approvals) > 8:
            raise ValueError("invalid guardian approval count")
        approvals = []
        for item in raw_approvals:
            if not isinstance(item, dict) or set(item) != {"payload", "signature"}:
                raise ValueError("malformed signed approval")
            approvals.append(SignedGuardianApproval(item["payload"], item["signature"]))
        # Crucial: compiled ceiling and fixture policy originate inside the
        # signer, not from coordinator RPC input.
        context = session.context if session else authority_context(fixture_request(), arguments.reference_time)
        expected = session.request if session else fixture_request()
        if request.canonical_payload() != expected.canonical_payload():
            raise GuardianAuthorityError("only exact approved fixture request is issuable")
        if session and issued_count >= 2:
            raise GuardianAuthorityError("session issuance budget exhausted")
        issued = issuer.issue(
            request, message["challenge"], approvals,
            context["compiled_ceiling"],
        )
        issued_count += 1
        return {"capability": issued.to_dict(), "attestation": context["attestation"]}

    def audited(message):
        from .canonical import digest
        try:
            result = handle(message)
        except (ValueError, TypeError, KeyError, PermissionError) as exc:
            if session:
                print(json.dumps({"audit": "signer", "message_digest": digest(message),
                                  "accepted": False, "error_class": type(exc).__name__}), flush=True)
            raise
        if session:
            print(json.dumps({"audit": "signer", "message_digest": digest(message),
                              "accepted": True, "result_digest": digest(result)}), flush=True)
        return result

    serve(arguments.listener_fd, arguments.coordinator_uid, audited)


def _challenge(signer: str, request: ActionRequest) -> str:
    reply = rpc(signer, {"method": "challenge", "request": request.canonical_payload()})
    if reply["ok"] is not True:
        raise RuntimeError("trusted signer denied the challenge")
    return reply["result"]["challenge"]


def _votes(sockets: dict[str, str], request: ActionRequest, challenge: str) -> list[dict]:
    results = []
    for identity in sorted(REQUIRED_GUARDIANS):
        answer = rpc(sockets[identity], {
            "method": "evaluate", "request": request.canonical_payload(),
            "challenge": challenge,
        })
        if answer["ok"] is not True:
            raise RuntimeError("required guardian service failed")
        results.append(answer["result"])
    return results


def attack(scenario: str, signer: str, guardians: dict[str, str],
           *, signer_config: str, signer_pid: int, distinct_uids: bool) -> dict:
    """Run from the deliberately untrusted coordinator child."""
    request = fixture_request()
    if scenario == "read_protected_config":
        denied = False
        try:
            with open(signer_config, "rb") as file:
                file.read(1)
        except (OSError, PermissionError):
            denied = True
        return {"denied": denied, "kind": "os-credential-protection"}
    if scenario == "read_signer_memory":
        denied = False
        try:
            with open(f"/proc/{signer_pid}/mem", "rb") as file:
                file.read(1)
        except (OSError, PermissionError):
            denied = True
        return {"denied": denied, "kind": "os-process-protection"}
    if scenario == "prohibited_operation":
        request = ActionRequest(
            "isolated-auth-read", "isolated-auth-session", "attacker-agent",
            "network.connect", "internet", "exec-1", {},
            "owned signer-compromise experiment",
        )
    challenge = _challenge(signer, request)
    approvals = _votes(guardians, request, challenge)
    if scenario == "forge_guardian":
        approvals[0]["signature"] = "A" * 86
    elif scenario == "omit_guardian":
        approvals.pop()
    elif scenario == "duplicate_guardian":
        approvals[1] = copy.deepcopy(approvals[0])
    elif scenario == "widen_request":
        request = ActionRequest(
            "isolated-auth-read", "isolated-auth-session", "attacker-agent",
            "object.read", "synthetic-dataset", "exec-1",
            {"offset": 0, "length": 12}, "owned signer-compromise experiment",
        )
    elif scenario == "forge_claimed_policy":
        approvals[0]["payload"]["allowed"] = True
        approvals[0]["payload"]["policy_digest"] = "0" * 64
    message = {
        "method": "issue", "request": request.canonical_payload(),
        "challenge": challenge, "approvals": approvals,
    }
    first = rpc(signer, message)
    if scenario == "legitimate":
        second = rpc(signer, message)
        return {
            "issued": first["ok"] is True,
            "replay_denied": second["ok"] is False,
            "capability": first["result"].get("capability") if first["ok"] else None,
            "attestation": first["result"].get("attestation") if first["ok"] else None,
        }
    return {"denied": first["ok"] is False, "kind": "signer-denied"}


def coordinator_main(arguments) -> None:
    paths = json.loads(arguments.guardian_paths)
    outcome = attack(
        arguments.scenario, arguments.signer_path, paths,
        signer_config=arguments.pins_path,
        signer_pid=arguments.signer_pid,
        distinct_uids=arguments.distinct_uids,
    )
    print(json.dumps({
        "scenario": arguments.scenario,
        "coordinator_pid": os.getpid(),
        "coordinator_uid": os.geteuid(),
        "outcome": outcome,
    }), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("guardian", "signer", "coordinator"), required=True)
    parser.add_argument("--listener-fd", type=int)
    parser.add_argument("--coordinator-uid", type=int)
    parser.add_argument("--guardian")
    parser.add_argument("--pins-path")
    parser.add_argument("--session-config")
    parser.add_argument("--reference-time", type=float)
    parser.add_argument("--scenario")
    parser.add_argument("--guardian-paths")
    parser.add_argument("--signer-path")
    parser.add_argument("--signer-pid", type=int)
    parser.add_argument("--distinct-uids", action="store_true")
    arguments = parser.parse_args()
    if arguments.role == "guardian":
        if arguments.guardian not in REQUIRED_GUARDIANS:
            parser.error("unknown guardian")
        guardian_main(arguments)
    elif arguments.role == "signer":
        signer_main(arguments)
    else:
        coordinator_main(arguments)


if __name__ == "__main__":
    main()
