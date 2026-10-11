#!/usr/bin/env python3
"""Owned coordinator-compromise campaign with optional OS-separated Linux UIDs.

Default (CI): five services + adversarial coordinator are different Linux
processes, SAME UID. This proves only process/RPC and cryptographic logic.
--distinct-uids: explicit root operator opt-in, roles execute as separate
UNALLOCATED fixed Linux UIDs, signer pinset is readable only by signer.
No user account creation, chmod of host resources, Docker, cloud access or
external network is performed; source is staged in a disposable public code
directory because home folders can be inaccessible to these UIDs.

This is NOT an independently witnessed agent-containment certificate.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from event_horizon.broker import CapabilityVerifier
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.component_ids import REQUIRED_GUARDIANS
from event_horizon.models import IssuedCapability
from event_horizon.isolated_authority_lab import (
    fixture_request, wrong_uid_probe, confirm_wrong_uid_rejection,
)
from scripts.capability_fixture_support import authority_context, verify_options

SCENARIOS = (
    "legitimate", "forge_guardian", "omit_guardian", "duplicate_guardian",
    "widen_request", "forge_claimed_policy", "prohibited_operation",
    "read_protected_config", "read_signer_memory",
)
UIDS = {
    **{name: 64001 + index for index, name in enumerate(sorted(REQUIRED_GUARDIANS))},
    "signer": 64010, "coordinator": 64020,
}


def _demote(uid: int):
    # Applied by child between fork and exec, before any private-key
    # creation or reading of role-only signer pin files.
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop


def _ready(proc: subprocess.Popen, expected: str) -> dict:
    import select
    selected, _, _ = select.select([proc.stdout], [], [], 8)
    if not selected:
        raise RuntimeError(f"{expected} did not complete bounded startup")
    line = proc.stdout.readline(4096)
    try:
        hello = json.loads(line)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"{expected} returned malformed startup") from exc
    if hello.get("type") != expected or hello.get("pid") != proc.pid:
        raise RuntimeError(f"{expected} readiness identity mismatched")
    return hello


def _spawn(module_env: dict[str, str], working: Path, args: list[str],
           *, uid: int | None = None, fds: tuple[int, ...] = ()):
    return subprocess.Popen(
        [sys.executable, "-u", "-m", "event_horizon.isolated_authority_lab", *args],
        cwd=working, env=module_env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, pass_fds=fds,
        preexec_fn=_demote(uid) if uid is not None else None,
    )


def _bind(path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    # Synthetic loopback-only socket; authenticated admission is done by
    # SO_PEERCRED, never the world-readable path itself.
    path.chmod(0o666)
    sock.listen(12)
    return sock


def run(*, distinct_uids: bool) -> dict:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("requires Linux AF_UNIX peer credentials")
    if distinct_uids and os.geteuid() != 0:
        raise PermissionError("--distinct-uids requires explicit root operator")
    if distinct_uids:
        for name, uid in UIDS.items():
            try:
                pwd.getpwuid(uid)
            except KeyError:
                continue
            raise PermissionError(
                f"reserved test UID {uid} ({name}) is allocated; "
                "refusing to impersonate an existing account"
            )

    reference_time = float(int(time.time()))
    with tempfile.TemporaryDirectory(prefix="ehh-signing-isolation-") as tmp:
        base = Path(tmp)
        base.chmod(0o755)
        stage = base / "stage"
        (stage / "src").mkdir(parents=True)
        shutil.copytree(
            ROOT / "src/event_horizon", stage / "src/event_horizon",
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "*.pyo", "*.pem", "*.key", ".env*",
            ),
        )
        (stage / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/capability_fixture_support.py",
                     stage / "scripts/capability_fixture_support.py")
        # Only public source is staged; no downloaded key or private fixture.
        for path in stage.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(0o644)
        service_dir = base / "sockets"
        service_dir.mkdir(mode=0o755)
        trusted_dir = base / "trusted"
        trusted_dir.mkdir(mode=0o711)
        pins_path = trusted_dir / "signer-pins.json"
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": f"{stage / 'src'}:{stage}",
            "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp",
        }
        coordinator_uid = UIDS["coordinator"] if distinct_uids else os.geteuid()
        services = []
        sockets = []
        try:
            paths: dict[str, str] = {}
            keys: dict[str, str] = {}
            role_observed: dict[str, dict] = {}
            for identity in sorted(REQUIRED_GUARDIANS):
                path = service_dir / f"{identity}.sock"
                listener = _bind(path)
                sockets.append(listener)
                arguments = [
                    "--role", "guardian", "--guardian", identity,
                    "--listener-fd", str(listener.fileno()),
                    "--coordinator-uid", str(coordinator_uid),
                    "--reference-time", str(reference_time),
                ]
                proc = _spawn(
                    env, stage, arguments, fds=(listener.fileno(),),
                    uid=UIDS[identity] if distinct_uids else None,
                )
                services.append(proc)
                hello = _ready(proc, "guardian-ready")
                if hello["identity"] != identity or (
                    distinct_uids and hello["uid"] != UIDS[identity]
                ):
                    raise AssertionError("guardian boot identity was substituted")
                keys[identity] = hello["public_key"]
                role_observed[identity] = {"pid": proc.pid, "uid": hello["uid"]}
                paths[identity] = str(path)
            pins_path.write_bytes(canonical_bytes({
                "public_keys": keys, "reference_time": reference_time,
            }))
            pins_path.chmod(0o600)
            if distinct_uids:
                os.chown(pins_path, UIDS["signer"], UIDS["signer"])
            signer_path = service_dir / "signer.sock"
            signer_listener = _bind(signer_path)
            sockets.append(signer_listener)
            signer = _spawn(
                env, stage,
                [
                    "--role", "signer", "--listener-fd", str(signer_listener.fileno()),
                    "--pins-path", str(pins_path),
                    "--coordinator-uid", str(coordinator_uid),
                    "--reference-time", str(reference_time),
                ],
                fds=(signer_listener.fileno(),),
                uid=UIDS["signer"] if distinct_uids else None,
            )
            services.append(signer)
            hello = _ready(signer, "signer-ready")
            if distinct_uids and hello["uid"] != UIDS["signer"]:
                raise AssertionError("signer UID unexpectedly changed")
            role_observed["signer"] = {"pid": signer.pid, "uid": hello["uid"]}
            signer_public = hello["public_key"]
            key_id = hello["key_id"]
            # Challenge the signer socket from the trusted supervisor's
            # *different* UID. Only the configured coordinator UID may be
            # admitted, regardless of having the pathname.
            peer_rejected = False
            if distinct_uids:
                from event_horizon.isolated_authority_lab import rpc
                peer_observation = wrong_uid_probe(lambda: rpc(str(signer_path), {
                    "method": "challenge",
                    "request": fixture_request().canonical_payload(),
                }))
            outcomes = []
            for scenario in SCENARIOS:
                coordinator = _spawn(
                    env, stage,
                    [
                        "--role", "coordinator", "--scenario", scenario,
                        "--guardian-paths", json.dumps(paths, sort_keys=True),
                        "--signer-path", str(signer_path),
                        "--signer-pid", str(signer.pid),
                        "--pins-path", str(pins_path),
                        *(["--distinct-uids"] if distinct_uids else []),
                    ],
                    uid=coordinator_uid if distinct_uids else None,
                )
                try:
                    output, stderr = coordinator.communicate(timeout=12)
                except subprocess.TimeoutExpired:
                    coordinator.kill()
                    coordinator.communicate(timeout=2)
                    raise AssertionError(f"coordinator {scenario} timed out")
                if coordinator.returncode != 0:
                    raise AssertionError(
                        f"coordinator scenario {scenario} exited {coordinator.returncode}: "
                        + stderr.decode(errors="replace")[-500:]
                    )
                statement = json.loads(output)
                if statement.get("scenario") != scenario:
                    raise AssertionError("coordinator scenario substitution")
                if distinct_uids and statement["coordinator_uid"] != coordinator_uid:
                    raise AssertionError("coordinator was not deprivileged")
                details = statement["outcome"]
                if scenario == "legitimate":
                    if not (details.get("issued") is True
                            and details.get("replay_denied") is True):
                        raise AssertionError("legitimate capability or replay control failed")
                    if distinct_uids:
                        peer_rejected = confirm_wrong_uid_rejection(
                            peer_observation, alive=signer.poll() is None,
                            authorized_succeeded=details.get("issued") is True,
                        )
                    cap = IssuedCapability.from_dict(details["capability"])
                    context = authority_context(fixture_request(), reference_time)
                    verified = CapabilityVerifier(signer_public, key_id).verify_and_consume(
                        cap, fixture_request(), **verify_options(context),
                    )
                    if verified.capability_id != cap.claims.capability_id:
                        raise AssertionError("legitimate capability signature invalid")
                    # Do not include raw capability/attestation in the report.
                    outcome = {"scenario": scenario, "status": "PASS",
                               "issued": True, "replay_denied": True,
                               "capability_sha256": digest(cap.to_dict())}
                elif scenario in ("read_protected_config", "read_signer_memory"):
                    if distinct_uids and not details.get("denied"):
                        raise AssertionError("separate UID failed credential isolation")
                    outcome = {
                        "scenario": scenario,
                        "status": "PASS" if distinct_uids else "NOT-ASSESSED",
                        "os_access_denied": bool(details.get("denied")),
                    }
                else:
                    if details.get("denied") is not True:
                        raise AssertionError(f"coordinator attack {scenario} obtained authority")
                    outcome = {"scenario": scenario, "status": "PASS",
                               "issuer_denied": True}
                outcomes.append(outcome)
            if distinct_uids:
                names = [role["uid"] for role in role_observed.values()]
                if len(set(names + [coordinator_uid])) != len(names) + 1:
                    raise AssertionError("OS role UIDs are not distinct")
            return {
                "schema": "event-horizon.coordinator-compromise-lab.v1",
                "status": "PASS",
                "run_mode": "separate-linux-uids" if distinct_uids else "same-uid-processes",
                "os_identity_isolation_tested": distinct_uids,
                "wrong_uid_socket_admission_rejected": peer_rejected if distinct_uids else None,
                "actual_processes": len(services) + len(SCENARIOS),
                "roles": role_observed,
                "coordinator_uid": coordinator_uid,
                "public_key_id": key_id,
                "tests": outcomes,
                "limitations": (
                    "owned synthetic attestations and pinned signer contract; "
                    "no guest agent, no Firecracker, no external witness; "
                    "same-UID mode does not establish OS privilege isolation"
                ),
            }
        finally:
            for proc in services:
                if proc.poll() is None:
                    proc.terminate()
            for proc in services:
                try:
                    proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)
            for sock in sockets:
                sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distinct-uids", action="store_true",
                        help="explicit root-only Linux isolation trial; never sudo automatically")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(distinct_uids=args.distinct_uids)
    # In root mode only the caller selects destination; never emit a private
    # signing key, credential, or raw approval in the report.
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_bytes(canonical_bytes(report))
    print(f"PASS: {len(SCENARIOS)} coordinator compromise controls; "
          f"mode={report['run_mode']}; OS identity tested={report['os_identity_isolation_tested']}")


if __name__ == "__main__":
    main()
