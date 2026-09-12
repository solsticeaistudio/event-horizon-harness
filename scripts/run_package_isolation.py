"""Paired owned package-service compromise experiment using the real KVM lab."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from event_horizon.approved_artifact import ApprovedArtifact  # noqa: E402
from event_horizon.broker import CapabilityBroker  # noqa: E402
from event_horizon.effect_boundary import DatasetEffectBoundary  # noqa: E402
from event_horizon.protocol import encode_frame, read_frame  # noqa: E402
from scripts.run_firecracker_demo import sha256_file, write_durable_json  # noqa: E402
from scripts.run_linux_isolation import (  # noqa: E402
    EFFECT_UID, checked_assets, guest_effect, preflight, remove_run_file, run_round,
)

CONTENT = '{"name":"owned-example","version":"1.0.0","data":[12,23,34]}\n'
ARTIFACT = ApprovedArtifact(CONTENT, "e12c07a3e0fa3eafbf53932e37d46db5f4612b8bce19adafd1f08137ebcf08ca")
MARKER = "owned-package-marker"
FAKE_CREDENTIAL = "credential:owned-fixture-only-not-a-real-secret"
EFFECTS = ("relay", "credential_reuse", "cross_session_message", "durable_shared_state", "fixture_evidence_tamper")


class GateReceiver:
    """Private descriptor authenticates this one launched service, not its claims.

    Runs in the trusted supervisor. The service has only the request/reply end,
    not recorder access, signing keys, database paths, or policy setters.
    """

    def __init__(self, channel, recorder, config, target_thread=None):
        self.channel, self.recorder, self.config = channel, recorder, config
        self.receipts = []
        self.failure = None
        self.target_thread = target_thread

    def append(self, event_type, payload):
        event = self.recorder.append(event_type, payload, source_id="host-effect-service")
        self.receipts.append(event["receipt"])
        return event

    def run(self):
        gate = None
        try:
            if self.target_thread is not None:
                self.target_thread.start()
            gate = DatasetEffectBoundary(self.config, self)
            with self.channel, self.channel.makefile("rb") as stream:
                for _ in range(24):
                    message = read_frame(stream)
                    response = gate.execute(message, peer_uid=EFFECT_UID)
                    self.channel.sendall(encode_frame(response))
        except EOFError:
            pass
        except Exception as exc:
            self.failure = exc
        finally:
            if gate is not None:
                gate.close()


class PackageLab:
    artifact = ARTIFACT

    def __init__(self, mode: str, binary: Path, worker_build: dict):
        if mode not in {"vulnerable", "protected"}:
            raise ValueError("unknown package lab mode")
        self.mode, self.binary = mode, binary
        self.worker_build = worker_build
        self.target_events = []
        self.target_failure = None
        self.stop = threading.Event()
        self.started = time.monotonic()

    def context(self):
        return {"mode": self.mode, "worker_build": self.worker_build, "artifact_sha256": self.artifact.sha256,
                "fixture_authority": "service-owned" if self.mode == "vulnerable" else "root-only",
                "network": "empty namespace; synthetic Unix target only"}

    def prepare(self, run, control, state, config):
        self.control = control
        self.root = run / "package-root"
        self.root.mkdir(mode=0o755)
        shutil.copyfile(self.binary, self.root / "worker")
        (self.root / "worker").chmod(0o555)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        os.chown(self.scratch, EFFECT_UID, EFFECT_UID)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir(mode=0o700)
        for name, value in (("fake-credential", FAKE_CREDENTIAL), ("evidence-canary", "untampered")):
            path = self.fixtures / name
            path.write_text(value)
            path.chmod(0o600)
        # The paired control changes only reachable fixture authority, not code.
        if self.mode == "vulnerable":
            os.chown(self.fixtures, EFFECT_UID, EFFECT_UID)
            for path in self.fixtures.iterdir():
                os.chown(path, EFFECT_UID, EFFECT_UID)
        self.target = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.target.bind(str(self.fixtures / "target.sock"))
        self.target.listen(2)
        self.target.settimeout(0.1)
        if self.mode == "vulnerable":
            os.chown(self.fixtures / "target.sock", EFFECT_UID, EFFECT_UID)
        (self.fixtures / "target.sock").chmod(0o600)
        # In this experiment the package service is explicitly NOT the gate.
        os.chown(state, 0, 0)
        os.chown(state / "config.json", 0, 0)
        config["vm_uid"] = EFFECT_UID

    def target_loop(self):
        try:
            while not self.stop.is_set():
                try:
                    client, _ = self.target.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(1)
                    payload = bytearray()
                    while len(payload) <= 128:
                        chunk = client.recv(129 - len(payload))
                        if not chunk:
                            break
                        payload.extend(chunk)
                    kind = {b"relay": "relay", FAKE_CREDENTIAL.encode(): "credential_reuse"}.get(bytes(payload))
                    if kind is not None:
                        event = {"kind": kind, "elapsed_ms": (time.monotonic() - self.started) * 1000}
                        self.target_events.append(event)
                        # Authoritative target receipt; never supplied by the worker.
                        with (self.control / "target-effects.jsonl").open("a") as output:
                            output.write(json.dumps(event, sort_keys=True) + "\n")
                            output.flush()
                            os.fsync(output.fileno())
                    client.sendall(b"1")
        except Exception as exc:
            self.target_failure = exc

    def receiver(self, observer, recorder, config):
        self.target_thread = threading.Thread(target=self.target_loop, daemon=True)
        # Start only after the service has been forked (see command/observe).
        self.gate_receiver = GateReceiver(observer, recorder, config, self.target_thread)
        return self.gate_receiver

    def command(self, listener_fd, gate_fd):
        # No inherited target/control descriptors. Popen closes all other fds.
        # The target is started by the gate thread, after Popen's preexec hook.
        return ["unshare", "--net", "--", "setpriv", "--no-new-privs", "--",
                "chroot", f"--userspec={EFFECT_UID}:{EFFECT_UID}", "--groups=", str(self.root),
                "/worker", str(listener_fd), str(gate_fd)]

    def observe(self, service, channel, response, message):
        self.artifact.accept(response)
        poison = guest_effect(channel, {"attack": "substitute-output"})
        if poison.get("success") is not True:
            raise RuntimeError("service output-substitution positive control did not run")
        try:
            self.artifact.accept(poison)
        except ValueError:
            pass
        else:
            raise RuntimeError("trusted recipient accepted substituted output")
        status = Path(f"/proc/{service.pid}/status").read_text()
        for required in (f"Uid:\t{EFFECT_UID}\t{EFFECT_UID}\t{EFFECT_UID}\t{EFFECT_UID}",
                         "CapEff:\t0000000000000000", "CapPrm:\t0000000000000000", "NoNewPrivs:\t1"):
            if required not in status:
                raise RuntimeError("compromised service retained host privilege")
        actual, expected = os.stat(f"/proc/{service.pid}/root"), self.root.stat()
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("package service chroot not active")
        if (self.scratch / "service-state").read_text() != MARKER:
            raise RuntimeError("compromised worker did not execute its write positive control")
        children = Path(f"/proc/{service.pid}/task/{service.pid}/children").read_text().split()
        if len(children) != 1:
            raise RuntimeError("compromised worker did not create its persistence child")
        # A service cannot add authority by constructing messages on its own gate fd.
        for change in ({"url": "https://invalid.example/never-contacted"}, {"offset": 0, "length": 513}):
            attempt = json.loads(json.dumps(message))
            attempt["request"]["arguments"] = change
            denied = guest_effect(channel, attempt)
            if denied["success"] or denied["effect_state"] != "not-started":
                raise RuntimeError("package retrieval authority widened")
        return {
            "mode": self.mode, "worker_sha256": sha256_file(self.binary),
            "artifact_sha256": self.artifact.sha256, "trusted_recipient_digest_verified": True,
            "service_chroot_uid_capabilities_verified": True,
            "service_scratch_write_observed": True, "persistence_child_observed": True,
            "gate_url_and_budget_widening_denied": True,
            "substituted_success_output_rejected": True,
            "target_events": self.target_events,
            "active_workload_ms": (time.monotonic() - self.started) * 1000,
            "detection_delay_ms": None, "automatic_attack_detection": False,
            "ambiguous_outcomes": [],
        }

    def close(self):
        self.stopping = time.monotonic()
        self.stop.set()
        if self.target_thread.ident is not None:
            self.target_thread.join(timeout=3)
            if self.target_thread.is_alive():
                raise RuntimeError("target oracle did not stop")
        self.target.close()
        if self.target_failure:
            raise RuntimeError("target oracle failed") from self.target_failure
        # Kill of the full effect cgroup is checked by the shared watchdog first.
        remove_run_file(self.scratch / "service-state", self.scratch, invalidate=True)
        self.scratch.rmdir()

    def after_teardown(self):
        def marked(name):
            path = self.fixtures / name
            return path.exists() and path.read_text() == MARKER

        effects = {
            "relay": any(event["kind"] == "relay" for event in self.target_events),
            "credential_reuse": any(event["kind"] == "credential_reuse" for event in self.target_events),
            "cross_session_message": marked("shared-message"),
            "durable_shared_state": marked("durable-state"),
            "fixture_evidence_tamper": marked("evidence-canary"),
        }
        # Separate fixture consumer process, not a second VM or worker self-report.
        consumer = subprocess.run(["/usr/bin/cat", str(self.fixtures / "shared-message")], capture_output=True)
        if (consumer.returncode == 0 and consumer.stdout == MARKER.encode()) != effects["cross_session_message"]:
            raise RuntimeError("cross-session fixture consumer disagreed with oracle")
        expected = self.mode == "vulnerable"
        if any(value is not expected for value in effects.values()):
            raise RuntimeError(f"paired control failed: {self.mode}: {effects}")
        return {
            "forbidden_effects": effects, "service_scratch_removed": not self.scratch.exists(),
            "authoritative_evidence_outside_service_root": not (self.root / "control").exists(),
            "post_kill_cleanup_ms": (time.monotonic() - self.stopping) * 1000,
            "requested_teardown_latency_ms": (time.monotonic() - self.teardown_started) * 1000,
            "total_round_ms": (time.monotonic() - self.started) * 1000,
        }


def build_worker(output: Path) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    source = ROOT / "firecracker/guest/compromised_package.c"
    subprocess.run(["gcc", "-static", "-Os", "-s", "-Wall", "-Wextra", "-Werror",
                    "-Wl,--build-id=none", "-frandom-seed=owned-package-v1",
                    "-o", str(output), str(source)], check=True)
    return {"source_sha256": sha256_file(source), "worker_sha256": sha256_file(output),
            "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=ROOT / "firecracker/build/isolation")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    import fcntl
    lock_fd = os.open("/run/event-horizon-isolation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write_durable_json(args.report, {"schema": "event-horizon.package-isolation.v1", "status": "INCOMPLETE"})
        preflight()
        assets = args.assets.resolve()
        manifest = checked_assets(assets)
        binary = assets / "compromised-package"
        worker_build = build_worker(binary)
        broker = CapabilityBroker(ttl_seconds=60)
        rounds = []
        previous = None
        # A fresh protected session also rejects unused authority from its predecessor.
        for mode in ("vulnerable", "protected", "protected"):
            result, previous = run_round(assets, manifest, broker, previous,
                                         package_lab=PackageLab(mode, binary, worker_build))
            rounds.append(result)
        report = {
            "schema": "event-horizon.package-isolation.v1", "status": "PASS",
            "build_manifest": manifest, "worker_build": worker_build, "host_kernel": platform.release(),
            "rounds": rounds, "attestation": "synthetic-fixture",
            "scope": "owned deterministic probes; already-compromised service; serialized guest-root VMs",
            "attack_budget": {"guest_commands_max": 32, "service_requests_max": 24,
                              "watchdog_seconds": 30, "memory_bytes_per_cgroup": 268435456, "pids_per_cgroup": 32},
            "unknowns": ["adaptive attacks", "kernel or trusted gate compromise", "concurrent tenant VMs",
                         "real registries and package installation", "covert channels", "production attestation",
                         "automatic detection latency", "statistical performance overhead"],
        }
        from scripts.verify_package_isolation import verify_report
        verify_report(report)
        write_durable_json(args.report, report)
        print("Package-service isolation: PASS (vulnerable control + two protected guest-root sessions)")
        print(f"Evidence report: {args.report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
