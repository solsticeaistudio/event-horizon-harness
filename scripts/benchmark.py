#!/usr/bin/env python3
"""Benchmark Event Horizon Harness components."""

from __future__ import annotations

import argparse
import base64
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.broker import CapabilityBroker
from event_horizon.factory import build_local_harness
from event_horizon.recorder import ExternalRecorder
from event_horizon.remote_replay import (
    ReferenceReplayService,
    AuthenticatedReplayClient,
    ReplayRequestSigner,
    ReplayClientPolicy,
    RemoteCapabilityConsumptionStore,
    HttpReplayTransport,
    ReplayHttpServer,
)
from event_horizon.production_attestation import ProductionAttestationManager
sys.path.insert(0, str(Path(__file__).parent))

from event_horizon.models import ActionRequest
from capability_fixture_support import authority_context, issue_options, verify_options


def benchmark_capability_issue(iterations: int = 1000) -> dict:
    """Benchmark capability issuance."""
    broker = CapabilityBroker(b"benchmark-signing-key-seed-that-is-32-bytes-long", ttl_seconds=60)
    request = {
        "request_id": "bench-request",
        "session_id": "bench-session",
        "agent_id": "bench-agent",
        "operation": "object.read",
        "resource_id": "bench-source",
        "executor_id": "bench-exec",
        "arguments": {"length": 1, "offset": 0},
        "purpose": "benchmark",
    }
    authority = authority_context(ActionRequest.from_dict(request), 1_700_000_000.0)

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        broker.issue(
            ActionRequest.from_dict(request),
            **issue_options(authority),
            max_output_bytes=1024,
            now=1_700_000_000.0,
        )
        times.append(time.perf_counter() - start)

    return {
        "operation": "capability_issue",
        "iterations": iterations,
        "mean_ms": statistics.mean(times) * 1000,
        "median_ms": statistics.median(times) * 1000,
        "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
        "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
    }


def benchmark_capability_verify(iterations: int = 100) -> dict:
    """Benchmark capability verification."""
    broker = CapabilityBroker(b"benchmark-signing-key-seed-that-is-32-bytes-long", ttl_seconds=300)

    times = []
    for i in range(iterations):
        request = ActionRequest.from_dict({
            "request_id": f"bench-request-{i}",
            "session_id": f"bench-session-{i}",
            "agent_id": "bench-agent",
            "operation": "object.read",
            "resource_id": "bench-source",
            "executor_id": "bench-exec",
            "arguments": {"length": 1, "offset": 0},
            "purpose": "benchmark",
        })
        authority = authority_context(request, 1_700_000_000.0)
        capability = broker.issue(request, **issue_options(authority), max_output_bytes=1024, now=1_700_000_000.0)
        context = verify_options(authority)

        start = time.perf_counter()
        broker.verify_and_consume(capability, request, now=1_700_000_000.0, **context)
        times.append(time.perf_counter() - start)

    return {
        "operation": "capability_verify",
        "iterations": iterations,
        "mean_ms": statistics.mean(times) * 1000,
        "median_ms": statistics.median(times) * 1000,
        "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
        "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
    }


def benchmark_executor(iterations: int = 100) -> dict:
    """Benchmark executor execution."""
    with tempfile.TemporaryDirectory() as tmp:
        authority, executor, recorder, _ = build_local_harness(tmp)
        executor.objects["bench-source"] = {"data": "benchmark-data"}

        request, capability, attestation = authority.request_capability({
            "request_id": "bench-request",
            "session_id": "bench-session",
            "agent_id": "bench-agent",
            "operation": "object.read",
            "resource_id": "bench-source",
            "executor_id": "bench-exec",
            "arguments": {"length": 1, "offset": 0},
            "purpose": "benchmark",
        })

        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            executor.execute(request, capability, attestation)
            times.append(time.perf_counter() - start)

        return {
            "operation": "executor_execute",
            "iterations": iterations,
            "mean_ms": statistics.mean(times) * 1000,
            "median_ms": statistics.median(times) * 1000,
            "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
            "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
        }


def benchmark_recorder(iterations: int = 1000) -> dict:
    """Benchmark recorder append."""
    with tempfile.TemporaryDirectory() as tmp:
        recorder = ExternalRecorder(Path(tmp) / "bench-recorder.jsonl")
        times = []
        for i in range(iterations):
            start = time.perf_counter()
            recorder.append("benchmark.event", {"index": i, "data": "x" * 100})
            times.append(time.perf_counter() - start)

        return {
            "operation": "recorder_append",
            "iterations": iterations,
            "mean_ms": statistics.mean(times) * 1000,
            "median_ms": statistics.median(times) * 1000,
            "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
            "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
        }


def benchmark_remote_replay(iterations: int = 100) -> dict:
    """Benchmark remote replay service."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with tempfile.TemporaryDirectory() as tmp:
        server_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        signer = ReplayRequestSigner(client_key, "event-horizon-replay")
        policy = ReplayClientPolicy.create(
            signer.public_key_pem,
            operations={"capability-consume"},
            partitions={"capability.authority"},
        )
        service = ReferenceReplayService(
            Path(tmp) / "authority.sqlite3",
            service_id="event-horizon-replay",
            epoch=1,
            signing_key=server_key,
            clients={policy.key_id: policy},
        )

        client = AuthenticatedReplayClient(signer, service.handle, service.public_key_pem, epoch=1)
        store = RemoteCapabilityConsumptionStore(client, partition="capability.authority")

        times = []
        for i in range(iterations):
            capability_id = f"cap_{i:024x}"
            start = time.perf_counter()
            store.consume(capability_id, "a" * 64, 5000, 1000 + i)
            times.append(time.perf_counter() - start)

        return {
            "operation": "remote_replay_consume",
            "iterations": iterations,
            "mean_ms": statistics.mean(times) * 1000,
            "median_ms": statistics.median(times) * 1000,
            "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
            "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
        }


def benchmark_http_replay(iterations: int = 50) -> dict:
    """Benchmark HTTP replay transport."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with tempfile.TemporaryDirectory() as tmp:
        server_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        client_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        signer = ReplayRequestSigner(client_key, "event-horizon-replay")
        policy = ReplayClientPolicy.create(
            signer.public_key_pem,
            operations={"capability-consume"},
            partitions={"capability.authority"},
        )
        service = ReferenceReplayService(
            Path(tmp) / "authority.sqlite3",
            service_id="event-horizon-replay",
            epoch=1,
            signing_key=server_key,
            clients={policy.key_id: policy},
        )

        server = ReplayHttpServer(service)
        server.start()
        try:
            client = AuthenticatedReplayClient(signer, HttpReplayTransport(server.url), service.public_key_pem, epoch=1)
            store = RemoteCapabilityConsumptionStore(client, partition="capability.authority")

            times = []
            for i in range(iterations):
                capability_id = f"cap_{i:024x}"
                start = time.perf_counter()
                store.consume(capability_id, "a" * 64, 5000, 1000 + i)
                times.append(time.perf_counter() - start)

            return {
                "operation": "http_replay_consume",
                "iterations": iterations,
                "mean_ms": statistics.mean(times) * 1000,
                "median_ms": statistics.median(times) * 1000,
                "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
                "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
            }
        finally:
            server.close()


def benchmark_production_attestation(iterations: int = 100) -> dict:
    """Benchmark production attestation verification."""
    with tempfile.TemporaryDirectory() as tmp:
        recorder = ExternalRecorder(Path(tmp) / "recorder" / "events.jsonl")
        manager = ProductionAttestationManager(
            recorder=recorder,
            enrollment_db_path=Path(tmp) / "enrollment.sqlite3",
            policy_db_path=Path(tmp) / "policy.sqlite3",
            signing_key=Ed25519PrivateKey.generate(),
        )
        device_key = Ed25519PrivateKey.generate()
        device_pem = device_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        enrollment = manager.enroll_device("device-1", device_pem)
        policy = manager.create_measurement_policy("policy-1", {"pcr0": {"type": "exact", "value": "abc123"}})

        bundle = {
            "version": "eh-attestation-1",
            "method": "tpm2",
            "deviceId": "device-1",
            "nonce": "A" * 43,
            "issuedAt": "2026-09-10T00:00:00Z",
            "expiresAt": "2026-09-10T01:00:00Z",
            "keyId": enrollment.key_id,
            "measurements": {"pcr0": "abc123"},
            "evidence": {},
        }

        now_ts = time.time()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts - 30))
        later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts + 3600))

        times = []
        for i in range(iterations):
            bundle = {
                "version": "eh-attestation-1",
                "method": "tpm2",
                "deviceId": "device-1",
                "nonce": "A" * 43,
                "issuedAt": now,
                "expiresAt": later,
                "keyId": enrollment.key_id,
                "measurements": {"pcr0": "abc123"},
                "evidence": {},
            }
            bundle_copy = dict(bundle)
            signature = base64.urlsafe_b64encode(
                Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(canonical_bytes(bundle_copy))
            ).rstrip(b"=").decode("ascii")
            bundle["signature"] = signature

            start = time.perf_counter()
            manager.verify_attestation_bundle(
                bundle,
                nonce="A" * 43,
                nonce_context={"deviceId": "device-1", "executorId": "exec-1", "purpose": "test", "sessionId": "sess-1"},
                measurement_policy=ProductionAttestationManager._row_to_enrollment(0) if hasattr(ProductionAttestationManager, '_row_to_enrollment') else None,
            )
            times.append(time.perf_counter() - start)

        return {
            "operation": "production_attestation_verify",
            "iterations": iterations,
            "mean_ms": statistics.mean(times) * 1000,
            "median_ms": statistics.median(times) * 1000,
            "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
            "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
        }


def benchmark_emergency_stop(iterations: int = 100) -> dict:
    """Benchmark emergency stop controller."""
    with tempfile.TemporaryDirectory() as tmp:
        recorder = ExternalRecorder(Path(tmp) / "recorder" / "events.jsonl")
        controller = EmergencyStopController(
            component_id="test-component",
            recorder=recorder,
        )
        key = Ed25519PrivateKey.generate()
        key_id_str = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import hashlib
        key_id_str = f"ed25519:{hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()[:32]}"
        key_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        controller.enroll_key(key_id_str, key_pem)

        times = []
        for i in range(iterations):
            controller._state = "armed"
            challenge = controller.issue_challenge(int(time.time() * 1000))
            claims = {
                "schema": "event-horizon.emergency-stop.v1",
                "component_id": "test-component",
                "challenge_id": challenge.challenge_id,
                "challenge_nonce": challenge.nonce,
                "sequence": i + 1,
                "issued_at_ms": int(time.time() * 1000) - 100,
                "expires_at_ms": int(time.time() * 1000) + 1000,
                "action": "kill",
                "action_payload": {"reason": "benchmark"},
                "key_id": key_id_str,
            }
            signature = base64.urlsafe_b64encode(
                Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(canonical_bytes(claims))
            ).rstrip(b"=").decode("ascii")
            action = SignedEmergencyAction(claims, signature)

            start = time.perf_counter()
            controller.receive_action(action, now_ms=int(time.time() * 1000))
            times.append(time.perf_counter() - start)

        return {
            "operation": "emergency_stop_kill",
            "iterations": iterations,
            "mean_ms": statistics.mean(times) * 1000,
            "median_ms": statistics.median(times) * 1000,
            "p95_ms": sorted(times)[int(iterations * 0.95)] * 1000,
            "p99_ms": sorted(times)[int(iterations * 0.99)] * 1000,
        }


def run_all_benchmarks() -> dict:
    """Run all benchmarks and return results."""

    results = {}

    print("Running capability issue benchmark...")
    results["capability_issue"] = benchmark_capability_issue(100)

    print("Running capability verify benchmark...")
    results["capability_verify"] = benchmark_capability_verify(100)

    print("Running recorder benchmark...")
    results["recorder"] = benchmark_recorder(500)

    print("Running remote replay benchmark...")
    results["remote_replay"] = benchmark_remote_replay(50)

    print("Running HTTP replay benchmark...")
    results["http_replay"] = benchmark_http_replay(25)

    return results


def main():
    parser = argparse.ArgumentParser(description="Event Horizon Harness Benchmarks")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    parser.add_argument("--iterations", type=int, default=100, help="Iterations per benchmark")
    args = parser.parse_args()

    results = run_all_benchmarks()

    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": "Windows" if os.name == "nt" else "Linux",
        "python_version": sys.version,
        "benchmarks": results,
    }

    if args.output:
        args.output.write_text(json.dumps(output, indent=2))
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    import os
    import sys
    main()