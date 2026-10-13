#!/usr/bin/env python3
"""Five real Firecracker guest/vsock/guardian/etcd SIGKILL windows.

Requires owned three-node etcd and root Ubuntu 24.04 with /dev/kvm.
Never falls back to a host-only test. Every round creates an independent
Firecracker VM, signer/guardian session, external recipient, and guest worker.
No PASS is written until all five phases and the strict v1 verifier succeed.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts.integrated_authority_session import IsolatedSession
from scripts.integrated_gateway_campaign import FirecrackerCrashPackageLab, OwnedQuorum
from scripts.package_authority_oracle import owned_etcd_config
from scripts.real_gateway_crash_checkpoints import PHASES
from scripts.run_linux_isolation import preflight, checked_assets, run_round
from scripts.run_package_isolation import build_worker
from scripts.verify_integrated_kvm_crash import verify_report


SCHEMA = "event-horizon.firecracker-gateway-sigkill.v1"
MODE = "real-kvm-guardian-etcd-recipient-gateway-sigkill"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=ROOT / "firecracker/build/isolation")
    parser.add_argument("--etcd-endpoint", required=True)
    parser.add_argument("--etcd-cluster-id", required=True)
    parser.add_argument("--etcd-containers", nargs=3, required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report_path = args.report.resolve()
    if report_path.exists() or Path(str(report_path) + ".sha256").exists():
        raise FileExistsError("never overwrite original fault evidence")
    source = subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", "rev-parse", "HEAD"],
        cwd=ROOT, text=True,
    ).strip()
    if subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", "diff", "HEAD", "--name-only"],
        cwd=ROOT,
    ).strip():
        raise RuntimeError("hardware evidence requires committed implementation")
    preflight()
    config = {
        "authority_backend": "etcd",
        "etcd_gateway": owned_etcd_config(args.etcd_endpoint, args.etcd_cluster_id),
        "etcd_cluster_id": args.etcd_cluster_id,
    }
    config["etcd_gateway"]["timeout_seconds"] = 0.5
    quorum = OwnedQuorum(args.etcd_containers, config)
    report = {
        "schema": SCHEMA, "experiment_mode": MODE,
        "source_commit": source, "status": "INCOMPLETE", "rounds": [],
    }
    lockfd = os.open(
        "/run/event-horizon-isolation.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600,
    )
    try:
        with os.fdopen(lockfd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assets = args.assets.resolve()
            manifest = checked_assets(assets)
            if manifest.get("tpm2_enabled"):
                raise ValueError("only synthetic attestation in this lab")
            binary = assets / "compromised-package"
            worker_build = build_worker(binary)
            previous = None
            for idx, phase in enumerate(PHASES):
                session = IsolatedSession(source_commit=source)
                try:
                    round_record, previous, attestation = run_round(
                        assets, manifest, None, previous,
                        stop_mode="supervisor-channel-loss" if idx == 4 else "requested",
                        authority_session=session,
                        package_lab=FirecrackerCrashPackageLab(
                            "protected", binary, worker_build,
                            crash_phase=phase, authority_config=config, quorum=quorum,
                        ),
                    )
                    if attestation != "synthetic-fixture":
                        raise RuntimeError("attestation mode changed during crash campaign")
                    report["rounds"].append(round_record)
                finally:
                    session.close()
            report.update(
                status="PASS", build_manifest=manifest, worker_build=worker_build,
                host_kernel=platform.release(), attestation="synthetic-fixture",
                authority={
                    "backend": "etcd", "cluster_id": args.etcd_cluster_id,
                    "oracle": "host-supervisor-linearizable-etcd-read",
                },
                scope="five real SIGKILL windows in actual Firecracker/guardian/etcd bridge",
                unknowns=[
                    "host/kernel compromise", "hardware attestation",
                    "external witness", "physical multi-host separation",
                    "power-loss durability outside kernel assumptions",
                    "safe negative reconciliation and automatic retry",
                ],
            )
            verify_report(report)
    except BaseException as exc:
        report["status"] = "INCOMPLETE"
        report["failure_class"] = type(exc).__name__
        raise
    finally:
        restore_error = None
        try:
            quorum.restore()
        except BaseException as exc:
            restore_error = exc
            report["status"] = "INCOMPLETE"
            report["failure_class"] = "OwnedQuorumRestoreFailed"
        # Even a failed cluster restore must not erase the original failed
        # evidence; restore failures cannot be promoted to a PASS report.
        report_path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        with report_path.open("xb") as target:
            target.write(raw)
        sha = hashlib.sha256(raw).hexdigest()
        with Path(str(report_path) + ".sha256").open("x") as sidecar:
            sidecar.write(sha + "  " + report_path.name + "\n")
        print("Original report:", report_path, "SHA256:", sha,
              "status:", report["status"], flush=True)
        if restore_error is not None:
            raise RuntimeError("owned quorum restore failed; immutable INCOMPLETE report preserved") from restore_error
    print("PASS: five actual KVM guest-triggered gateway SIGKILL windows; internal receipts only")


if __name__ == "__main__":
    main()
