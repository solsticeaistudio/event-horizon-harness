#!/usr/bin/env python3
"""Two REAL Firecracker guest-triggered recipient SIGKILL/restart windows.

The independent recipient process dies before or after atomic SQLite commit;
the trusted gateway survives and resolves the ambiguity only after a fresh
four-guardian-signed authority, using the same private recipient ledger.
No hardware evidence exists until run on the operator's actual KVM host.
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
from scripts.integrated_gateway_campaign import FencedRecipientCrashKvmLab, OwnedQuorum
from scripts.fenced_recipient_service import PHASES as RECIPIENT_PHASES
from scripts.package_authority_oracle import owned_etcd_config
from scripts.run_linux_isolation import preflight, checked_assets, run_round
from scripts.run_package_isolation import build_worker
from scripts.verify_integrated_kvm_recipient_crash import verify_report

SCHEMA = "event-horizon.firecracker-fenced-recipient-crash-recovery.v1"
MODE = "real-kvm-guardian-etcd-fenced-recipient-restart"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, default=ROOT / "firecracker/build/isolation")
    parser.add_argument("--etcd-endpoint", required=True)
    parser.add_argument("--etcd-cluster-id", required=True)
    parser.add_argument("--etcd-containers", nargs=3, required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    path = args.report.resolve()
    if path.exists() or Path(str(path) + ".sha256").exists():
        raise FileExistsError("never overwrite an existing hardware experiment")
    source = subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", "rev-parse", "HEAD"],
        cwd=ROOT, text=True,
    ).strip()
    if subprocess.check_output(
        ["git", "-c", f"safe.directory={ROOT}", "diff", "HEAD", "--name-only"],
        cwd=ROOT,
    ).strip():
        raise RuntimeError("hardware evidence requires committed source")
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
    fd = os.open("/run/event-horizon-isolation.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assets = args.assets.resolve()
            manifest = checked_assets(assets)
            if manifest.get("tpm2_enabled"):
                raise ValueError("only synthetic guest attestation is supported by this lab")
            worker = assets / "compromised-package"
            worker_build = build_worker(worker)
            for phase in RECIPIENT_PHASES:
                session = IsolatedSession(source_commit=source)
                try:
                    result, unused, attestation = run_round(
                        assets, manifest, None, None, stop_mode="requested",
                        authority_session=session,
                        package_lab=FencedRecipientCrashKvmLab(
                            "protected", worker, worker_build,
                            crash_phase=phase,
                            authority_config=config, quorum=quorum,
                        ),
                    )
                    if attestation != "synthetic-fixture":
                        raise RuntimeError("fenced KVM attestation mode drifted")
                    report["rounds"].append(result)
                finally:
                    session.close()
            report.update(
                status="PASS", build_manifest=manifest, worker_build=worker_build,
                host_kernel=platform.release(), attestation="synthetic-fixture",
                authority={
                    "backend": "etcd", "cluster_id": args.etcd_cluster_id,
                    "oracle": "host-supervisor-linearizable-etcd-read",
                },
                scope="two real Firecracker guest-triggered independent recipient SIGKILL/restart windows",
                unknowns=[
                    "host/kernel compromise", "hardware attestation",
                    "external witness", "physical multi-host separation",
                    "power-loss durability", "external recipient APIs beyond atomic SQLite",
                    "two competing gateway processes and transport partitions",
                ],
            )
            verify_report(report)
    except BaseException as exc:
        report["status"] = "INCOMPLETE"
        report["failure_class"] = type(exc).__name__
        raise
    finally:
        restore_failure = None
        try:
            quorum.restore()
        except BaseException as exc:
            restore_failure = exc
            report["status"] = "INCOMPLETE"
            report["failure_class"] = "OwnedQuorumRestoreFailed"
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        with path.open("xb") as handle:
            handle.write(raw)
        sha = hashlib.sha256(raw).hexdigest()
        with Path(str(path) + ".sha256").open("x") as sidecar:
            sidecar.write(sha + "  " + path.name + "\n")
        print("Original report:", path, "SHA256:", sha,
              "status:", report["status"], flush=True)
        if restore_failure is not None:
            raise RuntimeError("owned etcd quorum restore failed") from restore_failure
    print("PASS: 2 real KVM recipient SIGKILL/restart recovery windows; internal signed evidence only")


if __name__ == "__main__":
    main()
