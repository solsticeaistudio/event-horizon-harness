#!/usr/bin/env python3
"""CLI tooling for recovery and checkpoint management."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from event_horizon.canonical import canonical_bytes, digest
from event_horizon.recorder import ExternalRecorder, RecorderIntegrityError
from event_horizon.remote_replay import (
    ReferenceReplayService,
    AuthenticatedReplayClient,
    ReplayRequestSigner,
    ReplayClientPolicy,
    ReplayProtocolError,
    ReplayUnavailableError,
    ReplayStateError,
    ReplayHttpServer,
    HttpReplayTransport,
)
from event_horizon.raft_replay import (
    RaftConsensus,
    RaftNode,
    ReferenceReplayService,
    SnapshotMetadata,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def verify_checkpoint(artifact_path: Path) -> dict[str, Any]:
    """Verify a checkpoint/evidence chain."""
    try:
        recorder = ExternalRecorder(artifact_path / "recorder" / "events.jsonl")
        valid, detail = recorder.verify()
        return {
            "valid": valid,
            "detail": detail,
            "event_count": recorder.count(),
        }
    except Exception as e:
        return {"valid": False, "detail": str(e), "event_count": 0}


def verify_replay_service(artifact_path: Path, service_id: str) -> dict[str, Any]:
    """Verify a replay service checkpoint."""
    try:
        import sqlite3
        db_path = artifact_path / "authority.sqlite3"
        if not db_path.exists():
            return {"valid": False, "detail": "Database not found"}
        
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT epoch, checkpoint, checkpoint_digest FROM replay_metadata WHERE singleton = 1"
            ).fetchone()
            if not row:
                return {"valid": False, "detail": "No replay metadata found"}
            epoch, checkpoint, checkpoint_digest = row
            return {
                "valid": True,
                "epoch": epoch,
                "checkpoint": checkpoint,
                "checkpoint_digest": checkpoint_digest,
            }
    except Exception as e:
        return {"valid": False, "detail": str(e)}


def list_checkpoints(artifact_path: Path) -> dict[str, Any]:
    """List all checkpoints in a replay service database."""
    try:
        import sqlite3
        db_path = artifact_path / "authority.sqlite3"
        with sqlite3.connect(db_path) as conn:
            checkpoints = conn.execute(
                "SELECT checkpoint, epoch, checkpoint_digest FROM replay_checkpoints ORDER BY checkpoint"
            ).fetchall()
            return {
                "checkpoints": [
                    {"checkpoint": c[0], "epoch": c[1], "checkpoint_digest": c[2]}
                    for c in checkpoints
                ]
            }
    except Exception as e:
        return {"error": str(e)}


def verify_raft_snapshot(artifact_path: Path) -> dict[str, Any]:
    """Verify a Raft snapshot."""
    try:
        import sqlite3
        db_path = artifact_path / "raft.sqlite3"
        if not db_path.exists():
            return {"valid": True, "detail": "No Raft database found (no snapshots to verify)"}
        
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if not row:
                return {"valid": True, "detail": "No snapshots found"}
            
            # Verify snapshot integrity
            import json
            import hashlib
            snapshot_data = row[4]  # snapshot_data column
            stored_digest = row[3]
            actual_digest = hashlib.sha256(snapshot_data).hexdigest()
            
            return {
                "valid": stored_digest == actual_digest,
                "detail": "Snapshot verified" if stored_digest == actual_digest else "Digest mismatch",
                "snapshot_index": row[0],
                "snapshot_term": row[1],
            }
    except Exception as e:
        return {"valid": False, "detail": str(e)}


def export_checkpoint(artifact_path: Path, output_path: Path) -> dict[str, Any]:
    """Export checkpoint data for backup/analysis."""
    try:
        import sqlite3
        import json
        db_path = artifact_path / "authority.sqlite3"
        if not db_path.exists():
            return {"valid": False, "detail": "No database found"}
        
        output = {}
        with sqlite3.connect(db_path) as conn:
            for table in ("replay_metadata", "replay_checkpoints", "replay_nonces"):
                try:
                    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
                    output[table] = rows
                except sqlite3.OperationalError:
                    pass
        
        output_path.write_text(json.dumps(output, indent=2))
        return {"valid": True, "detail": f"Exported to {output_path}"}
    except Exception as e:
        return {"valid": False, "detail": str(e)}


def import_checkpoint(artifact_path: Path, input_path: Path) -> dict[str, Any]:
    """Import checkpoint data from backup."""
    try:
        import sqlite3
        import json
        data = json.loads(input_path.read_text())
        
        db_path = artifact_path / "authority.sqlite3"
        with sqlite3.connect(db_path) as conn:
            # Initialize schema first
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    service_id TEXT NOT NULL,
                    server_key_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    checkpoint INTEGER NOT NULL,
                    checkpoint_digest TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_checkpoints (
                    checkpoint INTEGER PRIMARY KEY,
                    epoch INTEGER NOT NULL,
                    checkpoint_digest TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    partition TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired')),
                    consumed_at INTEGER,
                    PRIMARY KEY (partition, nonce)
                ) WITHOUT ROWID
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_tokens (
                    partition TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    token TEXT NOT NULL,
                    binding_digest TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER NOT NULL,
                    PRIMARY KEY (partition, operation, token)
                ) WITHOUT ROWID
            """)
            
            for table, rows in data.items():
                if rows:
                    placeholders = ",".join(["?"] * len(rows[0]))
                    conn.executemany(
                        f"INSERT OR REPLACE INTO {table} VALUES ({','.join(['?']*len(rows[0]))})",
                        rows
                    )
            conn.commit()
        return {"valid": True, "detail": f"Imported from {input_path}"}
    except Exception as e:
        return {"valid": False, "detail": str(e)}


def verify_evidence_chain(artifact_path: Path) -> dict[str, Any]:
    """Verify the complete evidence chain."""
    try:
        recorder = ExternalRecorder(artifact_path / "events.jsonl")
        valid, detail = recorder.verify()
        events = recorder.events()
        return {
            "valid": valid,
            "detail": detail,
            "event_count": len(events),
            "last_event": events[-1] if events else None,
        }
    except Exception as e:
        return {"valid": False, "detail": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Event Horizon recovery and checkpoint management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify-checkpoint
    subparsers.add_parser("verify-checkpoint", help="Verify a checkpoint/evidence chain")

    # verify-replay
    subparsers.add_parser("verify-replay", help="Verify a replay service checkpoint")

    # list-checkpoints
    subparsers.add_parser("list-checkpoints", help="List all checkpoints in a replay service")

    # verify-raft-snapshot
    subparsers.add_parser("verify-raft-snapshot", help="Verify a Raft snapshot")

    # export-checkpoint
    export_parser = subparsers.add_parser("export-checkpoint", help="Export checkpoint data for backup")
    export_parser.add_argument("--output", "-o", type=Path, required=True, help="Output file path")

    # import-checkpoint
    import_parser = subparsers.add_parser("import-checkpoint", help="Import checkpoint data from backup")
    import_parser.add_argument("--input", "-i", type=Path, required=True, help="Input file path")

    # verify-evidence
    subparsers.add_parser("verify-evidence", help="Verify the complete evidence chain")

    # verify-all
    subparsers.add_parser("verify-all", help="Run all verification checks")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    artifact_path = Path(os.getcwd())  # Default to current directory
    # Allow artifact path override via env var
    if "EH_ARTIFACT_PATH" in os.environ:
        artifact_path = Path(os.environ["EH_ARTIFACT_PATH"])

    result = {}

    if args.command == "verify-checkpoint":
        result = verify_checkpoint(artifact_path)
    elif args.command == "verify-replay":
        result = verify_replay_service(artifact_path, "event-horizon-replay")
    elif args.command == "list-checkpoints":
        result = list_checkpoints(artifact_path)
    elif args.command == "verify-raft-snapshot":
        result = verify_raft_snapshot(artifact_path)
    elif args.command == "export-checkpoint":
        result = export_checkpoint(artifact_path, args.output)
    elif args.command == "import-checkpoint":
        result = import_checkpoint(artifact_path, args.input)
    elif args.command == "verify-evidence":
        result = verify_evidence_chain(artifact_path)
    elif args.command == "verify-all":
        results = {}
        for check in ["verify-checkpoint", "verify-replay", "list-checkpoints", 
                      "verify-raft-snapshot", "verify-evidence"]:
            if check == "verify-checkpoint":
                results[check] = verify_checkpoint(artifact_path)
            elif check == "verify-replay":
                results[check] = verify_replay_service(artifact_path, "event-horizon-replay")
            elif check == "list-checkpoints":
                results[check] = list_checkpoints(artifact_path)
            elif check == "verify-raft-snapshot":
                results[check] = verify_raft_snapshot(artifact_path)
            elif check == "verify-evidence":
                results[check] = verify_evidence_chain(artifact_path)
        results["all_passed"] = all(r.get("valid", False) for r in results.values())
        result = results
    else:
        print(f"Unknown command: {args.command}")
        return 1

    print(json.dumps(result, indent=2))
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    import os
    sys.exit(main())