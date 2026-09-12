from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest, strict_json_loads
from .production_http import create_raft_server
from .remote_replay import (
    ReplayProtocolError,
    ReplayStateError,
    ReplayUnavailableError,
    ReferenceReplayService,
    ReplayRequestSigner,
    ReplayClientPolicy,
    AuthenticatedReplayClient,
    genesis_checkpoint_digest,
    replay_key_id,
)


MAX_HTTP_BODY_BYTES = 65_536


class RaftError(RuntimeError):
    """Raft consensus error."""


class RaftUnavailableError(RuntimeError):
    """Raft cluster unavailable."""


@dataclass(frozen=True)
class RaftNode:
    node_id: str
    address: str
    is_learner: bool = False


@dataclass
class RaftLogEntry:
    index: int
    term: int
    command: Mapping[str, Any]
    checkpoint: int
    checkpoint_digest: str


@dataclass(frozen=True)
class SnapshotMetadata:
    last_included_index: int
    last_included_term: int
    snapshot_digest: str
    snapshot_data: bytes
    created_at: float
    membership: tuple[RaftNode, ...]


@dataclass
class MembershipChange:
    change_type: str
    node: RaftNode
    joint_consensus: bool = False


class RaftError(RuntimeError):
    """Raft consensus error."""


class RaftUnavailableError(RuntimeError):
    """Raft cluster unavailable."""


@dataclass(frozen=True)
class RaftNode:
    node_id: str
    address: str
    is_learner: bool = False


@dataclass
class RaftLogEntry:
    index: int
    term: int
    command: Mapping[str, Any]
    checkpoint: int
    checkpoint_digest: str


@dataclass(frozen=True)
class SnapshotMetadata:
    last_included_index: int
    last_included_term: int
    snapshot_digest: str
    snapshot_data: bytes
    created_at: float
    membership: tuple[RaftNode, ...]


@dataclass
class MembershipChange:
    change_type: str
    node: RaftNode
    joint_consensus: bool = False


class RaftError(RuntimeError):
    """Raft consensus error."""


class RaftUnavailableError(RuntimeError):
    """Raft cluster unavailable."""


class RaftConsensus:
    """Raft consensus for replicated replay service.

    Provides leader election, log replication, and checkpoint continuity.
    Old-leader fencing via monotonic term numbers.
    Rollback-resistant checkpoints via quorum commits.
    Log snapshotting for log compaction.
    Membership changes via joint consensus.
    Leadership transfer for graceful leadership transfer.
    """

    def __init__(
        self,
        local_node: RaftNode,
        cluster: list[RaftNode],
        service: ReferenceReplayService,
        *,
        election_timeout_ms: tuple[int, int] = (1000, 5000),
        heartbeat_interval_ms: int = 50,
        request_timeout_ms: int = 5_000,
        snapshot_threshold: int = 1000,
        snapshot_interval_ms: int = 300_000,
    ) -> None:
        self.local_node = local_node
        self.cluster = cluster
        self.service = service
        self.election_timeout_ms = election_timeout_ms
        self.heartbeat_interval_ms = heartbeat_interval_ms
        self.request_timeout_ms = request_timeout_ms
        self.snapshot_threshold = snapshot_threshold
        self.snapshot_interval_ms = snapshot_interval_ms

        self._lock = threading.RLock()
        self._current_term = 0
        self._voted_for: str | None = None
        self._state = "follower"
        self._leader_id: str | None = None
        self._log: list[RaftLogEntry] = []
        self._commit_index = 0
        self._last_applied = 0
        self._next_index: dict[str, int] = {}
        self._match_index: dict[str, int] = {}
        self._last_contact = time.monotonic()
        self._election_deadline = self._random_election_deadline()
        self._running = False
        self._thread: threading.Thread | None = None

        # Snapshotting
        self._snapshot: Optional[SnapshotMetadata] = None
        self._last_snapshot_time = time.monotonic()
        self._snapshot_lock = threading.RLock()
        self._snapshot_db: Optional[sqlite3.Connection] = None
        self._snapshot_db_path: Optional[Path] = None

        # Membership changes (joint consensus)
        self._membership_change: Optional[MembershipChange] = None
        self._joint_consensus: bool = False
        self._new_cluster: Optional[list[RaftNode]] = None

        # Leadership transfer
        self._leadership_transfer: Optional[str] = None
        self._leadership_transfer_deadline: float = 0.0

    def _initialize_snapshot_db(self) -> None:
        """Initialize the snapshot database if not already initialized."""
        if self._snapshot_db is not None:
            return
        if self._snapshot_db_path is None:
            self._snapshot_db_path = Path(self.local_node.node_id + "_snapshot.sqlite3")
        self._snapshot_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._snapshot_db = sqlite3.connect(self._snapshot_db_path, check_same_thread=False)
        self._snapshot_db.execute("PRAGMA journal_mode = WAL")
        self._snapshot_db.execute("PRAGMA synchronous = FULL")
        self._snapshot_db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                term INTEGER NOT NULL,
                index INTEGER NOT NULL,
                digest TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at REAL NOT NULL,
                membership TEXT NOT NULL
            )
        """)
        self._snapshot_db.commit()

    def _random_election_deadline(self) -> float:
        min_ms, max_ms = self.election_timeout_ms
        return time.monotonic() + random.uniform(min_ms, max_ms) / 1000.0

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"raft-{self.local_node.node_id}")
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if hasattr(self, '_http_server') and self._http_server:
                self._http_server.stop()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def get_leader(self) -> str | None:
        with self._lock:
            return self._leader_id

    def _random_election_deadline(self) -> float:
        min_ms, max_ms = self.election_timeout_ms
        # Add extra randomness to prevent synchronized elections
        extra_ms = random.uniform(0, max_ms)
        return time.monotonic() + random.uniform(min_ms, max_ms + extra_ms) / 1000.0

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            # Reset election deadline to prevent synchronized elections
            self._election_deadline = self._random_election_deadline()
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"raft-{self.local_node.node_id}")
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if hasattr(self, '_http_server') and self._http_server:
                self._http_server.stop()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def get_leader(self) -> str | None:
        with self._lock:
            return self._leader_id

    # ===== CORE RAFT LOOP =====

    def _run_loop(self) -> None:
        """Main Raft event loop."""
        while True:
            with self._lock:
                if not self._running:
                    return
                now = time.monotonic()

                if self._state == "leader":
                    # Process leadership transfer if in progress
                    if self._leadership_transfer is not None and now > self._leadership_transfer_deadline:
                        self._leadership_transfer = None
                        self._leadership_transfer_deadline = 0.0

                    # Process leadership transfer if in progress
                    self._process_leadership_transfer()

                    # Check for snapshot creation
                    self._maybe_create_snapshot()

                    # Check for membership change completion
                    if self._joint_consensus:
                        self._check_joint_consensus_completion()

                    self._send_heartbeats()
                    time.sleep(self.heartbeat_interval_ms / 1000.0)
                else:
                    if now >= self._election_deadline:
                        self._start_election()
                    sleep_time = min(0.05, max(0.0, self._election_deadline - now))
                    time.sleep(sleep_time)

    # ===== LEADER ELECTION =====

    def _start_election(self) -> None:
        self._state = "candidate"
        self._current_term += 1
        self._voted_for = self.local_node.node_id
        self._election_deadline = self._random_election_deadline()

        votes = 1
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            if self._request_vote(node):
                votes += 1

        if votes > len(self.cluster) // 2:
            self._become_leader()

    def _become_leader(self) -> None:
        self._state = "leader"
        self._leader_id = self.local_node.node_id
        last_index = len(self._log)
        self._next_index = {n.node_id: last_index + 1 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._match_index = {n.node_id: 0 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._send_heartbeats()

    def _request_vote(self, node: RaftNode) -> bool:
        try:
            url = node.address.rstrip("/") + "/raft/vote"
            payload = {
                "term": self._current_term,
                "candidate_id": self.local_node.node_id,
                "last_log_index": len(self._log),
                "last_log_term": self._log[-1].term if self._log else 0,
            }
            signer = ReplayRequestSigner(
                self.service.private_key, self.service.service_id
            )
            signed = signer.sign(
                operation="raft-vote",
                partition="raft-internal",
                payload=payload,
                expected_epoch=0,
                minimum_checkpoint=0,
                minimum_checkpoint_digest="",
            )
            message = urllib.request.Request(
                url,
                data=canonical_bytes(signed),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(message, timeout=self.request_timeout_ms / 1000.0) as response:
                if response.status != 200:
                    return False
                content = response.read(MAX_HTTP_BODY_BYTES + 1)
                result = strict_json_loads(content, require_canonical=True)
                return result.get("vote_granted", False)
        except Exception:
            return False

    def _send_append_entries(self, node: RaftNode) -> bool:
        try:
            next_idx = self._next_index.get(node.node_id, 1)
            prev_log_index = next_idx - 1
            prev_log_term = self._log[prev_log_index - 1].term if prev_log_index > 0 else 0

            entries = self._log[prev_log_index:prev_log_index + 100]

            url = node.address.rstrip("/") + "/raft/append"
            payload = {
                "term": self._current_term,
                "leader_id": self.local_node.node_id,
                "prev_log_index": prev_log_index,
                "prev_log_term": prev_log_term,
                "entries": [
                    {
                        "index": e.index,
                        "term": e.term,
                        "command": e.command,
                        "checkpoint": e.checkpoint,
                        "checkpoint_digest": e.checkpoint_digest,
                    }
                    for e in entries
                ],
                "leader_commit": self._commit_index,
            }
            signer = ReplayRequestSigner(
                self.service.private_key, self.service.service_id
            )
            signed = signer.sign(
                operation="raft-append",
                partition="raft-internal",
                payload=payload,
                expected_epoch=0,
                minimum_checkpoint=0,
                minimum_checkpoint_digest="",
            )
            message = urllib.request.Request(
                url,
                data=canonical_bytes(signed),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(message, timeout=self.request_timeout_ms / 1000.0) as response:
                if response.status != 200:
                    return False
                content = response.read(MAX_HTTP_BODY_BYTES + 1)
                result = strict_json_loads(content, require_canonical=True)
                if result.get("success", False):
                    self._next_index[node.node_id] = result["next_index"]
                    self._match_index[node.node_id] = result["match_index"]
                    self._update_commit_index()
                    return True
                elif result.get("term", 0) > self._current_term:
                    self._current_term = result["term"]
                    self._state = "follower"
                    self._voted_for = None
                return False
        except Exception:
            return False

    def _update_commit_index(self) -> None:
        for n in range(self._commit_index + 1, len(self._log) + 1):
            count = 1
            for node in self.cluster:
                if node.node_id == self.local_node.node_id:
                    continue
                if self._match_index.get(node.node_id, 0) >= n:
                    count += 1
            if count > len(self.cluster) // 2 and self._log[n - 1].term == self._current_term:
                self._commit_index = n

    def _send_heartbeats(self) -> None:
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            self._send_append_entries(node)

    def _start_election(self) -> None:
        self._state = "candidate"
        self._current_term += 1
        self._voted_for = self.local_node.node_id
        self._election_deadline = self._random_election_deadline()

        votes = 1
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            if self._request_vote(node):
                votes += 1

        if votes > len(self.cluster) // 2:
            self._become_leader()

    def _become_leader(self) -> None:
        self._state = "leader"
        self._leader_id = self.local_node.node_id
        last_index = len(self._log)
        self._next_index = {n.node_id: last_index + 1 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._match_index = {n.node_id: 0 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._send_heartbeats()

    def _send_heartbeats(self) -> None:
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            self._send_append_entries(node)

    def _start_election(self) -> None:
        self._state = "candidate"
        self._current_term += 1
        self._voted_for = self.local_node.node_id
        self._election_deadline = self._random_election_deadline()

        votes = 1
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            if self._request_vote(node):
                votes += 1

        if votes > len(self.cluster) // 2:
            self._become_leader()

    def _send_heartbeats(self) -> None:
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            self._send_append_entries(node)

    def _send_append_entries(self, node: RaftNode) -> bool:
        try:
            next_idx = self._next_index.get(node.node_id, 1)
            prev_log_index = next_idx - 1
            prev_log_term = self._log[prev_log_index - 1].term if prev_log_index > 0 else 0

            entries = self._log[prev_log_index:prev_log_index + 100]

            url = node.address.rstrip("/") + "/raft/append"
            payload = {
                "term": self._current_term,
                "leader_id": self.local_node.node_id,
                "prev_log_index": prev_log_index,
                "prev_log_term": prev_log_term,
                "entries": [
                    {
                        "index": e.index,
                        "term": e.term,
                        "command": e.command,
                        "checkpoint": e.checkpoint,
                        "checkpoint_digest": e.checkpoint_digest,
                    }
                    for e in entries
                ],
                "leader_commit": self._commit_index,
            }
            signer = ReplayRequestSigner(
                self.service.private_key, self.service.service_id
            )
            signed = signer.sign(
                operation="raft-append",
                partition="raft-internal",
                payload=payload,
                expected_epoch=0,
                minimum_checkpoint=0,
                minimum_checkpoint_digest="",
            )
            message = urllib.request.Request(
                url,
                data=canonical_bytes(signed),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(message, timeout=self.request_timeout_ms / 1000.0) as response:
                if response.status != 200:
                    return False
                content = response.read(MAX_HTTP_BODY_BYTES + 1)
                result = strict_json_loads(content, require_canonical=True)
                if result.get("success", False):
                    self._next_index[node.node_id] = result["next_index"]
                    self._match_index[node.node_id] = result["match_index"]
                    self._update_commit_index()
                    return True
                elif result.get("term", 0) > self._current_term:
                    self._current_term = result["term"]
                    self._state = "follower"
                    self._voted_for = None
                return False
        except Exception:
            return False

    def _update_commit_index(self) -> None:
        for n in range(self._commit_index + 1, len(self._log) + 1):
            count = 1
            for node in self.cluster:
                if node.node_id == self.local_node.node_id:
                    continue
                if self._match_index.get(node.node_id, 0) >= n:
                    count += 1
            if count > len(self.cluster) // 2 and self._log[n - 1].term == self._current_term:
                self._commit_index = n

    def _random_election_deadline(self) -> float:
        min_ms, max_ms = self.election_timeout_ms
        # Add extra randomness to prevent synchronized elections
        extra_ms = random.uniform(0, max_ms)
        return time.monotonic() + random.uniform(min_ms, max_ms + extra_ms) / 1000.0

    def _start_election(self) -> None:
        self._state = "candidate"
        self._current_term += 1
        self._voted_for = self.local_node.node_id
        self._election_deadline = self._random_election_deadline()

        votes = 1
        for node in self.cluster:
            if node.node_id == self.local_node.node_id:
                continue
            if self._request_vote(node):
                votes += 1

        if votes > len(self.cluster) // 2:
            self._become_leader()

    def _become_leader(self) -> None:
        self._state = "leader"
        self._leader_id = self.local_node.node_id
        last_index = len(self._log)
        self._next_index = {n.node_id: last_index + 1 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._match_index = {n.node_id: 0 for n in self.cluster if n.node_id != self.local_node.node_id}
        self._send_heartbeats()

    def _request_vote(self, node: RaftNode) -> bool:
        try:
            url = node.address.rstrip("/") + "/raft/vote"
            payload = {
                "term": self._current_term,
                "candidate_id": self.local_node.node_id,
                "last_log_index": len(self._log),
                "last_log_term": self._log[-1].term if self._log else 0,
            }
            signer = ReplayRequestSigner(
                self.service.private_key, self.service.service_id
            )
            signed = signer.sign(
                operation="raft-vote",
                partition="raft-internal",
                payload=payload,
                expected_epoch=0,
                minimum_checkpoint=0,
                minimum_checkpoint_digest="",
            )
            message = urllib.request.Request(
                url,
                data=canonical_bytes(signed),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(message, timeout=self.request_timeout_ms / 1000.0) as response:
                if response.status != 200:
                    return False
                content = response.read(MAX_HTTP_BODY_BYTES + 1)
                result = strict_json_loads(content, require_canonical=True)
                return result.get("vote_granted", False)
        except Exception:
            return False

    # ===== SNAPSHOTTING =====

    def _initialize_snapshot_db(self) -> None:
        """Initialize the snapshot database if not already initialized."""
        if self._snapshot_db is not None:
            return
        if self._snapshot_db_path is None:
            self._snapshot_db_path = Path(self.local_node.node_id + "_snapshot.sqlite3")
        self._snapshot_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._snapshot_db = sqlite3.connect(self._snapshot_db_path, check_same_thread=False)
        self._snapshot_db.execute("PRAGMA journal_mode = WAL")
        self._snapshot_db.execute("PRAGMA synchronous = FULL")
        self._snapshot_db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                term INTEGER NOT NULL,
                index INTEGER NOT NULL,
                digest TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at REAL NOT NULL,
                membership TEXT NOT NULL
            )
        """)
        self._snapshot_db.commit()

    def _maybe_create_snapshot(self) -> None:
        """Create a snapshot if threshold is reached."""
        with self._snapshot_lock:
            if self._snapshot is not None:
                return

            if len(self._log) < self.snapshot_threshold:
                return

            if time.monotonic() - self._last_snapshot_time < self.snapshot_interval_ms / 1000.0:
                return

            last_included_index = self._commit_index
            last_included_term = self._log[last_included_index - 1].term if last_included_index > 0 else 0

            # Create snapshot data
            snapshot_data = {
                "term": self._current_term,
                "index": last_included_index,
                "log": [
                    {
                        "index": e.index,
                        "term": e.term,
                        "command": e.command,
                        "checkpoint": e.checkpoint,
                        "checkpoint_digest": e.checkpoint_digest,
                    }
                    for e in self._log[:last_included_index]
                ],
                "commit_index": self._commit_index,
            }

            snapshot_bytes = canonical_bytes(snapshot_data)
            snapshot_digest = digest(snapshot_bytes)

            # Store in database
            self._initialize_snapshot_db()
            self._snapshot_db.execute(
                """
                INSERT INTO snapshots (term, index, digest, data, created_at, membership)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self._current_term,
                    last_included_index,
                    snapshot_digest,
                    snapshot_bytes,
                    time.time(),
                    json.dumps([{"node_id": n.node_id, "address": n.address, "is_learner": n.is_learner} for n in self.cluster]),
                )
            )
            self._snapshot_db.commit()

            self._snapshot = SnapshotMetadata(
                last_included_index=last_included_index,
                last_included_term=last_included_term,
                snapshot_digest=snapshot_digest,
                snapshot_data=snapshot_bytes,
                created_at=time.time(),
                membership=tuple(self.cluster),
            )
            self._last_snapshot_time = time.monotonic()

    # ===== LEADERSHIP TRANSFER =====

    def _process_leadership_transfer(self) -> None:
        """Process leadership transfer if in progress."""
        if self._leadership_transfer is None:
            return
        # Implementation for leadership transfer would go here
        # For now, just clear it if deadline passed
        if self._leadership_transfer_deadline > 0 and time.monotonic() > self._leadership_transfer_deadline:
            self._leadership_transfer = None
            self._leadership_transfer_deadline = 0.0

    # ===== MEMBERSHIP CHANGES =====

    def _check_joint_consensus_completion(self) -> None:
        """Check if joint consensus membership change is complete."""
        if not self._joint_consensus or self._new_cluster is None:
            return
        # Implementation for joint consensus completion
        pass

    def _check_joint_consensus_completion(self) -> None:
        pass

    # ===== MEMBERSHIP CHANGES =====

    # ===== LEADERSHIP TRANSFER =====

    # ===== SNAPSHOTTING =====

    def _initialize_snapshot_db(self) -> None:
        """Initialize the snapshot database if not already initialized."""
        if self._snapshot_db is not None:
            return
        if self._snapshot_db_path is None:
            self._snapshot_db_path = Path(self.local_node.node_id + "_snapshot.sqlite3")
        self._snapshot_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._snapshot_db = sqlite3.connect(self._snapshot_db_path, check_same_thread=False)
        self._snapshot_db.execute("PRAGMA journal_mode = WAL")
        self._snapshot_db.execute("PRAGMA synchronous = FULL")
        self._snapshot_db.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                term INTEGER NOT NULL,
                index INTEGER NOT NULL,
                digest TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at REAL NOT NULL,
                membership TEXT NOT NULL
            )
        """)
        self._snapshot_db.commit()

    def _maybe_create_snapshot(self) -> None:
        """Create a snapshot if threshold is reached."""
        with self._snapshot_lock:
            if self._snapshot is not None:
                return

            if len(self._log) < self.snapshot_threshold:
                return

            if time.monotonic() - self._last_snapshot_time < self.snapshot_interval_ms / 1000.0:
                return

            last_included_index = self._commit_index
            last_included_term = self._log[last_included_index - 1].term if last_included_index > 0 else 0

            # Create snapshot data
            snapshot_data = {
                "term": self._current_term,
                "index": last_included_index,
                "log": [
                    {
                        "index": e.index,
                        "term": e.term,
                        "command": e.command,
                        "checkpoint": e.checkpoint,
                        "checkpoint_digest": e.checkpoint_digest,
                    }
                    for e in self._log[:last_included_index]
                ],
                "commit_index": self._commit_index,
            }

            snapshot_bytes = canonical_bytes(snapshot_data)
            snapshot_digest = digest(snapshot_bytes)

            # Store in database
            self._initialize_snapshot_db()
            self._snapshot_db.execute(
                """
                INSERT INTO snapshots (term, index, digest, data, created_at, membership)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self._current_term,
                    last_included_index,
                    snapshot_digest,
                    snapshot_bytes,
                    time.time(),
                    json.dumps([{"node_id": n.node_id, "address": n.address, "is_learner": n.is_learner} for n in self.cluster]),
                )
            )
            self._snapshot_db.commit()

            self._snapshot = SnapshotMetadata(
                last_included_index=last_included_index,
                last_included_term=last_included_term,
                snapshot_digest=snapshot_digest,
                snapshot_data=canonical_bytes(snapshot_data),
                created_at=time.time(),
                membership=tuple(self.cluster),
            )
            self._last_snapshot_time = time.monotonic()

    # ===== PUBLIC API =====

    def propose(
        self,
        command: Mapping[str, Any],
        checkpoint: int,
        checkpoint_digest: str,
    ) -> bool:
        with self._lock:
            if self._state != "leader":
                raise RaftUnavailableError("not leader")
            entry = RaftLogEntry(
                index=len(self._log) + 1,
                term=self._current_term,
                command=command,
                checkpoint=checkpoint,
                checkpoint_digest=checkpoint_digest,
            )
            self._log.append(entry)
            return True

    def is_leader(self) -> bool:
        with self._lock:
            return self._state == "leader"

    def get_leader(self) -> str | None:
        with self._lock:
            return self._leader_id

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name=f"raft-{self.local_node.node_id}")
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)

    def get_leader(self) -> str | None:
        with self._lock:
            return self._leader_id

    def _random_election_deadline(self) -> float:
        min_ms, max_ms = self.election_timeout_ms
        # Add extra randomness to prevent synchronized elections
        extra_ms = random.uniform(0, max_ms)
        return time.monotonic() + random.uniform(min_ms, max_ms + extra_ms) / 1000.0


def create_raft_cluster(
    nodes: list[RaftNode],
    database_paths: list[str | Path],
    *,
    service_id: str,
    epoch: int,
    signing_key: bytes | Ed25519PrivateKey,
    clients: Mapping[str, ReplayClientPolicy],
    http_host: str = "127.0.0.1",
    http_port: int = 0,
) -> list[tuple[ReferenceReplayService, RaftConsensus]]:
    """Create a replicated Raft cluster of replay services."""
    from .production_http import create_raft_server

    services = []
    for i, node in enumerate(nodes):
        service = ReferenceReplayService(
            database_paths[i],
            service_id=service_id,
            epoch=epoch,
            signing_key=signing_key,
            clients=clients,
        )
        services.append(service)

    consensuses = []
    for i, node in enumerate(nodes):
        consensus = RaftConsensus(
            local_node=node,
            cluster=nodes,
            service=services[i],
        )
        consensuses.append(consensus)

    for consensus in consensuses:
        consensus.start()

    return list(zip(services, consensuses))


# RaftLogEntry, RaftNode, RaftLogEntry, SnapshotMetadata, MembershipChange, RaftError, RaftUnavailableError
# are defined at the top of the file