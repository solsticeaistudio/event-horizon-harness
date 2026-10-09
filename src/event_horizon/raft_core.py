"""Fixed-membership, deterministic Raft research core with durable hard state.

**NOT a production distributed authority**: this in-process RPC model intentionally
has no authenticated network transport, membership changes, snapshots, read-index
protocol, or adversarial process isolation. It is a runnable foundation for a
formalized, crash-fault Raft implementation, independent of the quarantined
legacy raft_replay.py. Use etcd for production distributed authority.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest
from .replay_state import CapabilityConsumptionError, _validate_transition


class RaftCoreUnavailable(RuntimeError):
    """A quorum-authorized transition could not be established."""


class RaftCoreError(RuntimeError):
    """An invalid or contradictory consensus transition was attempted."""


class DurableRaftNode:
    """Persisted term/vote/log, quorum commits and deterministic replay state.

    Each peer is a DurableRaftNode only for the deterministic fault laboratory.
    No external effects are applied inside the replicated state machine.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        node_id: str,
        member_ids: tuple[str, ...],
    ) -> None:
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("Raft node identity required")
        if (
            not isinstance(member_ids, tuple)
            or len(member_ids) % 2 != 1
            or len(member_ids) < 3
            or len(set(member_ids)) != len(member_ids)
            or node_id not in member_ids
            or any(not isinstance(v, str) or not v for v in member_ids)
        ):
            raise ValueError("Raft laboratory requires a fixed odd-sized cluster >=3")
        self.node_id = node_id
        self.members = member_ids
        self._lock = threading.RLock()
        self._path = Path(path).resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("PRAGMA trusted_schema = OFF")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS hard_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS raft_log "
            "(idx INTEGER PRIMARY KEY, term INTEGER NOT NULL, command BLOB NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS replay_results "
            "(idx INTEGER PRIMARY KEY, result TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS consumed "
            "(scope TEXT NOT NULL, token TEXT NOT NULL, binding TEXT NOT NULL, expiry INTEGER NOT NULL,"
            " PRIMARY KEY(scope, token))"
        )
        expected_membership = digest({"cluster": list(member_ids)})
        old_membership = self._state("membership", None)
        if old_membership is not None and old_membership != expected_membership:
            raise RaftCoreError("durable Raft membership mismatch on restart")
        self._set("membership", expected_membership)
        self.term = int(self._state("term", "0"))
        self.voted_for = self._state("voted_for", "")
        self.commit_index = int(self._state("commit_index", "0"))
        self.applied_index = int(self._state("applied_index", "0"))
        self.role = "follower"
        self.leader_id: str | None = None
        self.peers: dict[str, DurableRaftNode] = {}
        self._next: dict[str, int] = {}
        self._match: dict[str, int] = {}
        if not (0 <= self.applied_index <= self.commit_index <= self.last_index):
            raise RaftCoreError("durable Raft checkpoint is invalid")
        self._apply_committed()

    def connect(self, peers: Mapping[str, "DurableRaftNode"]) -> None:
        with self._lock:
            if set(peers) != set(self.members) - {self.node_id}:
                raise ValueError("Raft peers must match pinned membership")
            if any(peer.node_id != key for key, peer in peers.items()):
                raise ValueError("Raft peer identities mismatch")
            self.peers = dict(peers)

    def _state(self, name: str, default: str | None) -> str | None:
        result = self._db.execute(
            "SELECT value FROM hard_state WHERE key = ?", (name,)
        ).fetchone()
        return default if result is None else result[0]

    def _set(self, name: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO hard_state(key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (name, value)
        )

    @property
    def last_index(self) -> int:
        return int(self._db.execute("SELECT COALESCE(MAX(idx), 0) FROM raft_log").fetchone()[0])

    def _entry(self, index: int) -> tuple[int, dict[str, Any]] | None:
        if index == 0:
            return 0, {}
        row = self._db.execute(
            "SELECT term, command FROM raft_log WHERE idx = ?", (index,)
        ).fetchone()
        if row is None:
            return None
        return int(row[0]), json.loads(row[1])

    def _last_term(self) -> int:
        entry = self._entry(self.last_index)
        return entry[0] if entry is not None else 0

    def _step_down(self, new_term: int, leader: str | None = None) -> None:
        if new_term < self.term:
            raise RaftCoreError("cannot roll back Raft term")
        if new_term > self.term:
            self.term = new_term
            self.voted_for = ""
            with self._db:
                self._set("term", str(self.term))
                self._set("voted_for", "")
        self.role = "follower"
        self.leader_id = leader

    def request_vote(
        self, term: int, candidate_id: str,
        last_log_index: int, last_log_term: int,
    ) -> tuple[int, bool]:
        with self._lock:
            if candidate_id not in self.members or candidate_id == self.node_id:
                return self.term, False
            if term < self.term:
                return self.term, False
            if term > self.term:
                self._step_down(term)
            up_to_date = (last_log_term, last_log_index) >= (self._last_term(), self.last_index)
            granted = up_to_date and self.voted_for in ("", candidate_id)
            if granted:
                with self._db:
                    self.voted_for = candidate_id
                    self._set("voted_for", candidate_id)
            return self.term, granted

    def elect(self) -> bool:
        """Start one explicit deterministic election (no network timeouts)."""
        with self._lock:
            self._step_down(self.term + 1)
            self.role = "candidate"
            self.voted_for = self.node_id
            self._set("voted_for", self.node_id)
            election_term = self.term
            last_idx, last_term = self.last_index, self._last_term()
        votes = 1
        for peer in self.peers.values():
            try:
                their_term, grant = peer.request_vote(
                    election_term, self.node_id, last_idx, last_term
                )
            except (OSError, RaftCoreUnavailable):
                continue
            with self._lock:
                if their_term > self.term:
                    self._step_down(their_term)
                    return False
                if self.term != election_term or self.role != "candidate":
                    return False
                votes += int(grant)
        with self._lock:
            if votes <= len(self.members) // 2:
                return False
            self.role = "leader"
            self.leader_id = self.node_id
            self._next = {i: self.last_index + 1 for i in self.peers}
            self._match = {i: 0 for i in self.peers}
            return True

    def append_entries(
        self,
        term: int,
        leader_id: str,
        prev_index: int,
        prev_term: int,
        entries: list[dict[str, Any]],
        leader_commit: int,
    ) -> tuple[int, bool, int]:
        with self._lock:
            if leader_id not in self.members or leader_id == self.node_id:
                return self.term, False, self.last_index
            if term < self.term:
                return self.term, False, self.last_index
            if term > self.term or self.role != "follower":
                self._step_down(term, leader_id)
            else:
                self.leader_id = leader_id
            prev = self._entry(prev_index)
            if prev is None or prev[0] != prev_term:
                return self.term, False, self.last_index
            cursor = prev_index
            for item in entries:
                if (
                    not isinstance(item, Mapping)
                    or type(item.get("index")) is not int
                    or type(item.get("term")) is not int
                    or item["term"] < 1
                    or item["index"] != cursor + 1
                    or not isinstance(item.get("command"), Mapping)
                ):
                    raise RaftCoreError("invalid replicated Raft log entry")
                cursor = item["index"]
            with self._db:
                for item in entries:
                    index = item["index"]
                    old = self._entry(index)
                    value = dict(item["command"])
                    if old is not None and (old[0] != item["term"] or old[1] != value):
                        if index <= self.commit_index:
                            raise RaftCoreError("attempted truncation of committed log")
                        self._db.execute("DELETE FROM raft_log WHERE idx >= ?", (index,))
                        old = None
                    if old is None:
                        self._db.execute(
                            "INSERT INTO raft_log(idx,term,command) VALUES (?,?,?)",
                            (index, item["term"], canonical_bytes(value)),
                        )
                if leader_commit > self.commit_index:
                    self.commit_index = min(leader_commit, self.last_index)
                    self._set("commit_index", str(self.commit_index))
                self._apply_committed()
            return self.term, True, cursor

    def _apply_committed(self) -> None:
        """Replay authoritative consumption and checkpoint in one DB transaction."""
        with self._db:
            while self.applied_index < self.commit_index:
                idx = self.applied_index + 1
                entry = self._entry(idx)
                if entry is None:
                    raise RaftCoreError("committed Raft entry missing")
                _, command = entry
                if command.get("op") == "noop":
                    result = "noop"
                elif command.get("op") == "consume":
                    scope = command["scope"]
                    token = command["capability_id"]
                    binding = command["claims_digest"]
                    expiry = command["expires_at"]
                    _validate_transition(
                        token, binding, expiry, command["consumed_at"]
                    )
                    inserted = self._db.execute(
                        "INSERT INTO consumed(scope,token,binding,expiry) VALUES (?,?,?,?) "
                        "ON CONFLICT(scope,token) DO NOTHING",
                        (scope, token, binding, expiry),
                    ).rowcount
                    existing = self._db.execute(
                        "SELECT binding, expiry FROM consumed WHERE scope=? AND token=?",
                        (scope, token),
                    ).fetchone()
                    if existing != (binding, expiry):
                        result = "collision"
                    else:
                        result = "fresh" if inserted == 1 else "duplicate"
                else:
                    raise RaftCoreError("unrecognized committed command")
                self._db.execute(
                    "INSERT OR IGNORE INTO replay_results(idx,result) VALUES (?,?)",
                    (idx, result),
                )
                self.applied_index = idx
                self._set("applied_index", str(idx))

    def _replicate(self, peer_id: str) -> None:
        """Synchronous append with bounded conflicting-log backtracking."""
        peer = self.peers[peer_id]
        for _ in range(self.last_index + 1):
            with self._lock:
                if self.role != "leader":
                    return
                next_idx = self._next.get(peer_id, self.last_index + 1)
                previous = self._entry(next_idx - 1)
                if previous is None:
                    raise RaftCoreError("leader log has a gap")
                entries = []
                for idx in range(next_idx, self.last_index + 1):
                    item = self._entry(idx)
                    if item is None:
                        raise RaftCoreError("leader log has a gap")
                    entries.append({"index": idx, "term": item[0], "command": item[1]})
                term = self.term
                committed = self.commit_index
            try:
                peer_term, accepted, match_idx = peer.append_entries(
                    term, self.node_id, next_idx - 1, previous[0],
                    entries, committed,
                )
            except (OSError, RaftCoreUnavailable):
                return
            with self._lock:
                if peer_term > self.term:
                    self._step_down(peer_term)
                    return
                if self.role != "leader" or self.term != term:
                    return
                if accepted:
                    self._match[peer_id] = match_idx
                    self._next[peer_id] = match_idx + 1
                    return
                if next_idx <= 1:
                    return
                self._next[peer_id] = next_idx - 1

    def propose(self, command: Mapping[str, Any]) -> bool:
        """Commit a one-use consume command through quorum before acknowledging."""
        if (
            command.get("op") != "consume"
            or not isinstance(command.get("scope"), str)
            or not command["scope"]
        ):
            raise ValueError("only scoped consumption commands are allowed")
        _validate_transition(
            command["capability_id"], command["claims_digest"],
            command["expires_at"], command["consumed_at"],
        )
        with self._lock:
            if self.role != "leader":
                raise RaftCoreUnavailable("Raft node is not leader")
            position = self.last_index + 1
            with self._db:
                self._db.execute(
                    "INSERT INTO raft_log(idx,term,command) VALUES (?,?,?)",
                    (position, self.term, canonical_bytes(dict(command))),
                )
        for peer_id in self.peers:
            self._replicate(peer_id)
        with self._lock:
            if self.role != "leader":
                raise RaftCoreUnavailable("Raft leader lost term during proposal")
            matched = 1 + sum(int(idx >= position) for idx in self._match.values())
            if matched <= len(self.members) // 2:
                raise RaftCoreUnavailable("Raft proposal not durably acknowledged by quorum")
            with self._db:
                self.commit_index = position
                self._set("commit_index", str(position))
                self._apply_committed()
            row = self._db.execute(
                "SELECT result FROM replay_results WHERE idx = ?", (position,)
            ).fetchone()
        # Commit notifications do not affect the already quorum-backed decision.
        for peer_id in self.peers:
            self._replicate(peer_id)
        if row[0] == "collision":
            raise CapabilityConsumptionError("capability ID collided with different signed claims")
        return row[0] == "fresh"

    def known_consumption(self, scope: str, capability_id: str) -> tuple[str, int] | None:
        """Local observation ONLY: not a linearizable quorum read."""
        with self._lock:
            row = self._db.execute(
                "SELECT binding, expiry FROM consumed WHERE scope=? AND token=?",
                (scope, capability_id),
            ).fetchone()
            return (str(row[0]), int(row[1])) if row else None

    def close(self) -> None:
        with self._lock:
            self._db.close()
