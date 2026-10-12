"""Supervisor-only reconciliation of confirmed recipient commits.

Positive confirmations are supported. Absence of an entry is NOT proof an
in-flight operation cannot commit later; this module never releases a
reservation or requests another effect dispatch. Host-owned SQLite recipient
data is opened read-only and independently checked against the pinned journal.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat

from event_horizon.canonical import digest
from event_horizon.effect_outcome_journal import DurableEffectJournal, EffectJournalError


class RecipientReconciliationError(RuntimeError):
    pass


def reconcile_durable_commit(*, recipient_database: str | Path,
                             journal: DurableEffectJournal,
                             tenant: str, environment: str, effect_key: str,
                             capability_id: str, request_digest: str,
                             claims_digest: str) -> dict:
    """Confirm a recorded effect ONLY after direct trusted-recipient inspection.

    Returns a verified receipt digest, not an instruction to re-dispatch.
    This local-fixture recipient is not a remote independent witness.
    """
    path = Path(recipient_database)
    if not path.is_absolute():
        raise RecipientReconciliationError("recipient database path must be absolute")
    try:
        info = os.lstat(path)
        directory = os.lstat(path.parent)
    except OSError as exc:
        raise RecipientReconciliationError("recipient database does not exist") from exc
    uid = os.geteuid()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
            or info.st_mode & 0o077 or info.st_nlink != 1
            or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
            or directory.st_mode & 0o022):
        raise RecipientReconciliationError("recipient database is not private to supervisor")
    try:
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            rows = db.execute(
                "SELECT effect_key, request_digest FROM commits ORDER BY id"
            ).fetchall()
    except sqlite3.Error as exc:
        raise RecipientReconciliationError("recipient ledger cannot be independently read") from exc
    if len(rows) != 1 or rows[0] != (effect_key, request_digest):
        raise RecipientReconciliationError("recipient commit absent, duplicated, or rebound")
    reservation = journal.observe(
        tenant=tenant, environment=environment, capability_id=capability_id,
    )
    if (reservation is None or reservation["request_digest"] != request_digest
            or reservation["claims_digest"] != claims_digest):
        raise RecipientReconciliationError("recipient commit is not bound to journal")
    receipt_digest = digest([list(row) for row in rows])
    journal.confirm_from_trusted_recipient(
        tenant=tenant, environment=environment, effect_key=effect_key,
        capability_id=capability_id, request_digest=request_digest,
        claims_digest=claims_digest, receipt_digest=receipt_digest,
    )
    result = journal.observe(
        tenant=tenant, environment=environment, capability_id=capability_id,
    )
    if (result is None or result["state"] != "recipient-confirmed"
            or result["receipt_digest"] != receipt_digest):
        raise EffectJournalError("durable recipient confirmation not acknowledged")
    return {"state": "recipient-confirmed", "receipt_digest": receipt_digest,
            "recipient_commit_count": len(rows)}
