"""Effect Gateway: governed mediation of externally meaningful effects.

Trust topology::

    Executor -> Effect Gateway -> Provider Adapter -> External System

Invariants enforced here:

* **Durable intent before dispatch.** No provider invocation happens before
  an intent record (and its signed statement) is durably persisted.
* **Immutable idempotency identity.** The idempotency key is derived from the
  canonical effect request; retries after timeout/response loss reuse exactly
  the same identity, so a retry can never become a second logical effect.
* **Uncertainty stays uncertain.** Once dispatch starts, a missing or failed
  response is recorded as ``indeterminate`` — never as ``not committed``.
* **Signed gateway statements.** Intents, receipts, and reconciliations are
  independently signed under explicit domains, so certificates need not trust
  executor output for final effect state.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical import canonical_bytes, digest
from .execution_state import ExecutionStateError
from .statements import (
    StatementError,
    StatementSigner,
    TYPE_EFFECT_INTENT,
    TYPE_EFFECT_RECEIPT,
    TYPE_EFFECT_RECONCILIATION,
)


EFFECT_REQUEST_SCHEMA = "event-horizon.effect-request.v2"

# Provider-facing outcome vocabulary.
PROVIDER_COMMITTED = "committed"
PROVIDER_FAILED = "provider-failed"
PROVIDER_CONFIRMED_NOT_EXECUTED = "confirmed-not-executed"
PROVIDER_UNKNOWN = "unknown"
PROVIDER_UNANSWERABLE = "provider-cannot-answer"
PROVIDER_OUTCOMES = frozenset({
    PROVIDER_COMMITTED,
    PROVIDER_FAILED,
    PROVIDER_CONFIRMED_NOT_EXECUTED,
    PROVIDER_UNKNOWN,
    PROVIDER_UNANSWERABLE,
})

# Trust classification of the evidence behind a provider answer. The gateway
# never upgrades this classification itself: only adapters that preserve
# provider-supplied cryptographic evidence may claim stronger classes.
EVIDENCE_UNVERIFIED_ADAPTER_REPORT = "unverified_adapter_report"
EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT = "provider_authenticated_receipt"
EVIDENCE_PROVIDER_QUERY_RECONCILIATION = "provider_query_reconciliation"
EVIDENCE_PROVIDER_IDEMPOTENCY_CONFIRMATION = "provider_idempotency_confirmation"
PROVIDER_EVIDENCE_CLASSES = frozenset({
    EVIDENCE_UNVERIFIED_ADAPTER_REPORT,
    EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT,
    EVIDENCE_PROVIDER_QUERY_RECONCILIATION,
    EVIDENCE_PROVIDER_IDEMPOTENCY_CONFIRMATION,
})

# Gateway lifecycle states.
GATEWAY_AUTHORIZED = "authorized"
GATEWAY_INTENT_DURABLE = "intent_durable"
GATEWAY_DISPATCH_STARTED = "dispatch_started"
GATEWAY_PROVIDER_ACKNOWLEDGED = "provider_acknowledged"
GATEWAY_POSSIBLY_COMMITTED = "possibly_committed"
GATEWAY_COMMITTED = "committed"
GATEWAY_CONFIRMED_NOT_COMMITTED = "confirmed_not_committed"
GATEWAY_INDETERMINATE = "indeterminate"
GATEWAY_RECONCILED = "reconciled"

_TRANSITIONS: dict[str, frozenset[str]] = {
    GATEWAY_AUTHORIZED: frozenset({GATEWAY_INTENT_DURABLE}),
    GATEWAY_INTENT_DURABLE: frozenset({GATEWAY_DISPATCH_STARTED}),
    GATEWAY_DISPATCH_STARTED: frozenset({
        GATEWAY_PROVIDER_ACKNOWLEDGED,
        GATEWAY_POSSIBLY_COMMITTED,
        GATEWAY_INDETERMINATE,
    }),
    # An acknowledgement from the provider is positive evidence only when it
    # carries a success outcome; failures land in confirmed_not_committed via
    # reconciliation instead.
    GATEWAY_PROVIDER_ACKNOWLEDGED: frozenset({
        GATEWAY_COMMITTED,
        GATEWAY_INDETERMINATE,
    }),
    GATEWAY_POSSIBLY_COMMITTED: frozenset({GATEWAY_INDETERMINATE, GATEWAY_RECONCILED}),
    GATEWAY_COMMITTED: frozenset({GATEWAY_RECONCILED}),
    GATEWAY_CONFIRMED_NOT_COMMITTED: frozenset({GATEWAY_RECONCILED}),
    GATEWAY_INDETERMINATE: frozenset({GATEWAY_RECONCILED}),
    GATEWAY_RECONCILED: frozenset(),
}
TERMINAL_GATEWAY_STATES = frozenset({GATEWAY_RECONCILED})

REQUEST_FIELDS = {
    "schema",
    "deployment_id",
    "environment",
    "run_id",
    "session_id",
    "execution_id",
    "effect_id",
    "provider_scope",
    "capability_id",
    "request_digest",
    "operation",
    "arguments_digest",
    "authorization_digest",
    "policy_digest",
    "executor_identity",
}

# Logical effect identity: WHICH intended side effect this is. Retries of the
# same logical effect reuse these fields verbatim; two intentional effects
# always differ in at least effect_id/execution_id.
EFFECT_IDENTITY_FIELDS = (
    "deployment_id",
    "run_id",
    "session_id",
    "execution_id",
    "effect_id",
    "provider_scope",
)
# Effect fingerprint: WHAT the effect does. Deliberately excluded from the
# idempotency identity so identical semantics under a new logical identity are
# independent effects, and changed semantics under an existing identity become
# detectable collisions instead of silently forking a new key.
EFFECT_FINGERPRINT_FIELDS = ("operation", "arguments_digest")

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CAPABILITY_ID = re.compile(r"^(?:cap|canary)_[0-9a-f]{24}$")
_EXECUTION_ID = re.compile(r"^exec_[0-9a-f]{32}$")
_EFFECT_ID = re.compile(r"^eff_[0-9a-f]{32}$")


class EffectGatewayError(RuntimeError):
    pass


class EffectRequestError(EffectGatewayError):
    pass


class EffectIdentityCollision(EffectGatewayError):
    """Same logical identity presented with different effect content."""


def new_execution_id() -> str:
    import secrets

    return f"exec_{secrets.token_hex(16)}"


def new_effect_id() -> str:
    import secrets

    return f"eff_{secrets.token_hex(16)}"


class EffectRequest:
    """Validated request for one governed effect.

    The idempotency identity is derived ONLY from the logical-identity fields.
    Operation and arguments form a separate fingerprint that travels with the
    request and is enforced at the gateway: an identity may never be reused
    with different semantic content, and identical content under a fresh
    identity is a genuinely new effect.
    """

    __slots__ = ("fields", "idempotency_key", "fingerprint")

    def __init__(self, fields: Mapping[str, Any]) -> None:
        if not isinstance(fields, Mapping) or set(fields) != REQUEST_FIELDS:
            raise EffectRequestError("effect request fields are invalid")
        if fields["schema"] != EFFECT_REQUEST_SCHEMA:
            raise EffectRequestError(
                f"unsupported effect request schema: {fields['schema']!r}"
            )
        for name in ("deployment_id", "environment", "run_id", "session_id", "operation"):
            value = fields[name]
            if not isinstance(value, str) or not value or len(value) > 256:
                raise EffectRequestError(f"effect request {name} is invalid")
        if _SCOPE.fullmatch(str(fields["deployment_id"])) is None:
            raise EffectRequestError("deployment ID is malformed")
        if _SCOPE.fullmatch(str(fields["provider_scope"])) is None:
            raise EffectRequestError("provider scope is malformed")
        if not isinstance(fields["executor_identity"], str) or not fields["executor_identity"]:
            raise EffectRequestError("executor identity is required")
        if (
            not isinstance(fields["capability_id"], str)
            or _CAPABILITY_ID.fullmatch(fields["capability_id"]) is None
        ):
            raise EffectRequestError("effect request capability ID is malformed")
        execution_id = fields["execution_id"]
        if not isinstance(execution_id, str) or _EXECUTION_ID.fullmatch(execution_id) is None:
            raise EffectRequestError("execution ID is malformed")
        effect_id = fields["effect_id"]
        if not isinstance(effect_id, str) or _EFFECT_ID.fullmatch(effect_id) is None:
            raise EffectRequestError("effect ID is malformed")
        for name in ("request_digest", "arguments_digest", "policy_digest"):
            value = fields[name]
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise EffectRequestError(f"effect request {name} must be a SHA-256 digest")
        authorization = fields["authorization_digest"]
        if authorization is not None and (
            not isinstance(authorization, str) or _DIGEST.fullmatch(authorization) is None
        ):
            raise EffectRequestError("authorization digest is malformed")
        self.fields: dict[str, Any] = dict(fields)
        # Logical identity only: retries share it; new intents cannot collide
        # with prior ones merely because their contents look alike.
        self.idempotency_key = digest({
            name: self.fields[name] for name in EFFECT_IDENTITY_FIELDS
        })
        self.fingerprint = digest({
            name: self.fields[name] for name in EFFECT_FINGERPRINT_FIELDS
        })

    @property
    def execution_id(self) -> str:
        return self.fields["execution_id"]

    @property
    def effect_id(self) -> str:
        return self.fields["effect_id"]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.fields)


@dataclass(frozen=True)
class ProviderResult:
    """One provider adapter answer."""

    state: str
    receipt_digest: str | None = None
    detail: Mapping[str, Any] | None = None
    evidence_class: str = EVIDENCE_UNVERIFIED_ADAPTER_REPORT
    provider_receipt_envelope: Mapping[str, Any] | None = None


class ProviderAdapter(Protocol):
    """Contract for mediated providers.

    ``execute`` receives the immutable idempotency key; retries MUST reuse it.
    ``reconcile`` asks the provider what actually happened for that key and
    must distinguish confirmed-absence from ignorance.
    """

    def execute(
        self, effect_request: Mapping[str, Any], idempotency_key: str
    ) -> ProviderResult: ...

    def reconcile(self, idempotency_key: str) -> ProviderResult: ...


class SimulatedEffectProvider:
    """Deterministic provider modelling failure modes for adversarial tests.

    Scenarios are keyed by operation:

    * ``commit`` — execute once per idempotency key; duplicates return the
      original result without re-executing (true idempotency);
    * ``timeout-then-commit`` — first call raises TimeoutError but commits;
      reconciliation reveals the truth;
    * ``commit-lose-response`` — commits and returns unknown;
    * ``ambiguous`` — commits but reports inconsistent state until reconciled;
    * ``reject`` — positively confirms non-execution;
    * ``crash-after-commit`` — raises after committing (simulated crash).

    When ``signing_key`` is supplied the provider cryptographically
    authenticates its receipts (a stand-in for real providers exposing signed
    transaction evidence); answers then carry the
    ``provider_authenticated_receipt`` evidence class instead of
    ``unverified_adapter_report``.
    """

    def __init__(
        self,
        *,
        provider_id: str = "simulated-provider",
        signing_key: bytes | None = None,
    ) -> None:
        self.provider_id = provider_id
        self.scenarios: dict[str, str] = {}
        self._receipt_signer = (
            StatementSigner(signing_key, subject=f"provider:{provider_id}")
            if signing_key is not None
            else None
        )
        self._lock = threading.RLock()
        self._executions: dict[str, dict[str, Any]] = {}

    def configure(self, operation: str, scenario: str) -> None:
        self.scenarios[operation] = scenario

    def _receipt_digest(self, key: str) -> str:
        return digest({"provider": self.provider_id, "idempotency_key": key})

    def _evidence(self, key: str, receipt_digest: str) -> tuple[str, Mapping[str, Any] | None]:
        if self._receipt_signer is None or not receipt_digest:
            return EVIDENCE_UNVERIFIED_ADAPTER_REPORT, None
        envelope = self._receipt_signer.sign(
            "provider-receipt",
            {
                "provider_id": self.provider_id,
                "idempotency_key": key,
                "transaction_receipt_digest": receipt_digest,
                "issued_at_ms": time.time_ns() // 1_000_000,
            },
        ).to_dict()
        return EVIDENCE_PROVIDER_AUTHENTICATED_RECEIPT, envelope

    def execute(
        self, effect_request: Mapping[str, Any], idempotency_key: str
    ) -> ProviderResult:
        scenario = self.scenarios.get(str(effect_request.get("operation")), "commit")
        with self._lock:
            existing = self._executions.get(idempotency_key)
            if existing is not None and existing["executed"]:
                # Idempotent replay of the same logical effect.
                evidence_class, envelope = self._evidence(
                    idempotency_key, existing.get("receipt_digest") or ""
                )
                return ProviderResult(
                    state=PROVIDER_COMMITTED,
                    receipt_digest=existing.get("receipt_digest"),
                    detail={"duplicate": True},
                    evidence_class=evidence_class,
                    provider_receipt_envelope=envelope,
                )
            if scenario == "reject":
                return ProviderResult(
                    state=PROVIDER_CONFIRMED_NOT_EXECUTED,
                    detail={"reason": "rejected by policy"},
                )
            if scenario == "timeout-then-commit":
                self._executions[idempotency_key] = {
                    "executed": True,
                    "receipt_digest": self._receipt_digest(idempotency_key),
                    "response_lost": True,
                }
                raise TimeoutError("simulated response loss after commit")
            if scenario in {"commit-lose-response", "ambiguous"}:
                self._executions[idempotency_key] = {
                    "executed": True,
                    "receipt_digest": self._receipt_digest(idempotency_key),
                    "ambiguous": scenario == "ambiguous",
                }
                return ProviderResult(state=PROVIDER_UNKNOWN, detail={"scenario": scenario})
            if scenario == "crash-after-commit":
                self._executions[idempotency_key] = {
                    "executed": True,
                    "receipt_digest": self._receipt_digest(idempotency_key),
                    "crashed": True,
                }
                raise RuntimeError("simulated provider crash after commit")
            # Default: clean commit.
            receipt_digest = self._receipt_digest(idempotency_key)
            self._executions[idempotency_key] = {
                "executed": True,
                "receipt_digest": receipt_digest,
            }
            evidence_class, envelope = self._evidence(idempotency_key, receipt_digest)
            return ProviderResult(
                state=PROVIDER_COMMITTED,
                receipt_digest=receipt_digest,
                evidence_class=evidence_class,
                provider_receipt_envelope=envelope,
            )

    def reconcile(self, idempotency_key: str) -> ProviderResult:
        with self._lock:
            record = self._executions.get(idempotency_key)
            if record is None:
                return ProviderResult(
                    state=PROVIDER_CONFIRMED_NOT_EXECUTED,
                    detail={"reason": "no such execution at the provider"},
                )
            evidence_class, envelope = self._evidence(
                idempotency_key, record.get("receipt_digest") or ""
            )
            if record.get("crashed") or record.get("response_lost"):
                return ProviderResult(
                    state=PROVIDER_COMMITTED,
                    receipt_digest=record["receipt_digest"],
                    detail={"reconciled": True},
                    evidence_class=evidence_class,
                    provider_receipt_envelope=envelope,
                )
            if record.get("ambiguous"):
                return ProviderResult(
                    state=PROVIDER_UNKNOWN,
                    detail={"reason": "provider cannot determine outcome"},
                )
            return ProviderResult(
                state=PROVIDER_COMMITTED,
                receipt_digest=record.get("receipt_digest"),
                detail={"reconciled": True},
                evidence_class=evidence_class,
                provider_receipt_envelope=envelope,
            )


class EffectIntentStore(Protocol):
    """Durable storage for gateway lifecycle records."""

    def save(self, record: Mapping[str, Any]) -> None: ...

    def load(self, idempotency_key: str) -> Mapping[str, Any] | None: ...


class SqliteEffectIntentStore:
    """Single-host durable store; WAL + FULL synchronous like sibling stores."""

    SCHEMA_VERSION = 1

    def __init__(self, database_path: str | os.PathLike[str]) -> None:
        path = Path(database_path)
        if str(path) == ":memory:":
            raise ValueError("effect intent store must be durable")
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        database = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        try:
            database.execute("PRAGMA journal_mode = WAL")
            database.execute("PRAGMA synchronous = FULL")
            database.execute("PRAGMA trusted_schema = OFF")
            database.execute(
                """
                CREATE TABLE IF NOT EXISTS effect_intents (
                    idempotency_key TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL
                ) WITHOUT ROWID
                """
            )
        finally:
            database.close()
        if os.name != "nt":
            path.chmod(0o600)

    def save(self, record: Mapping[str, Any]) -> None:
        encoded = json.dumps(dict(record), sort_keys=True, separators=(",", ":"))
        with self._lock:
            database = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            try:
                database.execute("BEGIN IMMEDIATE")
                database.execute(
                    """
                    INSERT INTO effect_intents (idempotency_key, record_json)
                    VALUES (?, ?)
                    ON CONFLICT(idempotency_key) DO UPDATE SET record_json = excluded.record_json
                    """,
                    (record["idempotency_key"], encoded),
                )
                database.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    database.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise EffectGatewayError("effect intent persistence failed closed") from exc
            finally:
                database.close()

    def load(self, idempotency_key: str) -> Mapping[str, Any] | None:
        with self._lock:
            database = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
            try:
                row = database.execute(
                    "SELECT record_json FROM effect_intents WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
            finally:
                database.close()
        return json.loads(row[0]) if row else None


class EffectGateway:
    """Mediates every externally meaningful effect for one deployment."""

    def __init__(
        self,
        *,
        gateway_id: str,
        statement_signer: StatementSigner,
        intent_store: EffectIntentStore,
        deployment_id: str,
    ) -> None:
        if not isinstance(gateway_id, str) or not gateway_id:
            raise EffectGatewayError("gateway identity is required")
        if not hasattr(statement_signer, "sign"):
            raise EffectGatewayError("gateway statement signer is required")
        if not hasattr(intent_store, "save") or not hasattr(intent_store, "load"):
            raise EffectGatewayError("durable intent store is required")
        self.gateway_id = gateway_id
        self.signer = statement_signer
        self.store = intent_store
        self.deployment_id = deployment_id

    # ------------------------------------------------------------------ flow

    def begin_effect(self, request: EffectRequest) -> Mapping[str, Any]:
        """Authorize + durably record intent BEFORE any provider contact."""
        if request.fields["deployment_id"] != self.deployment_id:
            raise EffectGatewayError("effect request belongs to a different deployment")
        existing = self.store.load(request.idempotency_key)
        if existing is not None:
            # Identity reuse is only legal for an identical logical effect.
            # Changed semantics under the same identity is a collision and
            # fails closed instead of silently forking a new key.
            if existing.get("fingerprint") != request.fingerprint:
                raise EffectIdentityCollision(
                    "effect identity reused with different operation/arguments"
                )
            stored_request = existing["request"]
            if digest(stored_request) != digest(request.to_dict()):
                raise EffectIdentityCollision(
                    "effect identity reused with different bound context"
                )
            return existing
        intent_payload = {
            "gateway_id": self.gateway_id,
            "deployment_id": request.fields["deployment_id"],
            "run_id": request.fields["run_id"],
            "session_id": request.fields["session_id"],
            "execution_id": request.execution_id,
            "capability_id": request.fields["capability_id"],
            "request_digest": request.fields["request_digest"],
            "operation": request.fields["operation"],
            "arguments_digest": request.fields["arguments_digest"],
            "policy_digest": request.fields["policy_digest"],
            "idempotency_key": request.idempotency_key,
            "issued_at_ms": time.time_ns() // 1_000_000,
        }
        statement = self.signer.sign(TYPE_EFFECT_INTENT, intent_payload).to_dict()
        record = {
            "idempotency_key": request.idempotency_key,
            "request": request.to_dict(),
            "fingerprint": request.fingerprint,
            "state": GATEWAY_INTENT_DURABLE,
            "intent_statement": statement,
            "attempts": [],
        }
        self.store.save(record)
        return record

    def dispatch(self, request: EffectRequest, provider: ProviderAdapter) -> Mapping[str, Any]:
        record = self.begin_effect(request)
        state = record["state"]
        if state in TERMINAL_GATEWAY_STATES:
            return record
        if state in {GATEWAY_COMMITTED, GATEWAY_CONFIRMED_NOT_COMMITTED}:
            # A retry after a positively resolved outcome is an idempotent
            # no-op: the operator may not know the effect landed, and the
            # immutable identity guarantees it can never land twice.
            return record
        if state not in {GATEWAY_INTENT_DURABLE, GATEWAY_INDETERMINATE, GATEWAY_DISPATCH_STARTED}:
            raise EffectGatewayError(
                f"dispatch is illegal from gateway state {state!r}"
            )
        attempts = list(record.get("attempts", []))
        attempts.append({"started_at_ms": time.time_ns() // 1_000_000})
        next_state = GATEWAY_DISPATCH_STARTED
        record = {**record, "state": next_state, "attempts": attempts}
        self.store.save(record)
        try:
            result = provider.execute(request.to_dict(), request.idempotency_key)
        except Exception as exc:
            # Response lost / provider crash / transport failure: the effect
            # may have happened. Record uncertainty, never denial.
            record = {
                **record,
                "state": GATEWAY_INDETERMINATE,
                "last_error_type": type(exc).__name__,
            }
            self.store.save(record)
            receipt_statement = self._sign_receipt(request, GATEWAY_INDETERMINATE, None)
            record = {**record, "receipt_statement": receipt_statement}
            self.store.save(record)
            return record
        return self._apply_provider_result(record, request, result)

    def _apply_provider_result(
        self,
        record: Mapping[str, Any],
        request: EffectRequest,
        result: ProviderResult,
    ) -> Mapping[str, Any]:
        if result.state == PROVIDER_COMMITTED:
            next_state = GATEWAY_PROVIDER_ACKNOWLEDGED
        elif result.state in {PROVIDER_UNKNOWN, PROVIDER_UNANSWERABLE}:
            next_state = GATEWAY_INDETERMINATE
        elif result.state == PROVIDER_CONFIRMED_NOT_EXECUTED:
            next_state = GATEWAY_CONFIRMED_NOT_COMMITTED
        elif result.state == PROVIDER_FAILED:
            # The provider ran but reported failure: absence is NOT proven.
            next_state = GATEWAY_POSSIBLY_COMMITTED
        else:
            raise EffectGatewayError(f"unknown provider outcome: {result.state!r}")
        record = {**record, "state": next_state}
        self.store.save(record)
        receipt_digest = result.receipt_digest
        if next_state == GATEWAY_PROVIDER_ACKNOWLEDGED:
            record = {**record, "state": GATEWAY_COMMITTED}
            self.store.save(record)
        receipt_statement = self._sign_receipt(request, record["state"], receipt_digest, result.detail)
        record = {
            **record,
            "provider_receipt_digest": receipt_digest,
            "provider_evidence_class": result.evidence_class,
            "provider_receipt_envelope": (
                dict(result.provider_receipt_envelope)
                if result.provider_receipt_envelope is not None
                else None
            ),
            "receipt_statement": receipt_statement,
        }
        self.store.save(record)
        return record

    def reconcile(
        self,
        request: EffectRequest,
        provider: ProviderAdapter,
    ) -> Mapping[str, Any]:
        record = self.store.load(request.idempotency_key)
        if record is None:
            raise EffectGatewayError("no durable intent exists for this execution")
        state = record["state"]
        if state in TERMINAL_GATEWAY_STATES:
            return record
        if state not in {
            GATEWAY_DISPATCH_STARTED,
            GATEWAY_PROVIDER_ACKNOWLEDGED,
            GATEWAY_POSSIBLY_COMMITTED,
            GATEWAY_COMMITTED,
            GATEWAY_CONFIRMED_NOT_COMMITTED,
            GATEWAY_INDETERMINATE,
        }:
            raise EffectGatewayError(f"reconciliation is illegal from {state!r}")
        result = provider.reconcile(request.idempotency_key)
        resolution = {
            PROVIDER_COMMITTED: "committed",
            PROVIDER_CONFIRMED_NOT_EXECUTED: "confirmed_not_committed",
            PROVIDER_FAILED: "indeterminate",
            PROVIDER_UNKNOWN: "indeterminate",
            PROVIDER_UNANSWERABLE: "indeterminate",
        }[result.state]
        reconciliation_payload = {
            "gateway_id": self.gateway_id,
            "execution_id": request.execution_id,
            "idempotency_key": request.idempotency_key,
            "resolution": resolution,
            "provider_outcome": result.state,
            "provider_receipt_digest": result.receipt_digest,
            "provider_evidence_class": result.evidence_class,
            "provider_receipt_envelope": (
                dict(result.provider_receipt_envelope)
                if result.provider_receipt_envelope is not None
                else None
            ),
            "issued_at_ms": time.time_ns() // 1_000_000,
        }
        statement = self.signer.sign(
            TYPE_EFFECT_RECONCILIATION, reconciliation_payload
        ).to_dict()
        record = {
            **record,
            "state": GATEWAY_RECONCILED,
            "resolution": resolution,
            "reconciliation_statement": statement,
            "provider_evidence_class": result.evidence_class,
            "provider_receipt_envelope": (
                dict(result.provider_receipt_envelope)
                if result.provider_receipt_envelope is not None
                else None
            ),
            "provider_receipt_digest": result.receipt_digest or record.get("provider_receipt_digest"),
        }
        self.store.save(record)
        return record

    def status(self, request: EffectRequest) -> Mapping[str, Any]:
        record = self.store.load(request.idempotency_key)
        if record is None:
            raise EffectGatewayError("no durable intent exists for this execution")
        return record

    def unresolved_count(self) -> int:
        """Records past intent whose final effect state is still unresolved."""
        count = getattr(self.store, "count_unresolved", None)
        if callable(count):
            return int(count())
        return -1

    # ------------------------------------------------------------- statements

    def _sign_receipt(
        self,
        request: EffectRequest,
        state: str,
        provider_receipt_digest: str | None,
        detail: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {
            "gateway_id": self.gateway_id,
            "deployment_id": request.fields["deployment_id"],
            "run_id": request.fields["run_id"],
            "session_id": request.fields["session_id"],
            "execution_id": request.execution_id,
            "capability_id": request.fields["capability_id"],
            "operation": request.fields["operation"],
            "state": state,
            "provider_receipt_digest": provider_receipt_digest,
            "issued_at_ms": time.time_ns() // 1_000_000,
        }
        return self.signer.sign(TYPE_EFFECT_RECEIPT, payload).to_dict()

    @staticmethod
    def verify_effect_statements(
        envelope: Mapping[str, Any],
        verifier: Any,
        *,
        expected_type: str,
    ) -> Any:
        try:
            return verifier.verify(envelope, expected_type=expected_type)
        except (StatementError, TypeError, ValueError) as exc:
            raise EffectGatewayError(f"invalid effect statement: {exc}") from exc


def make_effect_request(
    *,
    deployment_id: str,
    environment: str,
    run_id: str,
    session_id: str,
    capability_id: str,
    request_digest: str,
    operation: str,
    arguments_digest: str,
    policy_digest: str,
    executor_identity: str,
    execution_id: str | None = None,
    effect_id: str | None = None,
    provider_scope: str = "default",
    authorization_digest: str | None = None,
) -> EffectRequest:
    return EffectRequest({
        "schema": EFFECT_REQUEST_SCHEMA,
        "deployment_id": deployment_id,
        "environment": environment,
        "run_id": run_id,
        "session_id": session_id,
        "execution_id": execution_id or new_execution_id(),
        "effect_id": effect_id or new_effect_id(),
        "provider_scope": provider_scope,
        "capability_id": capability_id,
        "request_digest": request_digest,
        "operation": operation,
        "arguments_digest": arguments_digest,
        "authorization_digest": authorization_digest,
        "policy_digest": policy_digest,
        "executor_identity": executor_identity,
    })
