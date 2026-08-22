"""Quorum approval policies for high-value transitions.

Multiple independently verified signatures are sufficient — no custom
threshold cryptography. An approval is a typed signed statement binding:

* the transition action (e.g. ``issue-containment-certificate``);
* the exact subject digest (e.g. the candidate evidence root);
* the approver's key identity.

:func:`evaluate_approvals` enforces, per approval:

1. cryptographic validity under the statement's domain;
2. subject/action binding (an approval cannot be replayed onto another
   transition);
3. distinct key identities — one key satisfies at most one slot;
4. manifest role + purpose authorization for the approver at the applicable
   manifest version (revoked or retired approvers fail closed).

The policy is satisfied only when the number of valid distinct authorized
approvals reaches ``required_approvals``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .statements import TYPE_APPROVAL, StatementError


# Transition actions and the approval purpose each requires.
APPROVAL_ACTIONS = {
    "issue-containment-certificate": "approve-containment-certificate",
    "rotate-trust-manifest": "rotate-trust-manifest",
    "issue-high-authority-capability": "approve-capability-quorum",
    "approve-emergency-revocation": "approve-emergency-revocation",
}


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovalPolicy:
    """k-of-n independent approvals for one transition action."""

    action: str
    required_role: str = "approver"
    required_approvals: int = 1

    def __post_init__(self) -> None:
        if self.action not in APPROVAL_ACTIONS:
            raise ApprovalError(f"unknown approval action: {self.action!r}")
        if type(self.required_approvals) is not int or self.required_approvals < 1:
            raise ApprovalError("required approvals must be a positive integer")
        if self.required_approvals > 16:
            raise ApprovalError("approval quorum is unreasonably large")


def make_approval(
    signer: Any,
    *,
    policy: ApprovalPolicy,
    subject_digest: str,
    issued_at_ms: int | None = None,
) -> dict[str, Any]:
    """Create one approval envelope bound to the transition subject."""
    payload: dict[str, Any] = {
        "action": policy.action,
        "subject_digest": subject_digest,
        "purpose": APPROVAL_ACTIONS[policy.action],
        "issued_at_ms": issued_at_ms if issued_at_ms is not None else _now_ms(),
    }
    return signer.sign(TYPE_APPROVAL, payload).to_dict()


def _now_ms() -> int:
    import time

    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class ApprovalOutcome:
    satisfied: bool
    approved_by: tuple[str, ...]
    rejected: tuple[tuple[int, str], ...]
    required: int

    @property
    def detail(self) -> str:
        reasons = "; ".join(f"[{index}] {reason}" for index, reason in self.rejected)
        suffix = f" rejected: {reasons}" if reasons else ""
        return (
            f"{len(self.approved_by)}/{self.required} valid distinct approvals"
            f"{suffix}"
        )


def evaluate_approvals(
    envelopes: list[Mapping[str, Any]],
    *,
    policy: ApprovalPolicy,
    expected_subject_digest: str,
    chain: Any,
    statement_verifier: Any,
    at_manifest_version: int | None = None,
) -> ApprovalOutcome:
    """Evaluate approval envelopes against one quorum policy."""
    purpose = APPROVAL_ACTIONS[policy.action]
    seen_keys: set[str] = set()
    approved: list[str] = []
    rejected: list[tuple[int, str]] = []
    for index, envelope in enumerate(envelopes):
        try:
            statement = statement_verifier.verify(envelope, expected_type=TYPE_APPROVAL)
        except (StatementError, TypeError, ValueError) as exc:
            rejected.append((index, f"invalid signature or domain: {exc}"))
            continue
        payload = statement.payload
        if payload.get("action") != policy.action:
            rejected.append((index, "approval bound to a different action"))
            continue
        if payload.get("purpose") != purpose:
            rejected.append((index, "approval purpose does not match its action"))
            continue
        if payload.get("subject_digest") != expected_subject_digest:
            # Subject binding prevents replaying an approval onto a different
            # certificate/evidence root.
            rejected.append((index, "approval subject digest mismatch"))
            continue
        key_id = statement.key_id
        if key_id in seen_keys:
            # One private key satisfies at most one quorum identity.
            rejected.append((index, "duplicate approver key identity"))
            continue
        try:
            chain.authorize(
                key_id,
                role=policy.required_role,
                purpose=purpose,
                at_manifest_version=at_manifest_version,
                at_ms=payload.get("issued_at_ms")
                if isinstance(payload.get("issued_at_ms"), int)
                else None,
            )
        except Exception as exc:
            reason = getattr(exc, "reason_code", None) or str(exc)
            rejected.append((index, f"approver not authorized: {reason}"))
            continue
        seen_keys.add(key_id)
        approved.append(key_id)
    satisfied = len(approved) >= policy.required_approvals
    return ApprovalOutcome(
        satisfied=satisfied,
        approved_by=tuple(approved),
        rejected=tuple(rejected),
        required=policy.required_approvals,
    )
