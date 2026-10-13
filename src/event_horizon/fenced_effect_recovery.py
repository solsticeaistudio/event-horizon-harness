"""Opt-in recovery gateway for a COOPERATING atomic SQLite recipient.

This intentionally does NOT change TrustedEffectGateway.execute or the
six archived Firecracker SIGKILL experiments. Only newly verified/consumed
signed capabilities can recover a previously reserved identical request.
A recipient reapply may commit after an older in-flight request; both share
the same durable UNIQUE effect key. There is NO journal reservation release.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from .canonical import canonical_bytes, digest
from .effect_outcome_journal import DurableEffectJournal, EffectAlreadyReserved
from .fenced_recipient import FencedSqliteRecipient
from .models import ActionRequest, IssuedCapability
from .trusted_effect_gateway import GatewayDecision


class FencedEffectRecoveryGateway:
    """Trusted host-owned gateway with explicit atomic-recipient contract.

    NOTE: the recipient is the trusted business effect. This implementation
    cannot safely wrap arbitrary external network calls not sharing its SQLite
    transaction. No guest chooses the recipient, output or journal path.
    """

    def __init__(
        self, verifier, recorder, journal: DurableEffectJournal,
        recipient: FencedSqliteRecipient, *,
        output_factory: Callable[[ActionRequest], Any],
        tenant: str = "default", environment: str = "synthetic",
        pre_dispatch_rule: Callable[[ActionRequest, Any], bool] | None = None,
    ):
        if (not isinstance(journal, DurableEffectJournal)
                or not isinstance(recipient, FencedSqliteRecipient)
                or not callable(output_factory)
                or (pre_dispatch_rule is not None and not callable(pre_dispatch_rule))):
            raise TypeError("fenced recovery requires trusted concrete storage and callbacks")
        self.verifier = verifier
        self.recorder = recorder
        self.journal = journal
        self.recipient = recipient
        self.output_factory = output_factory
        self.tenant = tenant
        self.environment = environment
        self.pre_dispatch_rule = pre_dispatch_rule

    def execute(
        self, request: ActionRequest, capability: IssuedCapability,
        attestation: Mapping[str, Any], *,
        executor_measurement: str, device_id: str,
        verifier_policy_digest: str, policy_digest: str,
        now: float | None = None,
    ) -> GatewayDecision:
        # Authorization, expiry, signature and fresh token consumption remain
        # mandatory FOR EVERY attempt, including previously committed effects.
        try:
            claims = self.verifier.verify_and_consume(
                capability, request,
                executor_measurement=executor_measurement,
                device_id=device_id, attestation=attestation,
                verifier_policy_digest=verifier_policy_digest,
                policy_digest=policy_digest, tenant=self.tenant,
                environment=self.environment, now=now,
            )
        except Exception:
            return GatewayDecision(False, "not-started", "authority-denied")
        try:
            self.recorder.append("fenced.authorized", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "capability_id": claims.capability_id,
            })
        except Exception:
            return GatewayDecision(False, "not-started", "evidence-unavailable")

        # All output for this synthetic transactional recipient is computed
        # by a pinned trusted host callback before any side-effect dispatch.
        try:
            if (self.pre_dispatch_rule is not None
                    and self.pre_dispatch_rule(request, claims) is not True):
                return GatewayDecision(False, "not-started", "pre-dispatch-denied")
            result = self.output_factory(request)
            encoded = canonical_bytes(result)
            ceiling = claims.max_output_bytes
            if type(ceiling) is not int or len(encoded) > ceiling:
                return GatewayDecision(False, "not-started", "pre-dispatch-denied")
        except Exception:
            return GatewayDecision(False, "not-started", "pre-dispatch-denied")

        effect_key = digest({
            "session_id": request.session_id, "request_id": request.request_id,
        })
        claims_digest = digest(claims.to_dict())
        recovered = False
        try:
            try:
                first = self.journal.reserve_fenced(
                    tenant=self.tenant, environment=self.environment,
                    effect_key=effect_key,
                    capability_id=claims.capability_id,
                    request_digest=request.request_digest,
                    claims_digest=claims_digest,
                    recipient_id=self.recipient.recipient_id,
                    output_digest=digest(result),
                )
                recovered = not first
            except EffectAlreadyReserved:
                recovered = True
            binding = self.journal.observe_effect(
                tenant=self.tenant, environment=self.environment,
                effect_key=effect_key,
            )
            if (binding is None
                    or binding["request_digest"] != request.request_digest
                    or binding["fenced_protocol"] != "atomic-sqlite-v1"
                    or binding["fenced_recipient_id"] != self.recipient.recipient_id
                    or binding["fenced_output_digest"] != digest(result)
                    or binding["state"] not in ("possibly-committed", "recipient-confirmed")
                    or (not recovered and (
                        binding["capability_id"] != claims.capability_id
                        or binding["claims_digest"] != claims_digest
                    ))):
                return GatewayDecision(False, "possibly-committed", "effect-binding-conflict")
        except Exception:
            return GatewayDecision(False, "not-started", "effect-journal-unavailable")

        # CRITICAL: when reserved previously, NEVER ask whether the recipient is
        # absent and then remove a reservation. Send only the *same* binding
        # to an explicitly transactional, durably idempotent recipient.
        try:
            receipt = self.recipient.apply(
                effect_key=effect_key, request_digest=request.request_digest,
                output=result,
            )
            # Re-read the independently durable ledger; an in-process handler
            # return alone is insufficient to mark a previously uncertain
            # operation completed.
            observed = self.recipient.observe(
                effect_key=effect_key, request_digest=request.request_digest,
            )
            if (observed is None or observed.receipt_digest != receipt.receipt_digest
                    or observed.output_digest != digest(result)
                    or observed.sequence != receipt.sequence
                    or observed.recipient_id != self.recipient.recipient_id):
                raise RuntimeError("recipient positive receipt not corroborated")
        except Exception:
            return GatewayDecision(False, "possibly-committed", "recipient-indeterminate")

        try:
            self.journal.confirm_from_trusted_recipient(
                tenant=self.tenant, environment=self.environment,
                effect_key=effect_key,
                # Only the ORIGINAL reservation is confirmable; a fresh
                # recovery capability never rewrites its provenance.
                capability_id=binding["capability_id"],
                request_digest=binding["request_digest"],
                claims_digest=binding["claims_digest"],
                receipt_digest=observed.receipt_digest,
            )
        except Exception:
            return GatewayDecision(False, "possibly-committed", "journal-confirmation-indeterminate")
        try:
            self.recorder.append("fenced.recipient-confirmed", {
                "request_id": request.request_id,
                "request_digest": request.request_digest,
                "capability_id": claims.capability_id,
                "original_capability_id": binding["capability_id"],
                "receipt_digest": observed.receipt_digest,
                "recipient_id": observed.recipient_id,
                "commit_sequence": observed.sequence,
                "recovery": recovered,
                "new_effect_commit": receipt.newly_committed,
            })
        except Exception:
            return GatewayDecision(False, "possibly-committed", "evidence-indeterminate")
        return GatewayDecision(
            True, "completed", output=observed.output, output_bytes=len(encoded),
        )
