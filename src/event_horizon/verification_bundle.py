"""Portable Event Horizon Verification Bundle.

A self-contained artifact allowing a third party to verify a containment
certificate WITHOUT trusting a live Event Horizon service, holding private
keys, or contacting the coordinator. Verification needs only:

* the bundle itself;
* an externally pinned deployment root public key;
* externally pinned witness public key(s).

The offline verifier returns structured results per property and never
upgrades a claim beyond what the bundled evidence supports.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .certificate import ContainmentCertificateBuilder
from .recorder import ExternalRecorder
from .statements import (
    TYPE_DEPLOYMENT_POLICY,
    StatementError,
    StatementVerifier,
)
from .witness import (
    WITNESS_CONFLICT_FIELDS,
    WITNESS_CONFLICT_STATEMENT_TYPE,
    compare_recorder_with_witness,
    verify_witness_acknowledgment_signature,
    WitnessPolicy,
)

BUNDLE_SCHEMA = "event-horizon.verification-bundle.v1"

_BUNDLE_SECTIONS = {
    "schema",
    "certificate",
    "trust_manifest_envelopes",
    "deployment_policy_statement",
    "witness_acknowledgments",
    "witness_conflicts",
    "recorder_checkpoints",
    "effect_reconciliation_statements",
    "approval_envelopes",
}


class BundleError(ValueError):
    pass


def build_bundle(
    *,
    certificate: Mapping[str, Any],
    trust_manifest_envelopes: list[Mapping[str, Any]],
    deployment_policy_statement: Mapping[str, Any] | None = None,
    witness_acknowledgments: list[Mapping[str, Any]] | None = None,
    witness_conflicts: list[Mapping[str, Any]] | None = None,
    recorder_checkpoints: list[Mapping[str, Any]] | None = None,
    effect_reconciliation_statements: list[Mapping[str, Any]] | None = None,
    approval_envelopes: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble the minimal self-contained evidence set for one certificate."""
    if not isinstance(certificate, Mapping):
        raise BundleError("certificate is required")
    return {
        "schema": BUNDLE_SCHEMA,
        "certificate": dict(certificate),
        "trust_manifest_envelopes": [dict(item) for item in trust_manifest_envelopes],
        "deployment_policy_statement": (
            dict(deployment_policy_statement)
            if deployment_policy_statement is not None
            else None
        ),
        "witness_acknowledgments": [dict(i) for i in (witness_acknowledgments or [])],
        "witness_conflicts": [dict(i) for i in (witness_conflicts or [])],
        "recorder_checkpoints": [dict(i) for i in (recorder_checkpoints or [])],
        "effect_reconciliation_statements": [
            dict(i) for i in (effect_reconciliation_statements or [])
        ],
        "approval_envelopes": [dict(i) for i in (approval_envelopes or [])],
    }


@dataclass(frozen=True)
class BundleReport:
    cryptographic_validity: bool
    historical_trust_validity: bool
    namespace_integrity: bool
    evidence_completeness: str          # complete | incomplete | conflicted | unverifiable
    effect_reconciliation: str          # reconciled | unresolved | none-bundled
    mediation_status: str               # enforced-exclusive | observed-only | not-mediated
    history_status: str                 # witnessed | locally-anchored-only | unanchored | conflicted-evidence
    independence_status: str            # independent | local-only | unknown
    conflicts: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    assurance_facts: dict[str, bool] = field(default_factory=dict)
    profile: str = "DEVELOPMENT"
    detail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cryptographic_validity": self.cryptographic_validity,
            "historical_trust_validity": self.historical_trust_validity,
            "namespace_integrity": self.namespace_integrity,
            "evidence_completeness": self.evidence_completeness,
            "effect_reconciliation": self.effect_reconciliation,
            "mediation_status": self.mediation_status,
            "history_status": self.history_status,
            "independence_status": self.independence_status,
            "conflicts": self.conflicts,
            "unknowns": self.unknowns,
            "assurance_facts": self.assurance_facts,
            "profile": self.profile,
            "detail": self.detail,
        }


def _load_manifest_actors_key(
    envelopes: list[Mapping[str, Any]], role: str
) -> str | None:
    for envelope in envelopes:
        for actor in envelope.get("actors", []):
            if actor.get("role") == role:
                return actor.get("public_key_pem")
    return None


def verify_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_root_public_key_pem: str,
    trusted_witness_public_keys_pem: list[str] | tuple[str, ...] = (),
) -> BundleReport:
    """Verify a bundle entirely offline against externally pinned roots."""
    detail: list[str] = []
    unknowns: list[str] = []
    conflicts: list[str] = []

    if not isinstance(bundle, Mapping) or set(bundle) != _BUNDLE_SECTIONS:
        raise BundleError("verification bundle fields are invalid")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise BundleError(f"unsupported bundle schema: {bundle['schema']!r}")

    certificate = bundle["certificate"]
    payload = certificate.get("certificate") if isinstance(certificate, Mapping) else None
    if not isinstance(payload, Mapping):
        raise BundleError("bundle carries no certificate")

    # ---- trust-manifest chain ---------------------------------------------
    manifests = bundle["trust_manifest_envelopes"]
    historical_trust_validity = False
    chain: ManifestChain | None = None
    if not manifests:
        unknowns.append("trust-manifest-chain")
    else:
        try:
            chain = ManifestChain(
                trusted_root_public_key_pem,
                deployment_id=str(payload["deployment_id"]),
                environment="synthetic",
            )
            for envelope in manifests:
                # append() verifies AND links each manifest into the chain.
                chain.append(envelope)
            claimed_digest = payload.get("trust_root_manifest_digest")
            if claimed_digest is None:
                historical_trust_validity = True
                detail.append("certificate declares no manifest binding")
            else:
                chain.version_for_digest(str(claimed_digest))
                historical_trust_validity = True
                detail.append(
                    f"manifest binding resolves within verified chain "
                    f"(v{chain.version_for_digest(str(claimed_digest))})"
                )
        except TrustManifestError as exc:
            detail.append(f"manifest chain invalid: {exc}")

    # ---- cryptographic validity -------------------------------------------
    # The certificate is signed by the certificate-signer key, which the
    # verified manifest authorizes — never by the deployment root directly.
    cert_signer_pem = (
        _load_manifest_actors_key(manifests, "certificate-signer")
        if manifests
        else None
    )
    crypto_ok = False
    if cert_signer_pem is None:
        unknowns.append("certificate-signer-key-in-manifest")
        detail.append("no certificate-signer key in bundled manifest")
    else:
        crypto_ok = ContainmentCertificateBuilder.verify(
            certificate, public_key_pem=cert_signer_pem
        )
        if not crypto_ok:
            detail.append("certificate signature failed against manifest-authorized signer key")
        else:
            detail.append("certificate signature verified against manifest-authorized signer")

    # ---- namespace integrity ---------------------------------------------
    namespace_ok = (
        isinstance(payload.get("run_id"), str)
        and bool(payload["run_id"])
        and isinstance(payload.get("deployment_id"), str)
        and bool(payload["deployment_id"])
        and payload["session_id"] is not None
    )
    if not namespace_ok:
        detail.append("namespace fields incomplete")

    # ---- deployment policy -------------------------------------------------
    policy_statement = bundle["deployment_policy_statement"]
    if policy_statement is not None:
        verifier = StatementVerifier({"root": trusted_root_public_key_pem})
        try:
            verified_policy = verifier.verify(
                policy_statement, expected_type=TYPE_DEPLOYMENT_POLICY
            )
            if verified_policy.payload.get("deployment_id") != payload["deployment_id"]:
                raise StatementError("policy belongs to another deployment")
            detail.append("signed deployment policy verified")
        except (StatementError, TypeError, ValueError) as exc:
            crypto_ok = False
            detail.append(f"deployment policy statement invalid: {exc}")
    else:
        unknowns.append("deployment-policy-statement")

    # ---- history ------------------------------------------------------------
    checkpoints = bundle["recorder_checkpoints"]
    acknowledgments = bundle["witness_acknowledgments"]
    history_status = "unanchored"
    facts = dict(payload.get("assurance_facts", {}))
    if facts.get("history_witnessed"):
        if not acknowledgments:
            conflicts.append("certificate claims witnessed history without bundled acknowledgment")
            history_status = "conflicted-evidence"
        else:
            ack_envelope = acknowledgments[-1]
            pinned_match = any(
                verify_witness_acknowledgment_signature(ack_envelope, pem)
                for pem in trusted_witness_public_keys_pem
            )
            if not pinned_match:
                conflicts.append("witness acknowledgment does not verify against pinned witness keys")
                history_status = "conflicted-evidence"
            else:
                verdict = compare_recorder_with_witness(
                    snapshot_event_count=int(payload.get("total_event_count", 0)),
                    snapshot_chain_tip=str(payload.get("event_chain_tip", "")),
                    acknowledgment={
                        # Full envelope: verification filters the signed
                        # fields itself and needs signature/key_id.
                        "ack": dict(ack_envelope),
                        "witness_public_key_pem": next(
                            pem for pem in trusted_witness_public_keys_pem
                            if verify_witness_acknowledgment_signature(ack_envelope, pem)
                        ),
                    },
                    deployment_id=str(payload["deployment_id"]),
                    manifest_digest=str(ack_envelope.get("manifest_digest", "")),
                    policy=WitnessPolicy(require_witness=True),
                )
                history_status = (
                    "witnessed" if verdict.ok else f"conflicted-evidence:{verdict.status}"
                )
                if not verdict.ok:
                    conflicts.append(f"witness continuity: {verdict.detail}")
    elif checkpoints:
        recorder_pem = _load_manifest_actors_key(manifests, "recorder")
        anchored_any = any(
            ExternalRecorder.verify_checkpoint_signature(env, recorder_pem)
            for env in checkpoints
            if isinstance(env, Mapping) and recorder_pem
        )
        history_status = "locally-anchored-only" if anchored_any else "unanchored"
        if not anchored_any:
            unknowns.append("verifiable-recorder-checkpoint")
    else:
        unknowns.append("recorder-checkpoint")

    for conflict_record in bundle["witness_conflicts"]:
        if set(conflict_record) >= WITNESS_CONFLICT_FIELDS - {"signature", "key_id"}:
            conflicts.append(
                f"witness conflict record present: {conflict_record.get('conflict_kind')}"
            )

    # ---- effects --------------------------------------------------------------
    reconciliations = bundle["effect_reconciliation_statements"]
    mediation_status = "not-mediated"
    effect_reconciliation = "none-bundled"
    if payload.get("effects", {}).get("reconciled_count"):
        if not reconciliations:
            conflicts.append(
                "certificate claims reconciled effects without bundled reconciliation statements"
            )
            effect_reconciliation = "unresolved"
        else:
            gateway_pem = _load_manifest_actors_key(manifests, "effect-gateway")
            gateway_verifier = (
                StatementVerifier({"gw": gateway_pem}) if gateway_pem else None
            )
            valid = 0
            for index, envelope in enumerate(reconciliations):
                if gateway_verifier is None:
                    conflicts.append("no effect-gateway key in bundled manifests")
                    break
                try:
                    gateway_verifier.verify(
                        envelope, expected_type="effect-reconciliation"
                    )
                    valid += 1
                except (StatementError, TypeError, ValueError):
                    conflicts.append(f"reconciliation [{index}] signature invalid")
            if valid == len(reconciliations) and valid:
                effect_reconciliation = (
                    "reconciled"
                    if payload.get("claims", {}).get("effect_mediation_consistent")
                    == "satisfied"
                    else "partial"
                )
                mediation_status = (
                    "enforced-exclusive"
                    if facts.get("effect_mediation_enforced")
                    else "observed-only"
                )
    if facts.get("provider_receipts_authenticated") and not reconciliations:
        unknowns.append("provider-receipt-envelopes")

    # ---- completeness ---------------------------------------------------------
    evidence_completeness = str(payload.get("status", "unverifiable"))

    # ---- approvals ---------------------------------------------------------------
    quorum_fact = bool(facts.get("quorum_approval_present"))
    approvals = bundle["approval_envelopes"]
    if quorum_fact and not approvals:
        unknowns.append("approval-envelopes")

    independence_status = (
        "independent"
        if facts.get("witness_administratively_independent")
        and facts.get("witness_storage_independent")
        else ("local-only" if facts.get("history_witnessed") else "unknown")
    )
    if facts.get("keys_independently_administered") is False:
        detail.append("deployment policy declares keys are NOT independently administered")

    return BundleReport(
        cryptographic_validity=crypto_ok,
        historical_trust_validity=historical_trust_validity,
        namespace_integrity=namespace_ok,
        evidence_completeness=evidence_completeness,
        effect_reconciliation=effect_reconciliation,
        mediation_status=mediation_status,
        history_status=history_status,
        independence_status=independence_status,
        conflicts=conflicts,
        unknowns=unknowns,
        assurance_facts=facts,
        profile=str(payload.get("assurance_profile", "DEVELOPMENT")),
        detail=detail,
    )


from .trust_manifest import ManifestChain, TrustManifestError  # noqa: E402

_WITNESS_ACK_FIELD_NAMES = {
    "statement_type",
    "witness_id",
    "deployment_id",
    "manifest_digest",
    "recorder_key_id",
    "checkpoint_sequence",
    "chain_tip",
    "previous_checkpoint_digest",
    "checkpoint_digest",
    "independence",
    "witnessed_at_ms",
}


def write_bundle(bundle: Mapping[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(bundle), indent=2, sort_keys=True), encoding="utf-8")
    return target


def read_bundle(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BundleError("bundle file must contain an object")
    return value