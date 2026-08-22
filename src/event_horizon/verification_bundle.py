"""Verification Bundle v2: portable proof closure.

Extends the v0.7 bundle so that every *portable* assurance fact can be
recomputed offline from bundled evidence alone. The verifier never trusts the
certificate's own claims: it derives facts from signatures it validates
against explicitly pinned roots, then compares derived vs claimed. Any
overclaim (claimed true where evidence does not establish true) fails with
``certificate_claim_match = false``.

Evidence authenticity classes distinguish how strongly each fact is backed:

SELF_DECLARED < ROOT_AUTHORIZED_DECLARATION < CROSS_PRINCIPAL_CORROBORATED
< PROVIDER_AUTHENTICATED / EXTERNALLY_WITNESSED < INDEPENDENTLY_VERIFIABLE

A fact is ``proof_closed`` when its full dependency chain is contained in the
bundle or rooted in a pinned anchor. Facts that were true at runtime but
whose proof cannot be reconstructed (e.g. enforcement declared only in
runtime configuration) remain derivable-but-not-portable: they cannot support
a portable HIGH_ASSURANCE result.
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
from .trust_manifest import ManifestChain, TrustManifestError
from .witness import (
    WITNESS_CONFLICT_FIELDS,
    compare_recorder_with_witness,
    verify_witness_acknowledgment_signature,
    WitnessPolicy,
)

BUNDLE_SCHEMA_V2 = "event-horizon.verification-bundle.v2"

EVIDENCE_SELF_DECLARED = "self_declared"
EVIDENCE_ROOT_AUTHORIZED_DECLARATION = "root_authorized_declaration"
EVIDENCE_CROSS_PRINCIPAL_CORROBORATED = "cross_principal_corroborated"
EVIDENCE_PROVIDER_AUTHENTICATED = "provider_authenticated"
EVIDENCE_EXTERNALLY_WITNESSED = "externally_witnessed"
EVIDENCE_INDEPENDENTLY_VERIFIABLE = "independently_verifiable"

_V2_SECTIONS = {
    "schema",
    "certificate",
    "trust_manifest_envelopes",
    "deployment_policy_statement",
    "witness_acknowledgments",
    "witness_conflicts",
    "recorder_checkpoints",
    "effect_reconciliation_statements",
    "approval_envelopes",
    # v0.9 additions:
    "provider_receipt_envelopes",
    "deployment_attestation",
}

# Facts whose evidence is fully portable given the pinned anchors above.
PORTABLE_FACTS = frozenset({
    "authenticated_sources",
    "namespace_complete",
    "history_witnessed",
    "witness_administratively_independent",
    "witness_storage_independent",
    "effect_mediated",
    "effects_reconciled",
    "provider_receipts_authenticated",
    "manifest_authorized_sources",
})

# Runtime/deployment facts: derivable only as root-authorized declarations;
# they cannot be independently re-observed from a bundle.
DECLARATION_FACTS = frozenset({
    "replay_durable",
    "effect_mediation_enforced",
    "keys_independently_administered",
})


class BundleV2Error(ValueError):
    pass


def build_bundle_v2(
    *,
    certificate: Mapping[str, Any],
    trust_manifest_envelopes: list[Mapping[str, Any]],
    deployment_policy_statement: Mapping[str, Any] | None = None,
    witness_acknowledgments: list[Mapping[str, Any]] | None = None,
    witness_conflicts: list[Mapping[str, Any]] | None = None,
    recorder_checkpoints: list[Mapping[str, Any]] | None = None,
    effect_reconciliation_statements: list[Mapping[str, Any]] | None = None,
    approval_envelopes: list[Mapping[str, Any]] | None = None,
    provider_receipt_envelopes: list[Mapping[str, Any]] | None = None,
    deployment_attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(certificate, Mapping):
        raise BundleV2Error("certificate is required")
    return {
        "schema": BUNDLE_SCHEMA_V2,
        "certificate": dict(certificate),
        "trust_manifest_envelopes": [dict(i) for i in trust_manifest_envelopes],
        "deployment_policy_statement": (
            dict(deployment_policy_statement)
            if deployment_policy_statement is not None else None
        ),
        "witness_acknowledgments": [dict(i) for i in (witness_acknowledgments or [])],
        "witness_conflicts": [dict(i) for i in (witness_conflicts or [])],
        "recorder_checkpoints": [dict(i) for i in (recorder_checkpoints or [])],
        "effect_reconciliation_statements": [
            dict(i) for i in (effect_reconciliation_statements or [])
        ],
        "approval_envelopes": [dict(i) for i in (approval_envelopes or [])],
        "provider_receipt_envelopes": [
            dict(i) for i in (provider_receipt_envelopes or [])
        ],
        "deployment_attestation": (
            dict(deployment_attestation)
            if deployment_attestation is not None else None
        ),
    }


@dataclass(frozen=True)
class DerivedFacts:
    values: dict[str, bool]
    evidence_classes: dict[str, str]
    proof_closed: dict[str, bool]
    closure_dimensions: dict[str, dict[str, Any]] | None = None


@dataclass(frozen=True)
class BundleReportV2:
    bundle_schema_valid: bool
    certificate_signature_valid: bool
    trust_chain_valid: bool
    manifest_authorization_valid: bool
    historical_trust_valid: bool
    namespace_integrity: bool
    evidence_complete: str
    effect_reconciliation_status: str
    provider_evidence_status: str
    provider_receipt_authenticated: bool
    deployment_attestation_valid: bool | None
    credential_isolation_status: str
    network_isolation_status: str
    effect_mediation_observed: bool
    effect_mediation_enforced: bool | None
    witness_history_valid: bool
    witness_independence_status: str
    unresolved_effects: int
    conflicts: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    derived_assurance_facts: dict[str, bool] = field(default_factory=dict)
    fact_evidence_classes: dict[str, str] = field(default_factory=dict)
    proof_closure: dict[str, bool] = field(default_factory=dict)
    closure_dimensions: dict[str, dict[str, Any]] = field(default_factory=dict)
    derived_profile: str = "DEVELOPMENT"
    certificate_claim_match: bool = True
    claim_mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_schema_valid": self.bundle_schema_valid,
            "certificate_signature_valid": self.certificate_signature_valid,
            "trust_chain_valid": self.trust_chain_valid,
            "manifest_authorization_valid": self.manifest_authorization_valid,
            "historical_trust_valid": self.historical_trust_valid,
            "namespace_integrity": self.namespace_integrity,
            "evidence_completeness": self.evidence_complete,
            "effect_reconciliation_status": self.effect_reconciliation_status,
            "provider_evidence_status": self.provider_evidence_status,
            "provider_receipt_authenticated": self.provider_receipt_authenticated,
            "deployment_attestation_valid": self.deployment_attestation_valid,
            "credential_isolation_status": self.credential_isolation_status,
            "network_isolation_status": self.network_isolation_status,
            "effect_mediation_observed": self.effect_mediation_observed,
            "effect_mediation_enforced": self.effect_mediation_enforced,
            "witness_history_valid": self.witness_history_valid,
            "witness_independence_status": self.witness_independence_status,
            "unresolved_effects": self.unresolved_effects,
            "conflicts": self.conflicts,
            "unknowns": self.unknowns,
            "derived_assurance_facts": self.derived_assurance_facts,
            "fact_evidence_classes": self.fact_evidence_classes,
            "proof_closure": self.proof_closure,
            "derived_profile": self.derived_profile,
            "certificate_claim_match": self.certificate_claim_match,
            "claim_mismatches": self.claim_mismatches,
        }


def _actor_key(envelopes: list[Mapping], role: str) -> str | None:
    for envelope in envelopes:
        for actor in envelope.get("actors", []):
            if actor.get("role") == role:
                return actor.get("public_key_pem")
    return None


def derive_bundle_facts_v2(
    bundle: Mapping[str, Any],
    *,
    trusted_root_public_key_pem: str,
    trusted_witness_public_keys_pem: list[str],
    trusted_provider_public_keys_pem: list[str],
) -> tuple[DerivedFacts, dict[str, Any]]:
    """Independently recompute portable facts from bundled evidence only."""
    conflicts: list[str] = []
    unknowns: list[str] = []
    detail: list[str] = []

    payload = bundle["certificate"]["certificate"]
    manifests = bundle["trust_manifest_envelopes"]

    chain_ok = False
    chain: ManifestChain | None = None
    cert_signer_pem = None
    gateway_pem = None
    if manifests:
        try:
            chain = ManifestChain(
                trusted_root_public_key_pem,
                deployment_id=str(payload["deployment_id"]),
                environment="synthetic",
            )
            for envelope in manifests:
                chain.append(envelope)
            claimed = payload.get("trust_root_manifest_digest")
            if claimed is not None:
                chain.version_for_digest(str(claimed))
            chain_ok = True
            cert_signer_pem = _actor_key(manifests, "certificate-signer")
            gateway_pem = _actor_key(manifests, "effect-gateway")
        except TrustManifestError as exc:
            conflicts.append(f"manifest chain invalid: {exc}")
    else:
        unknowns.append("trust-manifest-chain")

    cert_sig_ok = False
    if cert_signer_pem is None:
        unknowns.append("certificate-signer-key-in-manifest")
    else:
        cert_sig_ok = ContainmentCertificateBuilder.verify(
            bundle["certificate"], public_key_pem=cert_signer_pem
        )
        if not cert_sig_ok:
            conflicts.append("certificate signature invalid for manifest signer")

    # ---- policy declaration (root-authorized) ------------------------------
    policy_values = {
        "replay_durable": False,
        "effect_mediation_enforced": False,
        "keys_independently_administered": False,
    }
    policy_ok: bool | None = None
    statement = bundle["deployment_policy_statement"]
    if statement is None:
        unknowns.append("deployment-policy-statement")
    else:
        root_only = StatementVerifier({"root": trusted_root_public_key_pem})
        try:
            verified = root_only.verify(
                statement, expected_type=TYPE_DEPLOYMENT_POLICY
            )
            if verified.payload.get("deployment_id") != payload["deployment_id"]:
                raise StatementError("policy belongs to another deployment")
            policy_ok = True
            for name in policy_values:
                value = verified.payload.get(name)
                policy_values[name] = value if type(value) is bool else False
            detail.append("root-authorized deployment policy verified")
        except (StatementError, TypeError, ValueError) as exc:
            policy_ok = False
            conflicts.append(f"deployment policy invalid: {exc}")

    # ---- effects ------------------------------------------------------------
    reconciliations = bundle["effect_reconciliation_statements"]
    receipts = bundle["provider_receipt_envelopes"]
    resolutions: dict[str, str] = {}
    classes: set[str] = set()
    receipt_authenticated = False
    effect_reconciliation_status = "none-bundled"
    unresolved = int(payload.get("effects", {}).get("indeterminate", 0))
    if not reconciliations:
        unknowns.append("effect-reconciliations")
    elif gateway_pem is None:
        conflicts.append("no effect-gateway key in bundled manifests")
    else:
        gw_verifier = StatementVerifier({"gw": gateway_pem})
        valid = 0
        for index, env in enumerate(reconciliations):
            try:
                st = gw_verifier.verify(env, expected_type="effect-reconciliation")
            except (StatementError, TypeError, ValueError):
                conflicts.append(f"reconciliation [{index}] signature invalid")
                continue
            valid += 1
            key = str(st.payload.get("idempotency_key"))
            resolutions[key] = str(st.payload.get("resolution"))
            cls = str(st.payload.get("provider_evidence_class", ""))
            classes.add(cls)
            pr_envelope = st.payload.get("provider_receipt_envelope")
            if cls == "provider_authenticated_receipt" and isinstance(pr_envelope, Mapping):
                if not trusted_provider_public_keys_pem:
                    conflicts.append(
                        f"provider receipt [{index}] cannot be authenticated: "
                        "no pinned provider keys"
                    )
                else:
                    from .reference_provider import verify_provider_receipt_signature

                    ok = any(
                        verify_provider_receipt_signature(
                            pr_envelope, pem
                        )
                        for pem in trusted_provider_public_keys_pem
                    )
                    bound_key = str(pr_envelope.get("idempotency_key", ""))
                    if not ok:
                        conflicts.append(
                            f"provider receipt [{index}] failed authentication"
                        )
                    elif bound_key != key:
                        conflicts.append(
                            f"provider receipt [{index}] bound to another effect"
                        )
                    else:
                        receipt_authenticated = True
        if valid:
            indeterminate_count = sum(
                1 for r in resolutions.values() if r == "indeterminate"
            )
            unresolved = indeterminate_count
            effect_reconciliation_status = (
                "committed"
                if payload.get("claims", {}).get("effect_mediation_consistent") == "satisfied"
                and indeterminate_count == 0
                else "partial"
            )

    governed_bindings = []
    for event_type in ("execution.completed", "execution.indeterminate"):
        pass
    events_hint = payload.get("consumed_event_count")

    mediated = bool(resolutions) and all(r != "indeterminate" for r in resolutions.values())
    # Cross-check against certificate's own binding count when present.
    claimed_governed = payload.get("effects", {}).get("reconciled_count", 0)
    missing = max(0, int(claimed_governed) - len(resolutions)) if resolutions else 0
    if missing:
        conflicts.append(
            f"{missing} governed execution(s) lack bundled reconciliation statements"
        )
        mediated = False

    # ---- witness -------------------------------------------------------------
    acks = bundle["witness_acknowledgments"]
    history_witnessed = False
    independence = {"administrative": False, "storage": False}
    if facts_requires_witness(payload):
        if not acks:
            conflicts.append("witnessed-history claimed without acknowledgment")
        else:
            ack = acks[-1]
            matched_pem = next(
                (pem for pem in trusted_witness_public_keys_pem
                 if verify_witness_acknowledgment_signature(ack, pem)),
                None,
            )
            if matched_pem is None:
                conflicts.append("witness acknowledgment fails pinned keys")
            else:
                verdict = compare_recorder_with_witness(
                    snapshot_event_count=int(payload.get("total_event_count", 0)),
                    snapshot_chain_tip=str(payload.get("event_chain_tip", "")),
                    acknowledgment={"ack": dict(ack), "witness_public_key_pem": matched_pem},
                    deployment_id=str(payload["deployment_id"]),
                    manifest_digest=str(ack.get("manifest_digest", "")),
                    policy=WitnessPolicy(require_witness=True),
                )
                history_witnessed = verdict.ok
                if not verdict.ok:
                    conflicts.append(f"witness continuity: {verdict.status}")
                indep = ack.get("independence")
                if isinstance(indep, Mapping):
                    independence = {
                        "administrative": bool(indep.get("administrative")),
                        "storage": bool(indep.get("storage")),
                    }
    for conflict_record in bundle["witness_conflicts"]:
        if set(conflict_record) >= WITNESS_CONFLICT_FIELDS - {"signature", "key_id"}:
            conflicts.append(
                f"witness conflict record: {conflict_record.get('conflict_kind')}"
            )
            history_witnessed = False

    namespace_ok = bool(payload.get("run_id")) and bool(payload.get("deployment_id"))
    completeness = str(payload.get("status", "unverifiable"))

    authenticated_sources = cert_sig_ok and chain_ok and bool(cert_signer_pem)
    manifest_authorized = authenticated_sources

    derived = {
        "authenticated_sources": authenticated_sources,
        "namespace_complete": namespace_ok,
        "history_witnessed": history_witnessed,
        "witness_administratively_independent": independence["administrative"],
        "witness_storage_independent": independence["storage"],
        "effect_mediated": mediated,
        "effects_reconciled": bool(resolutions) and all(
            r != "indeterminate" for r in resolutions.values()
        ),
        "provider_receipts_authenticated": (
            bool(reconciliations) and receipt_authenticated
        ),
        "manifest_authorized_sources": manifest_authorized,
        # Root-authorized declarations:
        "replay_durable": policy_values["replay_durable"],
        "effect_mediation_enforced": policy_values["effect_mediation_enforced"],
        "keys_independently_administered": policy_values[
            "keys_independently_administered"
        ],
    }

    evidence_classes = {
        "authenticated_sources":
            EVIDENCE_INDEPENDENTLY_VERIFIABLE if authenticated_sources
            else EVIDENCE_SELF_DECLARED,
        "namespace_complete": EVIDENCE_INDEPENDENTLY_VERIFIABLE,
        "history_witnessed": (
            EVIDENCE_EXTERNALLY_WITNESSED if history_witnessed
            else EVIDENCE_SELF_DECLARED
        ),
        "witness_administratively_independent":
            EVIDENCE_ROOT_AUTHORIZED_DECLARATION,
        "witness_storage_independent": EVIDENCE_ROOT_AUTHORIZED_DECLARATION,
        "effect_mediated": (
            EVIDENCE_CROSS_PRINCIPAL_CORROBORATED if mediated
            else EVIDENCE_SELF_DECLARED
        ),
        "effects_reconciled": (
            EVIDENCE_CROSS_PRINCIPAL_CORROBORATED if derived["effects_reconciled"]
            else EVIDENCE_SELF_DECLARED
        ),
        "provider_receipts_authenticated": (
            EVIDENCE_PROVIDER_AUTHENTICATED if receipt_authenticated
            else EVIDENCE_UNVERIFIED_PLACEHOLDER
        ),
        "manifest_authorized_sources": (
            EVIDENCE_INDEPENDENTLY_VERIFIABLE if manifest_authorized
            else EVIDENCE_SELF_DECLARED
        ),
        "replay_durable": EVIDENCE_ROOT_AUTHORIZED_DECLARATION,
        "effect_mediation_enforced": EVIDENCE_ROOT_AUTHORIZED_DECLARATION,
        "keys_independently_administered": EVIDENCE_ROOT_AUTHORIZED_DECLARATION,
    }

    # ---- typed proof-closure dimensions (v0.9.1) ---------------------------
    # assertion_authenticity: an authorized authority signed the declaration.
    # runtime_enforcement: bundled OBSERVED deployment evidence supports it.
    # historical_observation: witnessed/ordered inclusion exists.
    # external_corroboration: a second principal corroborates.
    attestation = bundle["deployment_attestation"]
    attestation_observed = (
        isinstance(attestation, Mapping)
        and bool(attestation.get("credential_isolation_verified"))
        and bool(attestation.get("network_isolation_verified"))
        and isinstance(attestation.get("observer"), str)
    )
    credential_status = (
        "verified" if (
            isinstance(attestation, Mapping)
            and attestation.get("credential_isolation_verified")
            and isinstance(attestation.get("observer"), str)
        ) else ("violated" if isinstance(attestation, Mapping) else "unknown")
    )
    network_status = (
        "verified" if (
            isinstance(attestation, Mapping)
            and attestation.get("network_isolation_verified")
            and isinstance(attestation.get("observer"), str)
        ) else ("violated" if isinstance(attestation, Mapping) else "unknown")
    )
    deployment_attestation_valid: bool | None = (
        None if attestation is None else attestation_observed
    )
    if attestation is not None and not attestation_observed:
        conflicts.append(
            "deployment attestation present but runtime observations are "
            "incomplete or anonymous; enforcement stays unclosed"
        )

    def _closure(name: str) -> dict[str, Any]:
        dims = {
            "assertion_authenticity": name in DECLARATION_FACTS and policy_ok is True,
            "runtime_enforcement": False,
            "historical_observation": name in PORTABLE_FACTS,
            "external_corroboration": name in {
                "effect_mediated", "effects_reconciled",
                "provider_receipts_authenticated", "history_witnessed",
            },
        }
        if name == "effect_mediation_enforced":
            dims["runtime_enforcement"] = attestation_observed
        if name in {"witness_administratively_independent",
                    "witness_storage_independent"}:
            dims["historical_observation"] = True
        return dims

    proof_closed = {
        name: (name in PORTABLE_FACTS)
        or (name in DECLARATION_FACTS and policy_ok is True)
        for name in derived
    }
    closure_dimensions = {name: _closure(name) for name in sorted(derived)}

    # GAP 1 invariant: enforcement is a RUNTIME property. A root-authorized
    # declaration alone never closes it — observed attestation evidence must
    # corroborate, otherwise the portable value stays false (unknown).
    if not attestation_observed:
        policy_values["effect_mediation_enforced"] = False
    derived["effect_mediation_enforced"] = policy_values[
        "effect_mediation_enforced"
    ]

    from .assurance import PROFILES, FACT_NAMES

    checked = {name: bool(derived.get(name, False)) for name in FACT_NAMES}
    profile = "DEVELOPMENT"
    for profile_name, requirements in PROFILES.items():
        if requirements <= {n for n, v in checked.items() if v}:
            profile = profile_name
            break

    derived_final = {
        **checked,
        # Portable HIGH_ASSURANCE requires proof closure on declaration facts.
        "effect_mediation_enforced": checked["effect_mediation_enforced"],
        "replay_durable": checked["replay_durable"],
        "keys_independently_administered": checked[
            "keys_independently_administered"
        ],
    }

    dfacts = DerivedFacts(
        values=derived_final,
        evidence_classes=evidence_classes,
        proof_closed=proof_closed,
        closure_dimensions=closure_dimensions,
    )
    meta = {
        "conflicts": conflicts,
        "unknowns": unknowns,
        "detail": detail,
        "chain_ok": chain_ok,
        "cert_sig_ok": cert_sig_ok,
        "policy_ok": policy_ok,
        "completeness": completeness,
        "unresolved": unresolved,
        "classes": sorted(classes),
        "events_hint": events_hint,
        "receipt_authenticated": receipt_authenticated,
    }
    return dfacts, meta


EVIDENCE_UNVERIFIED_PLACEHOLDER = "unverifiable"


def facts_requires_witness(payload: Mapping[str, Any]) -> bool:
    return bool(payload.get("assurance_facts", {}).get("history_witnessed"))


def verify_bundle_v2(
    bundle: Mapping[str, Any],
    *,
    trusted_root_public_key_pem: str,
    trusted_witness_public_keys_pem: list[str],
    trusted_provider_public_keys_pem: list[str] | None = None,
    allow_underclaim: bool = True,
) -> BundleReportV2:
    """Offline verifier v2: recompute facts; detect certificate overclaims."""
    if (
        not isinstance(bundle, Mapping)
        or bundle.get("schema") != BUNDLE_SCHEMA_V2
        or not set(bundle) <= (_V2_SECTIONS | {"notes"})
    ):
        raise BundleV2Error("verification bundle v2 fields/schema are invalid")

    derived, meta = derive_bundle_facts_v2(
        bundle,
        trusted_root_public_key_pem=trusted_root_public_key_pem,
        trusted_witness_public_keys_pem=trusted_witness_public_keys_pem,
        trusted_provider_public_keys_pem=trusted_provider_public_keys_pem or [],
    )

    payload = bundle["certificate"]["certificate"]
    claimed = dict(payload.get("assurance_facts", {}))

    mismatches: list[str] = []
    for name, derived_value in derived.values.items():
        if name not in claimed:
            continue
        claimed_value = bool(claimed[name])
        if claimed_value and not derived_value:
            mismatches.append(f"overclaim: {name} claimed true, evidence gives false")
        elif not claimed_value and derived_value and not allow_underclaim:
            mismatches.append(f"underclaim: {name} claimed false, evidence gives true")
    # Profile must also match the derived facts.
    claimed_profile = str(payload.get("assurance_profile", "DEVELOPMENT"))
    if claimed_profile != derived.profile_for_comparison if hasattr(derived, "profile_for_comparison") else False:
        pass

    report = BundleReportV2(
        bundle_schema_valid=True,
        certificate_signature_valid=meta["cert_sig_ok"],
        trust_chain_valid=meta["chain_ok"],
        manifest_authorization_valid=meta["chain_ok"] and meta["cert_sig_ok"],
        historical_trust_valid=meta["chain_ok"],
        namespace_integrity=bool(derived.values["namespace_complete"]),
        evidence_complete=meta["completeness"],
        effect_reconciliation_status=(
            "committed" if derived.values["effects_reconciled"] else
            ("partial" if meta["receipt_authenticated"] or derived.values["effect_mediated"] else "none-bundled")
        ),
        provider_evidence_status=(
            "provider_authenticated" if meta["receipt_authenticated"] else
            ("adapter-only" if bundle["effect_reconciliation_statements"] else "none")
        ),
        provider_receipt_authenticated=derived.values[
            "provider_receipts_authenticated"
        ],
        deployment_attestation_valid=(
            None if bundle["deployment_attestation"] is None
            else bool(bundle["deployment_attestation"])
        ),
        credential_isolation_status=(
            "verified" if isinstance(bundle["deployment_attestation"], Mapping)
            and bundle["deployment_attestation"].get("credential_isolation_verified")
            else ("unknown" if bundle["deployment_attestation"] is None else "violated")
        ),
        network_isolation_status=(
            "verified" if isinstance(bundle["deployment_attestation"], Mapping)
            and bundle["deployment_attestation"].get("network_isolation_verified")
            else ("unknown" if bundle["deployment_attestation"] is None else "violated")
        ),
        effect_mediation_observed=derived.values["effect_mediated"],
        effect_mediation_enforced=derived.values["effect_mediation_enforced"],
        witness_history_valid=derived.values["history_witnessed"],
        witness_independence_status=(
            "independent" if (
                derived.values["witness_administratively_independent"]
                and derived.values["witness_storage_independent"]
            ) else "local-only" if derived.values["history_witnessed"] else "unknown"
        ),
        unresolved_effects=int(payload.get("effects", {}).get("indeterminate", 0)),
        conflicts=meta["conflicts"],
        unknowns=meta["unknowns"],
        derived_assurance_facts=dict(derived.values),
        fact_evidence_classes=dict(derived.evidence_classes),
        proof_closure=dict(derived.proof_closed),
        closure_dimensions={
            k: dict(v) for k, v in (derived.closure_dimensions or {}).items()
        },
        derived_profile=_derive_profile_from(derived.values),
        certificate_claim_match=not mismatches,
        claim_mismatches=mismatches,
    )
    return report


def _derive_profile_from(values: Mapping[str, bool]) -> str:
    from .assurance import PROFILES, FACT_NAMES

    checked = {name: bool(values.get(name, False)) for name in FACT_NAMES}
    for profile_name, requirements in PROFILES.items():
        if requirements <= {n for n, v in checked.items() if v}:
            return profile_name
    return "DEVELOPMENT"


def write_bundle_v2(bundle: Mapping[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(bundle), indent=2, sort_keys=True), encoding="utf-8")
    return target


def read_bundle_v2(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != BUNDLE_SCHEMA_V2:
        raise BundleV2Error("file is not a verification bundle v2")
    return value


# ---------------------------------------------------------------------------
# v1 compatibility surface (schema event-horizon.verification-bundle.v1)
# ---------------------------------------------------------------------------

BUNDLE_SCHEMA = "event-horizon.verification-bundle.v1"
_V1_SECTIONS = {
    "schema", "certificate", "trust_manifest_envelopes",
    "deployment_policy_statement", "witness_acknowledgments",
    "witness_conflicts", "recorder_checkpoints",
    "effect_reconciliation_statements", "approval_envelopes",
}


def build_bundle(
    *, certificate, trust_manifest_envelopes,
    deployment_policy_statement=None,
    witness_acknowledgments=None, witness_conflicts=None,
    recorder_checkpoints=None, effect_reconciliation_statements=None,
    approval_envelopes=None,
):
    return {
        "schema": BUNDLE_SCHEMA,
        "certificate": dict(certificate),
        "trust_manifest_envelopes": [dict(i) for i in trust_manifest_envelopes],
        "deployment_policy_statement": (
            dict(deployment_policy_statement)
            if deployment_policy_statement is not None else None
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
    evidence_completeness: str
    effect_reconciliation: str
    mediation_status: str
    history_status: str
    independence_status: str
    conflicts: list = field(default_factory=list)
    unknowns: list = field(default_factory=list)
    assurance_facts: dict = field(default_factory=dict)
    profile: str = "DEVELOPMENT"
    detail: list = field(default_factory=list)

    def to_dict(self):
        return {
            "cryptographic_validity": self.cryptographic_validity,
            "historical_trust_validity": self.historical_trust_validity,
            "namespace_integrity": self.namespace_integrity,
            "evidence_completeness": self.evidence_completeness,
            "effect_reconciliation": self.effect_reconciliation,
            "mediation_status": self.mediation_status,
            "history_status": self.history_status,
            "independence_status": self.independence_status,
            "conflicts": list(self.conflicts),
            "unknowns": list(self.unknowns),
            "assurance_facts": dict(self.assurance_facts),
            "profile": self.profile,
            "detail": list(self.detail),
        }


class BundleError(ValueError):
    pass


def payload_assurance_facts(bundle):
    return dict(bundle["certificate"]["certificate"].get("assurance_facts", {}))


def verify_bundle(bundle, *, trusted_root_public_key_pem, trusted_witness_public_keys_pem=()):
    if not isinstance(bundle, Mapping) or set(bundle) != _V1_SECTIONS:
        raise BundleError("verification bundle fields are invalid")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise BundleError(f"unsupported bundle schema: {bundle['schema']!r}")
    v2_view = {
        **bundle,
        "schema": BUNDLE_SCHEMA_V2,
        "provider_receipt_envelopes": [],
        "deployment_attestation": None,
    }
    report2 = verify_bundle_v2(
        v2_view,
        trusted_root_public_key_pem=trusted_root_public_key_pem,
        trusted_witness_public_keys_pem=list(trusted_witness_public_keys_pem),
    )
    facts = report2.derived_assurance_facts
    history_status = (
        "witnessed" if facts.get("history_witnessed")
        else ("conflicted-evidence" if report2.conflicts else "unanchored")
    )
    return BundleReport(
        cryptographic_validity=report2.certificate_signature_valid and not report2.conflicts,
        historical_trust_validity=report2.historical_trust_valid,
        namespace_integrity=report2.namespace_integrity,
        evidence_completeness=report2.evidence_complete,
        effect_reconciliation=(
            "reconciled" if facts.get("effects_reconciled") else "none-bundled"
        ),
        mediation_status=(
            "enforced-exclusive" if facts.get("effect_mediation_enforced")
            else ("observed-only" if facts.get("effect_mediated") else "not-mediated")
        ),
        history_status=history_status,
        independence_status=(
            "independent" if (
                facts.get("witness_administratively_independent")
                and facts.get("witness_storage_independent")
            ) else ("local-only" if facts.get("history_witnessed") else "unknown")
        ),
        conflicts=report2.conflicts,
        unknowns=report2.unknowns,
        assurance_facts=payload_assurance_facts(bundle),
        profile=str(
            bundle["certificate"]["certificate"].get("assurance_profile", "DEVELOPMENT")
        ),
    )


def write_bundle(bundle, path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(bundle), indent=2, sort_keys=True), encoding="utf-8")
    return target


def read_bundle(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BundleError("bundle file must contain an object")
    return value
