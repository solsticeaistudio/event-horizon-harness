"""Assurance facts and derived profiles.

v0.7 replaces the linear assurance ladder with independently evaluated,
machine-readable **facts**. Named profiles are *derived from* the facts —
never the reverse. A caller cannot request a profile; failure of any single
requirement automatically downgrades the result.

Every fact answers one precise question:

| fact | question |
|---|---|
| authenticated_sources | were all consumed statements cryptographically verified against pinned keys? |
| namespace_complete | is every consumed event bound to this run's namespace? |
| replay_durable | is capability replay state durable rather than volatile? |
| history_witnessed | did an external witness acknowledge the recorder checkpoint? |
| witness_administratively_independent | is the witness declared+signed as administratively separate? |
| witness_storage_independent | is witness storage a separate trust domain? |
| effect_mediated | did every governed effect traverse the Effect Gateway? |
| effect_mediation_enforced | does signed deployment policy declare no bypass path? |
| effects_reconciled | are there unresolved gateway effects? |
| provider_receipts_authenticated | do reconciliations carry provider-authenticated evidence? |
| manifest_authorized_sources | were signers authorized under the Trust Root Manifest? |
| quorum_approval_present | was k-of-n independent approval satisfied? |

Unknown fact names fail closed. Profiles never grant facts.
"""
from __future__ import annotations

ASSURANCE_FACTS_SCHEMA = "event-horizon.assurance-facts.v1"

FACT_NAMES = frozenset({
    "authenticated_sources",
    "namespace_complete",
    "replay_durable",
    "history_witnessed",
    "witness_administratively_independent",
    "witness_storage_independent",
    "keys_independently_administered",
    "effect_mediated",
    "effect_mediation_enforced",
    "effects_reconciled",
    "provider_receipts_authenticated",
    "manifest_authorized_sources",
    "quorum_approval_present",
})

# Ordered most-strict first: derivation returns the first profile whose
# required facts are ALL satisfied.
PROFILES: dict[str, frozenset[str]] = {
    "HIGH_ASSURANCE": frozenset({
        "authenticated_sources",
        "namespace_complete",
        "replay_durable",
        "history_witnessed",
        "witness_administratively_independent",
        "witness_storage_independent",
        "keys_independently_administered",
        "effect_mediated",
        "effect_mediation_enforced",
        "effects_reconciled",
        "provider_receipts_authenticated",
        "manifest_authorized_sources",
        "quorum_approval_present",
    }),
    "INDEPENDENT_CONTROL_PLANE": frozenset({
        "authenticated_sources",
        "namespace_complete",
        "replay_durable",
        "history_witnessed",
        "witness_administratively_independent",
        "witness_storage_independent",
        "keys_independently_administered",
        "effect_mediated",
        "effect_mediation_enforced",
        "effects_reconciled",
    }),
    "GOVERNED_EFFECTS": frozenset({
        "authenticated_sources",
        "namespace_complete",
        "effect_mediated",
        "effects_reconciled",
    }),
    "WITNESSED_HISTORY": frozenset({
        "authenticated_sources",
        "namespace_complete",
        "history_witnessed",
    }),
    "LOCAL_HARDENED": frozenset({
        "authenticated_sources",
        "namespace_complete",
        "replay_durable",
    }),
    "DEVELOPMENT": frozenset(),
}


class AssuranceError(ValueError):
    pass


def normalize_facts(values: dict[str, bool] | None) -> dict[str, bool]:
    """Validate a fact mapping; unknown names fail closed."""
    normalized: dict[str, bool] = {}
    if values is None:
        values = {}
    if not isinstance(values, dict):
        raise AssuranceError("assurance facts must be an object")
    unknown = set(values) - FACT_NAMES
    if unknown:
        raise AssuranceError(f"unknown assurance facts: {sorted(unknown)!r}")
    for name in FACT_NAMES:
        value = values.get(name, False)
        if type(value) is not bool:
            raise AssuranceError(f"assurance fact {name!r} must be boolean")
        normalized[name] = value
    return normalized


def derive_profile(facts: dict[str, bool]) -> str:
    """Derive the strongest satisfied profile from the fact set.

    Facts are inputs only: no caller may select a profile directly, and a
    single missing requirement downgrades the result.
    """
    checked = normalize_facts(facts)
    for profile, requirements in PROFILES.items():
        if requirements <= {name for name, value in checked.items() if value}:
            return profile
    return "DEVELOPMENT"
