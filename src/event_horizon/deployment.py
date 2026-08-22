"""Deployment attestation primitives: credential inventory and mode gates.

These are *configuration/runtime* checks — deployment configuration
attestation, not hardware measurement. They make isolation claims mechanically
inspectable: an executor that holds a provider credential fails its inventory,
and high-assurance mode fails closed when any mandatory boundary is absent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class DeploymentBoundaryError(RuntimeError):
    pass


DEPLOYMENT_MODES = ("development", "compatibility", "governed", "high_assurance")


@dataclass(frozen=True)
class CredentialBinding:
    """One secret that MUST live with exactly one service role."""

    credential_id: str
    owner_role: str
    purpose: str

    def __post_init__(self) -> None:
        if not all(isinstance(getattr(self, n), str) and getattr(self, n)
                   for n in ("credential_id", "owner_role", "purpose")):
            raise DeploymentBoundaryError("credential binding fields are invalid")


def verify_credential_inventory(
    observed: Mapping[str, str],
    bindings: list[CredentialBinding],
) -> dict[str, Any]:
    """Check actual secret exposure against the expected ownership table.

    ``observed`` maps service role -> list/str of credential ids it can read.
    Violations are returned; a non-empty violation list means the deployment
    must not attest exclusive boundaries.
    """
    expected: dict[str, set[str]] = {}
    owner_of: dict[str, str] = {}
    for binding in bindings:
        expected.setdefault(binding.owner_role, set()).add(binding.credential_id)
        if binding.credential_id in owner_of and owner_of[binding.credential_id] != binding.owner_role:
            raise DeploymentBoundaryError(
                f"credential {binding.credential_id} double-bound"
            )
        owner_of[binding.credential_id] = binding.owner_role

    violations: list[str] = []
    for role, held in observed.items():
        held_set = (
            {held} if isinstance(held, str) else set(held)
        ) - {""}
        for credential_id in held_set:
            owner = owner_of.get(credential_id)
            if owner is None:
                violations.append(
                    f"unregistered credential {credential_id!r} exposed to {role!r}"
                )
            elif owner != role:
                violations.append(
                    f"role {role!r} holds {credential_id!r} owned by {owner!r}"
                )
    for role, required in expected.items():
        held_set = {observed.get(role, "")} if isinstance(observed.get(role, ""), str) \
            else set(observed.get(role, []))
        missing = required - held_set
        for credential_id in sorted(missing):
            violations.append(
                f"role {role!r} is missing its own credential {credential_id!r}"
            )
    return {
        "violations": violations,
        "clean": not violations,
    }


# Facts that HIGH_ASSURANCE requires, with their mandatory values. The gate is
# evaluated over OBSERVED evidence (inventory/network probes/attestation), so
# a caller cannot satisfy it by declaration alone.
HIGH_ASSURANCE_REQUIREMENTS = {
    "provider_credentials_gateway_only": True,
    "executor_provider_route_denied": True,
    "witness_storage_independent": True,
    "manifest_enforced_end_to_end": True,
    "root_offline_from_runtime": True,
}


def assert_high_assurance_requirements(
    observed_facts: Mapping[str, bool],
    *,
    mode: str,
) -> None:
    """Fail closed unless every mandatory high-assurance fact is observed.

    Missing facts are failures — never silent downgrades — when the operator
    has explicitly selected ``high_assurance`` mode.
    """
    if mode not in DEPLOYMENT_MODES:
        raise DeploymentBoundaryError(f"unknown deployment mode: {mode!r}")
    if mode != "high_assurance":
        return
    missing = [
        name for name, required in HIGH_ASSURANCE_REQUIREMENTS.items()
        if observed_facts.get(name) is not required
    ]
    if missing:
        raise DeploymentBoundaryError(
            "high_assurance mode requires enforced boundaries that are absent: "
            f"{sorted(missing)!r}"
        )


def summarize_network_policy(
    declared: Mapping[str, str],
    observed_probes: Mapping[str, bool],
) -> dict[str, Any]:
    """Compare declared connectivity with probe results.

    ``declared`` maps "src->dst" to "allow"|"deny". ``observed_probes`` maps
    the same keys to whether the connection SUCCEEDED when attempted.
    Distinct declared/observed/enforced states are returned honestly.
    """
    results: dict[str, Any] = {
        "declared": dict(declared),
        "observed": {},
        "enforced": True,
        "violations": [],
    }
    for key, verdict in declared.items():
        reachable = observed_probes.get(key)
        if reachable is None:
            results["observed"][key] = "unknown"
            continue
        should_allow = verdict == "allow"
        actually_allowed = bool(reachable)
        results["observed"][key] = (
            "allowed" if actually_allowed else "blocked"
        )
        if should_allow != actually_allowed:
            results["enforced"] = False
            results["violations"].append(
                f"{key}: declared {verdict} but observed "
                f"{'allowed' if actually_allowed else 'blocked'}"
            )
    return results
