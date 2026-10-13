"""Trusted post-SIGKILL journal observation for the Firecracker supervisor.

The authority_context object describes attestation/policy, not the tenant
namespace. Tenant and environment are pinned by verify_options(...) in the
gateway's trusted service_config["verification_context"].
"""
from __future__ import annotations

from collections.abc import Mapping

from event_horizon.effect_outcome_journal import DurableEffectJournal


def observe_crash_reservation(service_config: Mapping, *,
                              capability_id: str, request_digest: str,
                              claims_digest: str):
    """Read the durable reservation without changing it or permitting retry."""
    verification = service_config.get("verification_context")
    if not isinstance(verification, Mapping):
        raise ValueError("trusted verification context missing")
    tenant, environment = verification.get("tenant"), verification.get("environment")
    if any(not isinstance(value, str) or not value
           for value in (tenant, environment, capability_id, request_digest, claims_digest)):
        raise ValueError("journal namespace or request binding not pinned")
    path = service_config.get("outcome_journal")
    if not isinstance(path, str) or not path:
        raise ValueError("trusted durable outcome journal missing")
    record = DurableEffectJournal(path).observe(
        tenant=tenant, environment=environment, capability_id=capability_id,
    )
    if record is not None and (
            record["request_digest"] != request_digest
            or record["claims_digest"] != claims_digest):
        raise RuntimeError("journal reservation rebound to a different signed request")
    return record
