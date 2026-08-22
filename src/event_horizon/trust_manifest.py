"""Trust Root Manifest: role-authorized key identities for one deployment.

A cryptographic signature proves *some* key signed a statement. This module
answers the harder question: **was that key authorized, by this deployment's
trust root, to perform that role at that time?**

Properties enforced here:

* the entire actor registry is signed by an explicit deployment root authority;
* manifest updates form a hash-chained, monotonically ordered sequence;
* one key may hold exactly one role (cross-role substitution fails closed);
* authorization binds ``key identity + role + purpose``;
* key lifecycle is explicit: active -> retired -> revoked;
* revocation never silently reinterprets history: statements are validated
  against the manifest version applicable at their issuance context;
* unknown future schema versions fail closed.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest


MANIFEST_SCHEMA = "event-horizon.trust-manifest.v1"
MANIFEST_ALGORITHM = "Ed25519"
AUTHORITY_GRANT_SCHEMA = "event-horizon.authority-grant.v1"

# Fields of a root-issued intermediate authority grant.
GRANT_FIELDS = {
    "schema",
    "algorithm",
    "grant_id",
    "deployment_id",
    "environment",
    "intermediate_key_id",
    "intermediate_public_key_pem",
    "allowed_roles",
    "may_replace_witness",
    "max_manifest_sequence",
    "issued_at_ms",
    "signature",
}
MAX_MANIFEST_ACTORS = 64
_MAX_TEXT = 256

_KEY_ID = re.compile(r"^ed25519:[0-9a-f]{32}$")
_SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")

ROLES = frozenset({
    "deployment-root",
    "certificate-signer",
    "capability-signer",
    "verifier",
    "guardian",
    "executor",
    "watchdog",
    "recorder",
    "effect-gateway",
    "replay-service",
    "witness",
    "approver",
})

# Purpose identifiers bind signing APIs to roles. A signer authorized for one
# purpose cannot satisfy another, even inside the same role family.
PURPOSES = {
    "certificate-signer": frozenset({"issue-containment-certificate"}),
    "capability-signer": frozenset({"issue-capability"}),
    "verifier": frozenset({"verify-executor-attestation"}),
    "guardian": frozenset({"approve-request"}),
    "executor": frozenset({"emit-execution-receipt"}),
    "watchdog": frozenset({"attest-teardown"}),
    "recorder": frozenset({"record-evidence", "issue-recorder-checkpoint"}),
    "effect-gateway": frozenset({
        "record-effect-intent", "emit-effect-receipt", "emit-effect-reconciliation",
    }),
    "replay-service": frozenset({"operate-replay-state"}),
    "witness": frozenset({"witness-checkpoint"}),
    # Independent approvers satisfy quorum policies for high-value
    # transitions; multiple distinct approver keys are verified per action.
    "approver": frozenset({
        "approve-containment-certificate",
        "rotate-trust-manifest",
        "approve-capability-quorum",
        "approve-emergency-revocation",
    }),
}

ACTOR_STATUSES = frozenset({"active", "retired", "revoked"})
ALLOWED_ALGORITHMS = frozenset({"Ed25519"})


class TrustManifestError(ValueError):
    """The manifest is malformed, untrusted, stale, or conflicting."""


class KeyNotAuthorizedError(TrustManifestError):
    """The key exists but is not authorized for this role/purpose/time."""

    def __init__(self, message: str, *, reason_code: str = "not-authorized") -> None:
        super().__init__(message)
        self.reason_code = reason_code


def genesis_manifest_digest(deployment_id: str, environment: str) -> str:
    return digest({
        "schema": MANIFEST_SCHEMA,
        "genesis": True,
        "deployment_id": deployment_id,
        "environment": environment,
    })


def _require_scope(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SCOPE.fullmatch(value) is None:
        raise TrustManifestError(f"{label} is invalid")
    return value


def _load_private(value: bytes | Ed25519PrivateKey) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) >= 32:
        return Ed25519PrivateKey.from_private_bytes(value[:32])
    raise TrustManifestError("deployment root signing key must be Ed25519")


def _key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()[:32]}"


def public_key_id(public_key_pem: str) -> str:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise TrustManifestError("actor public key PEM is malformed") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise TrustManifestError("actor public key must be Ed25519")
    return _key_id_for(key)


def make_actor(
    *,
    role: str,
    public_key_pem: str,
    purposes: set[str] | frozenset[str] | None = None,
    status: str = "active",
    valid_from_ms: int = 0,
    valid_until_ms: int | None = None,
    constraints: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one actor entry, deriving its key ID from the PEM."""
    if role not in ROLES:
        raise TrustManifestError(f"unknown actor role: {role!r}")
    if status not in ACTOR_STATUSES:
        raise TrustManifestError(f"invalid actor status: {status!r}")
    allowed = PURPOSES.get(role, frozenset())
    resolved = frozenset(purposes) if purposes is not None else allowed
    if not resolved or not resolved <= allowed:
        raise TrustManifestError(
            f"purposes {sorted(resolved)} are not valid for role {role!r}"
        )
    if type(valid_from_ms) is not int or valid_from_ms < 0:
        raise TrustManifestError("actor validity start is invalid")
    if valid_until_ms is not None and (
        type(valid_until_ms) is not int or valid_until_ms < valid_from_ms
    ):
        raise TrustManifestError("actor validity end precedes its start")
    if constraints is not None and not isinstance(constraints, dict):
        raise TrustManifestError("actor constraints must be an object")
    entry: dict[str, Any] = {
        "role": role,
        "key_id": public_key_id(public_key_pem),
        "public_key_pem": public_key_pem,
        "purposes": sorted(resolved),
        "status": status,
        "valid_from_ms": valid_from_ms,
        "valid_until_ms": valid_until_ms,
    }
    if constraints:
        entry["constraints"] = dict(constraints)
    return entry


def _validate_actor_entry(entry: Any) -> dict[str, Any]:
    base_fields = {
        "role", "key_id", "public_key_pem", "purposes", "status",
        "valid_from_ms", "valid_until_ms",
    }
    if not isinstance(entry, dict) or not base_fields.issubset(set(entry)):
        raise TrustManifestError("actor entry fields are invalid")
    extra = set(entry) - base_fields - {"constraints"}
    if extra:
        raise TrustManifestError(f"unknown actor entry fields: {sorted(extra)!r}")
    if entry["role"] not in ROLES:
        raise TrustManifestError(f"unknown actor role: {entry['role']!r}")
    if not isinstance(entry["key_id"], str) or _KEY_ID.fullmatch(entry["key_id"]) is None:
        raise TrustManifestError("actor key ID is malformed")
    derived = public_key_id(entry["public_key_pem"])
    if derived != entry["key_id"]:
        raise TrustManifestError("actor key ID does not match its public key")
    allowed = PURPOSES.get(entry["role"], frozenset())
    purposes = entry["purposes"]
    if (
        not isinstance(purposes, list)
        or not purposes
        or any(item not in allowed for item in purposes)
        or len(set(purposes)) != len(purposes)
    ):
        raise TrustManifestError(f"actor purposes are invalid for role {entry['role']!r}")
    if entry["status"] not in ACTOR_STATUSES:
        raise TrustManifestError("actor status is invalid")
    if type(entry["valid_from_ms"]) is not int or entry["valid_from_ms"] < 0:
        raise TrustManifestError("actor validity start is invalid")
    until = entry["valid_until_ms"]
    if until is not None and (type(until) is not int or until < entry["valid_from_ms"]):
        raise TrustManifestError("actor validity window is invalid")
    if "constraints" in entry and not isinstance(entry["constraints"], dict):
        raise TrustManifestError("actor constraints must be an object")
    return entry


_MANIFEST_FIELDS = {
    "schema",
    "algorithm",
    "deployment_id",
    "environment",
    "manifest_version",
    "sequence",
    "issued_at_ms",
    "previous_manifest_digest",
    "actors",
    "policy_roots",
    "allowed_algorithms",
    "revocations",
    "root_key_id",
    "signature",
}


@dataclass(frozen=True)
class VerifiedManifest:
    """One cryptographically verified manifest envelope."""

    envelope: Mapping[str, Any]
    deployment_id: str
    environment: str
    manifest_version: int
    sequence: int
    manifest_digest: str

    @property
    def actors(self) -> tuple[dict[str, Any], ...]:
        return tuple(self.envelope["actors"])

    def actor(self, key_id: str) -> dict[str, Any] | None:
        for entry in self.envelope["actors"]:
            if entry["key_id"] == key_id:
                return entry
        return None

    def digest_of_payload(self) -> str:
        unsigned = {k: v for k, v in self.envelope.items() if k != "signature"}
        return digest(unsigned)


class TrustRootAuthority:
    """Signs manifest envelopes as the deployment root authority."""

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey,
        *,
        deployment_id: str,
        environment: str,
    ) -> None:
        self._private_key = _load_private(signing_key)
        self.public_key = self._private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.key_id = _key_id_for(self.public_key)
        self.deployment_id = _require_scope(deployment_id, "deployment ID")
        self.environment = _require_scope(environment, "environment")

    def issue_manifest(
        self,
        actors: list[dict[str, Any]],
        *,
        manifest_version: int,
        sequence: int,
        issued_at_ms: int,
        previous_manifest_digest: str | None,
        policy_roots: list[str] | None = None,
        revocations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(manifest_version, int) or manifest_version < 1:
            raise TrustManifestError("manifest version must be a positive integer")
        if not isinstance(sequence, int) or sequence < 1:
            raise TrustManifestError("manifest sequence must be a positive integer")
        if type(issued_at_ms) is not int or issued_at_ms < 0:
            raise TrustManifestError("manifest issuance time must be integer milliseconds")
        expected_previous = (
            genesis_manifest_digest(self.deployment_id, self.environment)
            if manifest_version == 1
            else previous_manifest_digest
        )
        if not isinstance(expected_previous, str) or re.fullmatch(
            r"[0-9a-f]{64}", expected_previous
        ) is None:
            raise TrustManifestError("previous manifest digest is required for chained versions")
        if not actors or len(actors) > MAX_MANIFEST_ACTORS:
            raise TrustManifestError("manifest actor count is invalid")
        seen_keys: set[str] = set()
        validated: list[dict[str, Any]] = []
        for entry in actors:
            validated_entry = _validate_actor_entry(dict(entry))
            if validated_entry["key_id"] in seen_keys:
                # One key, one role: cross-role substitution fails at issuance.
                raise TrustManifestError(
                    f"key {validated_entry['key_id']} appears under multiple actors"
                )
            seen_keys.add(validated_entry["key_id"])
            validated.append(validated_entry)
        if any(entry["role"] == "deployment-root" for entry in validated):
            raise TrustManifestError(
                "the deployment root authorizes itself through possession of the root key, "
                "not through manifest entries"
            )
        roots = policy_roots or []
        if not isinstance(roots, list) or any(
            not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
            for item in roots
        ):
            raise TrustManifestError("policy roots must be SHA-256 digests")
        revs = revocations or []
        for revocation in revs:
            if not isinstance(revocation, dict) or set(revocation) != {
                "key_id", "reason_code", "effective_sequence"
            }:
                raise TrustManifestError("revocation entry fields are invalid")
            # A revocation may target a key that has already been rotated out
            # of the active roster; the chain validates its existence when
            # authorization is evaluated.
            if not isinstance(revocation["key_id"], str) or _KEY_ID.fullmatch(
                revocation["key_id"]
            ) is None:
                raise TrustManifestError("revocation key ID is malformed")
            if not isinstance(revocation.get("reason_code"), str) or not revocation["reason_code"]:
                raise TrustManifestError("revocation reason is required")
            if type(revocation.get("effective_sequence")) is not int or revocation["effective_sequence"] < 1:
                raise TrustManifestError("revocation effective sequence is invalid")
        payload = {
            "schema": MANIFEST_SCHEMA,
            "algorithm": MANIFEST_ALGORITHM,
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "manifest_version": manifest_version,
            "sequence": sequence,
            "issued_at_ms": issued_at_ms,
            "previous_manifest_digest": expected_previous,
            "actors": validated,
            "policy_roots": sorted(roots),
            "allowed_algorithms": sorted(ALLOWED_ALGORITHMS),
            "revocations": sorted(
                revs,
                key=lambda item: (item["effective_sequence"], item["key_id"]),
            ),
            "root_key_id": self.key_id,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        return {**payload, "signature": signature}


class IntermediateAuthority:
    """Delegated manifest signer constrained by a root-issued grant."""

    def __init__(
        self,
        signing_key: bytes | Ed25519PrivateKey,
        *,
        deployment_id: str,
        environment: str,
        grant: Mapping[str, Any],
    ) -> None:
        self._private_key = _load_private(signing_key)
        public_key = self._private_key.public_key()
        self.key_id = _key_id_for(public_key)
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        if not isinstance(grant, Mapping) or grant.get("intermediate_key_id") != self.key_id:
            raise TrustManifestError(
                "intermediate authority does not match its delegation grant"
            )
        self.grant = grant
        self.deployment_id = _require_scope(deployment_id, "deployment ID")
        self.environment = _require_scope(environment, "environment")

    def issue_manifest(
        self,
        actors: list[dict[str, Any]],
        *,
        manifest_version: int,
        sequence: int,
        issued_at_ms: int,
        previous_manifest_digest: str | None,
        policy_roots: list[str] | None = None,
        revocations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        # Reuse the root issuer's payload construction by temporarily signing
        # with the intermediate key: build unsigned payload here directly.
        from dataclasses import dataclass as _dc  # noqa: F401

        expected_previous = (
            genesis_manifest_digest(self.deployment_id, self.environment)
            if manifest_version == 1
            else previous_manifest_digest
        )
        if not isinstance(expected_previous, str):
            raise TrustManifestError("previous manifest digest is required")
        validated = []
        seen: set[str] = set()
        for entry in actors:
            e = _validate_actor_entry(dict(entry))
            if e["key_id"] in seen:
                raise TrustManifestError("duplicate actor key")
            seen.add(e["key_id"])
            validated.append(e)
        payload = {
            "schema": MANIFEST_SCHEMA,
            "algorithm": MANIFEST_ALGORITHM,
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "manifest_version": manifest_version,
            "sequence": sequence,
            "issued_at_ms": issued_at_ms,
            "previous_manifest_digest": expected_previous,
            "actors": validated,
            "policy_roots": sorted(policy_roots or []),
            "allowed_algorithms": sorted(ALLOWED_ALGORITHMS),
            "revocations": sorted(
                revocations or [],
                key=lambda item: (item["effective_sequence"], item["key_id"]),
            ),
            "root_key_id": self.key_id,
        }
        signature = base64.urlsafe_b64encode(
            self._private_key.sign(canonical_bytes(payload))
        ).rstrip(b"=").decode("ascii")
        return {**payload, "signature": signature}


def issue_authority_grant(
    root_authority: "TrustRootAuthority",
    intermediate_public_key_pem: str,
    *,
    grant_id: str,
    allowed_roles: list[str],
    may_replace_witness: bool,
    max_manifest_sequence: int,
    issued_at_ms: int,
) -> dict[str, Any]:
    """Offline root operation: delegate constrained authority to an intermediate."""
    for role in allowed_roles:
        if role not in ROLES or role == "deployment-root":
            raise TrustManifestError(
                f"role {role!r} cannot be delegated by an authority grant"
            )
    key_id = public_key_id(intermediate_public_key_pem)
    payload = {
        "schema": AUTHORITY_GRANT_SCHEMA,
        "algorithm": MANIFEST_ALGORITHM,
        "grant_id": grant_id,
        "deployment_id": root_authority.deployment_id,
        "environment": root_authority.environment,
        "intermediate_key_id": key_id,
        "intermediate_public_key_pem": intermediate_public_key_pem,
        "allowed_roles": sorted(allowed_roles),
        "may_replace_witness": bool(may_replace_witness),
        "max_manifest_sequence": max_manifest_sequence,
        "issued_at_ms": issued_at_ms,
    }
    private_key = root_authority._private_key
    signature = base64.urlsafe_b64encode(
        private_key.sign(canonical_bytes(payload))
    ).rstrip(b"=").decode("ascii")
    return {**payload, "signature": signature}


class ManifestChain:
    """Verifies and stores the tamper-evident manifest chain for a deployment."""

    def __init__(
        self,
        trusted_root_public_key_pem: str,
        *,
        deployment_id: str,
        environment: str,
        authority_grant: Mapping[str, Any] | None = None,
    ) -> None:
        try:
            loaded = serialization.load_pem_public_key(
                trusted_root_public_key_pem.encode("ascii")
            )
        except (ValueError, TypeError, UnicodeError) as exc:
            raise TrustManifestError("trusted root public key is malformed") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise TrustManifestError("trusted root public key must be Ed25519")
        self._root_key = loaded
        self.root_key_id = _key_id_for(loaded)
        self.deployment_id = _require_scope(deployment_id, "deployment ID")
        self.environment = _require_scope(environment, "environment")
        self._chain: list[VerifiedManifest] = []
        # v0.8 root blast-radius reduction: when an authority grant is
        # supplied, manifests may be signed by the delegated intermediate key
        # only, and only within the grant's explicit constraints. The offline
        # root private key is never needed at runtime.
        self.authority_grant: Mapping[str, Any] | None = None
        self.signing_authority_key: Ed25519PublicKey = loaded
        if authority_grant is not None:
            self._accept_grant(authority_grant)

    def _accept_grant(self, grant: Mapping[str, Any]) -> None:
        if not isinstance(grant, dict) or set(grant) != GRANT_FIELDS:
            raise TrustManifestError("authority grant fields are invalid")
        if grant["schema"] != AUTHORITY_GRANT_SCHEMA:
            raise TrustManifestError("unsupported authority grant schema")
        unsigned = {k: v for k, v in grant.items() if k != "signature"}
        if (
            grant["deployment_id"] != self.deployment_id
            or grant["environment"] != self.environment
        ):
            raise TrustManifestError("authority grant binds a different deployment")
        try:
            intermediate = serialization.load_pem_public_key(
                grant["intermediate_public_key_pem"].encode("ascii")
            )
        except (ValueError, TypeError, UnicodeError, AttributeError) as exc:
            raise TrustManifestError("intermediate key PEM is malformed") from exc
        if not isinstance(intermediate, Ed25519PublicKey):
            raise TrustManifestError("intermediate key must be Ed25519")
        if grant["intermediate_key_id"] != _key_id_for(intermediate):
            raise TrustManifestError("grant intermediate key identity mismatch")
        decoded = base64.urlsafe_b64decode(grant["signature"] + "=" * (-len(grant["signature"]) % 4))
        try:
            self._root_key.verify(decoded, canonical_bytes(unsigned))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise TrustManifestError("authority grant signature is invalid") from exc
        allowed = grant["allowed_roles"]
        if (
            not isinstance(allowed, list)
            or not allowed
            or any(role not in ROLES for role in allowed)
        ):
            raise TrustManifestError("grant allowed roles are invalid")
        if type(grant["max_manifest_sequence"]) is not int or grant["max_manifest_sequence"] < 1:
            raise TrustManifestError("grant max manifest sequence is invalid")
        if type(grant["may_replace_witness"]) is not bool:
            raise TrustManifestError("grant witness-replacement flag is invalid")
        self.authority_grant = grant
        self.signing_authority_key = intermediate

    def _enforce_grant(self, envelope: Mapping[str, Any], previous: VerifiedManifest | None) -> None:
        grant = self.authority_grant
        if grant is None:
            return
        if envelope["root_key_id"] != _key_id_for(self.signing_authority_key):
            raise KeyNotAuthorizedError(
                "manifest was not signed by the delegated intermediate authority",
                reason_code="wrong-intermediate-key",
            )
        new_roles = {entry["role"] for entry in envelope["actors"]}
        disallowed = sorted(new_roles - set(grant["allowed_roles"]))
        if disallowed:
            # Authority widening attempt: the intermediate exceeds its grant.
            raise KeyNotAuthorizedError(
                f"intermediate granted roles {sorted(grant['allowed_roles'])} "
                f"but manifest authorizes {disallowed!r}",
                reason_code="role-outside-grant",
            )
        if envelope["sequence"] > grant["max_manifest_sequence"]:
            raise KeyNotAuthorizedError(
                "manifest sequence exceeds the intermediate's delegated maximum",
                reason_code="sequence-outside-grant",
            )
        if previous is not None:
            old_witnesses = {
                entry["key_id"] for entry in previous.envelope["actors"]
                if entry["role"] == "witness"
            }
            new_witnesses = {
                entry["key_id"] for entry in envelope["actors"]
                if entry["role"] == "witness"
            }
            if new_witnesses and old_witnesses and new_witnesses != old_witnesses:
                if not grant["may_replace_witness"]:
                    raise KeyNotAuthorizedError(
                        "intermediate attempted witness replacement without authority",
                        reason_code="witness-replacement-forbidden",
                    )

    def issue_delegated_grant_stub(self):  # pragma: no cover - documentation seam
        raise NotImplementedError

    @property
    def current(self) -> VerifiedManifest | None:
        return self._chain[-1] if self._chain else None

    @property
    def version(self) -> int:
        return self._chain[-1].manifest_version if self._chain else 0

    def verify_envelope(self, envelope: Any) -> VerifiedManifest:
        if not isinstance(envelope, dict) or set(envelope) != _MANIFEST_FIELDS:
            raise TrustManifestError("manifest envelope fields are invalid")
        if envelope["schema"] != MANIFEST_SCHEMA:
            raise TrustManifestError(
                f"unsupported manifest schema: {envelope['schema']!r}"
            )
        if envelope["algorithm"] not in ALLOWED_ALGORITHMS:
            raise TrustManifestError("manifest algorithm is not allowed")
        # Delegated authority (v0.8): when a grant is pinned, the intermediate
        # key signs manifests and grant constraints are enforced; otherwise
        # the offline deployment root signs directly.
        signing_key = self.signing_authority_key
        expected_key_id = (
            _key_id_for(self.signing_authority_key)
            if self.authority_grant is not None
            else self.root_key_id
        )
        if envelope["root_key_id"] != expected_key_id:
            code = (
                "wrong-intermediate-key"
                if self.authority_grant is not None
                else "wrong-root-key"
            )
            raise KeyNotAuthorizedError(
                "manifest was not signed by the pinned "
                + ("intermediate authority" if self.authority_grant is not None else "deployment root"),
                reason_code=code,
            )
        if envelope["deployment_id"] != self.deployment_id:
            raise TrustManifestError("manifest belongs to a different deployment")
        if envelope["environment"] != self.environment:
            raise TrustManifestError("manifest belongs to a different environment")
        if not isinstance(envelope["actors"], list) or not (
            1 <= len(envelope["actors"]) <= MAX_MANIFEST_ACTORS
        ):
            raise TrustManifestError("manifest actor list is invalid")
        seen: set[str] = set()
        for entry in envelope["actors"]:
            _validate_actor_entry(entry)
            if entry["key_id"] in seen:
                raise TrustManifestError("duplicate actor key in manifest")
            seen.add(entry["key_id"])
        if envelope["allowed_algorithms"] != sorted(ALLOWED_ALGORITHMS):
            raise TrustManifestError("allowed algorithm registry changed shape")
        signature = envelope["signature"]
        if not isinstance(signature, str):
            raise TrustManifestError("manifest signature is malformed")
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        try:
            decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if len(decoded) != 64:
                raise TrustManifestError("manifest signature length is invalid")
            signing_key.verify(decoded, canonical_bytes(unsigned))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise TrustManifestError("manifest signature is invalid") from exc
        manifest = VerifiedManifest(
            envelope=envelope,
            deployment_id=envelope["deployment_id"],
            environment=envelope["environment"],
            manifest_version=envelope["manifest_version"],
            sequence=envelope["sequence"],
            manifest_digest=digest(unsigned),
        )
        self._enforce_grant(envelope, self._chain[-1] if self._chain else None)
        self._check_chaining(manifest)
        return manifest

    def _check_chaining(self, manifest: VerifiedManifest) -> None:
        if not self._chain:
            expected_genesis = genesis_manifest_digest(
                self.deployment_id, self.environment
            )
            if manifest.manifest_version != 1:
                raise TrustManifestError("chain must begin at manifest version 1")
            if manifest.envelope["previous_manifest_digest"] != expected_genesis:
                raise TrustManifestError("first manifest does not anchor to genesis")
            return
        previous = self._chain[-1]
        if manifest.manifest_version != previous.manifest_version + 1:
            raise TrustManifestError(
                f"manifest version regression or gap: {previous.manifest_version} -> "
                f"{manifest.manifest_version}"
            )
        if manifest.sequence <= previous.sequence:
            raise TrustManifestError("manifest ordering sequence regressed")
        if manifest.envelope["previous_manifest_digest"] != previous.manifest_digest:
            raise TrustManifestError("manifest chain linkage failure")

    def append(self, envelope: Any) -> VerifiedManifest:
        manifest = self.verify_envelope(envelope)
        self._chain.append(manifest)
        return manifest

    def manifest_at(self, manifest_version: int) -> VerifiedManifest:
        for manifest in self._chain:
            if manifest.manifest_version == manifest_version:
                return manifest
        raise TrustManifestError(
            f"manifest version {manifest_version} is not part of this verified chain"
        )

    def version_for_digest(self, manifest_digest: str) -> int:
        """Resolve a manifest digest to its position in this verified chain."""
        if not isinstance(manifest_digest, str) or re.fullmatch(
            r"[0-9a-f]{64}", manifest_digest
        ) is None:
            raise TrustManifestError("manifest digest is malformed")
        for manifest in self._chain:
            if manifest.manifest_digest == manifest_digest:
                return manifest.manifest_version
        raise TrustManifestError("manifest digest is unknown to this verified chain")

    # ------------------------------------------------------------ authorization

    def authorize(
        self,
        key_id: str,
        *,
        role: str,
        purpose: str | None = None,
        at_manifest_version: int | None = None,
        at_ms: int | None = None,
    ) -> dict[str, Any]:
        """Authorize a key for one role/purpose under the applicable manifest.

        ``at_manifest_version`` selects historical verification: the manifest
        that was authoritative when the statement was issued. Revocation is
        therefore never applied retroactively to provably earlier statements.
        """
        manifest = (
            self.manifest_at(at_manifest_version)
            if at_manifest_version is not None
            else (self.current if self.current is not None else None)
        )
        if manifest is None:
            raise KeyNotAuthorizedError("no verified manifest is available")
        if at_manifest_version is None:
            # Current-context revocation wins even if the key was already
            # rotated out of the active roster.
            self._check_revocations(manifest, key_id, historical=False)
        entry = manifest.actor(key_id)
        if entry is None:
            raise KeyNotAuthorizedError(
                f"key {key_id} is not registered in manifest "
                f"v{manifest.manifest_version}",
                reason_code="unknown-key",
            )
        if entry["role"] != role:
            raise KeyNotAuthorizedError(
                f"key {key_id} holds role {entry['role']!r}, not {role!r}",
                reason_code="wrong-role",
            )
        if purpose is not None and purpose not in entry["purposes"]:
            raise KeyNotAuthorizedError(
                f"key {key_id} is not authorized for purpose {purpose!r}",
                reason_code="wrong-purpose",
            )
        if at_ms is not None:
            if at_ms < entry["valid_from_ms"] or (
                entry["valid_until_ms"] is not None and at_ms > entry["valid_until_ms"]
            ):
                raise KeyNotAuthorizedError(
                    f"key {key_id} validity window excludes t={at_ms}",
                    reason_code="expired-key",
                )
        active_statuses = {"active"}
        if at_manifest_version is not None:
            # Historical context: the key only needed to be usable then.
            if entry["status"] == "revoked":
                self._assert_not_revoked_then(manifest, key_id, at_manifest_version)
            elif entry["status"] not in active_statuses:
                raise KeyNotAuthorizedError(
                    f"key {key_id} was not active in manifest "
                    f"v{manifest.manifest_version}",
                    reason_code="inactive-key",
                )
        else:
            if entry["status"] != "active":
                raise KeyNotAuthorizedError(
                    f"key {key_id} is {entry['status']}",
                    reason_code=f"{entry['status']}-key",
                )
        self._check_revocations(manifest, key_id, historical=at_manifest_version is not None)
        return entry

    def _assert_not_revoked_then(
        self,
        manifest: VerifiedManifest,
        key_id: str,
        at_manifest_version: int,
    ) -> None:
        for revocation in manifest.envelope["revocations"]:
            if (
                revocation["key_id"] == key_id
                and revocation["effective_sequence"] <= manifest.sequence
            ):
                raise KeyNotAuthorizedError(
                    f"key {key_id} was already revoked at manifest "
                    f"v{manifest.manifest_version}",
                    reason_code="revoked-key",
                )

    def _check_revocations(
        self,
        manifest: VerifiedManifest,
        key_id: str,
        *,
        historical: bool,
    ) -> None:
        for revocation in manifest.envelope["revocations"]:
            if revocation["key_id"] != key_id:
                continue
            if not historical and revocation["effective_sequence"] <= manifest.sequence:
                raise KeyNotAuthorizedError(
                    f"key {key_id} is revoked",
                    reason_code="revoked-key",
                )


@dataclass(frozen=True)
class HistoricalTrustVerdict:
    """Independently modeled predicates for historical statement trust.

    Only the conjunction of all four predicates yields a historically
    trusted statement. A signer-supplied timestamp or claimed manifest
    version alone never establishes pre-revocation existence.
    """

    signature_valid: bool
    key_authorized_for_claimed_manifest: bool
    statement_observed_before_revocation: bool
    historically_trusted: bool
    reason: str


def _verdict(
    signature_valid: bool,
    authorized: bool,
    observed: bool,
    reason: str,
) -> HistoricalTrustVerdict:
    return HistoricalTrustVerdict(
        signature_valid=signature_valid,
        key_authorized_for_claimed_manifest=authorized,
        statement_observed_before_revocation=observed,
        historically_trusted=signature_valid and authorized and observed,
        reason=reason,
    )


_OBSERVATION_KIND_WITNESSED_CHECKPOINT = "witnessed_recorder_checkpoint"


def historical_trust(
    chain: "ManifestChain",
    *,
    key_id: str,
    role: str,
    purpose: str | None = None,
    manifest_version: int,
    signature_valid: bool,
    observation: Mapping[str, Any] | None = None,
) -> HistoricalTrustVerdict:
    """Evaluate whether a statement may carry strong historical claims.

    ``signature_valid`` must be established by the caller through the typed
    statement verifier. Existence before revocation requires an independent
    observation; the supported kind binds the statement's event into a
    recorder checkpoint whose acknowledgment was produced by an external
    witness. Signer-supplied timestamps are never consulted.
    """
    if not signature_valid:
        return _verdict(False, False, False, "signature-invalid")
    try:
        chain.authorize(
            key_id,
            role=role,
            purpose=purpose,
            at_manifest_version=manifest_version,
        )
    except TrustManifestError as exc:
        return _verdict(
            True, False, False, f"not-authorized-at-claimed-manifest ({exc})"
        )

    if not isinstance(observation, Mapping):
        return _verdict(True, True, False, "statement-existence-unobserved")
    if observation.get("kind") != _OBSERVATION_KIND_WITNESSED_CHECKPOINT:
        return _verdict(True, True, False, "unsupported-observation-kind")

    from .witness import verify_witness_acknowledgment_signature

    ack = observation.get("ack")
    witness_public_key_pem = observation.get("witness_public_key_pem")
    checkpoint_sequence = observation.get("checkpoint_sequence")
    event_hash = observation.get("event_hash")
    if (
        not verify_witness_acknowledgment_signature(ack, witness_public_key_pem)
        or type(checkpoint_sequence) is not int
        or checkpoint_sequence < 1
        or not isinstance(event_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", event_hash) is None
    ):
        return _verdict(True, True, False, "observation-unverifiable")

    try:
        checkpoint_trust_version = chain.version_for_digest(str(ack["manifest_digest"]))
    except TrustManifestError:
        return _verdict(True, True, False, "observation-from-unknown-trust-state")

    # The claimed manifest must not be newer than the trust state under which
    # the statement was observed.
    if manifest_version > checkpoint_trust_version:
        return _verdict(True, True, False, "claimed-manifest-newer-than-observation")

    # The observation must predate every revocation of this key: both in
    # manifest-chain order (the checkpointed trust state precedes the
    # revoking manifest) and in recorder order (the witnessed checkpoint
    # precedes the revocation's effective sequence).
    revocation_versions = [
        manifest.manifest_version
        for manifest in chain._chain
        for revocation in manifest.envelope["revocations"]
        if revocation["key_id"] == key_id
    ]
    if revocation_versions:
        earliest_revocation_version = min(revocation_versions)
        if checkpoint_trust_version >= earliest_revocation_version:
            return _verdict(True, True, False, "observed-at-or-after-revocation")
        effective_sequences = [
            revocation["effective_sequence"]
            for manifest in chain._chain
            for revocation in manifest.envelope["revocations"]
            if revocation["key_id"] == key_id
        ]
        if checkpoint_sequence >= min(effective_sequences):
            return _verdict(True, True, False, "observed-at-or-after-revocation")

    return _verdict(True, True, True, "historically-trusted")


class AuthorizedStatementVerifier:
    """Compose signature verification with manifest role authorization.

    A statement verifies only when (1) its signature is cryptographically
    valid for its typed domain, and (2) its signing key is manifest-authorized
    for the expected role and purpose.
    """

    def __init__(
        self,
        chain: ManifestChain,
        statement_verifier: Any,
    ) -> None:
        self.chain = chain
        self.statement_verifier = statement_verifier

    def verify(
        self,
        envelope: Mapping[str, Any],
        *,
        expected_type: str,
        expected_role: str,
        expected_purpose: str | None = None,
        issued_at_ms_field: str = "issued_at",
        at_manifest_version: int | None = None,
        observation: Mapping[str, Any] | None = None,
        require_observation: bool = False,
    ) -> Any:
        statement = self.statement_verifier.verify(
            envelope, expected_type=expected_type
        )
        key_id = statement.key_id
        at_ms = (
            statement.payload.get("issued_at_ms")
            or statement.payload.get("issued_at")
        )
        self.chain.authorize(
            key_id,
            role=expected_role,
            purpose=expected_purpose,
            at_manifest_version=at_manifest_version,
            at_ms=at_ms if isinstance(at_ms, int) else None,
        )
        if require_observation or observation is not None:
            verdict = historical_trust(
                self.chain,
                key_id=key_id,
                role=expected_role,
                purpose=expected_purpose,
                manifest_version=(
                    at_manifest_version
                    if at_manifest_version is not None
                    else self.chain.version
                ),
                signature_valid=True,
                observation=observation,
            )
            if not verdict.historically_trusted:
                raise KeyNotAuthorizedError(
                    f"historical trust rejected: {verdict.reason}",
                    reason_code=verdict.reason.split(" ")[0],
                )
        return statement
