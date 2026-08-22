"""Evidence provenance graph.

Every security-relevant signed statement becomes a node that commits to:

* its statement type/version and signer identity;
* the execution namespace it belongs to (deployment/run/session);
* the digests of the nodes it depends upon;
* the trust-root manifest version applicable at issuance.

The graph is namespace-safe **by construction**: nodes from another run,
session, or deployment cannot be attached. A deterministic Merkle root over
the sorted node set gives certificates a single commitment to the exact
evidence collection used for derivation.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import digest


PROVENANCE_NODE_SCHEMA = "event-horizon.provenance-node.v1"
LEAF_DOMAIN = b"event-horizon:evidence-node:v1:"
INTERNAL_DOMAIN = b"event-horizon:evidence-internal:v1:"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")

NODE_FIELDS = {
    "schema",
    "node_type",
    "source_key_id",
    "deployment_id",
    "run_id",
    "session_id",
    "content_digest",
    "dependencies",
    "manifest_version",
}


class ProvenanceError(ValueError):
    pass


def _leaf_hash(node_digest: str) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + bytes.fromhex(node_digest)).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(INTERNAL_DOMAIN + left + right).digest()


def merkle_root_from_leaves(sorted_leaf_hashes: list[bytes]) -> str:
    """Deterministic binary Merkle root; odd levels duplicate the last node."""
    if not sorted_leaf_hashes:
        return hashlib.sha256(LEAF_DOMAIN + b"empty").hexdigest()
    layer = list(sorted_leaf_hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_internal_hash(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0].hex()


@dataclass(frozen=True)
class ProvenanceNode:
    node_type: str
    source_key_id: str
    deployment_id: str
    run_id: str
    session_id: str
    content_digest: str
    dependencies: tuple[str, ...] = field(default=())
    manifest_version: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PROVENANCE_NODE_SCHEMA,
            "node_type": self.node_type,
            "source_key_id": self.source_key_id,
            "deployment_id": self.deployment_id,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "content_digest": self.content_digest,
            "dependencies": list(self.dependencies),
            "manifest_version": self.manifest_version,
        }

    @property
    def node_digest(self) -> str:
        return digest(self.to_dict())


class EvidenceGraph:
    """A verified, append-only, single-namespace provenance DAG."""

    MAX_NODES = 4_096

    def __init__(
        self,
        *,
        deployment_id: str,
        run_id: str,
        session_id: str,
    ) -> None:
        self.deployment_id = deployment_id
        self.run_id = run_id
        self.session_id = session_id
        self._nodes: dict[str, ProvenanceNode] = {}
        self._envelopes: dict[str, Mapping[str, Any]] = {}

    def __len__(self) -> int:
        return len(self._nodes)

    def add_node(
        self,
        node: ProvenanceNode,
        *,
        statement_envelope: Mapping[str, Any],
    ) -> str:
        if len(self._nodes) >= self.MAX_NODES:
            raise ProvenanceError("evidence graph capacity exceeded")
        if node.node_digest in self._nodes:
            raise ProvenanceError("duplicate evidence node")
        if (
            node.deployment_id != self.deployment_id
            or node.run_id != self.run_id
            or node.session_id != self.session_id
        ):
            # Namespace safety: foreign-run evidence can never attach here.
            raise ProvenanceError(
                "evidence node belongs to a different execution namespace "
                f"(node={node.deployment_id}/{node.run_id}/{node.session_id}, "
                f"graph={self.deployment_id}/{self.run_id}/{self.session_id})"
            )
        if _DIGEST.fullmatch(node.content_digest) is None:
            raise ProvenanceError("node content digest is malformed")
        for dependency in node.dependencies:
            if dependency not in self._nodes:
                raise ProvenanceError(
                    "dependency references an unknown evidence node; "
                    "nodes must be added in dependency order"
                )
        self._nodes[node.node_digest] = node
        self._envelopes[node.node_digest] = statement_envelope
        return node.node_digest

    def build_node(
        self,
        *,
        node_type: str,
        source_key_id: str,
        statement_envelope: Mapping[str, Any],
        dependencies: tuple[str, ...] = (),
        manifest_version: int = 0,
    ) -> str:
        """Convenience: derive namespace fields from the graph itself."""
        node = ProvenanceNode(
            node_type=node_type,
            source_key_id=source_key_id,
            deployment_id=self.deployment_id,
            run_id=self.run_id,
            session_id=self.session_id,
            content_digest=digest(dict(statement_envelope)),
            dependencies=tuple(dependencies),
            manifest_version=manifest_version,
        )
        return self.add_node(node, statement_envelope=statement_envelope)

    def nodes(self) -> list[ProvenanceNode]:
        return [
            self._nodes[key]
            for key in sorted(self._nodes)
        ]

    def envelopes(self) -> dict[str, Mapping[str, Any]]:
        return dict(self._envelopes)

    def evidence_root(self) -> str:
        """Single deterministic commitment to this exact evidence set."""
        leaves = [_leaf_hash(key) for key in sorted(self._nodes)]
        return merkle_root_from_leaves(leaves)

    def inclusion_proof(self, node_digest: str) -> list[dict[str, Any]]:
        """Audit path with explicit sibling positions for verification."""
        if node_digest not in self._nodes:
            raise ProvenanceError("unknown node for inclusion proof")
        keys = sorted(self._nodes)
        index = keys.index(node_digest)
        layer = [_leaf_hash(key) for key in keys]
        proof: list[dict[str, Any]] = []
        position = index
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            sibling_index = position ^ 1
            proof.append({
                "sibling": layer[sibling_index].hex(),
                "sibling_is_right": sibling_index > position,
            })
            layer = [
                _internal_hash(layer[i], layer[i + 1])
                for i in range(0, len(layer), 2)
            ]
            position //= 2
        return proof

    @staticmethod
    def verify_inclusion(
        node_digest: str,
        proof: list[dict[str, Any]],
        expected_root: str,
    ) -> bool:
        current = _leaf_hash(node_digest)
        try:
            for step in proof:
                if set(step) != {"sibling", "sibling_is_right"}:
                    return False
                sibling = bytes.fromhex(step["sibling"])
                if step["sibling_is_right"]:
                    current = _internal_hash(current, sibling)
                else:
                    current = _internal_hash(sibling, current)
        except (TypeError, ValueError):
            return False
        return current.hex() == expected_root
