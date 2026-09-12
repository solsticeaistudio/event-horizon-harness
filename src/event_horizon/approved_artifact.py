"""Prepared, inert package bytes: no installer, URL fetcher, or archive parser."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class ApprovedArtifact:
    content: str
    sha256: str

    def __post_init__(self):
        if not isinstance(self.content, str) or not self.content.isascii() or not 0 < len(self.content) <= 512:
            raise ValueError("lab artifacts must be 1..512 ASCII bytes")
        if hashlib.sha256(self.content.encode("ascii")).hexdigest() != self.sha256:
            raise ValueError("prepared artifact digest mismatch")

    @property
    def resource_id(self) -> str:
        return "sha256:" + self.sha256

    def accept(self, response: dict) -> bytes:
        """Validate at the trusted recipient, after the compromised service.

        Returned bytes remain inert data. Matching an approved digest is not a
        claim that arbitrary approved packages are safe to install or execute.
        """
        if not isinstance(response, dict) or response.get("success") is not True or response.get("effect_state") != "completed":
            raise ValueError("artifact retrieval did not complete")
        content = response.get("output")
        if not isinstance(content, str) or content != self.content:
            raise ValueError("untrusted service substituted artifact output")
        return content.encode("ascii")
