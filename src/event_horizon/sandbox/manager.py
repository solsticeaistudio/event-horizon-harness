"""Sandbox manager for routing execution requests to appropriate backends."""
from __future__ import annotations

import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from event_horizon.sandbox import (
    SandboxBackend,
    SandboxType,
    ResourceLimits,
    ExecutionRequest,
    ExecutionResult,
)
from event_horizon.sandbox.process_sandbox import ProcessSandbox
from event_horizon.sandbox.docker_sandbox import DockerSandbox
from event_horizon.sandbox.gvisor_sandbox import GVisorSandbox
from event_horizon.sandbox.firecracker_sandbox import FirecrackerSandbox


class SandboxManager:
    """Manages sandbox backends and routes execution requests."""

    def __init__(
        self,
        default_backend: SandboxType = SandboxType.PROCESS,
        resource_limits: Optional[ResourceLimits] = None,
    ):
        self.default_backend = default_backend
        self.resource_limits = resource_limits or ResourceLimits()
        self._backends: Dict[SandboxType, SandboxBackend] = {}
        self._lock = threading.Lock()

        # Initialize available backends
        self._init_backends()

    def _init_backends(self) -> None:
        # Always available: process sandbox (dev only)
        self._backends[SandboxType.PROCESS] = ProcessSandbox()

        # Try Docker
        try:
            self._backends[SandboxType.DOCKER] = DockerSandbox()
        except Exception:
            pass

        # Try gVisor
        try:
            self._backends[SandboxType.GVISOR] = GVisorSandbox()
        except Exception:
            pass

        # Try Firecracker
        try:
            self._backends[SandboxType.FIRECRACKER] = FirecrackerSandbox()
        except Exception:
            pass

    def get_backend(self, sandbox_type: Optional[SandboxType] = None) -> SandboxBackend:
        """Get a backend instance."""
        backend_type = sandbox_type or self.default_backend
        with self._lock:
            backend = self._backends.get(backend_type)
            if not backend:
                raise ValueError(f"Backend {backend_type} not available")
            if not backend.is_available():
                raise RuntimeError(f"Backend {backend_type} not available")
            return backend

    async def execute(
        self,
        request: ExecutionRequest,
        sandbox_type: Optional[SandboxType] = None,
    ) -> ExecutionResult:
        """Execute a request using the appropriate backend."""
        backend = self.get_backend(sandbox_type)
        return await backend.execute(request)

    async def cleanup_all(self) -> None:
        """Clean up all backends."""
        for backend in self._backends.values():
            await backend.cleanup()

    def get_available_backends(self) -> List[SandboxType]:
        with self._lock:
            return [bt for bt, be in self._backends.items() if be.is_available()]

    def get_backend_stats(self, sandbox_type: SandboxType) -> Dict[str, Any]:
        backend = self.get_backend(sandbox_type)
        return asyncio.run(backend.get_stats())