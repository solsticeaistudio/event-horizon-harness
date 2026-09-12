"""Sandbox execution environment for model tool-use with isolation."""
from __future__ import annotations

import abc
import asyncio
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterator, List, Mapping, Optional, Union
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import grpc

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

try:
    import gvisor
    GVISOR_AVAILABLE = True
except ImportError:
    GVISOR_AVAILABLE = False


class SandboxType(str, Enum):
    """Supported sandbox types."""
    PROCESS = "process"           # Simple process isolation (dev only)
    DOCKER = "docker"             # Docker container
    GVISOR = "gvisor"             # gVisor sandbox
    FIRECRACKER = "firecracker"   # Firecracker microVM


class SandboxError(Exception):
    """Base sandbox error."""
    pass


class SandboxTimeoutError(SandboxError):
    """Operation timed out."""
    pass


class SandboxResourceError(SandboxError):
    """Resource limit exceeded."""
    pass


class SandboxSecurityError(SandboxError):
    """Security policy violation."""
    pass


@dataclass(frozen=True)
class ResourceLimits:
    """Resource limits for sandbox execution."""
    max_cpu_seconds: float = 30.0
    max_memory_bytes: int = 512 * 1024 * 1024  # 512 MB
    max_disk_bytes: int = 1024 * 1024 * 1024   # 1 GB
    max_processes: int = 50
    max_file_descriptors: int = 1024
    network_allowed: bool = False
    read_only_root: bool = True


@dataclass(frozen=True)
class ExecutionRequest:
    """Request to execute code in sandbox."""
    command: List[str]
    stdin: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    working_dir: Optional[str] = None
    resource_limits: Optional[ResourceLimits] = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class ExecutionResult:
    """Result of sandbox execution."""
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: float
    memory_peak_bytes: int
    cpu_time_ms: float
    timed_out: bool = False
    oom_killed: bool = False


class SandboxBackend(ABC):
    """Abstract base class for sandbox backends."""

    @property
    @abstractmethod
    def sandbox_type(self) -> SandboxType:
        """Return the sandbox type."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        ...

    @abstractmethod
    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a command in the sandbox."""
        ...

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up sandbox resources."""
        ...

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get sandbox statistics."""
        ...


from event_horizon.sandbox.process_sandbox import ProcessSandbox
from event_horizon.sandbox.docker_sandbox import DockerSandbox
from event_horizon.sandbox.gvisor_sandbox import GVisorSandbox
from event_horizon.sandbox.firecracker_sandbox import FirecrackerSandbox
from event_horizon.sandbox.manager import SandboxManager


__all__ = [
    "SandboxType",
    "SandboxError",
    "SandboxTimeoutError",
    "SandboxResourceError",
    "SandboxSecurityError",
    "ResourceLimits",
    "ExecutionRequest",
    "ExecutionResult",
    "SandboxBackend",
    "ProcessSandbox",
    "DockerSandbox",
    "GVisorSandbox",
    "FirecrackerSandbox",
    "SandboxManager",
]