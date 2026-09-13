"""gVisor sandbox backend."""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

try:
    import docker
    from docker.errors import DockerException, ImageNotFound, ContainerError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None
    DockerException = Exception
    ImageNotFound = Exception
    ContainerError = Exception

from event_horizon.sandbox import (
    SandboxType,
    ResourceLimits,
    ExecutionRequest,
    ExecutionResult,
)


class GVisorSandbox:
    """gVisor sandbox backend using runsc runtime."""

    sandbox_type = SandboxType.GVISOR

    def __init__(
        self,
        image: str = "python:3.11-slim",
        resource_limits: Optional[ResourceLimits] = None,
        docker_client: Optional[Any] = None,
        runtime: str = "runsc",
    ):
        if not DOCKER_AVAILABLE:
            raise RuntimeError("Docker not available. Install docker: pip install docker")

        self.image = image
        self.resource_limits = resource_limits or ResourceLimits()
        self._client = docker_client or docker.from_env()
        self._runtime = runtime
        self._containers: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def is_available(self) -> bool:
        try:
            self._client.ping()
            # Check if runsc runtime is available
            info = self._client.info()
            runtimes = info.get("Runtimes", {})
            return "runsc" in runtimes
        except Exception:
            return False

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        limits = request.resource_limits or self.resource_limits
        start_time = time.time()

        # Prepare container config with gVisor runtime
        container_config = {
            "image": self.image,
            "command": request.command,
            "environment": request.environment,
            "working_dir": request.working_dir or "/workspace",
            "stdin_open": request.stdin is not None,
            "stdout": True,
            "stderr": True,
            "detach": True,
            "remove": True,
            "mem_limit": f"{self.resource_limits.max_memory_bytes}b",
            "cpu_period": 100000,
            "cpu_quota": int(100000 * (self.resource_limits.max_cpu_seconds / 30.0)),
            "pids_limit": self.resource_limits.max_processes,
            "ulimits": [
                docker.types.Ulimit(name="nofile", soft=self.resource_limits.max_file_descriptors, hard=self.resource_limits.max_file_descriptors),
            ],
            "read_only": self.resource_limits.read_only_root,
            "network_mode": "none" if not self.resource_limits.network_allowed else "bridge",
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "runtime": self._runtime,
        }

        if request.stdin:
            container_config["stdin"] = True

        if request.working_dir:
            container_config["working_dir"] = request.working_dir

        container_id = None
        try:
            container = self._client.containers.run(**container_config)
            container_id = container.id

            with self._lock:
                self._containers[container_id] = container

            # Wait for completion with timeout
            try:
                result = container.wait(timeout=request.timeout_seconds)
                exit_code = result["StatusCode"]
                timed_out = False
            except Exception:
                # Timeout
                try:
                    container.kill()
                except Exception:
                    pass
                exit_code = -1
                timed_out = True

            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            exit_code = result["StatusCode"] if isinstance(result, dict) else 0

        except Exception as e:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
                memory_peak_bytes=0,
                cpu_time_ms=0,
                timed_out=False,
                oom_killed=False,
            )
        finally:
            with self._lock:
                if container_id and container_id in self._containers:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass
                    self._containers.pop(container_id, None)

        execution_time_ms = (time.time() - start_time) * 1000

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=execution_time_ms,
            memory_peak_bytes=0,
            cpu_time_ms=0,
            timed_out=timed_out,
            oom_killed=False,
        )

    async def cleanup(self) -> None:
        with self._lock:
            for container in self._containers.values():
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            self._containers.clear()

    async def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "gvisor",
            "active_containers": len(self._containers),
        }

    def is_available(self) -> bool:
        try:
            self._client.ping()
            info = self._client.info()
            runtimes = info.get("Runtimes", {})
            return "runsc" in runtimes
        except Exception:
            return False