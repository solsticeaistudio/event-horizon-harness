"""Process-based sandbox (development only, not secure)."""
from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

try:
    import resource
    RESOURCE_AVAILABLE = True
except ImportError:
    RESOURCE_AVAILABLE = False

from event_horizon.sandbox import (
    SandboxBackend,
    SandboxType,
    ResourceLimits,
    ExecutionRequest,
    ExecutionResult,
)


class ProcessSandbox:
    """Simple process-based sandbox (development only, not secure)."""

    sandbox_type = SandboxType.PROCESS

    def __init__(self, resource_limits: Optional[ResourceLimits] = None):
        self.resource_limits = resource_limits or ResourceLimits()
        self._active_processes: Dict[int, subprocess.Popen] = {}
        self._lock = threading.Lock()

    def is_available(self) -> bool:
        return True

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        limits = request.resource_limits or self.resource_limits
        start_time = time.time()

        # Prepare environment
        env = os.environ.copy()
        env.update(request.environment)

        # Set resource limits
        def preexec_fn():
            if RESOURCE_AVAILABLE:
                import resource
                if limits.max_cpu_seconds:
                    resource.setrlimit(resource.RLIMIT_CPU, (int(limits.max_cpu_seconds), int(limits.max_cpu_seconds) + 1))
                if limits.max_memory_bytes:
                    resource.setrlimit(resource.RLIMIT_AS, (limits.max_memory_bytes, limits.max_memory_bytes))
                if limits.max_file_descriptors:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (limits.max_file_descriptors, limits.max_file_descriptors))

        try:
            process = subprocess.Popen(
                request.command,
                stdin=subprocess.PIPE if request.stdin else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=request.working_dir,
                env=env,
                preexec_fn=preexec_fn,
                start_new_session=True,
            )

            with self._lock:
                self._active_processes[process.pid] = process

            try:
                stdout, stderr = process.communicate(
                    input=request.stdin.encode() if request.stdin else None,
                    timeout=request.timeout_seconds,
                )
                exit_code = process.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -1
                timed_out = True

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
                self._active_processes.pop(process.pid, None)

        execution_time_ms = (time.time() - start_time) * 1000

        # Get resource usage
        try:
            if RESOURCE_AVAILABLE:
                import resource
                usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                memory_peak_bytes = usage.ru_maxrss * 1024  # Convert KB to bytes
                cpu_time_ms = (usage.ru_utime + usage.ru_stime) * 1000
            else:
                memory_peak_bytes = 0
                cpu_time_ms = 0
        except Exception:
            memory_peak_bytes = 0
            cpu_time_ms = 0

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
            stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
            execution_time_ms=execution_time_ms,
            memory_peak_bytes=memory_peak_bytes,
            cpu_time_ms=cpu_time_ms,
            timed_out=timed_out,
            oom_killed=exit_code == -9,  # SIGKILL often means OOM
        )

    async def cleanup(self) -> None:
        with self._lock:
            for proc in self._active_processes.values():
                try:
                    proc.kill()
                except Exception:
                    pass
            self._active_processes.clear()

    async def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "process",
            "active_processes": len(self._active_processes),
        }

    def is_available(self) -> bool:
        return True