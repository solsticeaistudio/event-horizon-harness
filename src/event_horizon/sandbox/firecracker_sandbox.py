"""Firecracker microVM sandbox backend."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from event_horizon.sandbox import (
    SandboxBackend,
    SandboxType,
    ResourceLimits,
    ExecutionRequest,
    ExecutionResult,
)


class FirecrackerSandbox:
    """Firecracker microVM sandbox backend."""

    sandbox_type = SandboxType.FIRECRACKER

    def __init__(
        self,
        kernel_path: str = "/opt/firecracker/vmlinux",
        rootfs_path: str = "/opt/firecracker/rootfs.ext4",
        firecracker_binary: str = "/usr/bin/firecracker",
        resource_limits: Optional[ResourceLimits] = None,
    ):
        self.kernel_path = Path(kernel_path)
        self.rootfs_path = Path(rootfs_path)
        self.firecracker_binary = Path(firecracker_binary)
        self.resource_limits = resource_limits or ResourceLimits()
        self._vms: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # Validate paths
        if not self.kernel_path.exists():
            raise RuntimeError(f"Kernel not found: {self.kernel_path}")
        if not self.rootfs_path.exists():
            raise RuntimeError(f"Rootfs not found: {self.rootfs_path}")
        if not self.firecracker_binary.exists():
            raise RuntimeError(f"Firecracker binary not found: {self.firecracker_binary}")

    def is_available(self) -> bool:
        return (self.kernel_path.exists() and
                self.rootfs_path.exists() and
                self.firecracker_binary.exists())

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        limits = request.resource_limits or self.resource_limits
        start_time = time.time()

        vm_id = str(uuid.uuid4())[:8]
        socket_path = f"/tmp/firecracker-{uuid.uuid4().hex[:8]}.sock"

        # Create Firecracker config
        config = self._create_config(request, limits)

        # Write config to temp file
        config_path = Path(tempfile.mktemp(prefix=f"fc-{uuid.uuid4().hex[:8]}-", suffix=".json"))
        config_path.write_text(json.dumps(config))

        # Start Firecracker process
        fc_process = subprocess.Popen(
            [
                str(self.firecracker_binary),
                "--api-sock", socket_path,
                "--config-file", str(config_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        vm_info = {
            "process": fc_process,
            "socket": socket_path,
            "config": config_path,
            "start_time": time.time(),
        }

        with self._lock:
            self._vms[vm_id] = vm_info

        try:
            # Wait for socket to be ready
            await self._wait_for_socket(socket_path, timeout=10)

            # Send command via vsock or HTTP API
            # For simplicity, we'll use a simple approach
            # In practice, you'd use the Firecracker API to send commands
            result = await self._execute_in_vm(socket_path, request, request.timeout_seconds)

            exit_code = result.get("exit_code", -1)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            timed_out = result.get("timed_out", False)

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
            # Cleanup
            try:
                fc_process.terminate()
                fc_process.wait(timeout=5)
            except Exception:
                pass

            try:
                Path(socket_path).unlink(missing_ok=True)
            except Exception:
                pass

            try:
                config_path.unlink(missing_ok=True)
            except Exception:
                pass

            with self._lock:
                self._vms.pop(vm_id, None)

        execution_time_ms = (time.time() - start_time) * 1000

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=execution_time_ms,
            memory_peak_bytes=0,
            cpu_time_ms=0,
            timed_out=result.get("timed_out", False),
            oom_killed=False,
        )

    async def _wait_for_socket(self, socket_path: str, timeout: float = 10) -> None:
        """Wait for Firecracker API socket to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            if Path(socket_path).exists():
                return
            await asyncio.sleep(0.1)
        raise TimeoutError(f"Firecracker socket not ready after {timeout}s")

    async def _execute_in_vm(
        self,
        socket_path: str,
        request: ExecutionRequest,
        timeout: float,
    ) -> Dict[str, Any]:
        """Execute command in the VM via vsock or API."""
        # This is a simplified implementation
        # In practice, you'd use the Firecracker vsock or HTTP API
        # For now, we'll simulate execution

        # Create a simple HTTP request to the VM's API
        # This is a placeholder - real implementation would use vsock
        import urllib.request
        import json

        api_url = f"http://localhost:8080/execute"  # Would be vsock in reality

        payload = {
            "command": request.command,
            "stdin": request.stdin,
            "environment": request.environment,
            "working_dir": request.working_dir,
            "timeout_seconds": request.timeout_seconds,
        }

        try:
            req = urllib.request.Request(
                api_url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=request.timeout_seconds) as resp:
                result = json.loads(resp.read().decode())
                return result
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "timed_out": False,
            }

    def _create_config(self, request: ExecutionRequest, limits: ResourceLimits) -> Dict[str, Any]:
        """Create Firecracker configuration."""
        return {
            "boot-source": {
                "kernel_image_path": str(self.kernel_path),
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init",
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(self.rootfs_path),
                    "is_root_device": True,
                    "is_read_only": False,
                }
            ],
            "machine-config": {
                "vcpu_count": 1,
                "mem_size_mib": limits.max_memory_bytes // (1024 * 1024),
                "smt": False,
            },
            "vsock": {
                "guest_cid": 3,
                "uds_path": "/tmp/vsock.sock",
            },
        }

    async def cleanup(self) -> None:
        with self._lock:
            for vm_info in self._vms.values():
                try:
                    vm_info["process"].terminate()
                    vm_info["process"].wait(timeout=5)
                except Exception:
                    pass
            self._vms.clear()

    async def get_stats(self) -> Dict[str, Any]:
        return {
            "type": "firecracker",
            "active_vms": len(self._vms),
        }

    def is_available(self) -> bool:
        return (self.kernel_path.exists() and
                self.rootfs_path.exists() and
                self.firecracker_binary.exists())