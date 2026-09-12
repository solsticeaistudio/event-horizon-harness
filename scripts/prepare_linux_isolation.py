"""Fetch hash-pinned lab assets and build a deterministic minimal initramfs."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Hermetic toolchain configuration
MUSL_CROSS_VERSION = "1.2.4"
MUSL_CROSS_URL = f"https://musl.cc/x86_64-linux-musl-cross.tgz"
MUSL_CROSS_SHA256 = "sha256:PLACEHOLDER_NEEDS_ACTUAL_HASH"


def initramfs(init: bytes) -> bytes:
    """Fixed metadata newc archive, compressed without wall-clock timestamps."""
    archive = bytearray()
    entries = [(".", 0o040755, b""), ("init", 0o100555, init)]
    entries += [(name, 0o040755, b"") for name in ("proc", "sys", "dev", "scratch")]
    entries.append(("TRAILER!!!", 0, b""))
    for inode, (name, mode, data) in enumerate(entries, 1):
        filename = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(filename), 0]
        archive.extend(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
        archive.extend(filename)
        archive.extend(b"\0" * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b"\0" * (-len(archive) % 4))
    return gzip.compress(bytes(archive), compresslevel=9, mtime=0)


def fetch(url: str, expected: str, target: Path) -> None:
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        return
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"asset digest mismatch: {url}")
    target.write_bytes(data)


def fetch_and_verify_toolchain(output: Path, lock: dict) -> Path:
    """Fetch and verify the musl-cross toolchain."""
    toolchain_dir = output / "toolchain"
    toolchain_dir.mkdir(exist_ok=True)
    
    toolchain_archive = toolchain_dir / "musl-cross.tgz"
    expected_sha256 = lock.get("musl_cross_sha256", "").replace("sha256:", "")
    if not expected_sha256:
        raise ValueError("musl_cross_sha256 not found in lock file")
    
    fetch(lock["musl_cross_url"], expected_sha256, toolchain_archive)
    
    # Extract toolchain
    with tarfile.open(fileobj=io.BytesIO(toolchain_archive.read_bytes()), mode="r:gz") as package:
        package.extractall(toolchain_dir)
    
    # Find the toolchain root (x86_64-linux-musl-cross)
    toolchain_root = None
    for item in toolchain_dir.iterdir():
        if item.is_dir() and item.name.startswith("x86_64-linux-musl"):
            toolchain_root = item
            break
    
    if not toolchain_root:
        raise RuntimeError("Failed to locate musl-cross toolchain root")
    
    return toolchain_root


def build_with_container(image: str, cmd: list, env: dict, workdir: Path) -> subprocess.CompletedProcess:
    """Run build command inside a container for hermetic isolation."""
    volumes = [
        f"{Path.cwd()}:/src:ro",
        f"{Path.cwd()}/firecracker:/firecracker:ro",
    ]
    docker_cmd = [
        "docker", "run", "--rm",
        "--network=none",
        "--cpus=1",
        "--memory=2g",
    ]
    for vol in volumes:
        docker_cmd.extend(["-v", vol])
    docker_cmd.extend(["-w", "/src"])
    docker_cmd.extend(["-e", "SOURCE_DATE_EPOCH=0"])
    docker_cmd.append(image)
    docker_cmd.extend(cmd)
    
    return subprocess.run(docker_cmd, check=True, capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "firecracker/build/isolation")
    parser.add_argument("--with-tpm2", action="store_true", help="Build with TPM2 attestation support")
    parser.add_argument("--toolchain", choices=["system", "musl-cross", "container"], default="system",
                       help="Toolchain to use: system gcc, musl-cross static toolchain, or containerized build")
    parser.add_argument("--container-image", type=str, default="debian:bookworm-slim",
                       help="Container image for containerized builds")
    args = parser.parse_args()
    
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("build requires Linux x86_64")
    
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / "firecracker/linux-kvm.lock.json").read_text())
    archive = output / "firecracker.tgz"
    fetch(lock["archive_url"], lock["archive_sha256"], archive)
    fetch(lock["kernel_url"], lock["kernel_sha256"], output / "vmlinux")
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode="r:gz") as package:
        for binary in ("firecracker", "jailer"):
            name = f"{binary}-v{lock['firecracker_version']}-x86_64"
            matches = [member for member in package.getmembers() if Path(member.name).name == name and member.isfile()]
            if len(matches) != 1:
                raise ValueError(f"release must contain exactly one {name}")
            with package.extractfile(matches[0]) as source:
                (output / binary).write_bytes(source.read())
            (output / binary).chmod(0o755)
    
    # Determine toolchain
    if args.toolchain == "musl-cross":
        toolchain_root = fetch_and_verify_toolchain(output, lock)
        compiler = str(toolchain_root / "bin" / "x86_64-linux-musl-gcc")
        if not Path(compiler).exists():
            raise RuntimeError(f"musl-cross compiler not found at {compiler}")
        toolchain_info = "musl-cross"
    elif args.toolchain == "container":
        toolchain_info = "container"
    else:
        compiler = shutil.which("gcc")
        if compiler is None:
            raise RuntimeError("gcc is required")
        toolchain_info = "system-gcc"
    
    # Check for TPM2 development libraries if requested
    tpm2_libs = []
    tpm2_defines = []
    if args.with_tpm2:
        for lib in ("tss2-esys", "tss2-tcti-device", "tss2-mu"):
            try:
                subprocess.run(["pkg-config", "--exists", lib], check=True, capture_output=True)
                cflags = subprocess.check_output(["pkg-config", "--cflags", lib], text=True).strip()
                libs = subprocess.check_output(["pkg-config", "--libs", lib], text=True).strip()
                if cflags:
                    tpm2_defines.append(cflags)
                if libs:
                    tpm2_libs.append(libs)
            except subprocess.CalledProcessError:
                pass  # Optional dependency
        tpm2_defines.append("-DEH_HAS_TPM2")
    else:
        tpm2_defines.append("-UEH_HAS_TPM2")
    
    with tempfile.TemporaryDirectory(prefix="eh-init-build-") as staging:
        init = Path(staging) / "init"
        if args.toolchain == "container":
            # Containerized build - simplified for now
            cmd = [
                "gcc", "-static", "-Os", "-s", "-Wall", "-Wextra", "-Werror",
                "-Wl,--build-id=none", "-frandom-seed=event-horizon-guest-v1",
                '-DEH_SCRATCH_DEVICE="/dev/vda"',
            ]
            cmd.extend(["-o", "/tmp/init", "/src/firecracker/guest/guest_agent.c"])
            
            # For container build, we'd use docker run with volume mounts
            # This is a placeholder - full implementation would mount staging dir
            raise NotImplementedError("Containerized build not yet fully implemented")
        else:
            cmd = [
                compiler, "-static", "-Os", "-s", "-Wall", "-Wextra", "-Werror",
                "-Wl,--build-id=none", "-frandom-seed=event-horizon-guest-v1",
                '-DEH_SCRATCH_DEVICE="/dev/vda"',
            ]
            cmd.extend(tpm2_defines)
            cmd.extend(["-o", str(init), str(ROOT / "firecracker/guest/guest_agent.c")])
            subprocess.run(cmd, check=True, env={"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "0"})
            image = initramfs(init.read_bytes())
    
    (output / "initramfs.cpio.gz").write_bytes(image)
    manifest = {
        "schema": "event-horizon.isolation-build.v1", "asset_lock": lock,
        "compiler_version": subprocess.check_output([compiler, "--version"], text=True).splitlines()[0],
        "compiler_sha256": hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
        "toolchain": "musl-cross" if args.toolchain == "musl-cross" else ("container" if args.toolchain == "container" else "system-gcc"),
        "guest_source_sha256": hashlib.sha256((ROOT / "firecracker/guest/guest_agent.c").read_bytes()).hexdigest(),
        "artifacts": {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                      for name in ("firecracker", "jailer", "vmlinux", "initramfs.cpio.gz")},
        "reproducibility_scope": "identical guest source, compiler/static libc, Python and zlib toolchain",
        "tpm2_enabled": args.with_tpm2,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())