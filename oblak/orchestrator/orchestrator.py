from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import OrchestratorConfig
from .jailer import build_jailer_args, jailer_api_socket
from .vm_config import VmConfig


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    return_value: Optional[str]
    return_code: int
    duration_ms: float
    execution_mode: str  # always "microvm"


_CHROOT_BASE = "/srv/jailer"
_VSOCK_RESULT_PORT = 52


class Orchestrator:
    def __init__(self, config: Optional[OrchestratorConfig] = None) -> None:
        self._cfg = config or OrchestratorConfig()

    def execute(self, artifact_path: str, event: Optional[dict] = None) -> ExecutionResult:
        return self._execute_microvm(artifact_path, event or {})

    def _execute_microvm(self, artifact_path: str, event: dict) -> ExecutionResult:
        vm_id = uuid.uuid4().hex
        cfg = self._cfg
        vcfg = VmConfig(
            vcpu_count=cfg.vm_vcpus,
            mem_size_mib=cfg.vm_mem_mib,
            timeout_seconds=cfg.vm_timeout_seconds,
            network_enabled=cfg.vm_network_enabled,
        )

        chroot_dir = Path(_CHROOT_BASE) / "firecracker" / vm_id / "root"
        run_dir = chroot_dir / "run"
        vsock_listener = str(run_dir / f"vsock_{_VSOCK_RESULT_PORT}")

        self._setup_chroot(chroot_dir, artifact_path)

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0)
        try:
            srv.bind(vsock_listener)
        finally:
            os.umask(old_umask)
        srv.listen(1)

        fc_proc = self._start_firecracker(vm_id)
        t0 = time.monotonic()
        try:
            api_sock = jailer_api_socket(vm_id, _CHROOT_BASE)
            self._wait_for_api(api_sock)
            self._configure_vm(api_sock, vcfg)
            result = self._collect_result(srv, vcfg.timeout_seconds, event)
            duration_ms = (time.monotonic() - t0) * 1000
        finally:
            srv.close()
            try:
                fc_proc.kill()
                fc_proc.wait(timeout=5)
            except Exception:
                pass
            self._cleanup_vm(vm_id)

        return ExecutionResult(
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            return_value=json.dumps(result.get("return_value")),
            return_code=result.get("return_code", 0),
            duration_ms=duration_ms,
            execution_mode="microvm",
        )

    def _setup_chroot(self, chroot_dir: Path, artifact_path: str) -> None:
        run_dir = chroot_dir / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(run_dir), 0o777)
        _link_or_copy(self._cfg.kernel_path, str(chroot_dir / "vmlinux"))
        _link_or_copy(self._cfg.rootfs_path, str(chroot_dir / "rootfs.ext4"))
        code_drive = str(chroot_dir / "code.ext4")
        size_kb = max(65536, _dir_size_kb(artifact_path) * 3)
        subprocess.run(
            ["genext2fs", "-b", str(size_kb), "-d", artifact_path, code_drive],
            check=True,
            capture_output=True,
        )

    def _start_firecracker(self, vm_id: str) -> subprocess.Popen:
        args = build_jailer_args(
            jailer_bin=self._cfg.jailer_bin,
            firecracker_bin=self._cfg.firecracker_bin,
            vm_id=vm_id,
            uid=self._cfg.jailer_uid,
            gid=self._cfg.jailer_gid,
            chroot_base=_CHROOT_BASE,
        )
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _wait_for_api(self, api_sock: Path, retries: int = 100) -> None:
        for _ in range(retries):
            if api_sock.exists():
                return
            time.sleep(0.1)
        raise RuntimeError(f"Firecracker API socket did not appear: {api_sock}")

    def _configure_vm(self, api_sock: Path, vcfg: VmConfig) -> None:
        _unix_put(str(api_sock), "/boot-source", {
            "kernel_image_path": "/vmlinux",
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
        })
        _unix_put(str(api_sock), "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": "/rootfs.ext4",
            "is_root_device": True,
            "is_read_only": True,
        })
        _unix_put(str(api_sock), "/drives/code", {
            "drive_id": "code",
            "path_on_host": "/code.ext4",
            "is_root_device": False,
            "is_read_only": True,
        })
        _unix_put(str(api_sock), "/machine-config", vcfg.as_firecracker_machine_config())
        _unix_put(str(api_sock), "/vsock", {
            "vsock_id": "vsock0",
            "guest_cid": 3,
            "uds_path": "/run/vsock",
        })
        _unix_put(str(api_sock), "/actions", {"action_type": "InstanceStart"})

    def _collect_result(self, srv: socket.socket, timeout: int, event: dict) -> dict:
        srv.settimeout(timeout)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            return {
                "return_code": -1,
                "stdout": "",
                "stderr": "VM execution timed out",
                "return_value": None,
            }
        conn.settimeout(timeout)
        try:
            conn.sendall((json.dumps(event) + "\n").encode())
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            conn.close()
        try:
            return json.loads(data.decode())
        except json.JSONDecodeError:
            return {
                "return_code": 1,
                "stdout": data.decode(errors="replace"),
                "stderr": "",
                "return_value": None,
            }

    def _cleanup_vm(self, vm_id: str) -> None:
        subprocess.run(
            ["sudo", "/usr/local/bin/oblak-cleanup", f"{_CHROOT_BASE}/firecracker/{vm_id}"],
            check=False,
        )


def _link_or_copy(src: str, dst: str) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _dir_size_kb(path: str) -> int:
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return max(1, total // 1024)


def _unix_put(socket_path: str, path: str, body: dict) -> None:
    payload = json.dumps(body).encode()
    request = (
        f"PUT {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Accept: */*\r\n"
        f"\r\n"
    ).encode() + payload

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    try:
        sock.sendall(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        status_line = response.split(b"\r\n")[0].decode()
        status_code = int(status_line.split()[1])
        if status_code not in (200, 204):
            raise RuntimeError(f"Firecracker API {path} returned {status_line}")
    finally:
        sock.close()
