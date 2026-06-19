from __future__ import annotations

from pathlib import Path


def build_jailer_args(
    jailer_bin: str,
    firecracker_bin: str,
    vm_id: str,
    uid: int,
    gid: int,
    chroot_base: str = "/srv/jailer",
) -> list[str]:
    return [
        jailer_bin,
        "--id", vm_id,
        "--exec-file", firecracker_bin,
        "--uid", str(uid),
        "--gid", str(gid),
        "--chroot-base-dir", chroot_base,
        "--cgroup-version", "2",
        "--",
        "--api-sock", "/run/firecracker.socket",
        "--seccomp-level", "2",
    ]


def jailer_api_socket(vm_id: str, chroot_base: str = "/srv/jailer") -> Path:
    return Path(chroot_base) / "firecracker" / vm_id / "root" / "run" / "firecracker.socket"
