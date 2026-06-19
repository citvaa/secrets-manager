from __future__ import annotations

from dataclasses import dataclass, field
import os


@dataclass
class OrchestratorConfig:
    firecracker_bin: str = field(
        default_factory=lambda: os.environ.get("OBLAK_FIRECRACKER_BIN", "/usr/local/bin/firecracker")
    )
    jailer_bin: str = field(
        default_factory=lambda: os.environ.get("OBLAK_JAILER_BIN", "/usr/local/bin/jailer")
    )
    kernel_path: str = field(
        default_factory=lambda: os.environ.get("OBLAK_KERNEL_PATH", "/var/lib/oblak/vmlinux")
    )
    rootfs_path: str = field(
        default_factory=lambda: os.environ.get("OBLAK_ROOTFS_PATH", "/var/lib/oblak/rootfs.ext4")
    )
    vm_vcpus: int = field(
        default_factory=lambda: int(os.environ.get("OBLAK_VM_VCPUS", "1"))
    )
    vm_mem_mib: int = field(
        default_factory=lambda: int(os.environ.get("OBLAK_VM_MEM_MIB", "128"))
    )
    vm_timeout_seconds: int = field(
        default_factory=lambda: int(os.environ.get("OBLAK_VM_TIMEOUT_SECONDS", "30"))
    )
    vm_network_enabled: bool = field(
        default_factory=lambda: os.environ.get("OBLAK_VM_NETWORK_ENABLED", "false").lower() == "true"
    )
    jailer_uid: int = field(
        default_factory=lambda: int(os.environ.get("OBLAK_JAILER_UID", "65533"))
    )
    jailer_gid: int = field(
        default_factory=lambda: int(os.environ.get("OBLAK_JAILER_GID", "65533"))
    )
