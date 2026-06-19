from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VmConfig:
    vcpu_count: int = 1
    mem_size_mib: int = 128
    timeout_seconds: int = 30
    network_enabled: bool = False

    def as_firecracker_machine_config(self) -> dict:
        return {
            "vcpu_count": self.vcpu_count,
            "mem_size_mib": self.mem_size_mib,
            "smt": False,
        }
