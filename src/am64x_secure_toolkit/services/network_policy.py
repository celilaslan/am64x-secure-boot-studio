from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class NetworkPolicy:
    runtime_network_required: bool = False
    sdk_download_performed: bool = False
    telemetry_enabled: bool = False
    update_check_enabled: bool = False
    remote_key_service_used: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        data.update({
            "status": "PASS",
            "operation": "network_policy",
            "statement": "Secure Boot Studio core/GUI workflows are designed to run without network access.",
            "note": "External SDK/package installation is an environment setup concern; Studio does not silently download tools or send telemetry.",
        })
        return data


def runtime_network_policy() -> NetworkPolicy:
    return NetworkPolicy()
