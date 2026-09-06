from __future__ import annotations

from dataclasses import asdict, dataclass


_LIFECYCLES = {"GP", "HS-FS", "HS-SE"}
_ROOT_STATES = {"unknown", "not_provisioned", "provisioned", "hardware_verified"}


@dataclass(frozen=True)
class SecureBootProfile:
    """One explicit model for board state, build target and deployment permission.

    ``physical_lifecycle`` is what the connected board actually is. ``target_lifecycle``
    is the artifact family being produced.  Keeping these values separate prevents an
    offline HS-SE package from being mistaken for something that can boot on an HS-FS
    board (or vice versa).
    """

    physical_lifecycle: str
    target_lifecycle: str
    customer_root_state: str
    device_type: str
    output_family: str
    sdk_development_key_allowed: bool
    customer_signing_key_required: bool
    flash_allowed: bool
    offline_only: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def assess_secure_boot_profile(
    *,
    physical_lifecycle: str,
    target_lifecycle: str,
    customer_root_state: str = "unknown",
    has_customer_signing_key: bool = False,
    encrypted: bool = False,
    has_encryption_key: bool = False,
) -> SecureBootProfile:
    physical = physical_lifecycle.strip().upper()
    target = target_lifecycle.strip().upper()
    root_state = customer_root_state.strip().lower()
    if physical not in _LIFECYCLES:
        raise ValueError("Fiziksel kart durumu GP, HS-FS veya HS-SE olmalı")
    if target not in {"HS-FS", "HS-SE"}:
        raise ValueError("Üretim hedefi HS-FS veya HS-SE olmalı")
    if root_state not in _ROOT_STATES:
        raise ValueError("Customer RoT durumu unknown, not_provisioned, provisioned veya hardware_verified olmalı")

    blockers: list[str] = []
    warnings: list[str] = []
    if target == "HS-SE" and not has_customer_signing_key:
        blockers.append("HS-SE paketi için provision edilmiş Customer RoT ile eşleşen private signing key seçilmelidir.")
    if encrypted and not has_customer_signing_key:
        blockers.append("Şifreleme için açıkça seçilmiş bir private signing key de gereklidir.")
    if encrypted and not has_encryption_key:
        blockers.append("Şifreli application için 256-bit application MEK seçilmelidir.")
    if physical != target:
        warnings.append(
            f"{target} paketi çevrimdışı hazırlanabilir; fiziksel kart {physical} olduğu için bu karta yazma kapalıdır."
        )
    if target == "HS-SE" and root_state not in {"provisioned", "hardware_verified"}:
        warnings.append("HS-SE karta yazma için Customer Root of Trust eşleşmesi ayrıca doğrulanmalıdır.")

    lifecycle_match = physical == target
    root_ready = target != "HS-SE" or root_state in {"provisioned", "hardware_verified"}
    flash_allowed = lifecycle_match and root_ready and not blockers
    return SecureBootProfile(
        physical_lifecycle=physical,
        target_lifecycle=target,
        customer_root_state=root_state,
        device_type="HS" if target == "HS-SE" else "GP",
        output_family=".hs" if target == "HS-SE" else ".hs_fs",
        sdk_development_key_allowed=target == "HS-FS",
        customer_signing_key_required=target == "HS-SE",
        flash_allowed=flash_allowed,
        offline_only=not flash_allowed,
        blockers=tuple(blockers),
        warnings=tuple(warnings),
    )
