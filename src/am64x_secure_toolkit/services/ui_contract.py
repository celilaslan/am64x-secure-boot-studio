from __future__ import annotations

"""Pure-Python UI contract shared by Qt pages and tests.

Keep user-facing choices here so the GUI cannot silently drift away from the backend's
accepted semantic values. Labels may be Turkish/readable while values stay canonical.
"""

GUIDED_PAGE_KEYS: tuple[str, ...] = (
    "home", "guide", "environment", "project", "secure_boot", "application", "inspector", "certificate",
    "keys", "negative", "reports", "learn", "demo", "diagnostics",
)

EXPERT_PAGE_KEYS: tuple[str, ...] = (
    "home", "guide", "environment", "project", "secure_boot", "application", "rom", "inspector",
    "certificate", "keys", "negative", "sdk", "errata", "provisioning", "revision",
    "boardcfg", "secure_debug", "generic_data", "reports", "source_trace", "learn", "demo", "diagnostics",
)


def page_visible(mode: str, key: str) -> bool:
    if mode == "expert":
        return key in EXPERT_PAGE_KEYS
    if mode != "guided":
        raise ValueError("mode yalnız guided veya expert olabilir")
    return key in GUIDED_PAGE_KEYS


ERRATA_CATEGORY_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Tümü", "all"),
    ("Security", "security"),
    ("Boot media", "boot-media"),
    ("Debug", "debug"),
)

ERRATA_FLOW_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("Full combined ROM image", "full-combined"),
    ("Normal ROM flow", "normal"),
    ("Redundant / backup flow", "redundant-backup"),
)

ERRATA_OUTER_RSA_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("Degenerate RSA", "degenerate"),
    ("Non-degenerate RSA", "non-degenerate"),
)

ERRATA_CERT_INFO_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("Certificate info present", "present"),
    ("Certificate info absent", "absent"),
)

ERRATA_REDUNDANT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("Complete boot image", "complete-boot"),
    ("TIFS/SYSFW only", "tifs-only"),
    ("Other", "other"),
)

ERRATA_EMULATOR_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("External emulator var", "yes"),
    ("External emulator yok", "no"),
)

BOOT_MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("OSPI", "ospi"),
    ("xSPI", "xspi"),
    ("QSPI", "qspi"),
    ("SPI", "spi"),
    ("UART", "uart"),
    ("MMCSD", "mmcsd"),
    ("SD", "sd"),
    ("eMMC", "emmc"),
    ("USB", "usb"),
    ("Ethernet", "ethernet"),
    ("PCIe", "pcie"),
    ("GPMC", "gpmc"),
)

SDK_INTENT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Development", "development"),
    ("Production review", "production"),
)

SWREV_CONTEXT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("tiboot3 / ROM bootloader", "tiboot3"),
    ("Board Configuration", "boardcfg"),
    ("Secure Debug", "debug"),
    ("Application", "application"),
    ("Generic data", "generic"),
)

SECURE_DEBUG_TRANSPORT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("TISCI API", "tisci"),
    ("Sec-AP / JTAG-side delivery context", "sec-ap"),
)

JTAG_EFUSE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Bilinmiyor", "unknown"),
    ("Enabled", "enabled"),
    ("Disabled", "disabled"),
)
