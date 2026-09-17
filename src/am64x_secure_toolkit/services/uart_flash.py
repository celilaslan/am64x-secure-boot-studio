from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .secure_boot_profile import assess_secure_boot_profile

_PORT_RE = re.compile(r"^COM[1-9][0-9]{0,2}$", re.IGNORECASE)
_OFFSET_RE = re.compile(r"--flash-offset(?:=|\s+)(0x[0-9a-fA-F]+|[0-9]+)")
_FILE_RE = re.compile(r"--file(?:=|\s+)(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))")
_WRITER_RE = re.compile(r"--flash-writer(?:=|\s+)(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))")


@dataclass(frozen=True)
class UartFlashPlan:
    sdk_root: str
    tool: str
    source_config: str
    serial_port: str
    physical_lifecycle: str
    target_lifecycle: str
    boot_image: str
    application_image: str
    boot_offset: str
    application_offset: str
    flash_writer: str
    generated_config: str
    safe_command: tuple[str, ...]
    hardware_write: bool = True
    otp_efuse_write: bool = False
    lifecycle_transition: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _find_one(root: Path, names: tuple[str, ...]) -> Path:
    for name in names:
        direct = root / "tools" / "boot" / name
        if direct.is_file():
            return direct.resolve()
    matches: list[Path] = []
    for name in names:
        matches.extend(path for path in root.rglob(name) if path.is_file())
    if not matches:
        raise FileNotFoundError(f"MCU+ SDK içinde bulunamadı: {', '.join(names)}")
    return sorted(matches, key=lambda path: (len(path.parts), str(path)))[0].resolve()


def _resolve_cfg_file(raw: str, *, config: Path, tool_dir: Path) -> Path | None:
    candidate = Path(raw.replace("/", str(Path('/'))))
    if candidate.is_absolute() and candidate.is_file():
        return candidate.resolve()
    for base in (tool_dir, config.parent):
        path = (base / raw).resolve()
        if path.is_file():
            return path
    return None


def _source_layout(config: Path, tool_dir: Path) -> tuple[Path, Path, str, str]:
    writer: Path | None = None
    boot: Path | None = None
    boot_offset = "0x0"
    app_offset: str | None = None
    for raw_line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        file_match = _FILE_RE.search(line)
        path = _resolve_cfg_file(next((g for g in file_match.groups() if g), ""), config=config, tool_dir=tool_dir) if file_match else None
        if "--flash-writer" in line:
            # Some SDK versions spell this option as --flash-writer=<path>, not --file.
            writer_match = _WRITER_RE.search(line)
            value = next((g for g in writer_match.groups() if g), "") if writer_match else ""
            writer = _resolve_cfg_file(value, config=config, tool_dir=tool_dir)
            continue
        offset_match = _OFFSET_RE.search(line)
        if not offset_match or path is None:
            continue
        offset = offset_match.group(1)
        if int(offset, 0) == 0 and boot is None:
            boot, boot_offset = path, offset
        elif int(offset, 0) != 0 and app_offset is None:
            app_offset = offset
    if writer is None:
        raise ValueError("TI UniFlash config içinde flash-writer girdisi çözümlenemedi")
    if boot is None:
        raise ValueError("TI UniFlash config içinde offset 0 boot image girdisi çözümlenemedi")
    if app_offset is None:
        raise ValueError("TI UniFlash config içinde application flash offset'i bulunamadı; değer tahmin edilmedi")
    return writer, boot, boot_offset, app_offset


def create_uart_flash_plan(
    *,
    sdk_root: str | Path,
    serial_port: str,
    physical_lifecycle: str,
    target_lifecycle: str,
    customer_root_state: str,
    application_image: str | Path,
    boot_image: str | Path | None = None,
) -> UartFlashPlan:
    sdk = Path(sdk_root).expanduser().resolve()
    if not sdk.is_dir():
        raise NotADirectoryError(f"MCU+ SDK root bulunamadı: {sdk}")
    port = serial_port.strip().upper()
    if not _PORT_RE.fullmatch(port):
        raise ValueError("UART portu COM1..COM999 biçiminde olmalı")
    app = Path(application_image).expanduser().resolve()
    if not app.is_file():
        raise FileNotFoundError(f"Application image bulunamadı: {app.name}")
    expected_suffixes = (
        (".appimage.hs", ".mcelf.hs", ".appimage.hs_se", ".mcelf.hs_se")
        if target_lifecycle.upper() == "HS-SE"
        else (".appimage.hs_fs", ".mcelf.hs_fs")
    )
    if not app.name.casefold().endswith(expected_suffixes):
        expected = " veya ".join(f"*{suffix}" for suffix in expected_suffixes)
        raise ValueError(f"{target_lifecycle.upper()} için beklenen application çıktısı {expected}")

    profile = assess_secure_boot_profile(
        physical_lifecycle=physical_lifecycle,
        target_lifecycle=target_lifecycle,
        customer_root_state=customer_root_state,
        has_customer_signing_key=target_lifecycle.upper() != "HS-SE" or customer_root_state in {"provisioned", "hardware_verified"},
    )
    if not profile.flash_allowed:
        reason = profile.blockers[0] if profile.blockers else profile.warnings[0]
        raise PermissionError(f"Karta yazma kapalı: {reason}")

    tool = _find_one(sdk, ("uart_uniflash.py",))
    cfg_name = "default_sbl_ospi_hs.cfg" if target_lifecycle.upper() == "HS-SE" else "default_sbl_ospi_hs_fs.cfg"
    config = _find_one(sdk, (cfg_name,))
    writer, source_boot, boot_offset, app_offset = _source_layout(config, tool.parent)
    boot = Path(boot_image).expanduser().resolve() if boot_image else source_boot
    if not boot.is_file():
        raise FileNotFoundError(f"Boot image bulunamadı: {boot.name}")

    generated = "\n".join([
        "# Generated by AM64x Secure Boot Studio; SDK files are not modified.",
        f'--flash-writer="{writer}"',
        f'--file="{boot}" --operation=flash --flash-offset={boot_offset}',
        f'--file="{app}" --operation=flash --flash-offset={app_offset}',
        "",
    ])
    return UartFlashPlan(
        sdk_root=str(sdk), tool=str(tool), source_config=str(config), serial_port=port,
        physical_lifecycle=profile.physical_lifecycle, target_lifecycle=profile.target_lifecycle,
        boot_image=str(boot), application_image=str(app), boot_offset=boot_offset,
        application_offset=app_offset, flash_writer=str(writer), generated_config=generated,
        safe_command=(Path(sys.executable).name, tool.name, "-p", port, "--cfg", "<TEMP_FLASH_CONFIG>"),
    )


def execute_uart_flash_plan(
    plan: UartFlashPlan,
    *,
    confirm_hardware_write: bool = False,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    if not confirm_hardware_write:
        raise PermissionError("OSPI yazma için açık kullanıcı onayı gerekir")
    tool = Path(plan.tool)
    if not tool.is_file():
        raise FileNotFoundError("uart_uniflash.py artık bulunamıyor")
    try:
        with tempfile.TemporaryDirectory(prefix="securestudio-flash-") as temp_name:
            cfg = Path(temp_name) / "securestudio_ospi.cfg"
            cfg.write_text(plan.generated_config, encoding="utf-8")
            command = [sys.executable, str(tool), "-p", plan.serial_port, "--cfg", str(cfg)]
            proc = subprocess.run(
                command, cwd=tool.parent, capture_output=True, text=True,
                timeout=timeout_seconds, check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"UART UniFlash {timeout_seconds} saniyede tamamlanmadı") from exc
    console = "\n".join(((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines()[-160:])
    status = "PASS" if proc.returncode == 0 else "FAIL"
    return {
        "status": status, "operation": "uart_ospi_flash",
        "summary": (
            "UART UniFlash komutu tamamlandı. Kartı OSPI boot moduna alıp resetleyerek UART loguyla gerçek boot'u doğrulayın."
            if status == "PASS" else "UART UniFlash başarısız oldu; console ayrıntısını kontrol edin."
        ),
        "exit_code": proc.returncode, "safe_command": list(plan.safe_command),
        "console_excerpt": console, "hardware_write": True,
        "otp_efuse_write": False, "lifecycle_transition": False,
        "outputs": [
            {"type": "flashed_boot_image", "path": plan.boot_image},
            {"type": "flashed_application_image", "path": plan.application_image},
        ],
        "checks": [
            {"check": "lifecycle_target_match", "status": "PASS"},
            {"check": "explicit_hardware_write_confirmation", "status": "PASS"},
            {"check": "uart_uniflash_exit", "status": status},
            {"check": "otp_efuse_untouched", "status": "PASS"},
            {"check": "real_secure_boot_observation", "status": "NOT_CHECKED"},
        ],
        "claims": ["Seçilen boot ve application image UART UniFlash komutuna verildi."],
        "non_claims": [
            "Komut başarısı ROM/TIFS authentication kabulünü tek başına kanıtlamaz.",
            "OTP/eFuse veya HS-FS → HS-SE lifecycle geçişi yapılmadı.",
        ],
    }
