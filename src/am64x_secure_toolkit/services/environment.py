from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_VALIDATED_SDK = "12.00.00.27"


def _safe_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        home = Path.home().resolve()
        resolved = path.expanduser().resolve()
        if resolved == home:
            return "<HOME>"
        try:
            rel = resolved.relative_to(home)
            return f"<HOME>/{rel.as_posix()}"
        except ValueError:
            return str(resolved)
    except Exception:
        return str(path)


def _sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sdk_version_from_name(root: Path | None) -> str | None:
    if root is None:
        return None
    match = re.search(r"(?:am64x[_-])?(\d+)[_.-](\d+)[_.-](\d+)[_.-](\d+)", root.name.lower())
    if not match:
        return None
    return ".".join(match.groups())


def _candidate_roots(explicit: str | Path | None) -> list[Path]:
    raw: list[Path] = []
    if explicit is not None:
        raw.append(Path(explicit).expanduser())
    for env_name in ("MCU_PLUS_SDK_PATH", "SDK_INSTALL_PATH"):
        value = os.environ.get(env_name)
        if value:
            raw.append(Path(value).expanduser())
    ti_home = Path.home() / "ti"
    if ti_home.is_dir():
        raw.extend(sorted(ti_home.glob("mcu_plus_sdk_am64x_*"), reverse=True))
    seen: set[str] = set()
    result: list[Path] = []
    for item in raw:
        try:
            resolved = item.resolve()
        except Exception:
            resolved = item
        key = str(resolved)
        if key not in seen and resolved.is_dir():
            seen.add(key)
            result.append(resolved)
    return result


def _find_one(root: Path, name: str) -> Path | None:
    known = [
        root / "source" / "security" / "security_common" / "tools" / "boot" / "signing" / name,
        root / "tools" / "boot" / "signing" / name,
    ]
    for path in known:
        if path.is_file():
            return path
    try:
        return next((p for p in root.rglob(name) if p.is_file()), None)
    except OSError:
        return None


@dataclass(frozen=True)
class EnvironmentResolution:
    sdk_root: Path | None
    sdk_version: str | None
    app_signing_tool: Path | None
    rom_signing_tool: Path | None
    devconfig: Path | None
    openssl_path: Path | None
    openssl_version: str | None
    python_executable: Path
    compatibility: str

    @property
    def ready(self) -> bool:
        return bool(self.sdk_root and self.app_signing_tool and self.rom_signing_tool and self.openssl_path)

    def to_dict(self) -> dict[str, Any]:
        checks = [
            {"check": "sdk_root", "status": "PASS" if self.sdk_root else "FAIL", "detail": _safe_path(self.sdk_root)},
            {"check": "appimage_x509_cert_gen.py", "status": "PASS" if self.app_signing_tool else "FAIL", "sha256": _sha256(self.app_signing_tool)},
            {"check": "rom_image_gen.py", "status": "PASS" if self.rom_signing_tool else "FAIL", "sha256": _sha256(self.rom_signing_tool)},
            {"check": "devconfig.mak", "status": "PASS" if self.devconfig else "WARN", "sha256": _sha256(self.devconfig)},
            {"check": "OpenSSL", "status": "PASS" if self.openssl_path else "FAIL", "detail": self.openssl_version},
            {"check": "Python", "status": "PASS", "detail": sys.version.split()[0]},
        ]
        status = "PASS" if self.ready else "FAIL"
        if self.ready and self.compatibility != "VALIDATED_BASELINE":
            status = "PARTIAL"
        return {
            "status": status,
            "operation": "environment_discovery",
            "sdk_root": _safe_path(self.sdk_root),
            "sdk_version_observed_from_directory": self.sdk_version,
            "compatibility": self.compatibility,
            "validated_baseline": _VALIDATED_SDK,
            "app_signing_tool": _safe_path(self.app_signing_tool),
            "rom_signing_tool": _safe_path(self.rom_signing_tool),
            "devconfig": _safe_path(self.devconfig),
            "openssl": _safe_path(self.openssl_path),
            "openssl_version": self.openssl_version,
            "python": _safe_path(self.python_executable),
            "checks": checks,
            "note": "SDK version directory adından best-effort okunur; exact release identity için installed source/release metadata tercih edilir.",
        }


def resolve_environment(sdk_root: str | Path | None = None) -> EnvironmentResolution:
    roots = _candidate_roots(sdk_root)
    root = roots[0] if roots else None
    app_tool = _find_one(root, "appimage_x509_cert_gen.py") if root else None
    rom_tool = _find_one(root, "rom_image_gen.py") if root else None
    devconfig = None
    if root:
        candidate = root / "devconfig" / "devconfig.mak"
        if candidate.is_file():
            devconfig = candidate
        else:
            devconfig = _find_one(root, "devconfig.mak")

    openssl_bin = shutil.which("openssl")
    openssl_path = Path(openssl_bin).resolve() if openssl_bin else None
    openssl_version = None
    if openssl_path:
        try:
            proc = subprocess.run([str(openssl_path), "version"], capture_output=True, text=True, timeout=5, check=False)
            openssl_version = (proc.stdout or proc.stderr).strip() or None
        except Exception:
            openssl_version = None

    version = _sdk_version_from_name(root)
    compatibility = "VALIDATED_BASELINE" if version == _VALIDATED_SDK else ("UNVALIDATED_VERSION" if version else "VERSION_UNKNOWN")
    return EnvironmentResolution(
        sdk_root=root,
        sdk_version=version,
        app_signing_tool=app_tool,
        rom_signing_tool=rom_tool,
        devconfig=devconfig,
        openssl_path=openssl_path,
        openssl_version=openssl_version,
        python_executable=Path(sys.executable).resolve(),
        compatibility=compatibility,
    )
