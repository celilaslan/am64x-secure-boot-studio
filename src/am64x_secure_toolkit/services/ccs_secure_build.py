from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .ccs_build import scan_ccs_application_build


_MAKEFILE_NAMES = ("makefile", "Makefile", "GNUmakefile")
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}


def lifecycle_build_configuration(
    lifecycle: str,
    *,
    signing_key: str | Path | None = None,
    encryption_key: str | Path | None = None,
) -> dict[str, Any]:
    """Translate the user-facing lifecycle into the MCU+ SDK make contract."""
    normalized = lifecycle.strip().upper()
    if normalized not in {"GP", "HS-FS", "HS-SE"}:
        raise ValueError("Lifecycle GP, HS-FS veya HS-SE olmalı")
    if normalized == "HS-SE" and signing_key is None:
        raise ValueError(
            "HS-SE build için provision edilmiş Customer Root of Trust ile eşleşen private signing key gerekir"
        )
    if encryption_key is not None and signing_key is None:
        raise ValueError("Application encryption için signing key de seçilmelidir")

    device_type = "HS" if normalized == "HS-SE" else "GP"
    return {
        "lifecycle": normalized,
        "device_type": device_type,
        "encrypted": encryption_key is not None,
        "uses_sdk_development_key": signing_key is None,
        "expected_kind": "signed_hs" if normalized == "HS-SE" else "signed_hs_fs",
        "explanation": (
            "HS-SE: DEVICE_TYPE=HS ve provision edilmiş customer signing key kullanılır."
            if normalized == "HS-SE"
            else "HS-FS/GP geliştirme akışı: DEVICE_TYPE=GP kullanılır; key verilmezse SDK development key'i seçer."
        ),
    }


def find_mcu_plus_make_directory(root: str | Path) -> Path:
    """Find a CCS/MCU+ SDK make directory without requiring the user to know its name."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise NotADirectoryError(f"CCS proje/build klasörü bulunamadı: {base}")
    for name in _MAKEFILE_NAMES:
        if (base / name).is_file():
            return base

    candidates: list[tuple[int, Path]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        current = Path(dirpath)
        try:
            depth = len(current.relative_to(base).parts)
        except ValueError:
            continue
        dirnames[:] = [
            name for name in dirnames
            if name not in _SKIP_DIRS and not name.startswith(".") and depth < 4
        ]
        if not any(name in filenames for name in _MAKEFILE_NAMES):
            continue
        lower_parts = {part.casefold() for part in current.parts}
        score = 0
        if "release" in lower_parts:
            score += 30
        if "debug" in lower_parts:
            score += 20
        score -= depth
        candidates.append((score, current))
    if not candidates:
        raise FileNotFoundError(
            "Seçilen klasörde CCS/MCU+ SDK makefile bulunamadı. CCS proje klasörünü veya Debug/Release klasörünü seçin."
        )
    return sorted(candidates, key=lambda item: (-item[0], str(item[1])))[0][1]


def _find_make(explicit: str | Path | None = None) -> Path:
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if candidate.is_file():
            return candidate
        raise FileNotFoundError(f"Make executable bulunamadı: {candidate}")
    found = shutil.which("gmake") or shutil.which("make")
    if not found:
        raise FileNotFoundError(
            "GNU Make bulunamadı. CCS/MCU+ SDK terminalini kullanın veya make/gmake'i PATH'e ekleyin."
        )
    return Path(found).resolve()


def _safe_console(text: str, *, secret_stage: Path | None) -> str:
    value = text or ""
    if secret_stage is not None:
        value = value.replace(str(secret_stage), "<TEMP_SECRET_STAGE>")
        value = value.replace(str(secret_stage).replace("\\", "/"), "<TEMP_SECRET_STAGE>")
    lines = value.splitlines()
    return "\n".join(lines[-120:])


def run_mcu_plus_secure_build(
    project_or_build_dir: str | Path,
    *,
    lifecycle: str,
    sdk_root: str | Path | None = None,
    signing_key: str | Path | None = None,
    encryption_key: str | Path | None = None,
    make_executable: str | Path | None = None,
    target: str = "all",
    dry_run: bool = False,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Run the project's own MCU+ SDK make recipe with Studio-selected security inputs.

    Global ``devconfig.mak`` and CCS project files are not edited. Secret files are copied to
    a temporary stage with neutral names, and the stage is deleted after make exits.
    """
    config = lifecycle_build_configuration(
        lifecycle, signing_key=signing_key, encryption_key=encryption_key
    )
    selected_root = Path(project_or_build_dir).expanduser().resolve()
    make_dir = find_mcu_plus_make_directory(selected_root)
    make_bin = _find_make(make_executable)

    sdk = Path(sdk_root).expanduser().resolve() if sdk_root else None
    if sdk is not None and not sdk.is_dir():
        raise NotADirectoryError(f"MCU+ SDK root bulunamadı: {sdk}")

    key = Path(signing_key).expanduser().resolve() if signing_key else None
    mek = Path(encryption_key).expanduser().resolve() if encryption_key else None
    for label, path in (("Signing key", key), ("Application MEK", mek)):
        if path is not None and not path.is_file():
            raise FileNotFoundError(f"{label} dosyası bulunamadı")

    before = scan_ccs_application_build(selected_root)
    base_command = [str(make_bin), "-C", str(make_dir), target]
    public_variables = [
        f"DEVICE_TYPE={config['device_type']}",
        f"ENC_ENABLED={'yes' if config['encrypted'] else 'no'}",
    ]
    safe_command = [make_bin.name, "-C", str(make_dir), target, *public_variables]
    if key is not None:
        safe_command.append("APP_SIGNING_KEY=<TEMP_SECRET_STAGE>/app_signing_key.pem")
    if mek is not None:
        safe_command.append("APP_ENCRYPTION_KEY=<TEMP_SECRET_STAGE>/app_encryption_key.txt")

    if dry_run:
        return {
            "status": "NOT_CHECKED",
            "operation": "ccs_secure_build",
            "summary": "Secure build planı hazırlandı; make çalıştırılmadı.",
            "lifecycle": config["lifecycle"],
            "device_type": config["device_type"],
            "make_directory": str(make_dir),
            "safe_command": safe_command,
            "expected_kind": config["expected_kind"],
            "global_devconfig_modified": False,
        }

    secret_stage: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="securestudio-build-") as temp_name:
            secret_stage = Path(temp_name)
            command = [*base_command, *public_variables]
            if key is not None:
                staged_key = secret_stage / "app_signing_key.pem"
                shutil.copyfile(key, staged_key)
                command.append(f"APP_SIGNING_KEY={staged_key}")
            if mek is not None:
                staged_mek = secret_stage / "app_encryption_key.txt"
                shutil.copyfile(mek, staged_mek)
                command.append(f"APP_ENCRYPTION_KEY={staged_mek}")

            process_env = os.environ.copy()
            if sdk is not None:
                process_env["MCU_PLUS_SDK_PATH"] = str(sdk)
                process_env["SDK_INSTALL_PATH"] = str(sdk)
            proc = subprocess.run(
                command,
                cwd=make_dir,
                env=process_env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            console = _safe_console((proc.stdout or "") + "\n" + (proc.stderr or ""), secret_stage=secret_stage)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"CCS/MCU+ SDK secure build {timeout_seconds} saniyede tamamlanmadı") from exc

    after = scan_ccs_application_build(selected_root)
    expected = [item for item in after["signed"] if item["kind"] == config["expected_kind"]]
    output = expected[0] if expected else None
    status = "PASS" if proc.returncode == 0 and output is not None else "FAIL"
    if proc.returncode != 0:
        summary = "MCU+ SDK make işlemi başarısız oldu; son console satırları Teknik Ayrıntılar bölümünde."
    elif output is None:
        summary = "Make tamamlandı ancak lifecycle ile uyumlu signed application image bulunamadı."
    else:
        summary = f"Secure application hazır: {output['name']}"
    return {
        "status": status,
        "operation": "ccs_secure_build",
        "summary": summary,
        "lifecycle": config["lifecycle"],
        "device_type": config["device_type"],
        "encrypted": config["encrypted"],
        "uses_sdk_development_key": config["uses_sdk_development_key"],
        "make_directory": str(make_dir),
        "safe_command": safe_command,
        "exit_code": proc.returncode,
        "console_excerpt": console,
        "output": output,
        "outputs": ([{"type": "application_image", "path": output["path"]}] if output else []),
        "checks": [
            {"check": "mcu_plus_sdk_make", "status": "PASS" if proc.returncode == 0 else "FAIL"},
            {"check": "signed_output_discovery", "status": "PASS" if output else "FAIL"},
            {"check": "global_devconfig_unchanged", "status": "PASS"},
        ],
        "before_state": before["state"],
        "after_state": after["state"],
        "global_devconfig_modified": False,
        "secret_paths_persisted": False,
    }
