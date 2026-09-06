from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .ccs_build import scan_ccs_application_build


_MAKEFILE_NAMES = ("makefile", "Makefile", "GNUmakefile")
_CCS_BOOTIMAGE_MAKEFILE = "makefile_ccs_bootimage_gen"
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


def _find_ccs_bootimage_recipe(make_dir: Path) -> tuple[Path, Path] | None:
    """Locate TI's fixed-name CCS post-build recipe near the selected build directory."""
    current = make_dir
    for _ in range(5):
        recipe = current / _CCS_BOOTIMAGE_MAKEFILE
        if recipe.is_file():
            return current, recipe
        if current.parent == current:
            break
        current = current.parent
    return None


def _read_small_project_files(project_root: Path, make_dir: Path) -> list[str]:
    candidates = [
        project_root / ".cproject",
        project_root / ".project",
        project_root / _CCS_BOOTIMAGE_MAKEFILE,
        make_dir / "makefile",
        make_dir / "Makefile",
        *make_dir.glob("*.mk"),
    ]
    texts: list[str] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            if candidate.stat().st_size <= 2_000_000:
                texts.append(candidate.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return texts


def _assignment_path(texts: list[str], variable: str) -> Path | None:
    """Read a concrete make assignment without expanding or executing project text."""
    import re

    pattern = re.compile(
        rf"(?im)^\s*{re.escape(variable)}\s*(?::|\?|\+)?=\s*[\"']?([^\"'\r\n]+)"
    )
    for content in texts:
        match = pattern.search(content)
        if not match:
            continue
        raw = match.group(1).strip().rstrip("\\").strip()
        if "$" in raw or not raw:
            continue
        candidate = Path(raw).expanduser()
        if candidate.is_dir():
            return candidate.resolve()
    return None


def _discover_ccs_tool_paths(project_root: Path, make_dir: Path, sdk: Path | None) -> dict[str, str]:
    """Best-effort discovery of values normally injected by the CCS IDE."""
    texts = _read_small_project_files(project_root, make_dir)
    compiler = None
    env_compiler = os.environ.get("CG_TOOL_ROOT")
    if env_compiler and Path(env_compiler).is_dir():
        compiler = Path(env_compiler).resolve()
    if compiler is None:
        compiler = _assignment_path(texts, "CG_TOOL_ROOT")

    ccs_install = None
    env_ccs = os.environ.get("CCS_INSTALL_DIR")
    if env_ccs and Path(env_ccs).is_dir():
        ccs_install = Path(env_ccs).resolve()
    if ccs_install is None:
        ccs_install = _assignment_path(texts, "CCS_INSTALL_DIR")
    if ccs_install is None and compiler is not None:
        parents = list(compiler.parents)
        for parent in parents:
            if parent.name.casefold() == "tools":
                ccs_install = parent.parent
                break

    search_root = sdk.parent if sdk is not None else None
    if compiler is None and search_root is not None and search_root.is_dir():
        matches: list[Path] = []
        for ccs_dir in search_root.glob("ccs*"):
            matches.extend((ccs_dir / "tools" / "compiler").glob("ti-cgt-armllvm_*"))
            matches.extend((ccs_dir / "ccs" / "tools" / "compiler").glob("ti-cgt-armllvm_*"))
        matches = [path for path in matches if path.is_dir()]
        if matches:
            compiler = sorted(matches, key=lambda path: path.name, reverse=True)[0].resolve()
            if ccs_install is None:
                ccs_install = compiler.parents[2]

    values = {"CCS_IDE_MODE": os.environ.get("CCS_IDE_MODE", "desktop")}
    if compiler is not None:
        values["CG_TOOL_ROOT"] = str(compiler)
    if ccs_install is not None:
        values["CCS_INSTALL_DIR"] = str(ccs_install)
    return values


def _select_outname(scan: dict[str, Any], make_dir: Path) -> str | None:
    linked = scan.get("linked_elf", [])
    same_profile = [
        item for item in linked if Path(item["path"]).parent.resolve() == make_dir.resolve()
    ]
    candidates = same_profile or linked
    return Path(candidates[0]["name"]).stem if candidates else None


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
    post_command_safe: list[str] | None = None
    post_exit_code: int | None = None
    post_recipe_found = False
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
            console_text = (proc.stdout or "") + "\n" + (proc.stderr or "")

            after_main = scan_ccs_application_build(selected_root)
            expected_after_main = [
                item for item in after_main["signed"] if item["kind"] == config["expected_kind"]
            ]
            recipe_info = _find_ccs_bootimage_recipe(make_dir)
            if proc.returncode == 0 and not expected_after_main and recipe_info is not None:
                post_recipe_found = True
                project_root, recipe = recipe_info
                outname = _select_outname(after_main, make_dir)
                if outname is not None:
                    profile = make_dir.name
                    post_public_variables = [
                        f"OUTNAME={outname}",
                        f"PROFILE={profile}",
                        f"DEVICE=am64x",
                        *public_variables,
                    ]
                    if sdk is not None:
                        post_public_variables.append(f"MCU_PLUS_SDK_PATH={sdk}")
                    tool_paths = _discover_ccs_tool_paths(project_root, make_dir, sdk)
                    post_public_variables.extend(
                        f"{name}={value}" for name, value in tool_paths.items()
                    )
                    post_command = [
                        str(make_bin), "-C", str(project_root), "-f", recipe.name,
                        *post_public_variables,
                    ]
                    post_command_safe = [
                        make_bin.name, "-C", str(project_root), "-f", recipe.name,
                        *post_public_variables,
                    ]
                    if key is not None:
                        post_command.append(f"APP_SIGNING_KEY={staged_key}")
                        post_command_safe.append(
                            "APP_SIGNING_KEY=<TEMP_SECRET_STAGE>/app_signing_key.pem"
                        )
                    if mek is not None:
                        post_command.append(f"APP_ENCRYPTION_KEY={staged_mek}")
                        post_command_safe.append(
                            "APP_ENCRYPTION_KEY=<TEMP_SECRET_STAGE>/app_encryption_key.txt"
                        )
                    post_proc = subprocess.run(
                        post_command,
                        cwd=project_root,
                        env=process_env,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                        check=False,
                    )
                    post_exit_code = post_proc.returncode
                    console_text += "\n--- CCS boot-image post-build ---\n"
                    console_text += (post_proc.stdout or "") + "\n" + (post_proc.stderr or "")
            console = _safe_console(console_text, secret_stage=secret_stage)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"CCS/MCU+ SDK secure build {timeout_seconds} saniyede tamamlanmadı") from exc

    after = scan_ccs_application_build(selected_root)
    recipe_info = _find_ccs_bootimage_recipe(make_dir)
    if not any(item["kind"] == config["expected_kind"] for item in after["signed"]):
        if recipe_info is not None and recipe_info[0] != selected_root:
            project_scan = scan_ccs_application_build(recipe_info[0])
            if any(item["kind"] == config["expected_kind"] for item in project_scan["signed"]):
                after = project_scan
    expected = [item for item in after["signed"] if item["kind"] == config["expected_kind"]]
    output = expected[0] if expected else None
    commands_ok = proc.returncode == 0 and post_exit_code in (None, 0)
    status = "PASS" if commands_ok and output is not None else "FAIL"
    if proc.returncode != 0:
        summary = "MCU+ SDK make işlemi başarısız oldu; son console satırları Teknik Ayrıntılar bölümünde."
    elif post_exit_code not in (None, 0):
        summary = "CCS boot-image post-build işlemi başarısız oldu; son console satırları Teknik Ayrıntılar bölümünde."
    elif output is None:
        summary = (
            "CCS post-build tarifi bulundu ancak çalıştırılamadı: build klasöründe OUTNAME için .out bulunamadı."
            if post_recipe_found and post_command_safe is None
            else "Make tamamlandı ancak lifecycle ile uyumlu signed application image bulunamadı."
        )
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
        "post_build_safe_command": post_command_safe,
        "post_build_exit_code": post_exit_code,
        "console_excerpt": console,
        "output": output,
        "outputs": ([{"type": "application_image", "path": output["path"]}] if output else []),
        "checks": [
            {"check": "mcu_plus_sdk_make", "status": "PASS" if proc.returncode == 0 else "FAIL"},
            {
                "check": "ccs_bootimage_post_build",
                "status": (
                    "PASS" if post_exit_code == 0 else
                    "FAIL" if post_exit_code is not None or (post_recipe_found and post_command_safe is None) else
                    "NOT_NEEDED"
                ),
            },
            {"check": "signed_output_discovery", "status": "PASS" if output else "FAIL"},
            {"check": "global_devconfig_unchanged", "status": "PASS"},
        ],
        "before_state": before["state"],
        "after_state": after["state"],
        "global_devconfig_modified": False,
        "secret_paths_persisted": False,
    }
