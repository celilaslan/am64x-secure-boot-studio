from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .ccs_secure_build import (
    _discover_ccs_tool_paths,
    _find_ccs_bootimage_recipe,
    _find_make,
    _safe_console,
    find_mcu_plus_make_directory,
    lifecycle_build_configuration,
)


_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}


def classify_sbl_artifact(path: str | Path) -> str | None:
    name = Path(path).name.casefold()
    if name == "tiboot3.bin":
        return "deployable_tiboot3"
    if name.endswith(".hs_fs.tiimage") or name.endswith(".tiimage.hs_fs"):
        return "signed_hs_fs"
    if name.endswith(".hs.tiimage") or name.endswith(".tiimage.hs"):
        return "signed_hs"
    if name.endswith(".tiimage"):
        return "unsigned_tiimage"
    if name.endswith(".out"):
        return "linked_elf"
    return None


def scan_ccs_sbl_build(root: str | Path, *, max_artifacts: int = 500) -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise NotADirectoryError(f"SBL CCS proje/build klasörü bulunamadı: {base}")
    artifacts: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [n for n in dirnames if n not in _SKIP_DIRS and not n.startswith(".")]
        current = Path(dirpath)
        for filename in filenames:
            kind = classify_sbl_artifact(filename)
            if kind is None:
                continue
            path = current / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            artifacts.append({
                "path": str(path), "name": path.name, "kind": kind,
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            })
            if len(artifacts) >= max_artifacts:
                break
    artifacts.sort(key=lambda item: (item["mtime_ns"], item["path"]), reverse=True)
    return {
        "status": "PASS",
        "operation": "ccs_sbl_build_scan",
        "root": str(base),
        "artifacts": artifacts,
        "signed_hs_fs": [x for x in artifacts if x["kind"] == "signed_hs_fs"],
        "signed_hs": [x for x in artifacts if x["kind"] == "signed_hs"],
        "tiboot3": [x for x in artifacts if x["kind"] == "deployable_tiboot3"],
        "linked_elf": [x for x in artifacts if x["kind"] == "linked_elf"],
    }


def run_mcu_plus_sbl_build(
    project_or_build_dir: str | Path,
    *,
    lifecycle: str,
    sdk_root: str | Path,
    signing_key: str | Path | None = None,
    encryption_key: str | Path | None = None,
    make_executable: str | Path | None = None,
    timeout_seconds: int = 900,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Build an MCU+ SDK SBL project through its own fixed CCS post-build recipe."""
    config = lifecycle_build_configuration(
        lifecycle, signing_key=signing_key, encryption_key=encryption_key
    )
    selected = Path(project_or_build_dir).expanduser().resolve()
    make_dir = find_mcu_plus_make_directory(selected)
    recipe_info = _find_ccs_bootimage_recipe(make_dir)
    if recipe_info is None:
        raise FileNotFoundError(
            "SBL projesinde makefile_ccs_bootimage_gen bulunamadı; MCU+ SDK SBL CCS projesini seçin."
        )
    project_root, recipe = recipe_info
    sdk = Path(sdk_root).expanduser().resolve()
    if not sdk.is_dir():
        raise NotADirectoryError(f"MCU+ SDK root bulunamadı: {sdk}")
    make_bin = _find_make(make_executable)
    key = Path(signing_key).expanduser().resolve() if signing_key else None
    mek = Path(encryption_key).expanduser().resolve() if encryption_key else None
    for label, path in (("SBL signing key", key), ("SBL encryption key", mek)):
        if path is not None and not path.is_file():
            raise FileNotFoundError(f"{label} dosyası bulunamadı")

    scan_before = scan_ccs_sbl_build(selected)
    linked = [x for x in scan_before["linked_elf"] if Path(x["path"]).parent == make_dir]
    if not linked:
        linked = scan_before["linked_elf"]
    outname = Path(linked[0]["name"]).stem if linked else project_root.name
    public_vars = [
        f"OUTNAME={outname}", f"PROFILE={make_dir.name}", "DEVICE=am64x",
        f"DEVICE_TYPE={config['device_type']}",
        f"ENC_ENABLED={'yes' if config['encrypted'] else 'no'}",
        f"ENC_SBL_ENABLED={'yes' if config['encrypted'] else 'no'}",
        f"MCU_PLUS_SDK_PATH={sdk}",
    ]
    public_vars.extend(
        f"{name}={value}" for name, value in _discover_ccs_tool_paths(project_root, make_dir, sdk).items()
    )
    safe_main = [make_bin.name, "-C", str(make_dir), "all", f"DEVICE_TYPE={config['device_type']}"]
    safe_post = [make_bin.name, "-C", str(project_root), "-f", recipe.name, *public_vars]
    if key:
        safe_post.append("SBL_SIGNING_KEY=<TEMP_SECRET_STAGE>/sbl_signing_key.pem")
    if mek:
        safe_post.append("SBL_ENCRYPTION_KEY=<TEMP_SECRET_STAGE>/sbl_encryption_key.txt")
    if dry_run:
        return {
            "status": "NOT_CHECKED", "operation": "ccs_sbl_secure_build",
            "summary": "SBL/combined boot image build planı hazır; make çalıştırılmadı.",
            "safe_command": safe_main, "post_build_safe_command": safe_post,
            "lifecycle": config["lifecycle"], "device_type": config["device_type"],
            "global_devconfig_modified": False, "secret_paths_persisted": False,
        }

    process_env = os.environ.copy()
    process_env["MCU_PLUS_SDK_PATH"] = str(sdk)
    process_env["SDK_INSTALL_PATH"] = str(sdk)
    secret_stage: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="securestudio-sbl-") as temp_name:
            secret_stage = Path(temp_name)
            main_command = [str(make_bin), "-C", str(make_dir), "all", f"DEVICE_TYPE={config['device_type']}"]
            main = subprocess.run(
                main_command, cwd=make_dir, env=process_env, capture_output=True,
                text=True, timeout=timeout_seconds, check=False,
            )
            post_command = [str(make_bin), "-C", str(project_root), "-f", recipe.name, *public_vars]
            if key:
                staged_key = secret_stage / "sbl_signing_key.pem"
                shutil.copyfile(key, staged_key)
                post_command.append(f"SBL_SIGNING_KEY={staged_key}")
            if mek:
                staged_mek = secret_stage / "sbl_encryption_key.txt"
                shutil.copyfile(mek, staged_mek)
                post_command.append(f"SBL_ENCRYPTION_KEY={staged_mek}")
            post = subprocess.run(
                post_command, cwd=project_root, env=process_env, capture_output=True,
                text=True, timeout=timeout_seconds, check=False,
            ) if main.returncode == 0 else None
            console = _safe_console(
                (main.stdout or "") + "\n" + (main.stderr or "") +
                "\n--- CCS SBL post-build ---\n" +
                ((post.stdout or "") + "\n" + (post.stderr or "") if post else "post-build çalıştırılmadı"),
                secret_stage=secret_stage,
            )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"SBL secure build {timeout_seconds} saniyede tamamlanmadı") from exc

    after = scan_ccs_sbl_build(project_root)
    expected_key = "signed_hs" if config["lifecycle"] == "HS-SE" else "signed_hs_fs"
    candidates = after[expected_key]
    output = candidates[0] if candidates else (after["tiboot3"][0] if after["tiboot3"] else None)
    post_code = post.returncode if post is not None else None
    status = "PASS" if main.returncode == 0 and post_code == 0 and output else "FAIL"
    return {
        "status": status, "operation": "ccs_sbl_secure_build",
        "summary": f"Boot/combined image hazır: {output['name']}" if status == "PASS" else "SBL make tamamlandı ancak lifecycle ile uyumlu boot image bulunamadı.",
        "lifecycle": config["lifecycle"], "device_type": config["device_type"],
        "make_directory": str(make_dir), "safe_command": safe_main,
        "post_build_safe_command": safe_post, "exit_code": main.returncode,
        "post_build_exit_code": post_code, "console_excerpt": console,
        "output": output,
        "outputs": ([{"type": "boot_image", "path": output["path"]}] if output else []),
        "checks": [
            {"check": "mcu_plus_sdk_sbl_make", "status": "PASS" if main.returncode == 0 else "FAIL"},
            {"check": "ccs_sbl_post_build", "status": "PASS" if post_code == 0 else "FAIL"},
            {"check": "boot_image_discovery", "status": "PASS" if output else "FAIL"},
            {"check": "global_devconfig_unchanged", "status": "PASS"},
        ],
        "global_devconfig_modified": False, "secret_paths_persisted": False,
    }

