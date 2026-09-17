from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
}


def classify_application_artifact(path: str | Path) -> str | None:
    """Classify common MCU+ SDK application build outputs by filename only."""
    name = Path(path).name.casefold()
    # CCS 20 / MCU+ SDK 12 projects commonly emit ``<name>.mcelf.hs_fs`` or
    # ``<name>.mcelf.hs``. Makefile builds may use the appimage spelling.
    if name.endswith(".appimage.hs_fs") or name.endswith(".mcelf.hs_fs"):
        return "signed_hs_fs"
    if (
        name.endswith(".appimage.hs_se") or name.endswith(".appimage.hs")
        or name.endswith(".mcelf.hs_se") or name.endswith(".mcelf.hs")
    ):
        return "signed_hs"
    if name.endswith(".appimage"):
        return "unsigned_appimage"
    if name.endswith(".mcelf"):
        return "unsigned_mcelf"
    if name.endswith(".out"):
        return "linked_elf"
    return None


def scan_ccs_application_build(root: str | Path, *, max_artifacts: int = 500) -> dict[str, Any]:
    """Scan a CCS/project build tree without reading file contents or secret material."""
    base = Path(root).expanduser()
    if not base.exists():
        raise FileNotFoundError(f"Build klasörü bulunamadı: {base}")
    if not base.is_dir():
        raise NotADirectoryError(f"Build klasörü normal bir dizin değil: {base}")

    artifacts: list[dict[str, Any]] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [
            name for name in dirnames
            if name not in _SKIP_DIRS and not name.startswith(".")
        ]
        current = Path(dirpath)
        for filename in filenames:
            kind = classify_application_artifact(filename)
            if kind is None:
                continue
            path = current / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            artifacts.append({
                "path": str(path),
                "relative_path": str(path.relative_to(base)),
                "name": path.name,
                "kind": kind,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
            })
            if len(artifacts) >= max_artifacts:
                truncated = True
                break
        if truncated:
            break

    artifacts.sort(key=lambda item: (item["mtime_ns"], item["relative_path"]), reverse=True)
    by_kind = {
        kind: [item for item in artifacts if item["kind"] == kind]
        for kind in (
            "signed_hs_fs",
            "signed_hs",
            "unsigned_appimage",
            "unsigned_mcelf",
            "linked_elf",
        )
    }

    signed = by_kind["signed_hs_fs"] + by_kind["signed_hs"]
    unsigned = by_kind["unsigned_appimage"] + by_kind["unsigned_mcelf"]
    if signed:
        state = "READY_SIGNED"
        action = "VERIFY_EXISTING"
        recommended = signed[0]
        summary = (
            "CCS/MCU+ SDK tarafından üretilmiş imzalı application image bulundu. "
            "Yeniden certificate üretmek veya tekrar imzalamak gerekmez."
        )
    elif unsigned:
        state = "UNSIGNED_READY"
        action = "SIGN_OR_CONFIGURE"
        recommended = unsigned[0]
        summary = (
            "Unsigned application build çıktısı bulundu. Standalone signing kullanılabilir "
            "veya CCS secure-build key/config ayarı hazırlanıp proje yeniden build edilebilir."
        )
    elif by_kind["linked_elf"]:
        state = "BUILD_INCOMPLETE"
        action = "FINISH_CCS_BUILD"
        recommended = by_kind["linked_elf"][0]
        summary = (
            "Yalnız linker .out çıktısı bulundu; MCU+ SDK boot-image/post-build aşaması "
            "henüz uygun application image üretmemiş."
        )
    else:
        state = "NO_OUTPUT"
        action = "BUILD_IN_CCS"
        recommended = None
        summary = "Bu klasörde tanınan CCS/MCU+ SDK application build çıktısı bulunamadı."

    return {
        "status": "PASS",
        "operation": "ccs_application_build_scan",
        "root": str(base),
        "state": state,
        "recommended_action": action,
        "recommended": recommended,
        "signed": signed,
        "unsigned": unsigned,
        "linked_elf": by_kind["linked_elf"],
        "artifacts": artifacts,
        "truncated": truncated,
        "summary": summary,
    }
