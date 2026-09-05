from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from ..release_scan import scan_release_tree
from .network_policy import runtime_network_policy


def beta_readiness(root: str | Path | None = None) -> dict[str, Any]:
    """Return an explicit beta/readiness model.

    Real GUI render and standalone clean-machine validation are evidence-gated. Presence
    of PySide6/PyInstaller only means those checks can be attempted; it never marks them
    executed automatically.
    """
    pyside = importlib.util.find_spec("PySide6") is not None
    pyinstaller = importlib.util.find_spec("PyInstaller") is not None
    root_path = Path(root).resolve() if root is not None else None
    packaging = {
        "linux_recipe": bool(root_path and (root_path / "packaging" / "build_linux.sh").is_file()),
        "windows_recipe": bool(root_path and (root_path / "packaging" / "windows" / "build_windows.ps1").is_file()),
        "pyinstaller_spec": bool(root_path and (root_path / "packaging" / "pyinstaller" / "securestudio.spec").is_file()),
    }
    release_scan = scan_release_tree(root_path) if root_path and (root_path / "src").is_dir() else None
    local_checks = [
        {"check": "offline_runtime_policy", "status": "PASS" if runtime_network_policy().runtime_network_required is False else "FAIL"},
        {"check": "release_secret_path_scan", "status": release_scan["status"] if release_scan else "NOT_CHECKED"},
        {"check": "linux_packaging_recipe", "status": "PASS" if packaging["linux_recipe"] else "NOT_CHECKED"},
        {"check": "windows_packaging_recipe", "status": "PASS" if packaging["windows_recipe"] else "NOT_CHECKED"},
        {"check": "pyinstaller_spec", "status": "PASS" if packaging["pyinstaller_spec"] else "NOT_CHECKED"},
    ]
    blockers = [
        "real Qt window render/screenshot QA",
        "Linux standalone executable smoke on a clean supported host",
        "Windows standalone executable smoke on a clean supported host",
    ]
    if not pyside:
        blockers.insert(0, "PySide6 is not installed in this build environment")
    if not pyinstaller:
        blockers.insert(1 if not pyside else 0, "PyInstaller is not installed in this build environment")
    local_status = "FAIL" if any(x["status"] == "FAIL" for x in local_checks) else "PASS"
    return {
        "status": "PARTIAL" if local_status == "PASS" else "FAIL",
        "operation": "beta_readiness",
        "local_qa": local_status,
        "pyside6_available": pyside,
        "pyinstaller_available": pyinstaller,
        "checks": local_checks,
        "release_blockers": blockers,
        "real_qt_render": "NOT_EXECUTED",
        "linux_clean_machine": "NOT_EXECUTED",
        "windows_clean_machine": "NOT_EXECUTED",
        "project_final_completion": "NOT_DECLARED",
        "note": "Dependency presence is not execution evidence; render/standalone checks must be run on real target hosts.",
    }
