from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from am64x_secure_toolkit.release_scan import scan_release_tree
from am64x_secure_toolkit.services.beta_readiness import beta_readiness
from am64x_secure_toolkit.services.environment import resolve_environment
from am64x_secure_toolkit.services.network_policy import runtime_network_policy
from am64x_secure_toolkit.services.ux_audit import audit_gui_sources


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = resolve_environment(Path("/__am64x_missing_sdk_for_phase8_qa__"))
    network = runtime_network_policy().to_dict()
    release = scan_release_tree(root)
    ux = audit_gui_sources(root)
    beta = beta_readiness(root)

    network_imports = []
    pat = re.compile(r"^\s*(?:from|import)\s+(requests|httpx|aiohttp|urllib\.request|ftplib)\b", re.M)
    for p in (root / "src").rglob("*.py"):
        text = p.read_text(encoding="utf-8", errors="ignore")
        if pat.search(text):
            network_imports.append(p.relative_to(root).as_posix())

    local_status = "PASS" if release["status"] == "PASS" and not network_imports and ux["status"] == "PASS" else "FAIL"
    out = {
        "phase8_local_qa": local_status,
        "phase8_release_readiness": "PARTIAL" if local_status == "PASS" else "FAIL",
        "pyside6_available": importlib.util.find_spec("PySide6") is not None,
        "pyinstaller_available": importlib.util.find_spec("PyInstaller") is not None,
        "no_sdk_smoke": {
            "status": "PASS" if not env.ready else "FAIL",
            "environment_status": env.to_dict()["status"],
            "expected": "Studio reports missing SDK without network fallback or invented paths.",
        },
        "network_policy": network,
        "network_client_imports": network_imports,
        "ux_source_audit": ux,
        "release_scan": release,
        "beta_readiness": beta,
        "qa_harnesses": {
            "qt_visual_qa": (root / "tools" / "qt_visual_qa.py").is_file(),
            "standalone_smoke": (root / "tools" / "standalone_smoke.py").is_file(),
        },
        "not_executed_here": [
            "Windows clean-machine standalone smoke",
            "Linux standalone PyInstaller build when PySide6/PyInstaller are unavailable",
            "real Qt window render when PySide6 is unavailable",
        ],
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if out["phase8_local_qa"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
