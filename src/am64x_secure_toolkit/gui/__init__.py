"""AM64x Secure Boot Studio PySide6 GUI facade.

Importing this module does not require PySide6; only launch_gui() does.
"""
from __future__ import annotations

import importlib.util
import json
from typing import Any


def _result_text(obj: dict[str, Any]) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False)


def gui_available() -> bool:
    return importlib.util.find_spec("PySide6") is not None


def launch_gui() -> int:
    if not gui_available():
        raise RuntimeError("PySide6 kurulu değil. GUI için 'pip install am64x-secure-toolkit[gui]' kullanın; CLI çalışmaya devam eder.")
    from .app import run
    return run()


def main() -> int:
    import sys
    try:
        return launch_gui()
    except RuntimeError as exc:
        print(f"HATA: {exc}", file=sys.stderr)
        return 2
