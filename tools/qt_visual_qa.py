from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    root = Path(__file__).resolve().parents[1]
    out_dir = Path(argv[0]).expanduser().resolve() if argv else root / "qt-visual-qa"
    report_path = out_dir / "qt_visual_qa.json"

    if importlib.util.find_spec("PySide6") is None:
        result = {
            "status": "NOT_EXECUTED",
            "reason": "PySide6 is not installed in this environment",
            "automated_render": "NOT_EXECUTED",
            "human_visual_review": "NOT_EXECUTED",
            "note": "Static/source tests are not a substitute for real Qt rendering.",
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 3

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from am64x_secure_toolkit.gui.main_window import MainWindow

    out_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(["securestudio-qt-visual-qa"])
    window = MainWindow()
    window.resize(1440, 900)
    window.show()
    app.processEvents()

    pages: list[dict[str, object]] = []
    failures: list[str] = []
    for key, idx in window.index_by_key.items():
        try:
            window.navigate(key)
            app.processEvents()
            page = window.stack.widget(idx)
            shot = out_dir / f"{idx:02d}_{key}.png"
            pix = page.grab()
            ok = bool(pix.save(str(shot), "PNG"))
            size = shot.stat().st_size if shot.is_file() else 0
            if not ok or size == 0:
                failures.append(key)
            pages.append({"page": key, "screenshot": shot.name, "bytes": size, "saved": ok and size > 0})
        except Exception as exc:
            failures.append(key)
            pages.append({"page": key, "saved": False, "error": f"{type(exc).__name__}: {exc}"})

    window.close()
    app.processEvents()
    result = {
        "status": "PASS" if not failures else "FAIL",
        "operation": "automated_qt_offscreen_render",
        "qt_platform": os.environ.get("QT_QPA_PLATFORM"),
        "page_count": len(pages),
        "pages": pages,
        "failed_pages": failures,
        "automated_render": "PASS" if not failures else "FAIL",
        "human_visual_review": "NOT_EXECUTED",
        "release_gate": "PARTIAL",
        "note": "Offscreen screenshot generation detects render/runtime breakage but does not replace human visual QA on supported desktop hosts.",
    }
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
