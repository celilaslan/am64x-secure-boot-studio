"""Render Secure Boot Studio pages offscreen and save them as PNG screenshots.

This captures the full application window (navigation, device context bar and the
applied theme) so the images match what a user sees on a real desktop. It is a
documentation/QA helper: offscreen rendering proves the pages construct and paint
without errors, but it does not replace human visual QA on a supported desktop host.

Usage:
    python tools/capture_screenshots.py [OUTPUT_DIR] [--pages home,secure_boot,...]
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

# Pages used in the README/documentation gallery, in presentation order.
DEFAULT_PAGES = (
    "home",
    "secure_boot",
    "certificate",
    "inspector",
    "keys",
    "learn",
)

WINDOW_SIZE = (1440, 900)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])

    requested: tuple[str, ...] = DEFAULT_PAGES
    if "--pages" in argv:
        i = argv.index("--pages")
        if i + 1 >= len(argv):
            print("error: --pages requires a comma-separated page list", file=sys.stderr)
            return 2
        requested = tuple(p.strip() for p in argv[i + 1].split(",") if p.strip())
        del argv[i : i + 2]
    if "--all" in argv:
        argv.remove("--all")
        requested = ()

    root = Path(__file__).resolve().parents[1]
    out_dir = Path(argv[0]).expanduser().resolve() if argv else root / "docs" / "images"

    if importlib.util.find_spec("PySide6") is None:
        print(
            json.dumps(
                {
                    "status": "NOT_EXECUTED",
                    "reason": "PySide6 is not installed in this environment",
                    "hint": "pip install -e '.[gui]'",
                },
                indent=2,
            )
        )
        return 3

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from am64x_secure_toolkit.gui.main_window import MainWindow
    from am64x_secure_toolkit.gui.theme import apply_application_theme

    out_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(["securestudio-screenshots"])
    apply_application_theme(app)

    window = MainWindow()
    window.resize(*WINDOW_SIZE)
    window.show()
    app.processEvents()

    pages = requested or tuple(window.index_by_key)
    unknown = [key for key in pages if key not in window.index_by_key]
    if unknown:
        print(f"error: unknown page key(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"available: {', '.join(window.index_by_key)}", file=sys.stderr)
        return 2

    saved: list[dict[str, object]] = []
    failures: list[str] = []
    for key in pages:
        try:
            window.navigate(key)
            app.processEvents()
            shot = out_dir / f"{key}.png"
            ok = bool(window.grab().save(str(shot), "PNG"))
            size = shot.stat().st_size if shot.is_file() else 0
            if not ok or size == 0:
                failures.append(key)
            saved.append({"page": key, "file": shot.name, "bytes": size, "saved": ok and size > 0})
        except Exception as exc:  # pragma: no cover - defensive, reported in the result
            failures.append(key)
            saved.append({"page": key, "saved": False, "error": f"{type(exc).__name__}: {exc}"})

    window.close()
    app.processEvents()

    print(
        json.dumps(
            {
                "status": "PASS" if not failures else "FAIL",
                "output_dir": str(out_dir),
                "window_size": list(WINDOW_SIZE),
                "screenshots": saved,
                "failed_pages": failures,
                "human_visual_review": "NOT_EXECUTED",
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
