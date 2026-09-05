from __future__ import annotations

import json
from pathlib import Path

from am64x_secure_toolkit.services.ux_audit import audit_gui_sources


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = audit_gui_sources(root)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
