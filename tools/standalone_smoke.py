from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    if not argv:
        print("usage: standalone_smoke.py <securestudio-executable>", file=sys.stderr)
        return 2
    exe = Path(argv[0]).expanduser().resolve()
    if not exe.is_file():
        print(json.dumps({"status": "NOT_EXECUTED", "reason": "executable not found"}, indent=2))
        return 3
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        proc = subprocess.run([str(exe), "--smoke-test"], capture_output=True, text=True, timeout=30, env=env, check=False)
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 2
    result = {
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "returncode": proc.returncode,
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
        "clean_machine_claim": "NOT_ESTABLISHED_BY_THIS_SCRIPT_ALONE",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if proc.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
