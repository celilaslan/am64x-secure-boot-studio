from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .secret_policy import sanitize_for_record


class SessionRecorder:
    def __init__(self, session_file: str | Path) -> None:
        self.path = Path(session_file).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: dict[str, Any]) -> None:
        safe = sanitize_for_record(event)
        row = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            **safe,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
