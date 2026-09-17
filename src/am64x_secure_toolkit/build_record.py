"""Build kayıt dosyaları için yardımcı işlevler.

Private/symmetric key yolları ve key dosyalarının hash değerleri kaydedilmez.
Public veya secret olmayan girdiler, üretim zincirinin izlenebilmesi için hashlenebilir.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import sys
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .constants import VERIFICATION_SCOPE

_SECRET_FLAGS = {"--key", "--enckey", "--enc-key"}
_REDACTED = "<REDACTED_SECRET_PATH>"


def sha256_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_path(path: str | Path) -> str:
    """Render paths without hardcoding the current user's home directory."""
    text = str(Path(path).expanduser().resolve())
    home = str(Path.home().resolve())
    if text == home:
        return "<HOME>"
    prefix = home + os.sep
    if text.startswith(prefix):
        return "<HOME>" + os.sep + text[len(prefix):]
    return text


def redact_argv(argv: Iterable[str]) -> list[str]:
    """Redact values following known secret-path command-line options."""
    args = [str(x) for x in argv]
    out: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            out.append(_REDACTED)
            redact_next = False
            continue
        out.append(arg)
        if arg in _SECRET_FLAGS:
            redact_next = True
    return out


def redact_text(text: str, secret_values: Iterable[str | Path] = ()) -> str:
    """Remove explicit secret paths and normalize the home directory in logs."""
    out = text
    # Longest first avoids partial replacement when one path prefixes another.
    values = sorted({str(v) for v in secret_values if str(v)}, key=len, reverse=True)
    for value in values:
        out = out.replace(value, _REDACTED)
        try:
            out = out.replace(str(Path(value).expanduser().resolve()), _REDACTED)
        except Exception:
            pass
    home = str(Path.home().resolve())
    out = out.replace(home, "<HOME>")
    return out


def file_identity(path: str | Path, role: str) -> dict[str, Any]:
    p = Path(path)
    return {
        "role": role,
        "path": normalize_path(p),
        "size": p.stat().st_size,
        "sha256": sha256_file(p),
    }


def secret_identity(role: str, supplied: bool) -> dict[str, Any]:
    return {
        "role": role,
        "supplied": supplied,
        "path": _REDACTED if supplied else None,
        "sha256": "NOT_RECORDED" if supplied else None,
        "material_recorded": False,
    }


def write_json(path: str | Path, obj: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def make_build_record(
    *,
    operation: str,
    argv: list[str],
    working_directory: str | Path,
    signing_tool: str | Path,
    non_secret_inputs: list[tuple[str, str | Path]],
    signing_key_supplied: bool,
    encryption_key_supplied: bool,
    exit_code: int | None,
    execution_state: str,
    output_path: str | Path,
    log_path: str | Path | None,
    duration_ms: int | None,
    stream_meta: dict[str, Any] | None = None,
    post_verify: dict[str, Any] | None = None,
    overall_result: str | None = None,
) -> dict[str, Any]:
    out_p = Path(output_path)
    tool_p = Path(signing_tool)
    redacted = [redact_text(arg) for arg in redact_argv(argv)]
    result: dict[str, Any] = {
        "schema": "am64x-secure-toolkit.build-record/v1",
        "toolkit_version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "execution_state": execution_state,
        "working_directory": normalize_path(working_directory),
        "command": {
            "argv": redacted,
            "shell_redacted": shlex.join(redacted),
        },
        "runtime": {
            "python": normalize_path(sys.executable),
            "python_version": platform.python_version(),
        },
        "signing_tool": file_identity(tool_p, "signing_tool"),
        "inputs": [file_identity(path, role) for role, path in non_secret_inputs],
        "secret_inputs": [
            secret_identity("signing_key", signing_key_supplied),
            secret_identity("encryption_key", encryption_key_supplied),
        ],
        "result": {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "output": None,
            "log": None,
            "streams": stream_meta,
            "overall_result": overall_result,
        },
        "post_verify": post_verify,
        "verification_scope": VERIFICATION_SCOPE,
        "note": "Build veya image üretiminin başarılı olması, hardware/customer enforcement kanıtı değildir.",
    }
    if out_p.is_file():
        result["result"]["output"] = file_identity(out_p, "generated_output")
    else:
        result["result"]["output"] = {
            "role": "generated_output",
            "path": normalize_path(out_p),
            "exists": False,
        }
    if log_path is not None:
        lp = Path(log_path)
        if lp.is_file():
            result["result"]["log"] = file_identity(lp, "redacted_build_log")
        else:
            result["result"]["log"] = {
                "role": "redacted_build_log",
                "path": normalize_path(lp),
                "exists": False,
            }
    return result
