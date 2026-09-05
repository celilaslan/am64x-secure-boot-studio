from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

_PRIVATE_BLOCK = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_USER_PATHS = [
    re.compile(r"(?<!<)\/home\/[A-Za-z0-9._-]+\/"),
    re.compile(r"(?<!<)\/Users\/[A-Za-z0-9._-]+\/"),
    re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\"),
]
_SECRET_NAME = re.compile(r"(?:^|[._-])(mek|smek|bmek|enckey|encryption[-_]?key)(?:[._-]|$)", re.I)
_HEX64 = re.compile(rb"\A[0-9a-fA-F]{64}(?:\r?\n)?\Z")
_JSON_SECRET_KEYS = re.compile(r"(?:private[_-]?key|mek|smek|bmek|seed|passphrase|password|secret)", re.I)
_TEXT_EXTENSIONS = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".log", ".csv", ".ps1", ".sh", ".desktop"
}
_SKIP_DIRS = {".git", ".pytest_cache", "__pycache__", ".venv", "venv", "build"}


@dataclass(frozen=True)
class Finding:
    kind: str
    relative_path: str
    detail: str


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _scan_json(path: Path, rel: str, findings: list[Finding]) -> None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return

    def walk(value, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                child_prefix = f"{prefix}.{key_text}" if prefix else key_text
                if _JSON_SECRET_KEYS.search(key_text) and isinstance(child, str) and child.strip():
                    # Explicit safety/status labels are allowed. Secret-looking values are not.
                    allowed = child.strip().upper() in {
                        "NO", "NONE", "NOT_STORED", "NOT_RECORDED", "REDACTED", "MASKED", "NOT_APPLICABLE",
                        "SYNTHETIC", "NON-PRODUCTION", "UNPROVISIONED", "OFFLINE-ONLY",
                    }
                    if not allowed:
                        findings.append(Finding("secret_like_json_value", rel, f"non-empty value at key {child_prefix}"))
                walk(child, child_prefix)
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, f"{prefix}[{idx}]")

    walk(obj)


def scan_release_tree(root: str | Path) -> dict:
    """Scan a release/workspace tree for accidental secret material and user-specific paths.

    This is a conservative release-hygiene check, not a cryptographic proof that no secret
    exists. It intentionally avoids hashing or echoing any matched secret value.
    """
    root = Path(root).resolve()
    findings: list[Finding] = []
    scanned = 0

    if not root.exists():
        return {
            "status": "FAIL",
            "operation": "release_secret_path_scan",
            "root": str(root),
            "scanned_files": 0,
            "findings": [{"kind": "missing_root", "relative_path": ".", "detail": "scan root does not exist"}],
            "note": "No secret content is echoed by this scanner.",
        }

    for path in _iter_files(root):
        scanned += 1
        rel = path.relative_to(root).as_posix()
        try:
            data = path.read_bytes()
        except OSError:
            findings.append(Finding("unreadable_file", rel, "file could not be read"))
            continue

        # Real private-key blocks only. Source code containing marker strings is not a finding.
        if _PRIVATE_BLOCK.search(data):
            findings.append(Finding("private_key_material", rel, "private-key PEM/OpenSSH block detected"))

        # Exact raw 256-bit hex key in a secret-looking file name.
        if _SECRET_NAME.search(path.name) and _HEX64.fullmatch(data):
            findings.append(Finding("symmetric_key_material", rel, "64-hex secret-like file detected"))

        if path.suffix.lower() in _TEXT_EXTENSIONS or path.name in {"README", "LICENSE"}:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if text:
                for regex in _USER_PATHS:
                    if regex.search(text):
                        findings.append(Finding("user_specific_absolute_path", rel, "unsanitized user-home path detected"))
                        break
                if path.suffix.lower() == ".json":
                    _scan_json(path, rel, findings)

    return {
        "status": "PASS" if not findings else "FAIL",
        "operation": "release_secret_path_scan",
        "root": "<RELEASE_ROOT>",
        "scanned_files": scanned,
        "findings": [asdict(item) for item in findings],
        "limitations": [
            "Pattern-based release hygiene scan; not proof that arbitrary encoded secrets are absent.",
            "Secret values and secret hashes are never included in findings.",
        ],
    }
