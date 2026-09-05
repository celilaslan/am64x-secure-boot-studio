from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

_APP_DIR = "am64x-secure-boot-studio"
_PREF_FILE = "preferences.json"
_ALLOWED_MODES = {"guided", "expert"}
_ALLOWED_LIFECYCLES = {"GP", "HS-FS", "HS-SE"}
_MAX_RECENT = 8


def config_dir() -> Path:
    """Return a local-only config directory without requiring an extra dependency.

    AM64X_STUDIO_CONFIG_HOME exists mainly for tests and controlled deployments.
    This location is *not* a share-safe report location and may contain recent-project
    paths, but never key/MEK paths or secret values.
    """
    override = os.environ.get("AM64X_STUDIO_CONFIG_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "AM64x Secure Boot Studio"
        return Path.home() / "AppData" / "Local" / "AM64x Secure Boot Studio"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else Path.home() / ".config") / _APP_DIR


def preferences_path() -> Path:
    return config_dir() / _PREF_FILE


@dataclass(frozen=True)
class UserPreferences:
    schema: int = 1
    mode: str = "guided"
    device: str = "AM6442"
    silicon_revision: str = "SR2.0"
    lifecycle: str = "HS-FS"
    first_run_complete: bool = False
    recent_projects: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "mode": self.mode,
            "device": self.device,
            "silicon_revision": self.silicon_revision,
            "lifecycle": self.lifecycle,
            "first_run_complete": self.first_run_complete,
            "recent_projects": list(self.recent_projects),
            "local_only": True,
            "secret_values_stored": False,
            "secret_paths_stored": False,
        }


def _validated(data: dict[str, Any] | None) -> UserPreferences:
    data = data if isinstance(data, dict) else {}
    mode = str(data.get("mode") or "guided")
    lifecycle = str(data.get("lifecycle") or "HS-FS")
    recent_raw = data.get("recent_projects") if isinstance(data.get("recent_projects"), list) else []
    recent: list[str] = []
    for value in recent_raw:
        if not isinstance(value, str) or not value.strip():
            continue
        p = str(Path(value).expanduser())
        if p not in recent:
            recent.append(p)
        if len(recent) >= _MAX_RECENT:
            break
    return UserPreferences(
        schema=1,
        mode=mode if mode in _ALLOWED_MODES else "guided",
        device=str(data.get("device") or "AM6442"),
        silicon_revision=str(data.get("silicon_revision") or "SR2.0"),
        lifecycle=lifecycle if lifecycle in _ALLOWED_LIFECYCLES else "HS-FS",
        first_run_complete=bool(data.get("first_run_complete", False)),
        recent_projects=tuple(recent),
    )


def load_preferences(path: str | Path | None = None) -> UserPreferences:
    target = Path(path).expanduser() if path is not None else preferences_path()
    if not target.is_file():
        return UserPreferences()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return UserPreferences()
    return _validated(data)


def save_preferences(preferences: UserPreferences, path: str | Path | None = None) -> Path:
    target = Path(path).expanduser() if path is not None else preferences_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = preferences.to_dict()
    tmp = target.with_suffix(target.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    os.replace(tmp, target)
    if os.name != "nt":
        try:
            target.chmod(0o600)
        except OSError:
            pass
    return target


def with_mode(pref: UserPreferences, mode: str) -> UserPreferences:
    if mode not in _ALLOWED_MODES:
        raise ValueError("mode yalnız guided veya expert olabilir")
    return replace(pref, mode=mode)


def with_context(pref: UserPreferences, *, device: str, silicon_revision: str, lifecycle: str) -> UserPreferences:
    if lifecycle not in _ALLOWED_LIFECYCLES:
        raise ValueError("lifecycle GP, HS-FS veya HS-SE olmalı")
    return replace(pref, device=device, silicon_revision=silicon_revision, lifecycle=lifecycle)


def with_recent_project(pref: UserPreferences, project_root: str | Path) -> UserPreferences:
    root = str(Path(project_root).expanduser().resolve())
    recent = [root, *[x for x in pref.recent_projects if x != root]]
    return replace(pref, recent_projects=tuple(recent[:_MAX_RECENT]), first_run_complete=True)


def forget_recent_project(pref: UserPreferences, project_root: str | Path) -> UserPreferences:
    root = str(Path(project_root).expanduser().resolve())
    return replace(pref, recent_projects=tuple(x for x in pref.recent_projects if x != root))
