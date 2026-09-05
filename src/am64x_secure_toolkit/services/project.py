from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .secret_policy import sanitize_for_record

_PROJECT_DIR = ".am64x-studio"
_PROJECT_FILE = "project.json"
_ACTIVITY_FILE = "activity.jsonl"
_ARTIFACT_FILE = "artifacts.jsonl"
_WORKSPACE_DIRS = ("inputs", "outputs", "public", "negative-tests", "reports", "sessions")


@dataclass(frozen=True)
class ProjectContext:
    root: Path
    name: str
    device: str
    silicon_revision: str
    lifecycle: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "device": self.device,
            "silicon_revision": self.silicon_revision,
            "lifecycle": self.lifecycle,
            "root": str(self.root),
        }


def _metadata_path(root: Path) -> Path:
    return root / _PROJECT_DIR / _PROJECT_FILE


def _activity_path(project: ProjectContext) -> Path:
    return project.root / "sessions" / _ACTIVITY_FILE


def _artifact_path(project: ProjectContext) -> Path:
    return project.root / "sessions" / _ARTIFACT_FILE


def create_project(root: str | Path, *, name: str, device: str = "AM6442", silicon_revision: str = "SR2.0", lifecycle: str = "HS-FS") -> ProjectContext:
    base = Path(root).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    meta = _metadata_path(base)
    if meta.exists():
        raise FileExistsError("bu dizinde zaten AM64x Secure Boot Studio projesi var")
    for child in _WORKSPACE_DIRS:
        (base / child).mkdir(exist_ok=True)
    meta.parent.mkdir(exist_ok=True)
    payload = {
        "schema": 2,
        "name": name,
        "device": device,
        "silicon_revision": silicon_revision,
        "lifecycle": lifecycle,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "secret_paths_stored": False,
        "activity_log_schema": 1,
        "artifact_index_schema": 1,
        "workspace_policy": "project-relative public/generated outputs only; secrets are not persisted",
    }
    meta.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ProjectContext(base, name, device, silicon_revision, lifecycle)


def open_project(root: str | Path) -> ProjectContext:
    base = Path(root).expanduser().resolve()
    meta = _metadata_path(base)
    if not meta.is_file():
        raise FileNotFoundError("AM64x Secure Boot Studio project metadata bulunamadı")
    data = json.loads(meta.read_text(encoding="utf-8"))
    # Existing alpha9 schema-1 workspaces remain readable.
    return ProjectContext(
        root=base,
        name=str(data["name"]),
        device=str(data.get("device", "AM6442")),
        silicon_revision=str(data.get("silicon_revision", "SR2.0")),
        lifecycle=str(data.get("lifecycle", "HS-FS")),
    )


def project_workspace_paths(project: ProjectContext) -> dict[str, Path]:
    return {name: project.root / name for name in _WORKSPACE_DIRS}


def _safe_stem(source: str | Path | None, fallback: str) -> str:
    stem = Path(str(source)).stem if source else fallback
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return stem[:96] or fallback


def suggest_project_output(
    project: ProjectContext,
    *,
    workflow: str,
    source: str | Path | None = None,
    encrypted: bool = False,
) -> Path:
    """Suggest a deterministic non-secret output location inside the project.

    The helper only proposes a path; it never overwrites or moves an existing file.
    """
    paths = project_workspace_paths(project)
    stem = _safe_stem(source, workflow.replace("_", "-"))
    if workflow == "application":
        label = "encrypted_secure_application" if encrypted else "signed_secure_application"
        return paths["outputs"] / f"{stem}_{label}"
    if workflow == "rom":
        return paths["outputs"] / f"{stem}.tiimage"
    if workflow == "report":
        return paths["reports"] / f"{stem}_host_report.md"
    if workflow == "report_json":
        return paths["reports"] / f"{stem}_host_report.json"
    if workflow == "negative":
        return paths["negative-tests"] / f"{stem}_negative"
    if workflow == "public":
        return paths["public"] / f"{stem}.der"
    raise ValueError(f"desteklenmeyen project output workflow: {workflow}")


def path_is_within_project(project: ProjectContext, path: str | Path) -> bool:
    try:
        Path(path).expanduser().resolve().relative_to(project.root.resolve())
        return True
    except (ValueError, OSError, FileNotFoundError):
        return False


def project_safe_reference(project: ProjectContext, path: str | Path | None) -> dict[str, str]:
    """Return a path reference safe for persistent project metadata.

    Paths inside the project are stored project-relative. External paths are reduced to a
    basename so user-specific host directory names are not persisted in the artifact index.
    """
    if not path:
        return {"scope": "none", "path": "—"}
    p = Path(str(path)).expanduser()
    try:
        resolved = p.resolve()
        rel = resolved.relative_to(project.root.resolve())
        return {"scope": "project", "path": rel.as_posix()}
    except (ValueError, OSError, FileNotFoundError):
        return {"scope": "external-name-only", "path": p.name or "—"}


def _event_checks(safe: dict[str, Any]) -> list[dict[str, str]]:
    rows = safe.get("checks")
    if not isinstance(rows, list):
        verification = safe.get("verification") if isinstance(safe.get("verification"), dict) else {}
        rows = verification.get("checks", []) if isinstance(verification, dict) else []
    out: list[dict[str, str]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        out.append({
            "check": str(row.get("check") or "check"),
            "status": str(row.get("status") or "INFO"),
        })
    return out[:40]


def compact_project_event(result: dict[str, Any]) -> dict[str, Any]:
    """Create a persistent, share-safe activity event.

    No source/secret path, secret value, raw certificate blob, or arbitrary technical JSON is
    written to the project activity log. Output files are reduced to basenames.
    """
    safe = sanitize_for_record(result)
    outputs: list[dict[str, str]] = []
    for item in safe.get("outputs", []) if isinstance(safe.get("outputs"), list) else []:
        if not isinstance(item, dict):
            continue
        value = item.get("path") or item.get("file") or item.get("name")
        outputs.append({
            "type": str(item.get("type") or "output"),
            "name": Path(str(value)).name if value else "—",
        })
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "operation": str(safe.get("operation") or safe.get("classification") or "result"),
        "status": str(safe.get("status") or safe.get("overall_host_side_verification") or "INFO"),
        "summary": str(safe.get("summary") or safe.get("note") or "İşlem sonucu kaydedildi."),
        "checks": _event_checks(safe),
        "outputs": outputs[:20],
        "claims": [str(x) for x in safe.get("claims", []) if isinstance(x, (str, int, float))][:20],
        "non_claims": [str(x) for x in safe.get("non_claims", []) if isinstance(x, (str, int, float))][:20],
        "secret_values_stored": False,
        "secret_paths_stored": False,
        "full_host_paths_stored": False,
    }


def record_project_event(project: ProjectContext, result: dict[str, Any]) -> dict[str, Any]:
    event = compact_project_event(result)
    path = _activity_path(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def read_project_events(project: ProjectContext, *, limit: int = 100) -> list[dict[str, Any]]:
    path = _activity_path(project)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows[-max(1, int(limit)):]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compact_project_artifacts(project: ProjectContext, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract non-secret generated artifacts from a workflow result.

    Only top-level workflow outputs are considered. Secret-generating workflows deliberately
    do not expose their private/symmetric files through WorkflowResult.outputs.
    """
    safe = sanitize_for_record(result)
    outputs = safe.get("outputs") if isinstance(safe.get("outputs"), list) else []
    records: list[dict[str, Any]] = []
    for item in outputs:
        if not isinstance(item, dict):
            continue
        value = item.get("path") or item.get("file") or item.get("name")
        if not value:
            continue
        ref = project_safe_reference(project, value)
        p = Path(str(value)).expanduser()
        sha256 = None
        size = None
        if p.is_file():
            try:
                size = p.stat().st_size
                sha256 = _sha256_file(p)
            except OSError:
                pass
        records.append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "operation": str(safe.get("operation") or "result"),
            "type": str(item.get("type") or "output"),
            "reference": ref,
            "size": size,
            "sha256": sha256,
            "status": str(safe.get("status") or safe.get("overall_host_side_verification") or "INFO"),
            "secret_material": False,
            "full_host_path_stored": False,
        })
    return records[:20]


def record_project_artifacts(project: ProjectContext, result: dict[str, Any]) -> list[dict[str, Any]]:
    records = compact_project_artifacts(project, result)
    if not records:
        return []
    path = _artifact_path(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return records


def read_project_artifacts(project: ProjectContext, *, limit: int = 100) -> list[dict[str, Any]]:
    path = _artifact_path(project)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows[-max(1, int(limit)):]


def project_dashboard(project: ProjectContext) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for folder in _WORKSPACE_DIRS:
        base = project.root / folder
        if not base.is_dir():
            counts[folder] = 0
            continue
        counts[folder] = sum(1 for p in base.rglob("*") if p.is_file() and p.name not in {_ACTIVITY_FILE, _ARTIFACT_FILE})
    events = read_project_events(project, limit=100)
    artifacts = read_project_artifacts(project, limit=100)
    return {
        "name": project.name,
        "device": project.device,
        "silicon_revision": project.silicon_revision,
        "lifecycle": project.lifecycle,
        "workspace_counts": counts,
        "activity_count_loaded": len(events),
        "artifact_count_loaded": len(artifacts),
        "last_activity": events[-1] if events else None,
        "last_artifact": artifacts[-1] if artifacts else None,
        "activity_log": "sessions/activity.jsonl",
        "artifact_index": "sessions/artifacts.jsonl",
        "secret_paths_stored": False,
        "full_host_paths_stored": False,
    }
