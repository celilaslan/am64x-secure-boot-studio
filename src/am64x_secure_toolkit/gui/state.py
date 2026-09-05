from __future__ import annotations

from typing import Any

from PySide6.QtCore import QObject, Signal

from ..services.environment import EnvironmentResolution
from ..services.project import (
    ProjectContext, read_project_artifacts, read_project_events,
    record_project_artifacts, record_project_event,
)
from ..services.secret_policy import sanitize_for_record
from ..services.preferences import (
    UserPreferences, load_preferences, save_preferences, with_context, with_mode, with_recent_project,
)


class AppState(QObject):
    changed = Signal()
    mode_changed = Signal(str)
    result_changed = Signal(object)
    history_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        try:
            self.preferences = load_preferences()
        except Exception:
            self.preferences = UserPreferences()
        self.environment: EnvironmentResolution | None = None
        self.project: ProjectContext | None = None
        self.device = self.preferences.device
        self.silicon_revision = self.preferences.silicon_revision
        self.lifecycle = self.preferences.lifecycle
        self.mode = self.preferences.mode
        self.last_result: dict[str, Any] | None = None
        self.result_history: list[dict[str, Any]] = []
        self.project_history: list[dict[str, Any]] = []
        self.project_artifacts: list[dict[str, Any]] = []
        self.project_history_error: str | None = None

    def set_mode(self, mode: str) -> None:
        if mode not in {"guided", "expert"}:
            raise ValueError("mode yalnız guided veya expert olabilir")
        if self.mode == mode:
            return
        self.mode = mode
        self.preferences = with_mode(self.preferences, mode)
        self._save_preferences_best_effort()
        self.mode_changed.emit(mode)
        self.changed.emit()

    def set_environment(self, env: EnvironmentResolution) -> None:
        self.environment = env
        self.changed.emit()

    def set_project(self, project: ProjectContext) -> None:
        self.project = project
        self.device = project.device
        self.silicon_revision = project.silicon_revision
        self.lifecycle = project.lifecycle
        self.preferences = with_context(
            self.preferences, device=self.device, silicon_revision=self.silicon_revision, lifecycle=self.lifecycle
        )
        self.preferences = with_recent_project(self.preferences, project.root)
        self._save_preferences_best_effort()
        self.project_history_error = None
        try:
            self.project_history = read_project_events(project, limit=100)
            self.project_artifacts = read_project_artifacts(project, limit=100)
        except Exception as exc:  # logging/history must not break the active workflow
            self.project_history = []
            self.project_artifacts = []
            self.project_history_error = f"{type(exc).__name__}: {exc}"
        self.history_changed.emit()
        self.changed.emit()

    def set_context(self, *, device: str, silicon_revision: str, lifecycle: str) -> None:
        self.device = device
        self.silicon_revision = silicon_revision
        self.lifecycle = lifecycle
        self.preferences = with_context(
            self.preferences, device=device, silicon_revision=silicon_revision, lifecycle=lifecycle
        )
        self._save_preferences_best_effort()
        self.changed.emit()

    def _save_preferences_best_effort(self) -> None:
        try:
            save_preferences(self.preferences)
        except Exception:
            # Local convenience state must never break a security workflow.
            pass

    def set_last_result(self, result: dict[str, Any]) -> None:
        self.last_result = result
        # In-memory history is share-safe but intentionally transient.
        safe = sanitize_for_record(result)
        self.result_history.append(safe)
        if len(self.result_history) > 50:
            self.result_history = self.result_history[-50:]

        # When a Project Workspace is active, persist only a compact safe activity event.
        self.project_history_error = None
        if self.project is not None:
            try:
                event = record_project_event(self.project, result)
                artifacts = record_project_artifacts(self.project, result)
                self.project_history.append(event)
                self.project_artifacts.extend(artifacts)
                if len(self.project_history) > 100:
                    self.project_history = self.project_history[-100:]
                if len(self.project_artifacts) > 100:
                    self.project_artifacts = self.project_artifacts[-100:]
            except Exception as exc:
                self.project_history_error = f"{type(exc).__name__}: {exc}"

        self.result_changed.emit(result)
        self.history_changed.emit()
