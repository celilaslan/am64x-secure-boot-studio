from __future__ import annotations

from typing import Any

from PySide6.QtCore import QObject, Signal

from ..services.environment import EnvironmentResolution, resolve_environment
from ..services.project import (
    ProjectContext, read_project_artifacts, read_project_events,
    record_project_artifacts, record_project_event,
)
from ..services.secret_policy import sanitize_for_record
from ..services.preferences import (
    UserPreferences, load_preferences, save_preferences, with_context, with_mode, with_recent_project, with_sdk_root,
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
        # Build target is deliberately separate from the physical board lifecycle.
        # It is transient: changing a packaging target must not rewrite project/device truth.
        self.build_target_lifecycle = self.lifecycle if self.lifecycle in {"HS-FS", "HS-SE"} else "HS-FS"
        self.customer_root_state = "unknown"
        # Certificate Center can hand an identity to Secure Boot without writing
        # private-key paths into project history or user preferences.
        self.signing_certificate_path: str | None = None
        self.signing_private_key_path: str | None = None
        self.mode = self.preferences.mode
        self.last_result: dict[str, Any] | None = None
        self.result_history: list[dict[str, Any]] = []
        self.project_history: list[dict[str, Any]] = []
        self.project_artifacts: list[dict[str, Any]] = []
        self.project_history_error: str | None = None
        # Resolve the remembered SDK (or standard local TI installation) at startup.
        # Failure is non-fatal; SDK-independent inspection tools remain available.
        try:
            discovered = resolve_environment(self.preferences.sdk_root)
            if discovered.sdk_root is not None:
                self.environment = discovered
        except Exception:
            pass

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
        if env.sdk_root is not None:
            self.preferences = with_sdk_root(self.preferences, env.sdk_root)
            self._save_preferences_best_effort()
        self.changed.emit()

    def set_project(self, project: ProjectContext) -> None:
        self.project = project
        self.device = project.device
        self.silicon_revision = project.silicon_revision
        self.lifecycle = project.lifecycle
        self.build_target_lifecycle = self.lifecycle if self.lifecycle in {"HS-FS", "HS-SE"} else "HS-FS"
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

    def set_build_target_lifecycle(self, lifecycle: str) -> None:
        if lifecycle not in {"HS-FS", "HS-SE"}:
            raise ValueError("üretim hedefi yalnız HS-FS veya HS-SE olabilir")
        if self.build_target_lifecycle == lifecycle:
            return
        self.build_target_lifecycle = lifecycle
        self.changed.emit()

    def set_customer_root_state(self, root_state: str) -> None:
        if root_state not in {"unknown", "not_provisioned", "provisioned", "hardware_verified"}:
            raise ValueError("geçersiz Customer Root of Trust durumu")
        if self.customer_root_state == root_state:
            return
        self.customer_root_state = root_state
        self.changed.emit()

    def set_signing_identity(
        self,
        *,
        certificate_path: str | None,
        private_key_path: str | None,
    ) -> None:
        """Keep the active signing identity in memory for this Studio session."""
        certificate = certificate_path.strip() if certificate_path else None
        private_key = private_key_path.strip() if private_key_path else None
        if (
            self.signing_certificate_path == certificate
            and self.signing_private_key_path == private_key
        ):
            return
        self.signing_certificate_path = certificate
        self.signing_private_key_path = private_key
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
