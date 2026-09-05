from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class OnboardingStep:
    key: str
    title: str
    description: str
    page: str
    state: str  # DONE / CURRENT / OPTIONAL / PENDING


@dataclass(frozen=True)
class OnboardingModel:
    steps: tuple[OnboardingStep, ...]
    recommended_page: str
    recommended_title: str
    ready_for_first_workflow: bool
    summary: str

    def to_dict(self) -> dict:
        return {
            "steps": [asdict(step) for step in self.steps],
            "recommended_page": self.recommended_page,
            "recommended_title": self.recommended_title,
            "ready_for_first_workflow": self.ready_for_first_workflow,
            "summary": self.summary,
        }


def onboarding_model(*, environment_checked: bool, environment_ready: bool, project_active: bool, has_result: bool) -> OnboardingModel:
    """Return a beginner-safe quick-start model without inventing target state.

    Project Workspace is recommended because it keeps outputs/reports organized and
    provides persistent share-safe history, but it is not a technical requirement for
    read-only inspection or a one-off host-side workflow.
    """
    env_state = "DONE" if environment_ready else "CURRENT"
    project_state = "DONE" if project_active else ("CURRENT" if environment_ready else "PENDING")
    workflow_state = "DONE" if has_result else ("CURRENT" if environment_ready and project_active else "PENDING")

    steps = (
        OnboardingStep(
            "environment",
            "1. Environment kontrolü",
            "MCU+ SDK, installed TI signer araçları, Python ve host bağımlılıklarını kontrol eder.",
            "environment",
            env_state,
        ),
        OnboardingStep(
            "project",
            "2. Project Workspace",
            "Output, report, negative-test ve share-safe session history için kontrollü çalışma dizini kullanır.",
            "project",
            project_state,
        ),
        OnboardingStep(
            "workflow",
            "3. İlk işlemi başlatın",
            "Ne yapacağınızdan emin değilseniz Bana Yol Göster ile doğru workflow'a geçin.",
            "guide",
            workflow_state,
        ),
    )

    if not environment_ready:
        recommended_page = "environment"
        title = "Environment kontrolünü aç"
        summary = (
            "Build işlemine geçmeden önce host ve SDK durumunu kontrol edin. "
            + ("Environment kontrol edildi ancak henüz hazır değil." if environment_checked else "Environment henüz kontrol edilmedi.")
        )
    elif not project_active:
        recommended_page = "project"
        title = "Project Workspace oluştur"
        summary = "Environment hazır. Çıktıları ve raporları düzenli tutmak için bir Project Workspace oluşturabilirsiniz."
    elif not has_result:
        recommended_page = "guide"
        title = "İlk işlemi seç"
        summary = "Environment ve Project hazır. Şimdi yapmak istediğiniz işlemi seçebilirsiniz."
    else:
        recommended_page = "guide"
        title = "Yeni işlem seç"
        summary = "Başlangıç adımları tamamlandı. Yeni bir işlem seçerek devam edebilirsiniz."

    return OnboardingModel(
        steps=steps,
        recommended_page=recommended_page,
        recommended_title=title,
        ready_for_first_workflow=environment_ready,
        summary=summary,
    )
