from __future__ import annotations

from pathlib import Path
from typing import Any

PAGE_KEYS = (
    "home", "guide", "environment", "project", "application", "rom", "inspector",
    "certificate", "keys", "negative", "sdk", "errata", "provisioning", "revision",
    "boardcfg", "secure_debug", "generic_data", "reports", "source_trace", "learn", "demo", "diagnostics",
)

ACTION_PAGES = {
    "environment", "project", "application", "rom", "inspector", "certificate", "keys",
    "negative", "sdk", "errata", "provisioning", "revision", "boardcfg", "secure_debug",
    "generic_data", "reports", "demo", "diagnostics",
}

FORBIDDEN_GUI_TOKENS = (
    "PROVISION DEVICE",
    "BURN EFUSE",
    'addItems(["sec-ap","tisci","jtag"])',
    "subprocess.run(",
    "subprocess.Popen(",
)


def audit_gui_sources(root: str | Path) -> dict[str, Any]:
    """Run a source-level UX/safety consistency audit.

    This does not replace real Qt render/accessibility QA. It catches contract drift that can
    be evaluated without a PySide6 runtime in the release-build environment.
    """
    base = Path(root)
    pages = base / "src" / "am64x_secure_toolkit" / "gui" / "pages"
    findings: list[dict[str, str]] = []
    checks: list[dict[str, str]] = []

    for key in PAGE_KEYS:
        path = pages / f"{key}.py"
        if not path.is_file():
            findings.append({"severity": "ERROR", "page": key, "issue": "page source missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if 'setObjectName("pageTitle")' not in text:
            findings.append({"severity": "ERROR", "page": key, "issue": "pageTitle contract missing"})
        for token in FORBIDDEN_GUI_TOKENS:
            if token in text:
                findings.append({"severity": "ERROR", "page": key, "issue": f"forbidden GUI token: {token}"})
        if "/home/" in text or "C:\\Users\\" in text:
            findings.append({"severity": "ERROR", "page": key, "issue": "hard-coded user path in GUI source"})
        if key in ACTION_PAGES and "show_guided_error" not in text:
            findings.append({"severity": "WARN", "page": key, "issue": "guided error helper not referenced"})

    contracts = {
        "home_quick_start": "Hızlı Başlangıç" in (pages / "home.py").read_text(encoding="utf-8"),
        "application_project_output": "Proje Önerisini Kullan" in (pages / "application.py").read_text(encoding="utf-8"),
        "rom_project_output": "Project Output Kullan" in (pages / "rom.py").read_text(encoding="utf-8"),
        "project_artifact_index": "Üretilen Dosyalar" in (pages / "project.py").read_text(encoding="utf-8"),
        "project_setup_dashboard_split": "QStackedWidget" in (pages / "project.py").read_text(encoding="utf-8") and "Proje oluşturun veya mevcut projeyi açın" in (pages / "project.py").read_text(encoding="utf-8"),
        "project_recent_no_full_path_display": "p.parent" not in (pages / "project.py").read_text(encoding="utf-8"),
        "keys_project_secret_guard": "Secret-generating key output dizini Project Workspace içinde olamaz" in (pages / "keys.py").read_text(encoding="utf-8"),
        "negative_project_output": "Project Negative-Test" in (pages / "negative.py").read_text(encoding="utf-8"),
        "reports_project_output": "Project Reports Kullan" in (pages / "reports.py").read_text(encoding="utf-8"),
        "project_recent_local_only": "Son Projeler" in (pages / "project.py").read_text(encoding="utf-8"),
        "share_safe_diagnostics": "Share-safe" in (pages / "diagnostics.py").read_text(encoding="utf-8"),
        "certificate_center_manual_subject": (
            "Certificate Center" in (pages / "certificate.py").read_text(encoding="utf-8")
            and all(token in (base / "src" / "am64x_secure_toolkit" / "services" / "certificate_center.py").read_text(encoding="utf-8") for token in ["Country (C)", "Common Name (CN)"])
        ),
        "certificate_center_reissue_not_byte_edit": "Signed certificate byte'larını doğrudan değiştirmek signature'ı bozar" in (pages / "certificate.py").read_text(encoding="utf-8"),
        "certificate_center_context_separation": all(token in (pages / "certificate.py").read_text(encoding="utf-8") for token in ["ROM / RBL Certificate", "Keywriter / Provisioning Certificate", "Generic Data Certificate"]),
        "certificate_center_compare": "Certificate'ları Karşılaştır" in (pages / "certificate.py").read_text(encoding="utf-8"),
    }
    for name, passed in contracts.items():
        checks.append({"check": name, "status": "PASS" if passed else "FAIL"})
        if not passed:
            findings.append({"severity": "ERROR", "page": "contract", "issue": name})

    errors = [x for x in findings if x["severity"] == "ERROR"]
    warnings = [x for x in findings if x["severity"] == "WARN"]
    return {
        "status": "PASS" if not errors else "FAIL",
        "scope": "source-level UX/safety consistency only",
        "page_count": len(PAGE_KEYS),
        "checks": checks,
        "findings": findings,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "real_qt_render_qa": "NOT_EXECUTED_BY_THIS_AUDIT",
    }
