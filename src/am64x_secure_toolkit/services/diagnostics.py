from __future__ import annotations

import importlib.util
import json
import platform
from pathlib import Path
from typing import Any

from .. import __version__
from .beta_readiness import beta_readiness
from .environment import EnvironmentResolution, resolve_environment
from .network_policy import runtime_network_policy
from .project import ProjectContext, project_dashboard


def _dependency(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def diagnostics_snapshot(
    *,
    environment: EnvironmentResolution | None = None,
    project: ProjectContext | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    env = environment or resolve_environment(None)
    env_public = {
        "ready": env.ready,
        "sdk_version": env.sdk_version,
        "compatibility": env.compatibility,
        "app_signer_found": env.app_signing_tool is not None,
        "rom_signer_found": env.rom_signing_tool is not None,
        "devconfig_found": env.devconfig is not None,
        "openssl_found": env.openssl_path is not None,
        "openssl_version": env.openssl_version,
        "paths_included": False,
    }
    project_public = None
    if project is not None:
        dash = project_dashboard(project)
        project_public = {
            "name": dash["name"],
            "device": dash["device"],
            "silicon_revision": dash["silicon_revision"],
            "lifecycle": dash["lifecycle"],
            "workspace_counts": dash["workspace_counts"],
            "activity_count_loaded": dash["activity_count_loaded"],
            "artifact_count_loaded": dash["artifact_count_loaded"],
            "project_root_included": False,
        }
    return {
        "status": "PASS",
        "operation": "share_safe_diagnostics",
        "toolkit": {"version": __version__},
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "hostname_included": False,
            "username_included": False,
        },
        "dependencies": {
            "cryptography": _dependency("cryptography"),
            "asn1crypto": _dependency("asn1crypto"),
            "yaml": _dependency("yaml"),
            "PySide6": _dependency("PySide6"),
            "PyInstaller": _dependency("PyInstaller"),
        },
        "environment": env_public,
        "project": project_public,
        "network_policy": runtime_network_policy().to_dict(),
        "beta_readiness": beta_readiness(source_root),
        "privacy": {
            "secret_values_included": False,
            "secret_hashes_included": False,
            "secret_paths_included": False,
            "full_host_paths_included": False,
        },
    }


def diagnostics_markdown(snapshot: dict[str, Any]) -> str:
    rt = snapshot.get("runtime", {})
    env = snapshot.get("environment", {})
    deps = snapshot.get("dependencies", {})
    beta = snapshot.get("beta_readiness", {})
    lines = [
        "# AM64x Secure Boot Studio — Share-safe Diagnostics",
        "",
        f"- Toolkit: `{snapshot.get('toolkit', {}).get('version', '?')}`",
        f"- Python: `{rt.get('python', '?')}`",
        f"- OS: `{rt.get('os', '?')} {rt.get('os_release', '')}`",
        f"- Machine: `{rt.get('machine', '?')}`",
        "",
        "## Environment",
        "",
        f"- SDK version: `{env.get('sdk_version') or 'not resolved'}`",
        f"- Compatibility: `{env.get('compatibility', '?')}`",
        f"- Application signer found: `{env.get('app_signer_found')}`",
        f"- ROM signer found: `{env.get('rom_signer_found')}`",
        f"- OpenSSL: `{env.get('openssl_version') or 'not found'}`",
        "",
        "## Dependencies",
        "",
    ]
    lines.extend(f"- {name}: `{'YES' if present else 'NO'}`" for name, present in deps.items())
    lines.extend([
        "",
        "## Beta readiness",
        "",
        f"- Local QA: `{beta.get('local_qa', '?')}`",
        f"- Release readiness: `{beta.get('status', '?')}`",
        f"- Real Qt render: `{beta.get('real_qt_render', '?')}`",
        f"- Linux clean-machine: `{beta.get('linux_clean_machine', '?')}`",
        f"- Windows clean-machine: `{beta.get('windows_clean_machine', '?')}`",
        "",
        "## Privacy",
        "",
        "- Secret values: **NOT INCLUDED**",
        "- Secret hashes: **NOT INCLUDED**",
        "- Secret paths: **NOT INCLUDED**",
        "- Full host paths / username / hostname: **NOT INCLUDED**",
        "",
    ])
    return "\n".join(lines)


def write_diagnostics(snapshot: dict[str, Any], output: str | Path) -> Path:
    path = Path(output).expanduser()
    if path.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".md":
        path.write_text(diagnostics_markdown(snapshot), encoding="utf-8")
    else:
        path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
