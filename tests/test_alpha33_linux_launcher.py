from pathlib import Path


def test_linux_launcher_needs_no_sudo_git_or_manual_activation():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "studio.sh").read_text(encoding="utf-8")
    assert launcher.startswith("#!/usr/bin/env bash")
    assert "\nsudo " not in launcher.lower()
    assert "git " not in launcher.lower()
    assert "source " not in launcher.lower()
    assert "${XDG_CACHE_HOME" in launcher
    assert 'pip install -e "${STUDIO_ROOT}[gui]"' in launcher
    assert "from am64x_secure_toolkit.gui import main" in launcher
