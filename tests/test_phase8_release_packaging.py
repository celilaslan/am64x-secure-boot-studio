from __future__ import annotations

import ast
from pathlib import Path

from am64x_secure_toolkit.release_scan import scan_release_tree
from am64x_secure_toolkit.services.environment import resolve_environment
from am64x_secure_toolkit.services.network_policy import runtime_network_policy


def test_release_scan_detects_private_key_without_echoing_secret(tmp_path: Path):
    key = tmp_path / "oops.pem"
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    key.write_text(begin + "\nTHIS_IS_SECRET_MATERIAL_1234567890\n" + end + "\n")
    out = scan_release_tree(tmp_path)
    assert out["status"] == "FAIL"
    assert any(x["kind"] == "private_key_material" for x in out["findings"])
    assert "THIS_IS_SECRET" not in str(out)


def test_release_scan_detects_raw_mek_file_without_reporting_value(tmp_path: Path):
    value = "a1" * 32
    (tmp_path / "application-mek.hex").write_text(value)
    out = scan_release_tree(tmp_path)
    assert out["status"] == "FAIL"
    assert any(x["kind"] == "symmetric_key_material" for x in out["findings"])
    assert value not in str(out)


def test_release_scan_detects_unsanitized_user_path(tmp_path: Path):
    (tmp_path / "report.md").write_text("source=/home/example-user/secret/key.pem\n")
    out = scan_release_tree(tmp_path)
    assert out["status"] == "FAIL"
    assert any(x["kind"] == "user_specific_absolute_path" for x in out["findings"])


def test_runtime_network_policy_is_offline_by_design():
    out = runtime_network_policy().to_dict()
    assert out["status"] == "PASS"
    assert out["runtime_network_required"] is False
    assert out["telemetry_enabled"] is False
    assert out["update_check_enabled"] is False


def test_no_sdk_path_fails_closed_without_inventing_sdk(tmp_path: Path):
    env = resolve_environment(tmp_path / "does-not-exist")
    assert env.ready is False
    data = env.to_dict()
    assert data["status"] == "FAIL"
    assert data["sdk_root"] is None


def test_phase8_gui_sources_are_syntax_valid_and_accessibility_present():
    root = Path(__file__).parents[1]
    gui = root / "src/am64x_secure_toolkit/gui"
    for rel in ["app.py", "main_window.py", "theme.py", "widgets.py", "pages/environment.py", "pages/common.py"]:
        path = gui / rel
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    main = (gui / "main_window.py").read_text(encoding="utf-8")
    assert "setAccessibleName" in main
    assert "QShortcut" in main
    assert "setMinimumSize(1024, 700)" in main
    app = (gui / "app.py").read_text(encoding="utf-8")
    assert "HighDpiScaleFactorRoundingPolicy.PassThrough" in app


def test_packaging_recipes_exist_and_do_not_claim_windows_cross_build():
    root = Path(__file__).parents[1]
    expected = [
        "packaging/pyinstaller/securestudio.spec",
        "packaging/pyinstaller/securestudio_entry.py",
        "packaging/build_linux.sh",
        "packaging/windows/build_windows.ps1",
        "packaging/linux/am64x-secure-boot-studio.desktop",
        "packaging/README.md",
    ]
    for rel in expected:
        assert (root / rel).is_file(), rel
    text = (root / "packaging/README.md").read_text(encoding="utf-8")
    assert "Windows executable'ın Linux üzerinde üretildiği" in text


def test_source_tree_has_no_runtime_http_client_imports():
    root = Path(__file__).parents[1] / "src"
    banned = ("requests", "httpx", "aiohttp", "urllib.request", "ftplib")
    hits = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for mod in banned:
            if f"import {mod}" in text or f"from {mod}" in text:
                hits.append((path.name, mod))
    assert hits == []
