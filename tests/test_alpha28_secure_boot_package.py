from pathlib import Path
from types import SimpleNamespace

import pytest

from am64x_secure_toolkit.services.ccs_sbl_build import (
    classify_sbl_artifact,
    run_mcu_plus_sbl_build,
)
from am64x_secure_toolkit.services.secure_boot_profile import assess_secure_boot_profile
from am64x_secure_toolkit.services.secure_boot_package import build_secure_boot_package
from am64x_secure_toolkit.services.uart_flash import (
    create_uart_flash_plan,
    execute_uart_flash_plan,
)


def test_physical_lifecycle_and_build_target_are_not_conflated():
    profile = assess_secure_boot_profile(
        physical_lifecycle="HS-FS", target_lifecycle="HS-SE",
        customer_root_state="provisioned", has_customer_signing_key=True,
    )
    assert profile.device_type == "HS"
    assert profile.output_family == ".hs"
    assert profile.offline_only is True
    assert profile.flash_allowed is False
    assert "çevrimdışı" in profile.warnings[0]


def test_hs_se_requires_customer_key_and_root_before_flash():
    missing_key = assess_secure_boot_profile(
        physical_lifecycle="HS-SE", target_lifecycle="HS-SE",
        customer_root_state="provisioned", has_customer_signing_key=False,
    )
    assert missing_key.blockers and not missing_key.flash_allowed
    unknown_root = assess_secure_boot_profile(
        physical_lifecycle="HS-SE", target_lifecycle="HS-SE",
        customer_root_state="unknown", has_customer_signing_key=True,
    )
    assert not unknown_root.flash_allowed
    ready = assess_secure_boot_profile(
        physical_lifecycle="HS-SE", target_lifecycle="HS-SE",
        customer_root_state="hardware_verified", has_customer_signing_key=True,
    )
    assert ready.flash_allowed


def test_encryption_requires_both_signing_key_and_mek():
    profile = assess_secure_boot_profile(
        physical_lifecycle="HS-FS", target_lifecycle="HS-FS",
        encrypted=True, has_customer_signing_key=False, has_encryption_key=True,
    )
    assert any("private signing key" in item for item in profile.blockers)


def test_sbl_artifact_lifecycle_classification():
    assert classify_sbl_artifact("sbl_ospi.release.hs_fs.tiimage") == "signed_hs_fs"
    assert classify_sbl_artifact("sbl_ospi.release.hs.tiimage") == "signed_hs"
    assert classify_sbl_artifact("tiboot3.bin") == "deployable_tiboot3"


def test_sbl_build_runs_fixed_project_recipe_and_finds_output(tmp_path: Path, monkeypatch):
    project = tmp_path / "sbl_ospi"
    build = project / "Debug"
    build.mkdir(parents=True)
    (build / "makefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
    (build / "sbl_ospi.out").write_bytes(b"elf")
    (project / "makefile_ccs_bootimage_gen").write_text("all:\n", encoding="utf-8")
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    sdk.mkdir()
    make = tmp_path / "make.exe"
    make.write_text("fake", encoding="utf-8")
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if "-f" in command:
            (build / "sbl_ospi.release.hs_fs.tiimage").write_bytes(b"boot")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("am64x_secure_toolkit.services.ccs_sbl_build.subprocess.run", fake_run)
    result = run_mcu_plus_sbl_build(
        project, lifecycle="HS-FS", sdk_root=sdk, make_executable=make
    )
    assert result["status"] == "PASS"
    assert len(calls) == 2
    assert "DEVICE_TYPE=GP" in calls[1]
    assert result["output"]["name"].endswith(".hs_fs.tiimage")
    assert result["global_devconfig_modified"] is False


def _fake_sdk(tmp_path: Path, lifecycle: str = "hs_fs") -> Path:
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    boot = sdk / "tools" / "boot"
    images = boot / "sbl_prebuilt" / "am64x-evm"
    images.mkdir(parents=True)
    (boot / "uart_uniflash.py").write_text("# tool", encoding="utf-8")
    writer = images / f"sbl_uart_uniflash.release.{lifecycle}.tiimage"
    sbl = images / f"sbl_ospi.release.{lifecycle}.tiimage"
    app = images / f"example.appimage.{lifecycle}"
    writer.write_bytes(b"writer")
    sbl.write_bytes(b"boot")
    app.write_bytes(b"app")
    cfg = boot / f"default_sbl_ospi_{lifecycle}.cfg"
    cfg.write_text(
        f"--flash-writer=sbl_prebuilt/am64x-evm/{writer.name}\n"
        f"--file=sbl_prebuilt/am64x-evm/{sbl.name} --operation=flash --flash-offset=0x0\n"
        f"--file=sbl_prebuilt/am64x-evm/{app.name} --operation=flash --flash-offset=0x80000\n",
        encoding="utf-8",
    )
    return sdk


def test_flash_plan_uses_offsets_from_sdk_config_and_requires_matching_lifecycle(tmp_path: Path):
    sdk = _fake_sdk(tmp_path)
    app = tmp_path / "hello.appimage.hs_fs"
    app.write_bytes(b"signed")
    plan = create_uart_flash_plan(
        sdk_root=sdk, serial_port="com7", physical_lifecycle="HS-FS",
        target_lifecycle="HS-FS", customer_root_state="unknown",
        application_image=app,
    )
    assert plan.serial_port == "COM7"
    assert plan.application_offset == "0x80000"
    assert "0x80000" in plan.generated_config
    assert plan.otp_efuse_write is False

    with pytest.raises(PermissionError, match="Karta yazma kapalı"):
        create_uart_flash_plan(
            sdk_root=sdk, serial_port="COM7", physical_lifecycle="HS-SE",
            target_lifecycle="HS-FS", customer_root_state="unknown",
            application_image=app,
        )


def test_flash_execution_needs_explicit_confirmation(tmp_path: Path):
    sdk = _fake_sdk(tmp_path)
    app = tmp_path / "hello.appimage.hs_fs"
    app.write_bytes(b"signed")
    plan = create_uart_flash_plan(
        sdk_root=sdk, serial_port="COM3", physical_lifecycle="HS-FS",
        target_lifecycle="HS-FS", customer_root_state="unknown", application_image=app,
    )
    with pytest.raises(PermissionError, match="açık kullanıcı onayı"):
        execute_uart_flash_plan(plan)


def test_package_orchestrates_application_verify_and_optional_sbl(tmp_path: Path, monkeypatch):
    app_path = tmp_path / "hello.appimage.hs_fs"
    boot_path = tmp_path / "sbl.release.hs_fs.tiimage"
    app_path.write_bytes(b"app")
    boot_path.write_bytes(b"boot")
    monkeypatch.setattr(
        "am64x_secure_toolkit.services.secure_boot_package.run_mcu_plus_secure_build",
        lambda *_args, **_kwargs: {
            "status": "PASS", "output": {"path": str(app_path), "name": app_path.name},
            "outputs": [{"type": "application_image", "path": str(app_path)}],
        },
    )
    monkeypatch.setattr(
        "am64x_secure_toolkit.services.secure_boot_package.run_mcu_plus_sbl_build",
        lambda *_args, **_kwargs: {
            "status": "PASS", "output": {"path": str(boot_path), "name": boot_path.name},
            "outputs": [{"type": "boot_image", "path": str(boot_path)}],
        },
    )
    monkeypatch.setattr(
        "am64x_secure_toolkit.services.secure_boot_package.inspect_and_verify",
        lambda *_args, **_kwargs: SimpleNamespace(to_dict=lambda: {"status": "PASS"}),
    )
    result = build_secure_boot_package(
        application_project=tmp_path, sbl_project=tmp_path, sdk_root=tmp_path,
        physical_lifecycle="HS-FS", target_lifecycle="HS-FS",
    )
    assert result["status"] == "PASS"
    assert result["scope"] == "application_and_boot"
    assert result["application_verification"]["status"] == "PASS"
    assert {item["type"] for item in result["outputs"]} == {"application_image", "boot_image"}


def test_confirmed_flash_reports_command_success_but_not_boot_acceptance(tmp_path: Path, monkeypatch):
    sdk = _fake_sdk(tmp_path)
    app = tmp_path / "hello.appimage.hs_fs"
    app.write_bytes(b"signed")
    plan = create_uart_flash_plan(
        sdk_root=sdk, serial_port="COM3", physical_lifecycle="HS-FS",
        target_lifecycle="HS-FS", customer_root_state="unknown", application_image=app,
    )
    monkeypatch.setattr(
        "am64x_secure_toolkit.services.uart_flash.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="Success", stderr=""),
    )
    result = execute_uart_flash_plan(plan, confirm_hardware_write=True)
    assert result["status"] == "PASS"
    assert result["otp_efuse_write"] is False
    assert "tek başına kanıtlamaz" in result["non_claims"][0]
    assert result["checks"][-1]["status"] == "NOT_CHECKED"


def test_unified_page_is_guided_scrollable_and_exposes_real_boot_boundary():
    root = Path(__file__).resolve().parents[1]
    main = (root / "src/am64x_secure_toolkit/gui/main_window.py").read_text(encoding="utf-8")
    page = (root / "src/am64x_secure_toolkit/gui/pages/secure_boot.py").read_text(encoding="utf-8")
    ui = (root / "src/am64x_secure_toolkit/services/ui_contract.py").read_text(encoding="utf-8")
    assert '("secure_boot", "Secure Boot Paketi"' in main
    assert '"secure_boot"' in ui
    assert "QScrollArea" in page
    assert "CCS Debug/Run gerçek secure boot kanıtı değildir" in page
    assert "OTP/eFuse yazmaz" in page
    assert "execute_uart_flash_plan" in page
