from pathlib import Path
from types import SimpleNamespace

import pytest

from am64x_secure_toolkit.services.ccs_secure_build import (
    find_mcu_plus_make_directory,
    lifecycle_build_configuration,
    run_mcu_plus_secure_build,
)


def test_hs_fs_maps_to_gp_sdk_recipe_and_default_development_key():
    config = lifecycle_build_configuration("HS-FS")
    assert config["device_type"] == "GP"
    assert config["uses_sdk_development_key"] is True
    assert config["expected_kind"] == "signed_hs_fs"


def test_hs_se_requires_customer_key_and_maps_to_hs_recipe(tmp_path: Path):
    with pytest.raises(ValueError, match="Customer Root of Trust"):
        lifecycle_build_configuration("HS-SE")
    key = tmp_path / "customer.pem"
    key.write_text("test", encoding="utf-8")
    config = lifecycle_build_configuration("HS-SE", signing_key=key)
    assert config["device_type"] == "HS"
    assert config["expected_kind"] == "signed_hs"


def test_encryption_cannot_be_requested_without_signing_key(tmp_path: Path):
    mek = tmp_path / "mek.txt"
    mek.write_text("00", encoding="utf-8")
    with pytest.raises(ValueError, match="signing key"):
        lifecycle_build_configuration("HS-FS", encryption_key=mek)


def test_make_directory_is_discovered_below_ccs_project(tmp_path: Path):
    build = tmp_path / "Release"
    build.mkdir()
    (build / "makefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
    assert find_mcu_plus_make_directory(tmp_path) == build


def test_dry_run_does_not_modify_devconfig_or_persist_secret_path(tmp_path: Path):
    build = tmp_path / "Debug"
    build.mkdir()
    (build / "makefile").write_text("all:\n\t@echo ok\n", encoding="utf-8")
    fake_make = tmp_path / "gmake.exe"
    fake_make.write_text("placeholder", encoding="utf-8")
    key = tmp_path / "private-customer-name.pem"
    key.write_text("secret", encoding="utf-8")
    result = run_mcu_plus_secure_build(
        tmp_path,
        lifecycle="HS-SE",
        signing_key=key,
        make_executable=fake_make,
        dry_run=True,
    )
    assert result["status"] == "NOT_CHECKED"
    assert result["global_devconfig_modified"] is False
    assert str(key) not in " ".join(result["safe_command"])
    assert "APP_SIGNING_KEY=<TEMP_SECRET_STAGE>/app_signing_key.pem" in result["safe_command"]


def test_missing_signed_output_runs_fixed_name_ccs_bootimage_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    project = tmp_path / "hello_world"
    build = project / "Debug"
    build.mkdir(parents=True)
    (build / "makefile").write_text("all:\n\t@echo linked\n", encoding="utf-8")
    (build / "hello_world.out").write_bytes(b"elf")
    (project / "makefile_ccs_bootimage_gen").write_text("all:\n\t@echo image\n", encoding="utf-8")
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    sdk.mkdir()
    fake_make = tmp_path / "make.exe"
    fake_make.write_text("placeholder", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if "-f" in command:
            (build / "hello_world.mcelf.hs_fs").write_bytes(b"signed")
            return SimpleNamespace(returncode=0, stdout="post-build ok", stderr="")
        return SimpleNamespace(returncode=0, stdout="link ok", stderr="")

    monkeypatch.setattr(
        "am64x_secure_toolkit.services.ccs_secure_build.subprocess.run", fake_run
    )
    result = run_mcu_plus_secure_build(
        project,
        lifecycle="HS-FS",
        sdk_root=sdk,
        make_executable=fake_make,
    )

    assert result["status"] == "PASS"
    assert len(calls) == 2
    post_command = calls[1]
    assert post_command[post_command.index("-f") + 1] == "makefile_ccs_bootimage_gen"
    assert "OUTNAME=hello_world" in post_command
    assert "PROFILE=Debug" in post_command
    assert "DEVICE_TYPE=GP" in post_command
    assert f"MCU_PLUS_SDK_PATH={sdk.resolve()}" in post_command
    assert result["post_build_exit_code"] == 0
    assert {item["check"]: item["status"] for item in result["checks"]}[
        "ccs_bootimage_post_build"
    ] == "PASS"


def test_ccs_bootimage_recipe_is_not_guessed_from_arbitrary_makefile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    build = tmp_path / "Debug"
    build.mkdir()
    (build / "makefile").write_text("all:\n\t@echo linked\n", encoding="utf-8")
    (build / "hello.out").write_bytes(b"elf")
    (tmp_path / "custom_postbuild.mak").write_text("all:\n\t@echo no\n", encoding="utf-8")
    fake_make = tmp_path / "make.exe"
    fake_make.write_text("placeholder", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="link ok", stderr="")

    monkeypatch.setattr(
        "am64x_secure_toolkit.services.ccs_secure_build.subprocess.run", fake_run
    )

    result = run_mcu_plus_secure_build(
        tmp_path,
        lifecycle="HS-FS",
        make_executable=fake_make,
    )

    assert result["status"] == "FAIL"
    assert len(calls) == 1
    assert result["post_build_safe_command"] is None
