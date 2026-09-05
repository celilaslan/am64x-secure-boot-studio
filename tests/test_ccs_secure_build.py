from pathlib import Path

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
