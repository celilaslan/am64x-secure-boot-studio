from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.sdk_lint import lint_sdk_security


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _full_fixture(tmp_path: Path, *, debug: bool = True):
    devconfig = _write(
        tmp_path / "devconfig.mak",
        """
DEVICE_TYPE?=GP
ENC_ENABLED?=no
ENC_SBL_ENABLED?=yes
APP_SIGNING_KEY=
APP_ENCRYPTION_KEY=
ifeq ($(DEVICE_TYPE),HS)
APP_SIGNING_KEY=$(CUST_MPK)
APP_ENCRYPTION_KEY=$(CUST_MEK)
else
APP_SIGNING_KEY=$(APP_DEGENERATE_KEY)
endif
""",
    )
    app_makefile = _write(
        tmp_path / "app.make",
        """
TOOL=appimage_x509_cert_gen.py
ifeq ($(ENC_ENABLED),no)
CMD=$(TOOL) --authtype 1 --key $(APP_SIGNING_KEY)
else
CMD=$(TOOL) --authtype 1 --key $(APP_SIGNING_KEY) --enc y --enckey $(APP_ENCRYPTION_KEY)
endif
""",
    )
    debug_arg = " --debug DBG_FULL_ENABLE" if debug else ""
    sbl_makefile = _write(
        tmp_path / "sbl.make",
        f"""
TOOL=rom_image_gen.py
BOOTIMAGE_CERT_KEY=$(APP_SIGNING_KEY)
ifeq ($(ENC_SBL_ENABLED),yes)
CMD=$(TOOL) --key $(BOOTIMAGE_CERT_KEY) --sbl-enc --enc-key $(APP_ENCRYPTION_KEY){debug_arg}
endif
""",
    )
    app_tool = _write(
        tmp_path / "appimage_x509_cert_gen.py",
        """
# synthetic structural fixture
opts = ['--authtype', '--enc', '--enckey']
cipher = 'aes-256-cbc'
raw_key_flag = '-K'
enc_oid = '1.3.6.1.4.1.294.1.4'
integrity_oid = '1.3.6.1.4.1.294.1.34'
hash_name = 'sha512'
""",
    )
    rom_tool = _write(
        tmp_path / "rom_image_gen.py",
        """
# synthetic structural fixture
opts = ['--sbl-enc', '--enc-key']
cipher = 'aes-256-cbc'
raw_key_flag = '-K'
combined_oid = '1.3.6.1.4.1.294.1.9'
sbl_enc_oid = '1.3.6.1.4.1.294.1.10'
""",
    )
    return devconfig, app_makefile, sbl_makefile, app_tool, rom_tool


def test_full_static_chain_passes_in_development(tmp_path: Path):
    devconfig, app_makefile, sbl_makefile, app_tool, rom_tool = _full_fixture(tmp_path)
    out = lint_sdk_security(
        devconfig=devconfig,
        app_makefile=app_makefile,
        sbl_makefile=sbl_makefile,
        app_tool=app_tool,
        rom_tool=rom_tool,
        intent="development",
    )
    assert out["status"] == "PASS"
    assert out["execution"]["make_executed"] == "NO"
    assert out["cross_checks"][0]["check"] == "separate_encryption_control_chains"
    assert out["cross_checks"][0]["status"] == "PASS"
    assert out["summary"]["advisories"]  # synthetic hashes differ, but functional lint can still pass


def test_production_full_debug_is_rejected(tmp_path: Path):
    devconfig, app_makefile, sbl_makefile, app_tool, rom_tool = _full_fixture(tmp_path, debug=True)
    out = lint_sdk_security(
        devconfig=devconfig,
        app_makefile=app_makefile,
        sbl_makefile=sbl_makefile,
        app_tool=app_tool,
        rom_tool=rom_tool,
        intent="production",
    )
    assert out["status"] == "FAIL"
    assert "sbl_makefile:rom_full_debug_option" in out["summary"]["failures"]


def test_partial_input_set_is_partial(tmp_path: Path):
    devconfig, *_ = _full_fixture(tmp_path)
    out = lint_sdk_security(devconfig=devconfig)
    assert out["status"] == "PARTIAL"
    assert "partial_input_set" in out["summary"]["warnings"]


def test_make_db_enabled_encryption_requires_key(tmp_path: Path):
    devconfig, app_makefile, sbl_makefile, app_tool, rom_tool = _full_fixture(tmp_path, debug=False)
    make_db = _write(
        tmp_path / "make-db.txt",
        """
DEVICE_TYPE = HS
ENC_ENABLED = yes
ENC_SBL_ENABLED = yes
APP_SIGNING_KEY = /secret/signing.pem
APP_ENCRYPTION_KEY =
""",
    )
    out = lint_sdk_security(
        devconfig=devconfig,
        app_makefile=app_makefile,
        sbl_makefile=sbl_makefile,
        app_tool=app_tool,
        rom_tool=rom_tool,
        make_db=make_db,
    )
    assert out["status"] == "FAIL"
    assert "cross:resolved_application_encryption_has_key" in out["summary"]["failures"]
    assert out["make_database"]["resolved_variables"]["APP_SIGNING_KEY"]["state"] == "SET_REDACTED"
    assert "/secret/signing.pem" not in str(out)


def test_raw_mek_literal_is_not_echoed_and_fails(tmp_path: Path):
    devconfig, app_makefile, sbl_makefile, app_tool, rom_tool = _full_fixture(tmp_path, debug=False)
    secret = "a1" * 32
    with devconfig.open("a", encoding="utf-8") as f:
        f.write(f"\nCUST_MEK={secret}\n")
    out = lint_sdk_security(
        devconfig=devconfig,
        app_makefile=app_makefile,
        sbl_makefile=sbl_makefile,
        app_tool=app_tool,
        rom_tool=rom_tool,
    )
    assert out["status"] == "FAIL"
    assert secret not in str(out)
    assert any(f["code"] == "POTENTIAL_RAW_KEY_LITERAL" for f in out["inputs"]["devconfig"]["secret_hygiene"])


def test_report_does_not_overwrite(tmp_path: Path):
    devconfig, app_makefile, sbl_makefile, app_tool, rom_tool = _full_fixture(tmp_path, debug=False)
    report = tmp_path / "report.json"
    out = lint_sdk_security(
        devconfig=devconfig,
        app_makefile=app_makefile,
        sbl_makefile=sbl_makefile,
        app_tool=app_tool,
        rom_tool=rom_tool,
        report=report,
    )
    assert out["status"] == "PASS"
    assert report.exists()

    import pytest
    with pytest.raises(FileExistsError):
        lint_sdk_security(devconfig=devconfig, report=report)
