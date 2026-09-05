from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.services.environment import resolve_environment


def test_environment_resolves_explicit_sdk_layout(tmp_path: Path):
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    signing = sdk / "source/security/security_common/tools/boot/signing"
    signing.mkdir(parents=True)
    (signing / "appimage_x509_cert_gen.py").write_text("# test\n")
    (signing / "rom_image_gen.py").write_text("# test\n")
    (sdk / "devconfig").mkdir()
    (sdk / "devconfig/devconfig.mak").write_text("DEVICE_TYPE?=GP\n")
    env = resolve_environment(sdk)
    data = env.to_dict()
    assert env.sdk_version == "12.00.00.27"
    assert env.app_signing_tool is not None
    assert env.rom_signing_tool is not None
    assert data["compatibility"] == "VALIDATED_BASELINE"
    assert data["status"] in {"PASS", "FAIL"}  # OpenSSL presence is host dependent
