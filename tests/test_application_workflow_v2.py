from pathlib import Path

from am64x_secure_toolkit.keygen import generate_key_set
from am64x_secure_toolkit.services.environment import resolve_environment
from am64x_secure_toolkit.workflows.application import application_build_workflow


def test_application_workflow_dry_run_is_not_execution_pass(tmp_path: Path):
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    signing = sdk / "source/security/security_common/tools/boot/signing"
    signing.mkdir(parents=True)
    (signing / "appimage_x509_cert_gen.py").write_text("# fake tool\n")
    (signing / "rom_image_gen.py").write_text("# fake tool\n")
    (sdk / "devconfig").mkdir()
    (sdk / "devconfig/devconfig.mak").write_text("DEVICE_TYPE?=GP\n")
    keys = tmp_path / "keys"; keys.mkdir()
    generate_key_set(keys, profile="development")
    payload = tmp_path / "app.mcelf"; payload.write_bytes(b"test payload")
    env = resolve_environment(sdk)
    result = application_build_workflow(
        environment=env,
        input_image=payload,
        signing_key=keys / "app-signing-private.pem",
        encryption_key=keys / "app-encryption-key.hex",
        output=tmp_path / "out.appimage",
        dry_run=True,
        post_verify=False,
    )
    assert result.status == "NOT_CHECKED"
    assert "çalıştırılmadı" in result.summary
    assert not (tmp_path / "out.appimage").exists()
