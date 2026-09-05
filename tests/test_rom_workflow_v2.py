from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.services.environment import resolve_environment
from am64x_secure_toolkit.workflows.rom import rom_build_workflow


def _private_key(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _fake_sdk(tmp_path: Path) -> Path:
    sdk = tmp_path / "mcu_plus_sdk_am64x_12_00_00_27"
    signing = sdk / "source/security/security_common/tools/boot/signing"
    signing.mkdir(parents=True)
    (signing / "appimage_x509_cert_gen.py").write_text("# fake\n")
    (signing / "rom_image_gen.py").write_text("# fake\n")
    (sdk / "devconfig").mkdir(); (sdk / "devconfig/devconfig.mak").write_text("DEVICE_TYPE?=GP\n")
    return sdk


def test_rom_workflow_dry_run_keeps_addresses_explicit_and_not_executed(tmp_path: Path):
    sdk = _fake_sdk(tmp_path)
    key = tmp_path / "rom.pem"; _private_key(key)
    sbl = tmp_path / "sbl.bin"; sbl.write_bytes(b"sbl")
    sysfw = tmp_path / "sysfw.bin"; sysfw.write_bytes(b"sysfw")
    bcfg = tmp_path / "bcfg.bin"; bcfg.write_bytes(b"bcfg")
    result = rom_build_workflow(
        environment=resolve_environment(sdk),
        sbl_bin=sbl, sysfw_bin=sysfw, boardcfg_blob=bcfg,
        sbl_loadaddr="0x11110000", sysfw_loadaddr="0x22220000", bcfg_loadaddr="0x33330000",
        swrv=1, signing_key=key, output=tmp_path / "rom.tiimage",
        dry_run=True, post_verify=False,
    )
    assert result.status == "NOT_CHECKED"
    assert not (tmp_path / "rom.tiimage").exists()
    command = result.safe_details["build"]["command_redacted"]
    assert "0x11110000" in command and "0x22220000" in command and "0x33330000" in command
    assert str(key.resolve()) not in " ".join(command)


def test_rom_workflow_requires_private_key_for_build(tmp_path: Path):
    sdk = _fake_sdk(tmp_path)
    private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public = tmp_path / "pub.pem"
    public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    for name in ("sbl", "sysfw", "bcfg"):
        (tmp_path / f"{name}.bin").write_bytes(name.encode())
    result = rom_build_workflow(
        environment=resolve_environment(sdk), sbl_bin=tmp_path/"sbl.bin", sysfw_bin=tmp_path/"sysfw.bin", boardcfg_blob=tmp_path/"bcfg.bin",
        sbl_loadaddr="A", sysfw_loadaddr="B", bcfg_loadaddr="C", swrv=1, signing_key=public, output=tmp_path/"out.tiimage", dry_run=True,
    )
    assert result.status == "FAIL"
    assert any(c["check"] == "private_key_required_for_build" for c in result.checks)
