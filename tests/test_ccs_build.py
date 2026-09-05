from pathlib import Path

from am64x_secure_toolkit.services.ccs_build import (
    classify_application_artifact,
    scan_ccs_application_build,
)


def test_classifies_common_mcu_plus_sdk_application_outputs():
    assert classify_application_artifact("hello.release.appimage.hs_fs") == "signed_hs_fs"
    assert classify_application_artifact("hello.release.appimage.hs") == "signed_hs"
    assert classify_application_artifact("hello.release.appimage") == "unsigned_appimage"
    assert classify_application_artifact("hello.release.mcelf") == "unsigned_mcelf"
    assert classify_application_artifact("hello.release.out") == "linked_elf"
    assert classify_application_artifact("notes.txt") is None


def test_signed_hs_fs_output_is_preferred_over_unsigned_input(tmp_path: Path):
    (tmp_path / "hello.release.appimage").write_bytes(b"unsigned")
    signed = tmp_path / "hello.release.appimage.hs_fs"
    signed.write_bytes(b"signed")
    result = scan_ccs_application_build(tmp_path)
    assert result["state"] == "READY_SIGNED"
    assert result["recommended_action"] == "VERIFY_EXISTING"
    assert result["recommended"]["path"] == str(signed)
    assert len(result["unsigned"]) == 1


def test_unsigned_output_is_ready_for_signing_or_ccs_configuration(tmp_path: Path):
    image = tmp_path / "hello.release.mcelf"
    image.write_bytes(b"mcelf")
    result = scan_ccs_application_build(tmp_path)
    assert result["state"] == "UNSIGNED_READY"
    assert result["recommended_action"] == "SIGN_OR_CONFIGURE"
    assert result["recommended"]["path"] == str(image)


def test_out_only_means_boot_image_build_is_incomplete(tmp_path: Path):
    (tmp_path / "hello.release.out").write_bytes(b"elf")
    result = scan_ccs_application_build(tmp_path)
    assert result["state"] == "BUILD_INCOMPLETE"
    assert result["recommended_action"] == "FINISH_CCS_BUILD"


def test_scan_skips_virtualenv_and_hidden_directories(tmp_path: Path):
    hidden = tmp_path / ".venv"
    hidden.mkdir()
    (hidden / "ignored.appimage.hs_fs").write_bytes(b"signed")
    result = scan_ccs_application_build(tmp_path)
    assert result["state"] == "NO_OUTPUT"
    assert result["artifacts"] == []
