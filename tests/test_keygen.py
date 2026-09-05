from __future__ import annotations

import os
from pathlib import Path

import pytest

from am64x_secure_toolkit.keycheck import preflight_mek, preflight_signing_key
from am64x_secure_toolkit.keygen import generate_key_set, generate_mek, generate_signing_key


def test_generate_application_signing_key_is_rsa4096_and_secret_safe(tmp_path: Path):
    out = generate_signing_key(tmp_path, role="application")
    assert out["status"] == "PASS"
    assert out["key"]["bits"] == 4096
    assert out["key"]["public_exponent"] == 65537
    assert out["secret_paths_recorded"] is False
    assert out["secret_hashes_recorded"] is False
    private_path = tmp_path / "app-signing-private.pem"
    public_path = tmp_path / "app-signing-public.der"
    assert private_path.is_file() and public_path.is_file()
    assert preflight_signing_key(private_path, purpose="application")["status"] == "PASS"
    if os.name == "posix":
        assert private_path.stat().st_mode & 0o777 == 0o600
        assert public_path.stat().st_mode & 0o777 == 0o644


def test_generate_mek_is_exact_64_hex_without_newline(tmp_path: Path):
    out = generate_mek(tmp_path, role="application")
    assert out["status"] == "PASS"
    path = tmp_path / "app-encryption-key.hex"
    raw = path.read_bytes()
    assert len(raw) == 64
    assert b"\n" not in raw and b"\r" not in raw
    assert preflight_mek(path)["status"] == "PASS"
    assert "sha" not in " ".join(out.keys()).lower()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_generate_provisioning_test_set_has_public_hash_candidates_but_no_secret_hash(tmp_path: Path):
    out = generate_key_set(tmp_path, profile="provisioning-test", backup=True)
    assert out["status"] == "PASS"
    assert set(out["public_key_info"]) == {"smpk", "bmpk"}
    assert len(out["public_key_info"]["smpk"]["provisioning_public_der_sha512_candidate"]) == 128
    assert len(out["public_key_info"]["bmpk"]["provisioning_public_der_sha512_candidate"]) == 128
    assert (tmp_path / "smek.hex").read_bytes() != (tmp_path / "bmek.hex").read_bytes()
    assert out["secret_hashes_recorded"] is False
    assert out["otp_efuse_write"] == "NOT_EXECUTED"
    manifest = (tmp_path / "keyset-manifest.json").read_text()
    assert "smpk-private" not in manifest
    assert "smek.hex" not in manifest
    assert '"secret_file_names_recorded": false' in manifest


def test_keygen_refuses_overwrite(tmp_path: Path):
    generate_mek(tmp_path, role="application")
    with pytest.raises(FileExistsError):
        generate_mek(tmp_path, role="application")
