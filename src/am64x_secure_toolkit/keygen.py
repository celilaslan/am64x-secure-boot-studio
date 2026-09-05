from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import __version__
from .keycheck import preflight_mek, preflight_signing_key
from .services.claim_boundary import claims_for

_SIGNING_ROLES = {"application", "smpk", "bmpk", "debug"}
_MEK_ROLES = {"application", "smek", "bmek"}


def _signing_purpose(role: str) -> str:
    return "keywriter" if role in {"smpk", "bmpk"} else ("debug" if role == "debug" else "application")


def _signing_names(role: str) -> tuple[str, str]:
    prefix = {
        "application": "app-signing",
        "smpk": "smpk",
        "bmpk": "bmpk",
        "debug": "debug-signing",
    }[role]
    return f"{prefix}-private.pem", f"{prefix}-public.der"


def _mek_name(role: str) -> str:
    return {
        "application": "app-encryption-key.hex",
        "smek": "smek.hex",
        "bmek": "bmek.hex",
    }[role]


def _generate_signing_bytes() -> tuple[bytes, bytes, dict[str, Any]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    info = {
        "algorithm": "RSA",
        "bits": key.key_size,
        "public_exponent": key.public_key().public_numbers().e,
        "public_der_spki_sha256": hashlib.sha256(public_der).hexdigest(),
        "public_der_sha512": hashlib.sha512(public_der).hexdigest(),
    }
    return private_pem, public_der, info


def _generate_mek_bytes() -> bytes:
    return secrets.token_bytes(32).hex().encode("ascii")


def _stage(path: Path, data: bytes, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        finally:
            raise
    return temp


def _commit_bundle(items: list[tuple[Path, bytes, int]], validator) -> None:
    finals = [path for path, _, _ in items]
    for path in finals:
        if path.exists():
            raise FileExistsError(f"çıktı dosyası zaten mevcut: {path.name}")
    staged: list[tuple[Path, Path]] = []
    committed: list[Path] = []
    try:
        for final, data, mode in items:
            staged.append((final, _stage(final, data, mode)))
        validator({final.name: temp for final, temp in staged})
        for final, temp in staged:
            os.replace(temp, final)
            committed.append(final)
    except Exception:
        for _, temp in staged:
            temp.unlink(missing_ok=True)
        for final in committed:
            final.unlink(missing_ok=True)
        raise


def generate_signing_key(output_dir: str | Path, *, role: str = "application") -> dict[str, Any]:
    if role not in _SIGNING_ROLES:
        raise ValueError(f"desteklenmeyen signing role: {role}")
    out = Path(output_dir).expanduser().resolve()
    private_name, public_name = _signing_names(role)
    private_pem, public_der, info = _generate_signing_bytes()
    private_path, public_path = out / private_name, out / public_name

    def validate(staged: dict[str, Path]) -> None:
        result = preflight_signing_key(staged[private_name], purpose=_signing_purpose(role))
        if result.get("status") != "PASS":
            raise ValueError("üretilen signing key preflight kontrolünü geçmedi")

    _commit_bundle([(private_path, private_pem, 0o600), (public_path, public_der, 0o644)], validate)
    claims, non_claims = claims_for("key_generate_signing", "PASS")
    return {
        "status": "PASS",
        "operation": "key_generate_signing",
        "role": role,
        "classification": "development/test / synthetic / non-production / unprovisioned / offline-only",
        "key": {
            "algorithm": info["algorithm"],
            "bits": info["bits"],
            "public_exponent": info["public_exponent"],
            "public_der_spki_sha256": info["public_der_spki_sha256"],
            "provisioning_public_der_sha512_candidate": info["public_der_sha512"] if role in {"smpk", "bmpk"} else None,
        },
        "secret_files_created": [private_name],
        "public_files_created": [public_name],
        "secret_paths_recorded": False,
        "secret_hashes_recorded": False,
        "otp_efuse_write": "NOT_EXECUTED",
        "hsfs_to_hsse": "NOT_EXECUTED",
        "claims": claims,
        "non_claims": non_claims,
    }


def generate_mek(output_dir: str | Path, *, role: str = "application") -> dict[str, Any]:
    if role not in _MEK_ROLES:
        raise ValueError(f"desteklenmeyen MEK role: {role}")
    out = Path(output_dir).expanduser().resolve()
    name = _mek_name(role)
    data = _generate_mek_bytes()
    path = out / name

    def validate(staged: dict[str, Path]) -> None:
        result = preflight_mek(staged[name])
        if result.get("status") != "PASS":
            raise ValueError("üretilen MEK strict format kontrolünü geçmedi")

    _commit_bundle([(path, data, 0o600)], validate)
    claims, non_claims = claims_for("key_generate_mek", "PASS")
    return {
        "status": "PASS",
        "operation": "key_generate_mek",
        "role": role,
        "classification": "development/test / synthetic / non-production / unprovisioned / offline-only",
        "format": "64 lowercase hexadecimal characters / 256-bit",
        "secret_files_created": [name],
        "secret_paths_recorded": False,
        "secret_hashes_recorded": False,
        "otp_efuse_write": "NOT_EXECUTED",
        "hsfs_to_hsse": "NOT_EXECUTED",
        "claims": claims,
        "non_claims": non_claims,
    }


def generate_key_set(output_dir: str | Path, *, profile: str = "development", backup: bool = False) -> dict[str, Any]:
    if profile not in {"development", "provisioning-test"}:
        raise ValueError("profile development veya provisioning-test olmalı")
    out = Path(output_dir).expanduser().resolve()
    items: list[tuple[Path, bytes, int]] = []
    validation: list[tuple[str, str, str]] = []
    public_info: dict[str, Any] = {}
    secret_names: list[str] = []
    public_names: list[str] = []

    if profile == "development":
        private_name, public_name = _signing_names("application")
        priv, pub, info = _generate_signing_bytes()
        items += [(out / private_name, priv, 0o600), (out / public_name, pub, 0o644)]
        validation.append((private_name, "signing", "application"))
        public_info["application_signing"] = {
            "algorithm": "RSA",
            "bits": 4096,
            "public_exponent": 65537,
            "public_der_spki_sha256": info["public_der_spki_sha256"],
        }
        secret_names.append(private_name)
        public_names.append(public_name)
        mek_name = _mek_name("application")
        items.append((out / mek_name, _generate_mek_bytes(), 0o600))
        validation.append((mek_name, "mek", "application"))
        secret_names.append(mek_name)
    else:
        roles = ["smpk"] + (["bmpk"] if backup else [])
        previous_public_der: bytes | None = None
        for role in roles:
            private_name, public_name = _signing_names(role)
            priv, pub, info = _generate_signing_bytes()
            while previous_public_der is not None and pub == previous_public_der:
                priv, pub, info = _generate_signing_bytes()
            previous_public_der = pub
            items += [(out / private_name, priv, 0o600), (out / public_name, pub, 0o644)]
            validation.append((private_name, "signing", role))
            public_info[role] = {
                "algorithm": "RSA",
                "bits": 4096,
                "public_exponent": 65537,
                "public_der_spki_sha256": info["public_der_spki_sha256"],
                "provisioning_public_der_sha512_candidate": info["public_der_sha512"],
            }
            secret_names.append(private_name)
            public_names.append(public_name)
        mek_roles = ["smek"] + (["bmek"] if backup else [])
        previous_mek: bytes | None = None
        for role in mek_roles:
            name = _mek_name(role)
            mek = _generate_mek_bytes()
            while previous_mek is not None and mek == previous_mek:
                mek = _generate_mek_bytes()
            previous_mek = mek
            items.append((out / name, mek, 0o600))
            validation.append((name, "mek", role))
            secret_names.append(name)

    manifest = {
        "schema": 1,
        "toolkit_version": __version__,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "classification": "development/test / synthetic / non-production / unprovisioned / offline-only",
        "public_key_info": public_info,
        "encryption": {"algorithm": "AES-256", "format": "64 lowercase hexadecimal characters"},
        "public_files": public_names,
        "secret_file_names_recorded": False,
        "secret_files_created_count": len(secret_names),
        "secret_hashes_recorded": False,
        "otp_efuse_write": "NOT_EXECUTED",
        "hsfs_to_hsse": "NOT_EXECUTED",
    }
    items.append((out / "keyset-manifest.json", (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"), 0o644))

    def validate(staged: dict[str, Path]) -> None:
        for name, kind, role in validation:
            result = preflight_signing_key(staged[name], purpose=_signing_purpose(role)) if kind == "signing" else preflight_mek(staged[name])
            if result.get("status") != "PASS":
                raise ValueError(f"üretilen {name} preflight kontrolünü geçmedi")

    _commit_bundle(items, validate)
    claims, non_claims = claims_for("key_generate_set", "PASS")
    return {
        "status": "PASS",
        "operation": "key_generate_set",
        "profile": profile,
        "backup_included": backup,
        "classification": "development/test / synthetic / non-production / unprovisioned / offline-only",
        "public_key_info": public_info,
        "secret_files_created": secret_names,
        "public_files_created": public_names + ["keyset-manifest.json"],
        "manifest": "keyset-manifest.json",
        "secret_paths_recorded": False,
        "secret_hashes_recorded": False,
        "otp_efuse_write": "NOT_EXECUTED",
        "hsfs_to_hsse": "NOT_EXECUTED",
        "claims": claims,
        "non_claims": non_claims,
    }
