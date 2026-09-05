from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from ..der import first_der_object_length
from ..inspect import inspect_artifact
from ..keycheck import compare_key_material
from ..profiles import save_profile


SUBJECT_FIELDS: tuple[tuple[str, str, object], ...] = (
    ("country", "Country (C)", NameOID.COUNTRY_NAME),
    ("state", "State / Province (ST)", NameOID.STATE_OR_PROVINCE_NAME),
    ("locality", "Locality (L)", NameOID.LOCALITY_NAME),
    ("organization", "Organization (O)", NameOID.ORGANIZATION_NAME),
    ("organizational_unit", "Organizational Unit (OU)", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("common_name", "Common Name (CN)", NameOID.COMMON_NAME),
    ("email", "Email", NameOID.EMAIL_ADDRESS),
)

DEBUG_LEVELS: tuple[tuple[int, str, str], ...] = (
    (0, "DEBUG_DISABLE", "Debug kapalı"),
    (1, "DEBUG_PRESERVE", "Mevcut ayarı koru / register'ları kilitle"),
    (2, "DEBUG_PUBLIC", "Public non-secure user + privileged debug"),
    (3, "DEBUG_PUBLIC_USER", "Public non-secure user-level debug"),
    (4, "DEBUG_FULL", "Full secure + non-secure privileged/user debug"),
    (5, "DEBUG_SECURE_USER", "Secure + non-secure user-level debug"),
)

AUTH_MODES: tuple[tuple[int, str, str], ...] = (
    (0, "Normal copy", "Binary doğrulama sırasında destAddr adresine kopyalanır."),
    (1, "In-place", "Binary bulunduğu yerde doğrulanır; copy_as_host alanı host context taşıyabilir."),
    (2, "In-place variant", "TISCI tarafından tanımlanan ikinci in-place davranışıdır."),
)


@dataclass(frozen=True)
class CertificateFile:
    cert: x509.Certificate
    der: bytes
    appended: bytes
    source_format: str


def _load_certificate_file(path: str | Path) -> CertificateFile:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError("certificate/image dosyası bulunamadı")
    data = p.read_bytes()
    if not data:
        raise ValueError("certificate/image dosyası boş")

    if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        cert = x509.load_pem_x509_certificate(data)
        der = cert.public_bytes(serialization.Encoding.DER)
        return CertificateFile(cert=cert, der=der, appended=b"", source_format="PEM")

    cert_len = first_der_object_length(data)
    der = data[:cert_len]
    cert = x509.load_der_x509_certificate(der)
    return CertificateFile(cert=cert, der=der, appended=data[cert_len:], source_format="DER")


def _name_to_subject(name: x509.Name) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, _label, oid in SUBJECT_FIELDS:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            out[key] = attrs[0].value
    return out


def _spki_sha256(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _validity_state(cert: x509.Certificate, *, now: datetime | None = None) -> tuple[str, int | None]:
    """Certificate validity metadata; target acceptance/enforcement claim değildir."""
    now = now or datetime.now(timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42 compatibility
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now < not_before:
        return "NOT_YET_VALID", None
    if now > not_after:
        return "EXPIRED", 0
    return "CURRENT", max(0, int((not_after - now).total_seconds() // 86400))


def _public_key_metadata(cert: x509.Certificate) -> dict[str, Any]:
    pub = cert.public_key()
    info: dict[str, Any] = {"type": type(pub).__name__}
    try:
        info["key_size"] = int(pub.key_size)
    except Exception:
        info["key_size"] = None
    try:
        numbers = pub.public_numbers()
        if hasattr(numbers, "e"):
            info["public_exponent"] = int(numbers.e)
    except Exception:
        pass
    return info


def certificate_metadata(path: str | Path) -> dict[str, Any]:
    p = Path(path).expanduser()
    loaded = _load_certificate_file(p)
    cert = loaded.cert
    inspection: dict[str, Any]
    if loaded.source_format == "DER":
        inspection = inspect_artifact(p)
    else:
        inspection = {
            "classification": "X.509 certificate",
            "extensions": [
                {"oid": ext.oid.dotted_string, "name": ext.oid._name or "unknown", "critical": ext.critical}
                for ext in cert.extensions
            ],
            "decoded": {},
        }
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42 compatibility
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
    validity_state, days_remaining = _validity_state(cert)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        basic_constraints = {"ca": bool(bc.ca), "path_length": bc.path_length}
    except x509.ExtensionNotFound:
        basic_constraints = None
    return {
        "file": p.name,
        "source_format": loaded.source_format,
        "classification": inspection.get("classification", "X.509 certificate"),
        "certificate_size": len(loaded.der),
        "appended_size": len(loaded.appended),
        "certificate_sha256": hashlib.sha256(loaded.der).hexdigest(),
        "spki_sha256": _spki_sha256(cert),
        "public_key": _public_key_metadata(cert),
        "subject": _name_to_subject(cert.subject),
        "subject_rfc4514": cert.subject.rfc4514_string(),
        "issuer_rfc4514": cert.issuer.rfc4514_string(),
        "self_signed_name": cert.subject == cert.issuer,
        "serial_number_hex": f"0x{cert.serial_number:X}",
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "validity_state": validity_state,
        "days_remaining": days_remaining,
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "basic_constraints": basic_constraints,
        "extension_oids": [ext.oid.dotted_string for ext in cert.extensions],
        "inspection": inspection,
        "private_key_material_recorded": False,
        "secret_path_recorded": False,
        "validity_note": "Host clock ile hesaplanan validity metadata'sı target hardware acceptance/enforcement kanıtı değildir.",
    }


def export_certificate(path: str | Path, output: str | Path, *, encoding: str) -> dict[str, Any]:
    loaded = _load_certificate_file(path)
    out = Path(output).expanduser()
    if out.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    if encoding.lower() == "der":
        data = loaded.der
        fmt = "DER"
    elif encoding.lower() == "pem":
        data = loaded.cert.public_bytes(serialization.Encoding.PEM)
        fmt = "PEM"
    else:
        raise ValueError("encoding yalnız DER veya PEM olabilir")
    out.write_bytes(data)
    return {
        "status": "PASS",
        "operation": "certificate_export",
        "format": fmt,
        "output": str(out),
        "certificate_sha256": hashlib.sha256(loaded.der).hexdigest(),
        "outputs": [{"type": f"certificate_{fmt.lower()}", "path": str(out)}],
        "secret_material_recorded": False,
    }


def export_public_key_der(path: str | Path, output: str | Path) -> dict[str, Any]:
    loaded = _load_certificate_file(path)
    out = Path(output).expanduser()
    if out.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    data = loaded.cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    out.write_bytes(data)
    return {
        "status": "PASS",
        "operation": "certificate_public_key_export",
        "output": str(out),
        "spki_sha256": hashlib.sha256(data).hexdigest(),
        "outputs": [{"type": "public_der", "path": str(out)}],
        "secret_material_recorded": False,
    }


def compare_certificate_with_private_key(certificate: str | Path, private_key: str | Path) -> dict[str, Any]:
    out = compare_key_material(Path(private_key), Path(certificate))
    out["operation"] = "certificate_key_match"
    out["summary"] = "Certificate public key ile signing private key'in public tarafı karşılaştırıldı."
    return out


def _extension_value(inspection: dict[str, Any], key: str) -> dict[str, Any]:
    decoded = inspection.get("decoded") if isinstance(inspection.get("decoded"), dict) else {}
    value = decoded.get(key)
    return value if isinstance(value, dict) else {}


def profile_from_certificate(path: str | Path, *, payload_path: str | Path | None = None) -> tuple[dict[str, Any], list[str]]:
    """Application/debug certificate metadata'sını düzenlenebilir profile'a taşır.

    İmzalı certificate byte'ları değiştirilmez. Bu yalnız yeni certificate üretmek için bir başlangıç
    profile'ı oluşturur. Target-specific alanlar yalnız certificate içinde gerçekten decode edilmişse taşınır.
    """
    meta = certificate_metadata(path)
    inspection = meta["inspection"]
    classification = str(meta.get("classification") or "")
    subject = dict(meta.get("subject") or {})
    warnings: list[str] = [
        "Orijinal signed certificate değiştirilmez; bu profile yeni certificate/reissue için başlangıçtır."
    ]
    sw = _extension_value(inspection, "software_revision").get("software_revision", 1)

    # Keep a conservative validity duration; exact original dates are metadata, while the new cert gets new dates.
    profile_valid_days = 3650

    if "Secure Debug" in classification:
        dbg = _extension_value(inspection, "sysfw_debug")
        if not dbg:
            raise ValueError("Secure Debug extension decode edilemedi; clone/reissue profile oluşturulamaz")
        uid_hex = str(dbg.get("uid_hex") or "")
        return ({
            "type": "debug",
            "subject": subject,
            "software_revision": int(sw),
            "debug": {
                "soc_uid": uid_hex,
                "wildcard_uid": uid_hex == "00" * 32,
                "privilege": int(dbg.get("debug_privilege", 0)),
                "reserved": int(dbg.get("reserved_upper16", 0)),
                "nonsecure_core_ids": list(dbg.get("nonsecure_core_ids") or [255]),
                "secure_core_ids": list(dbg.get("secure_core_ids") or [255]),
            },
            "valid_days": profile_valid_days,
        }, warnings)

    if "application" in classification or "generic data" in classification:
        load = _extension_value(inspection, "sysfw_image_load")
        if not load:
            raise ValueError("Application Load Extension decode edilemedi; clone/reissue profile oluşturulamaz")
        boot = _extension_value(inspection, "sysfw_boot")
        payload = str(Path(payload_path).expanduser()) if payload_path else "<PAYLOAD_PATH>"
        if not payload_path:
            warnings.append("Yeni certificate için payload dosyasını ayrıca seçmek gerekir; certificate hash'i yeni payload üzerinden hesaplanır.")
        profile: dict[str, Any] = {
            "type": "application",
            "subject": subject,
            "input": payload,
            "software_revision": int(sw),
            "load": {
                "dest_addr": str(load.get("dest_addr_hex") or "<SOURCE_VERIFIED_VALUE>"),
                "auth_mode": int(load.get("auth_mode", 1)),
                "copy_as_host": int(load.get("copy_as_host", 0)),
            },
            "boot": {"enabled": bool(boot)},
            "valid_days": profile_valid_days,
        }
        if boot:
            profile["boot"].update({
                "boot_core": int(boot.get("boot_core", 0)),
                "config_flags_set": int(boot.get("config_flags_set", 0)),
                "config_flags_clr": int(boot.get("config_flags_clr", 0)),
                "reset_vector": str(boot.get("reset_vector_hex") or "<SOURCE_VERIFIED_VALUE>"),
                "field_valid": int(boot.get("field_valid", 0)),
            })
        return profile, warnings

    raise ValueError("Clone/reissue şu anda application/generalized-auth veya Secure Debug certificate için desteklenir")


def compare_certificates(left: str | Path, right: str | Path) -> dict[str, Any]:
    """İki public certificate'ı metadata/extension bazında karşılaştırır; secret material gerekmez."""
    a = certificate_metadata(left)
    b = certificate_metadata(right)
    fields = (
        "classification", "subject_rfc4514", "issuer_rfc4514", "serial_number_hex",
        "not_valid_before", "not_valid_after", "validity_state", "spki_sha256",
        "signature_algorithm_oid", "signature_hash_algorithm", "basic_constraints",
    )
    diffs: list[dict[str, Any]] = []
    for field in fields:
        av, bv = a.get(field), b.get(field)
        diffs.append({
            "field": field,
            "left": av,
            "right": bv,
            "same": av == bv,
        })
    ao, bo = set(a.get("extension_oids") or []), set(b.get("extension_oids") or [])
    return {
        "status": "PASS",
        "operation": "certificate_compare",
        "summary": "İki public certificate metadata ve extension seti karşılaştırıldı.",
        "same_certificate_sha256": a["certificate_sha256"] == b["certificate_sha256"],
        "same_public_key": a["spki_sha256"] == b["spki_sha256"],
        "field_differences": diffs,
        "extensions_only_left": sorted(ao - bo),
        "extensions_only_right": sorted(bo - ao),
        "extensions_common": sorted(ao & bo),
        "left": {k: a.get(k) for k in ("file", "classification", "certificate_sha256", "spki_sha256")},
        "right": {k: b.get(k) for k in ("file", "classification", "certificate_sha256", "spki_sha256")},
        "secret_material_recorded": False,
        "secret_path_recorded": False,
    }


def save_cloned_profile(path: str | Path, output: str | Path, *, payload_path: str | Path | None = None) -> dict[str, Any]:
    profile, warnings = profile_from_certificate(path, payload_path=payload_path)
    save_profile(profile, output)
    return {
        "status": "PASS",
        "operation": "certificate_clone_profile",
        "summary": "Existing certificate metadata'sından yeni reissue profile oluşturuldu; original certificate değiştirilmedi.",
        "profile_type": profile["type"],
        "warnings": warnings,
        "outputs": [{"type": "certificate_profile", "path": str(output)}],
        "secret_material_recorded": False,
    }


def _library_dir(project_root: str | Path) -> Path:
    return Path(project_root).expanduser().resolve() / "public" / "certificates"


def add_certificate_to_library(project_root: str | Path, certificate: str | Path, *, name: str | None = None) -> dict[str, Any]:
    loaded = _load_certificate_file(certificate)
    library = _library_dir(project_root)
    library.mkdir(parents=True, exist_ok=True)
    stem = Path(name or Path(certificate).stem).name
    stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in stem).strip("._-") or "certificate"
    out = library / f"{stem}.der"
    if out.exists():
        raise FileExistsError(f"certificate library girdisi zaten mevcut: {out.name}")
    incoming_hash = hashlib.sha256(loaded.der).hexdigest()
    for existing in library.glob("*.der"):
        try:
            if hashlib.sha256(existing.read_bytes()).hexdigest() == incoming_hash:
                raise FileExistsError(f"aynı certificate Library'de zaten mevcut: {existing.name}")
        except OSError:
            continue
    out.write_bytes(loaded.der)
    meta = certificate_metadata(out)
    return {
        "status": "PASS",
        "operation": "certificate_library_add",
        "summary": "Public certificate Project Certificate Library'ye eklendi.",
        "library_name": out.name,
        "classification": meta["classification"],
        "certificate_sha256": meta["certificate_sha256"],
        "spki_sha256": meta["spki_sha256"],
        "outputs": [{"type": "certificate_der", "path": str(out)}],
        "secret_material_recorded": False,
        "full_host_path_recorded": False,
    }


def list_certificate_library(project_root: str | Path) -> list[dict[str, Any]]:
    library = _library_dir(project_root)
    if not library.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(library.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_file() or path.suffix.lower() not in {".der", ".cer", ".crt", ".pem"}:
            continue
        try:
            meta = certificate_metadata(path)
            rows.append({
                "name": path.name,
                "relative_path": f"public/certificates/{path.name}",
                "classification": meta["classification"],
                "subject": meta["subject_rfc4514"],
                "not_valid_after": meta["not_valid_after"],
                "validity_state": meta["validity_state"],
                "certificate_sha256": meta["certificate_sha256"],
                "spki_sha256": meta["spki_sha256"],
                "size": meta["certificate_size"],
            })
        except Exception as exc:
            rows.append({
                "name": path.name,
                "relative_path": f"public/certificates/{path.name}",
                "classification": "parse-error",
                "subject": f"{type(exc).__name__}: {exc}",
                "not_valid_after": "—",
                "validity_state": "PARSE_ERROR",
                "certificate_sha256": None,
                "spki_sha256": None,
                "size": path.stat().st_size,
            })
    return rows


def remove_certificate_from_library(project_root: str | Path, relative_path: str) -> dict[str, Any]:
    library = _library_dir(project_root).resolve()
    target = (Path(project_root).expanduser().resolve() / relative_path).resolve()
    try:
        target.relative_to(library)
    except ValueError as exc:
        raise ValueError("yalnız Project Certificate Library girdileri kaldırılabilir") from exc
    if not target.is_file():
        raise FileNotFoundError("certificate library girdisi bulunamadı")
    target.unlink()
    return {
        "status": "PASS",
        "operation": "certificate_library_remove",
        "summary": "Certificate Library girdisi kaldırıldı; external/original certificate değiştirilmedi.",
        "removed": target.name,
        "secret_material_recorded": False,
    }
