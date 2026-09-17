from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from ..constants import TI_OIDS
from .source_registry import get_source


@dataclass(frozen=True)
class ExplorerEntry:
    key: str
    label: str
    value: str
    official_name: str
    oid: str | None
    context: str
    consumer: str
    meaning: str
    does_not_prove: str
    source_id: str
    decoded: Any = None
    anatomy_target: str = "certificate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_CONTEXT = {
    "ROM combined image": ("ROM combined-image certificate", "ROM / RBL", "TISCI-X509"),
    "Keywriter X.509 certificate": ("OTP Keywriter provisioning certificate", "OTP Keywriter", "TISCI-KEYWRITER"),
    "Secure Debug X.509 certificate": ("Secure Debug authorization certificate", "System Firmware / TIFS", "TISCI-DEBUG"),
    "encrypted+signed application/generic data": ("Application / generalized-auth certificate", "System Firmware / TIFS", "TISCI-AUTH"),
    "signed application/generic data": ("Application / generalized-auth certificate", "System Firmware / TIFS", "TISCI-AUTH"),
}

_EXTENSION_META: dict[str, tuple[str, str, str, str, str]] = {
    TI_OIDS["software_revision"]: (
        "System Firmware Software Revision Extension",
        "System Firmware / ROM context-dependent",
        "Software revision metadata taşıyan TI extension.",
        "Tek başına target rollback enforcement'ın hardware üzerinde doğrulandığını kanıtlamaz.",
        "TISCI-X509",
    ),
    TI_OIDS["sysfw_encryption"]: (
        "System Firmware Encryption Extension",
        "System Firmware / TIFS",
        "AES-256-CBC decryption için encryption metadata taşır.",
        "Certificate signature veya ciphertext integrity kontrolünün yerine geçmez.",
        "TISCI-AUTH",
    ),
    TI_OIDS["sysfw_debug"]: (
        "System Firmware Debug Extension",
        "System Firmware / TIFS",
        "Secure Debug authorization metadata taşır.",
        "JTAG'in target üzerinde gerçekten açıldığını veya eFuse policy'nin uygun olduğunu kanıtlamaz.",
        "TISCI-DEBUG",
    ),
    TI_OIDS["sysfw_boot"]: (
        "System Firmware Boot Extension",
        "System Firmware / TIFS",
        "Authenticated processor boot için boot-core/configuration metadata taşır.",
        "İmajın customer Root of Trust ile target üzerinde enforce edildiğini tek başına kanıtlamaz.",
        "TISCI-PROC-BOOT",
    ),
    TI_OIDS["sysfw_image_integrity"]: (
        "System Firmware Image Integrity Extension",
        "System Firmware / TIFS",
        "Payload veya ciphertext için SHA2-512 hash ve image size binding taşır.",
        "Certificate signature verification ile aynı kontrol değildir; authenticity veya freshness'i tek başına kanıtlamaz.",
        "TISCI-AUTH",
    ),
    TI_OIDS["sysfw_image_load"]: (
        "System Firmware Load Extension",
        "System Firmware / TIFS",
        "Payload'ın validate-in-place / copy ve destination semantics bilgisini taşır.",
        "Adres/core değerinin doğru target integration değeri olduğunu source olmadan kanıtlamaz.",
        "TISCI-AUTH",
    ),
    TI_OIDS["rom_ext_boot_info"]: (
        "ROM Boot Information / ext_boot_info",
        "ROM / RBL",
        "Combined ROM image component metadata ve hash ilişkisini taşır.",
        "Application certificate semantics veya System Firmware application auth sonucu değildir.",
        "SDK-TOOLS-SECURITY",
    ),
}

# Keywriter OIDs are numerous. Use the exact local OID name as the official-ish label and
# keep the meaning deliberately generic unless the toolkit has a decoder for the field.
for key, oid in TI_OIDS.items():
    if key.startswith("keywriter_") and oid not in _EXTENSION_META:
        _EXTENSION_META[oid] = (
            key.replace("keywriter_", "Keywriter: ").replace("_", " ").title(),
            "OTP Keywriter",
            "Keywriter provisioning certificate extension.",
            "Bu alanın varlığı OTP/eFuse programming'in çalıştırıldığını veya başarılı olduğunu kanıtlamaz.",
            "TISCI-KEYWRITER",
        )


_DECODE_KEY_BY_OID = {
    TI_OIDS["software_revision"]: "software_revision",
    TI_OIDS["sysfw_boot"]: "sysfw_boot",
    TI_OIDS["sysfw_encryption"]: "sysfw_encryption",
    TI_OIDS["sysfw_debug"]: "sysfw_debug",
    TI_OIDS["sysfw_image_integrity"]: "sysfw_image_integrity",
    TI_OIDS["sysfw_image_load"]: "sysfw_image_load",
    TI_OIDS["rom_ext_boot_info"]: "rom_ext_boot_info",
}
for name, oid in TI_OIDS.items():
    if name.startswith("keywriter_"):
        _DECODE_KEY_BY_OID[oid] = name


def _compact(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, dict):
        if "decode_error" in value:
            return f"Decode error: {value['decode_error']}"
        return ", ".join(f"{k}={v}" for k, v in value.items()) or "—"
    if isinstance(value, list):
        return f"{len(value)} item"
    return str(value)


def certificate_explorer_model(inspection: dict[str, Any]) -> dict[str, Any]:
    classification = str(inspection.get("classification") or "unknown")
    context, consumer, default_source = _CONTEXT.get(
        classification,
        ("X.509 certificate", "Context not determined", "TISCI-X509"),
    )
    entries: list[dict[str, Any]] = []

    def add(entry: ExplorerEntry) -> None:
        d = entry.to_dict()
        source = get_source(entry.source_id)
        d["source_title"] = source["title"]
        d["source_scope"] = source["scope"]
        entries.append(d)

    add(ExplorerEntry(
        "subject", "Subject", str(inspection.get("subject") or "—"), "Certificate Subject", None,
        context, "X.509 parser / metadata", "Certificate identity metadata.",
        "Subject text'i key veya Root of Trust değildir.", default_source,
    ))
    add(ExplorerEntry(
        "issuer", "Issuer", str(inspection.get("issuer") or "—"), "Certificate Issuer", None,
        context, "X.509 parser / metadata", "Certificate issuer metadata.",
        "Issuer text'i target trust enforcement kanıtı değildir.", default_source,
    ))
    add(ExplorerEntry(
        "public_key", "Public Key", str(inspection.get("spki_sha256") or "—"), "SubjectPublicKeyInfo", None,
        context, consumer, "Embedded public key'in DER-SPKI SHA-256 developer fingerprint'i.",
        "Embedded public key'in target üzerinde active customer Root of Trust olduğunu kanıtlamaz.", default_source,
    ))
    sig = f"{inspection.get('signature_algorithm_oid') or '—'} / {inspection.get('signature_hash_algorithm') or '—'}"
    add(ExplorerEntry(
        "signature", "Signature", sig, "Certificate Signature", None,
        context, consumer, "TBSCertificate üzerindeki digital signature metadata.",
        "Payload/ciphertext integrity hash verification ile aynı kontrol değildir.", default_source,
    ))

    decoded = inspection.get("decoded") if isinstance(inspection.get("decoded"), dict) else {}
    for ext in inspection.get("extensions", []):
        if not isinstance(ext, dict):
            continue
        oid = str(ext.get("oid") or "")
        meta = _EXTENSION_META.get(oid)
        if meta:
            official, ext_consumer, meaning, nonclaim, source_id = meta
        else:
            official = str(ext.get("name") or "Unknown extension")
            ext_consumer = consumer
            meaning = "Parsed X.509 extension; toolkit'te özel semantic açıklaması tanımlı değil."
            nonclaim = "Semantic meaning source-backed olarak tanımlanmadan güvenlik sonucu çıkarılmaz."
            source_id = "TISCI-X509"
        decode_key = _DECODE_KEY_BY_OID.get(oid)
        decoded_value = decoded.get(decode_key) if decode_key else None
        if oid == TI_OIDS["rom_ext_boot_info"]:
            anatomy_target = "rom_components"
        elif oid in {TI_OIDS["sysfw_image_integrity"], TI_OIDS["sysfw_image_load"], TI_OIDS["sysfw_encryption"]}:
            anatomy_target = "payload_or_ciphertext"
        else:
            anatomy_target = "certificate"
        add(ExplorerEntry(
            f"ext:{oid}", official, _compact(decoded_value), official, oid,
            context, ext_consumer, meaning, nonclaim, source_id, decoded=decoded_value,
            anatomy_target=anatomy_target,
        ))

    return {
        "classification": classification,
        "context": context,
        "consumer": consumer,
        "tisci_request_semantics": str(inspection.get("tisci_request_semantics") or "not_determined"),
        "entries": entries,
    }
