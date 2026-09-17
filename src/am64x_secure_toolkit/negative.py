"""Secure image kopyaları üzerinde kontrollü negatif testler üretir."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from asn1crypto import x509 as asn1_x509
from cryptography import x509

from .der import first_der_object_length
from .inspect import inspect_artifact
from .verify import verify_artifact


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _check_output(input_path: Path, output: Path) -> None:
    try:
        if input_path.resolve() == output.resolve():
            raise ValueError("negatif test çıktısı kaynak dosyayla aynı olamaz")
    except FileNotFoundError:
        pass
    if output.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {output}")


def _check_status(verification: dict[str, Any], check_name: str) -> str | None:
    for check in verification.get("checks", []):
        if check.get("check") == check_name:
            return check.get("status")
    return None


def _certificate_signature_mutation(data: bytes) -> tuple[bytes, dict[str, Any]]:
    cert_len = first_der_object_length(data)
    cert_der = data[:cert_len]
    appended = data[cert_len:]
    before = x509.load_der_x509_certificate(cert_der)
    parsed = asn1_x509.Certificate.load(cert_der)
    signature = bytearray(parsed["signature_value"].native)
    if not signature:
        raise ValueError("certificate signatureValue boş")
    signature[-1] ^= 0x01
    parsed["signature_value"] = bytes(signature)
    new_cert = parsed.dump()
    after = x509.load_der_x509_certificate(new_cert)
    if before.tbs_certificate_bytes != after.tbs_certificate_bytes:
        raise RuntimeError("signature mutation sırasında TBSCertificate değişti")
    if before.signature == after.signature:
        raise RuntimeError("signature mutation uygulanamadı")
    return new_cert + appended, {
        "target": "certificate.signatureValue",
        "change": "son signature byte üzerinde tek-bit XOR",
        "tbs_unchanged": True,
        "appended_data_unchanged": True,
    }


def _tbs_serial_mutation(data: bytes) -> tuple[bytes, dict[str, Any]]:
    cert_len = first_der_object_length(data)
    cert_der = data[:cert_len]
    appended = data[cert_len:]
    before = x509.load_der_x509_certificate(cert_der)
    parsed = asn1_x509.Certificate.load(cert_der)
    old_serial = int(parsed["tbs_certificate"]["serial_number"].native)
    new_serial = old_serial + 1
    parsed["tbs_certificate"]["serial_number"] = new_serial
    new_cert = parsed.dump()
    after = x509.load_der_x509_certificate(new_cert)
    if before.tbs_certificate_bytes == after.tbs_certificate_bytes:
        raise RuntimeError("TBSCertificate mutation uygulanamadı")
    if before.signature != after.signature:
        raise RuntimeError("TBSCertificate mutation sırasında signatureValue değişti")
    return new_cert + appended, {
        "target": "TBSCertificate.serialNumber",
        "change": "serialNumber + 1",
        "original_serial": str(old_serial),
        "modified_serial": str(new_serial),
        "signature_value_unchanged": True,
        "appended_data_unchanged": True,
    }


def _appended_byte_mutation(data: bytes, offset: int | None = None) -> tuple[bytes, dict[str, Any]]:
    cert_len = first_der_object_length(data)
    appended = bytearray(data[cert_len:])
    if not appended:
        raise ValueError("certificate sonrasında değiştirilecek veri yok")
    if offset is None:
        offset = len(appended) // 2
    if not 0 <= offset < len(appended):
        raise ValueError(f"offset appended data sınırları dışında: {offset}; geçerli aralık 0..{len(appended)-1}")
    old = appended[offset]
    appended[offset] ^= 0x01
    return data[:cert_len] + bytes(appended), {
        "target": "appended_data",
        "change": "tek byte üzerinde tek-bit XOR",
        "appended_offset": offset,
        "absolute_offset": cert_len + offset,
        "original_byte": f"0x{old:02x}",
        "modified_byte": f"0x{appended[offset]:02x}",
        "certificate_bytes_unchanged": True,
    }


def _rom_component_mutation(data: bytes, component_index: int) -> tuple[bytes, dict[str, Any]]:
    info = inspect_artifact_bytes(data)
    if info["classification"] != "ROM combined image":
        raise ValueError("component mutation yalnız ROM combined image için kullanılabilir")
    components = info.get("decoded", {}).get("rom_ext_boot_info", {}).get("components", [])
    if not 1 <= component_index <= len(components):
        raise ValueError(f"component index geçersiz: {component_index}; geçerli aralık 1..{len(components)}")
    # Validates that the image starts with a well-formed DER TLV; raises DERError if not.
    first_der_object_length(data)
    base = 0
    for comp in components[: component_index - 1]:
        base += int(comp["comp_size"])
    size = int(components[component_index - 1]["comp_size"])
    if size <= 0:
        raise ValueError("seçilen ROM component boş")
    local_offset = size // 2
    absolute_appended_offset = base + local_offset
    mutated, meta = _appended_byte_mutation(data, absolute_appended_offset)
    meta.update({
        "target": f"rom_component_{component_index}",
        "component_index": component_index,
        "component_local_offset": local_offset,
        "component_size": size,
    })
    return mutated, meta


def inspect_artifact_bytes(data: bytes) -> dict[str, Any]:
    """inspect_artifact için geçici dosya oluşturmadan kullanılan küçük adapter."""
    # inspect_artifact Path API'sini korumak için private geçici dosya kullanmak yerine
    # yalnız burada gereken alanları doğrudan parse ediyoruz.
    cert_len = first_der_object_length(data)
    cert = x509.load_der_x509_certificate(data[:cert_len])
    present = {ext.oid.dotted_string for ext in cert.extensions}
    from .constants import TI_OIDS
    classification = "unknown"
    if TI_OIDS["rom_ext_boot_info"] in present:
        classification = "ROM combined image"
    elif TI_OIDS["sysfw_debug"] in present:
        classification = "Secure Debug X.509 certificate"
    elif TI_OIDS["sysfw_image_integrity"] in present:
        classification = "encrypted+signed application/generic data" if TI_OIDS["sysfw_encryption"] in present else "signed application/generic data"

    decoded: dict[str, Any] = {}
    if classification == "ROM combined image":
        from .x509ext import decode_ext_boot_info
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(TI_OIDS["rom_ext_boot_info"])).value
        raw = ext.value if isinstance(ext, x509.UnrecognizedExtension) else getattr(ext, "value", None)
        if raw is not None:
            decoded["rom_ext_boot_info"] = decode_ext_boot_info(raw)
    return {"classification": classification, "decoded": decoded}


def _evaluate(kind: str, verification: dict[str, Any], component_index: int | None = None) -> tuple[str, str]:
    if kind in {"signature", "tbs"}:
        status = _check_status(verification, "certificate_signature_with_embedded_public_key")
        if status == "FAIL":
            return "PASS", "certificate signature değişikliği doğrulama tarafından yakalandı"
        if status == "NOT_CHECKED":
            return "PARTIAL", "certificate signature bu public-key türü/profili için doğrulanamadı"
        return "FAIL", f"certificate signature kontrolünde beklenen FAIL görülmedi: {status}"

    if kind in {"payload", "ciphertext"}:
        status = _check_status(verification, "appended_payload_sha512_binding")
        if status == "FAIL":
            return "PASS", "appended data değişikliği SHA2-512 integrity kontrolü tarafından yakalandı"
        return "FAIL", f"payload/ciphertext integrity kontrolünde beklenen FAIL görülmedi: {status}"

    if kind == "component":
        check = f"rom_component_{component_index}_sha512"
        status = _check_status(verification, check)
        if status == "FAIL":
            return "PASS", f"ROM component {component_index} değişikliği component SHA2-512 kontrolü tarafından yakalandı"
        return "FAIL", f"{check} için beklenen FAIL görülmedi: {status}"

    return "FAIL", "bilinmeyen negatif test türü"


def create_negative_variant(
    input_path: str | Path,
    kind: str,
    output: str | Path,
    *,
    offset: int | None = None,
    component_index: int | None = None,
) -> dict[str, Any]:
    """Kaynağı değiştirmeden bir negatif-test kopyası üretir ve doğrular."""
    source = Path(input_path)
    out = Path(output)
    if not source.is_file():
        raise FileNotFoundError(source)
    _check_output(source, out)
    original = source.read_bytes()
    original_sha = _sha256(original)
    info = inspect_artifact(source)
    classification = info["classification"]

    if kind == "signature":
        mutated, metadata = _certificate_signature_mutation(original)
    elif kind == "tbs":
        mutated, metadata = _tbs_serial_mutation(original)
    elif kind == "payload":
        if classification != "signed application/generic data":
            raise ValueError("payload mutation signed application/generic data için kullanılabilir; encrypted image için ciphertext kullan")
        mutated, metadata = _appended_byte_mutation(original, offset)
    elif kind == "ciphertext":
        if classification != "encrypted+signed application/generic data":
            raise ValueError("ciphertext mutation yalnız encrypted+signed application/generic data için kullanılabilir")
        mutated, metadata = _appended_byte_mutation(original, offset)
    elif kind == "component":
        if component_index is None:
            raise ValueError("component mutation için component_index gerekir")
        mutated, metadata = _rom_component_mutation(original, component_index)
    else:
        raise ValueError(f"desteklenmeyen negatif test türü: {kind}")

    if mutated == original:
        raise RuntimeError("negatif test kopyasında değişiklik oluşmadı")
    if source.read_bytes() != original or _sha256(source.read_bytes()) != original_sha:
        raise RuntimeError("kaynak dosya değişti; işlem durduruldu")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(mutated)
    verification = verify_artifact(out)
    result, reason = _evaluate(kind, verification, component_index)

    # Yazımdan sonra da source identity değişmediğini doğrula.
    source_unchanged = _sha256(source.read_bytes()) == original_sha
    return {
        "test": kind,
        "negative_test_result": result,
        "reason": reason,
        "classification": classification,
        "source": str(source),
        "source_sha256": original_sha,
        "source_unchanged": source_unchanged,
        "output": str(out),
        "output_sha256": _sha256(mutated),
        "differing_output": _sha256(mutated) != original_sha,
        "mutation": metadata,
        "verification": verification,
    }


def run_negative_suite(input_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Image türüne uygun negatif test kopyalarını üretir."""
    source = Path(input_path)
    outdir = Path(output_dir)
    if not source.is_file():
        raise FileNotFoundError(source)
    if outdir.exists() and any(outdir.iterdir()):
        raise FileExistsError(f"çıktı dizini boş değil: {outdir}")
    outdir.mkdir(parents=True, exist_ok=True)

    info = inspect_artifact(source)
    classification = info["classification"]
    stem = source.name
    cases: list[tuple[str, Path, dict[str, Any]]] = [
        ("signature", outdir / f"{stem}.neg-signature", {}),
        ("tbs", outdir / f"{stem}.neg-tbs", {}),
    ]
    if classification == "signed application/generic data":
        cases.append(("payload", outdir / f"{stem}.neg-payload", {}))
    elif classification == "encrypted+signed application/generic data":
        cases.append(("ciphertext", outdir / f"{stem}.neg-ciphertext", {}))
    elif classification == "ROM combined image":
        components = info.get("decoded", {}).get("rom_ext_boot_info", {}).get("components", [])
        for index in range(1, len(components) + 1):
            cases.append(("component", outdir / f"{stem}.neg-component-{index}", {"component_index": index}))

    results = []
    for kind, output, kwargs in cases:
        results.append(create_negative_variant(source, kind, output, **kwargs))

    statuses = [x["negative_test_result"] for x in results]
    suite_result = "FAIL" if "FAIL" in statuses else ("PARTIAL" if "PARTIAL" in statuses else "PASS")
    report = {
        "suite_result": suite_result,
        "source": str(source),
        "source_sha256": _sha256(source.read_bytes()),
        "classification": classification,
        "source_unchanged": all(x["source_unchanged"] for x in results),
        "cases": results,
    }
    report_path = outdir / "negative_test_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    report["report"] = str(report_path)
    report["report_sha256"] = _sha256(report_path.read_bytes())
    return report
