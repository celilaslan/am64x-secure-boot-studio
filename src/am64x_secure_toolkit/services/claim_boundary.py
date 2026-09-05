from __future__ import annotations

from typing import Any

_STANDARD_NON_CLAIMS = [
    "Hardware application-authentication enforcement doğrulanmış değildir.",
    "Hardware application-decryption enforcement doğrulanmış değildir.",
    "Customer Root of Trust enforcement doğrulanmış değildir.",
    "OTP/eFuse/customer-key provisioning çalıştırılmış değildir.",
    "HS-FS -> HS-SE transition çalıştırılmış değildir.",
]


def claims_for(operation: str, status: str, *, encrypted: bool = False) -> tuple[list[str], list[str]]:
    claims: list[str] = []
    if status == "PASS":
        if operation in {"inspect", "inspect_verify", "certificate_explore"}:
            claims.append("Seçilen dosyanın host-side parse/inspection kontrolleri tamamlandı.")
        if operation in {"verify", "inspect_verify", "application_build", "certificate_explore"}:
            claims.append("Çalıştırılan host-side signature/integrity kontrollerinin beklenen sonucu sağladığı doğrulandı.")
        if operation == "application_build":
            claims.append("Kurulu TI signing tool ile application image üretim adımı tamamlandı.")
            if encrypted:
                claims.append("Encrypted+signed application üretim yolu kullanıldı; confidentiality claim'i yalnız artifact-format bağlamındadır.")
        if operation == "rom_build":
            claims.append("Kurulu TI rom_image_gen.py ile ROM combined-image üretim adımı host üzerinde tamamlandı.")
            claims.append("Girilen SBL/SYSFW/BoardCfg bileşenleri ve generator invocation host-side kayıt bağlamında değerlendirildi.")
            if encrypted:
                claims.append("SBL encryption seçeneği generator invocation'a dahil edildi; target-side decryption enforcement sonucu çıkarılmaz.")
        if operation.startswith("key_generate"):
            claims.append("Synthetic/non-production key material local olarak üretildi ve format/preflight kontrolü geçti.")
        if operation == "key_preflight":
            claims.append("Key material yalnız public/format özellikleri üzerinden secret-safe host-side preflight ile değerlendirildi.")
        if operation == "negative_test":
            claims.append("Kontrollü değişiklik ayrı bir kopyada uygulandı ve host-side beklenen failure davranışı değerlendirildi.")
        if operation == "certificate_profile":
            claims.append("Application/debug certificate profile veya certificate çıktısı yalnız host-side format/crypto bağlamında değerlendirildi.")
        if operation == "sdk_lint":
            claims.append("Seçilen installed SDK/config source'ları read-only olarak security consumer-chain açısından incelendi.")
        if operation == "sdk_diff":
            claims.append("Verilen old/new SDK source setleri arasında security-relevant semantic fark analizi tamamlandı.")
        if operation == "errata":
            claims.append("Seçilen Rev. J errata kayıtları verilen silicon/boot context'e göre offline değerlendirildi.")
        if operation == "provision_preflight":
            claims.append("Provisioning profile ve verilen public/symmetric key girdileri yalnız host-side preflight kapsamıyla kontrol edildi.")
        if operation == "revision":
            claims.append("KEYREV/SWREV girdileri target'a yazılmadan offline simulator kurallarıyla değerlendirildi.")
        if operation == "boardcfg":
            claims.append("Security BoardCfg policy alanları target'a gönderilmeden offline değerlendirildi.")
        if operation == "secure_debug":
            claims.append("Debug certificate ve Security BoardCfg ilişkisi yalnız offline policy-decision bağlamında değerlendirildi.")
        if operation in {"generic_data", "generic_data_build"}:
            claims.append("Generic data package/profile host-side generalized-authentication formatı açısından değerlendirildi.")
            if operation == "generic_data_build":
                claims.append("Generic data certificate/package üretimi ve mevcut host-side verification adımları tamamlandı.")
                if encrypted:
                    claims.append("AES-256-CBC encrypted generic-data formatı üretildi; target decryption execution sonucu çıkarılmaz.")
    elif status in {"PARTIAL", "NOT_CHECKED"}:
        claims.append("Yalnız tamamlanan host-side kontroller raporlanabilir; eksik kontroller PASS sayılmaz.")

    non_claims = list(_STANDARD_NON_CLAIMS)
    if operation.startswith("key_generate"):
        non_claims.append("Üretilen key material production/customer provisioning key'i olarak sınıflandırılmaz.")
    if operation == "key_preflight":
        non_claims.append("Key preflight, ilgili key'in cihazda provision edildiğini veya target tarafından enforce edildiğini kanıtlamaz.")
    if operation == "rom_build":
        non_claims.append("ROM image'ın fiziksel cihaz tarafından kabul edildiği veya secure boot enforcement uygulandığı doğrulanmış değildir.")
    if operation == "sdk_diff":
        non_claims.append("Kaynak farkı tek başına runtime security behavior veya silicon acceptance kanıtı değildir.")
    if operation == "errata":
        non_claims.append("Errata advisor target üzerinde advisory tetiklenmesini veya workaround execution'ını kanıtlamaz.")
    if operation == "provision_preflight":
        non_claims.append("Preflight sonucu OTP Keywriter certificate execution veya eFuse programming anlamına gelmez.")
    if operation == "revision":
        non_claims.append("Simulator hiçbir SWREV/KEYREV/eFuse alanını değiştirmez.")
    if operation == "boardcfg":
        non_claims.append("BoardCfg target'a gönderilmez ve runtime security configuration değiştirilmez.")
    if operation == "secure_debug":
        non_claims.append("JTAG unlock, debug port açma veya permanent debug/security değişikliği çalıştırılmaz.")
    if operation in {"generic_data", "generic_data_build"}:
        non_claims.append("TISCI_MSG_PROC_AUTH_BOOT target çağrısı veya target acceptance/decryption bu toolkit tarafından çalıştırılmaz.")
    return claims, non_claims


def attach_claims(result: dict[str, Any], operation: str, status: str, *, encrypted: bool = False) -> dict[str, Any]:
    claims, non_claims = claims_for(operation, status, encrypted=encrypted)
    result = dict(result)
    result.setdefault("operation", operation)
    result["claims"] = claims
    result["non_claims"] = non_claims
    return result
