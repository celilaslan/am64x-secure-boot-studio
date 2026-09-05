from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class LearningCard:
    id: str
    title: str
    short: str
    body: str
    sources: tuple[str, ...]


_CARDS = [
    LearningCard("boot-chain", "RBL / SBL / SYSFW nedir?", "Boot zincirindeki üç farklı rol.", "RBL SoC içindeki ROM bootloader'dır. SBL ikinci aşama bootloader'dır. AM64x bağlamında SYSFW/DMSC security ve system-control hizmetlerini yürütür. Combined ROM image içinde SBL, SYSFW, BoardCfg ve HS bağlamında SYSFW inner certificate birlikte taşınabilir; application yükleme ise SBL + SYSFW/TIFS hizmetleriyle ayrı aşamadır.", ("SDK-SECURE-BOOT", "TRM-BOOT")),
    LearningCard("lifecycle", "GP / HS-FS / HS-SE", "Secure-boot enforcement lifecycle'a bağlıdır.", "HS-FS customer keys provision edilmeden önceki factory state'tir ve customer secure boot process'ini enforce etmez. HS-SE customer key provisioning sonrası secure-boot enforcement state'idir. Bu yüzden HS-FS üzerinde host-side signed image üretmek customer Root of Trust enforcement kanıtı değildir.", ("TISCI-KEYWRITER", "TRM-BOOT")),
    LearningCard("certificate-contexts", "ROM certificate vs application certificate", "İki signer aynı X.509 bağlamını üretmez.", "ROM combined image certificate RBL tarafından tüketilen boot image yapısına aittir. Application certificate ise System Firmware/TIFS tarafından authentication/decryption akışında tüketilen extension setini kullanır. Bu nedenle rom_image_gen.py ile appimage_x509_cert_gen.py birbirinin alternatifi değildir.", ("SDK-TOOLS-SECURITY", "TISCI-X509")),
    LearningCard("three-properties", "Signing / integrity / encryption", "Authenticity, integrity ve confidentiality aynı kontrol değildir.", "Certificate signature signed certificate metadata'nın kriptografik doğrulamasıdır. Image Integrity Extension actual payload/ciphertext hash binding'ini taşır. Encryption ise confidentiality sağlar. Birinin PASS olması diğerlerinin otomatik PASS olduğu anlamına gelmez.", ("TISCI-AUTH", "TISCI-SIGNING")),
    LearningCard("mpk-mek", "MPK / MEK", "Asymmetric signing key ile symmetric encryption key farklı görevlerdir.", "MPK bağlamı certificate signature/public-key trust için kullanılır; MEK bağlamı AES-256-CBC payload confidentiality için kullanılır. Encrypted binary signing flow'da encryption önce yapılır ve image-integrity hash ciphertext üzerinden hesaplanır.", ("TISCI-SIGNING", "TISCI-AUTH")),
    LearningCard("customer-keys", "SMPK/BMPK ve SMEK/BMEK", "Primary ve optional backup customer key setleri.", "SMPK/BMPK customer signing Root-of-Trust key pair bağlamlarıdır; corresponding public DER hash'leri provisioning'e gider. SMEK/BMEK 256-bit customer encryption key rolleridir. Key generation ile OTP/eFuse programming aynı işlem değildir.", ("TISCI-KEYWRITER",)),
    LearningCard("enc-switches", "ENC_ENABLED vs ENC_SBL_ENABLED", "Aynı encryption switch'i değiller.", "Installed SDK mapping'de ENC_ENABLED application encryption zincirini appimage_x509_cert_gen.py --enc/--enckey'e bağlar. ENC_SBL_ENABLED ise ROM/SBL encryption zincirini rom_image_gen.py --sbl-enc/--enc-key'e bağlar. Studio bu ikisini ayrı artifact katmanları olarak gösterir.", ("SDK-INSTALLED", "SDK-TOOLS-SECURITY")),
    LearningCard("signature-vs-hash", "Certificate signature vs payload hash", "İki bağımsız doğrulama.", "Certificate self-signature doğrulaması certificate içindeki TBSCertificate imzasını kontrol eder. Appended payload/ciphertext için Image Integrity Extension SHA2-512 binding'i ayrıca doğrulanır. Payload değişip certificate aynı kalırsa signature PASS kalabilirken payload hash FAIL olabilir.", ("TISCI-AUTH",)),
    LearningCard("host-vs-target", "Host-side verification vs hardware enforcement", "Dosyanın doğru olması target'ın enforce ettiğini kanıtlamaz.", "Host üzerinde certificate, hash ve encryption metadata doğrulanabilir. Customer Root of Trust eşleşmesi, hardware authentication/decryption enforcement ve lifecycle transition ise provision edilmiş uygun target üzerinde execution evidence gerektirir.", ("TISCI-AUTH", "TISCI-KEYWRITER")),
    LearningCard("debug-cert", "Secure Debug certificate ayrı bir bağlamdır", "Boot certificate ile aynı authorization değildir.", "Secure Debug certificate SYSFW tarafından debug authorization için işlenir. HS-SE üzerinde JTAG closed-by-default policy ve BoardCfg/eFuse koşulları vardır. Debug certificate üretmek tek başına JTAG açmak değildir.", ("TISCI-DEBUG", "TISCI-BOARDCFG")),
]

CARDS = {x.id: x for x in _CARDS}


def list_learning_cards() -> list[dict[str, Any]]:
    return [asdict(x) for x in _CARDS]


def get_learning_card(card_id: str) -> dict[str, Any]:
    if card_id not in CARDS:
        raise KeyError(card_id)
    return asdict(CARDS[card_id])


_CHECK_EXPLANATIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "certificate_signature_with_embedded_public_key": ("Embedded public key ile certificate signature doğrulaması yalnız certificate'ın matematiksel self-consistency durumunu gösterir. Bu public key'in cihazda trusted/provisioned olduğunu kanıtlamaz.", ("TISCI-AUTH",)),
    "appended_payload_sha512_binding": ("Actual appended payload/ciphertext SHA2-512 değeri certificate Image Integrity Extension ile karşılaştırılır. Certificate signature kontrolünden bağımsızdır.", ("TISCI-AUTH", "TISCI-SIGNING")),
    "system_firmware_load_extension_present": ("Authenticated application/generic binary için System Firmware Load Extension gereklidir. Studio exact destination/host değerini tahmin etmez.", ("TISCI-AUTH", "TISCI-X509")),
    "aes_cbc_ciphertext_block_alignment": ("AES-CBC ciphertext 16-byte block alignment gerektirir. Alignment tek başına doğru MEK veya doğru plaintext kanıtı değildir.", ("TISCI-SIGNING",)),
    "otp_efuse_programming_result": ("Certificate veya provisioning profile host-side incelenebilir; OTP/eFuse programming sonucu dosyadan çıkarılamaz ve Studio bu irreversible işlemi çalıştırmaz.", ("TISCI-KEYWRITER",)),
    "target_debug_authorization": ("Debug certificate yapısı host üzerinde incelenebilir; target UID, active customer key, BoardCfg ve eFuse izinleri target-side authorization sonucunu belirler.", ("TISCI-DEBUG", "TISCI-BOARDCFG")),
    "separate_encryption_control_chains": ("Bu kontrol ENC_ENABLED zincirinin application signer'a, ENC_SBL_ENABLED zincirinin ROM/SBL generator'a gittiğini ayrı ayrı doğrular. İki switch aynı artifact katmanını kontrol etmez.", ("SDK-TOOLS-SECURITY", "SDK-INSTALLED")),
    "application_encryption_selector": ("Application Makefile'ın ENC_ENABLED seçimini gerçekten tüketmesi gerekir; devconfig değeri tek başına signer'a ulaştığını kanıtlamaz.", ("SDK-INSTALLED",)),
    "application_encryption_options": ("Encryption enable edildiğinde application signer'a --enc ve --enckey seçeneklerinin aktarılması consumer chain'in kritik bağlantısıdır.", ("SDK-TOOLS-SECURITY", "SDK-INSTALLED")),
    "sbl_encryption_selector": ("SBL/ROM tarafında ENC_SBL_ENABLED ayrı seçimdir; application ENC_ENABLED ile karıştırılmamalıdır.", ("SDK-INSTALLED",)),
    "sbl_encryption_options": ("ROM/SBL encryption için rom_image_gen.py tarafına --sbl-enc ve --enc-key seçeneklerinin ulaştığı kontrol edilir.", ("SDK-TOOLS-SECURITY", "SDK-INSTALLED")),
    "application_encryption_oid": ("Application encryption metadata'sının System Firmware Encryption Extension OID .1.4 ile üretildiğini source üzerinde doğrular.", ("TISCI-X509", "SDK-TOOLS-SECURITY")),
    "application_integrity_oid": ("Application image-integrity extension .1.34 ile SHA-512 binding'in source zincirinde bulunduğunu doğrular.", ("TISCI-AUTH", "SDK-TOOLS-SECURITY")),
    "rom_sbl_encryption_oid": ("ROM/SBL encryption extension .1.10 application encryption extension .1.4'ten farklıdır.", ("SDK-TOOLS-SECURITY",)),
    "profile_type": ("Profile türü, yanlış workflow/profile formatının sessizce kabul edilmesini önler.", ()),
    "mode": ("Provisioning hazırlığı yalnız offline_only modunda kabul edilir; GUI irreversible execution'a geçmez.", ("TISCI-KEYWRITER",)),
    "key_count": ("KEYCNT mevcut customer key-set sayısını sınırlar ve KEYREV yorumunun hangi setlere izin verdiğini belirler.", ("TISCI-KEYWRITER",)),
    "key_revision": ("KEYREV active signing/encryption setinin SMPK/SMEK veya BMPK/BMEK bağlamını seçer; valid değer target write'ın yapıldığı anlamına gelmez.", ("TISCI-KEYWRITER",)),
    "smpk_rsa4096": ("Bu proje TISCI 12.00.02 Key Writer sürümünde SMPK/BMPK için RSA-4096 formatını kontrol eder.", ("TISCI-KEYWRITER",)),
    "bmpk_rsa4096": ("Backup signing public key yalnız key_count=2 bağlamında ve RSA-4096 olarak doğrulanır.", ("TISCI-KEYWRITER",)),
    "smpkh_sha512": ("SMPKH provisioning adayı exact DER public-key byte'larının SHA2-512 hash'idir; private key değildir.", ("TISCI-KEYWRITER",)),
    "bmpkh_sha512": ("BMPKH provisioning adayı exact DER backup public-key byte'larının SHA2-512 hash'idir.", ("TISCI-KEYWRITER",)),
    "smek_format": ("SMEK için yalnız AES-256 raw-hex formatı kontrol edilir; secret value/path/hash rapora alınmaz.", ("TISCI-KEYWRITER",)),
    "bmek_format": ("BMEK optional backup symmetric key'dir; yalnız format kontrolü yapılır ve secret değer paylaşılmaz.", ("TISCI-KEYWRITER",)),
    "ti_fek_keywriter_package_match": ("TISCI, TI FEK ile Keywriter firmware'in aynı Keywriter package'ından gelmesini ister. Package kanıtı verilmeden bu gate PASS sayılamaz.", ("TISCI-KEYWRITER",)),
    "otp_write_host": ("Security BoardCfg write_host alanı revision-write requester policy'sinin girdisidir; Host ID'nin gerçek SoC rolü exact host map olmadan tahmin edilmez.", ("TISCI-BOARDCFG",)),
    "otp_write_host_secure_proxy_mapping": ("TISCI write_host için secure-proxy thread mapping gereksinimi vardır; yalnız numeric Host ID görmek mapping'i kanıtlamaz.", ("TISCI-BOARDCFG",)),
    "allow_jtag_unlock": ("Runtime debug unlock ancak Security BoardCfg policy izin veriyorsa değerlendirilebilir; bu tek başına target JTAG unlock değildir.", ("TISCI-DEBUG", "TISCI-BOARDCFG")),
    "allow_wildcard_unlock": ("Wildcard UID policy SOC UID eşleşmesinin atlanıp atlanamayacağını belirler; production güvenliği açısından ayrıca değerlendirilmelidir.", ("TISCI-DEBUG", "TISCI-BOARDCFG")),
    "jtag_unlock_hosts": ("TISCI üzerinden debug request yapacak requester host BoardCfg allow-list ile ilişkilidir.", ("TISCI-DEBUG", "TISCI-BOARDCFG")),
    "execution_boundary": ("Bu kontrol aracın yalnız read-only/offline davranışta kaldığını ve build/signing/OTP/debug/lifecycle execution yapmadığını doğrular.", ()),
}


def _generic_explanation(check_id: str, status: str | None, detail: str | None) -> str:
    state = str(status or "INFO")
    detail_text = (detail or "").strip()
    if state == "PASS":
        lead = "Bu satırda tanımlanan host-side koşul gözlenen girdilerle sağlandı."
    elif state in {"FAIL", "ERROR"}:
        lead = "Bu koşul sağlanmadığı için ilgili workflow sonucu güvenli biçimde ilerletilemez veya daha dar yorumlanmalıdır."
    elif state in {"NOT_CHECKED", "PARTIAL", "WARN"}:
        lead = "Bu koşul için yeterli girdi/kanıt yok veya sonuç kısmi; Studio bunu PASS'e yükseltmez."
    else:
        lead = "Bu satır workflow'un bir teknik durumunu açıklar; tek başına daha geniş bir security claim oluşturmaz."
    if detail_text and detail_text != "—":
        return f"{lead} Gözlenen ayrıntı: {detail_text}"
    return lead


def explain_check(check_id: str, status: str | None = None, detail: str | None = None) -> dict[str, Any]:
    record = _CHECK_EXPLANATIONS.get(check_id)
    if record:
        text, sources = record
    else:
        text, sources = _generic_explanation(check_id, status, detail), ()
    return {"check": check_id, "explanation": text, "sources": list(sources)}


def explain_result(result: dict[str, Any]) -> dict[str, Any]:
    checks = result.get("checks") or result.get("verification", {}).get("checks") or []
    seen: set[str] = set()
    items = []
    for check in checks:
        cid = check.get("check")
        if cid and cid not in seen:
            seen.add(cid)
            exp = explain_check(cid, check.get("status"), check.get("detail") or check.get("reason"))
            exp["status"] = check.get("status")
            items.append(exp)
    return {
        "operation": result.get("operation") or result.get("classification") or "result",
        "status": result.get("status") or result.get("overall_host_side_verification") or "INFO",
        "items": items,
        "non_claims": result.get("non_claims", []),
    }
