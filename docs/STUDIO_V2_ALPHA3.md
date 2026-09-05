# AM64x Secure Boot Studio v2.0.0-alpha3

Alpha3, GUI/UX blueprint Phase 7'yi gerçek backend + GUI binding olarak ekler.

## Eklenenler

- **Bana Yol Göster**: kullanıcının tool/OID bilmeden hedefini seçerek doğru workflow'a yönlendirilmesi.
- **Source Trace**: installed-source → same-release SDK/TISCI → errata → TRM/datasheet source priority modeli ve local reference metadata.
- **Learn Mode**: RBL/SBL/SYSFW, lifecycle, certificate context, MPK/MEK, ENC switches, signature-vs-hash ve host-vs-target gibi kısa kaynaklı kartlar.
- **Neden?**: Result Center içinde known verification check'lerinin kısa açıklaması ve source trace bağlantısı.
- **5 Dakikalık Demo Workspace**: synthetic/non-production key set, küçük payload, educational certificate+payload ve copy üzerinde payload negative test.

## Demo'nun bilinçli sınırı

Demo exact System Firmware Load Extension değeri **uydurmaz**. Bu nedenle eğitim artifact'ı `NOT_TARGET_READY` olarak işaretlenir. Demo-level PASS şu gözlemlerin birlikte görülmesi demektir:

1. certificate signature = PASS;
2. payload SHA2-512 binding = PASS;
3. Load Extension eksikliği görünür = FAIL (beklenen / eğitim amaçlı);
4. payload copy mutation integrity tarafından yakalanır = PASS.

Bu demo TI installed signer output'u, hardware authentication/decryption enforcement, customer Root of Trust veya provisioning execution kanıtlamaz.

## Safety

OTP/eFuse write, HS-FS→HS-SE execution ve permanent debug/security change GUI'ye eklenmemiştir.
