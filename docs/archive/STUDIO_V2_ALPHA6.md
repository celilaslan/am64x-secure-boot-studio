# AM64x Secure Boot Studio v2.0.0-alpha7

## Amaç

`alpha6`, alpha5'te GUI'ye bağlanan workflow'ları daha az JSON, daha fazla insan-okunur sonuç ve gerçek adım-adım kullanım akışıyla sunan **UX polish** milestone'udur. Secure Boot teknik state'i veya frozen project evidence yeniden çalıştırılmaz; bu yalnız toolkit geliştirme scope'udur.

## Ana değişiklikler

### Gerçek Secure Application Wizard

Application ekranı artık tek uzun form değildir. Beş adım vardır:

1. Application / MCU+ SDK context
2. Signing + optional encryption
3. Output
4. Çalıştırmadan önce özet
5. Sonuç

Her adım yalnız kendi zorunlu alanlarını doğrular. Signing/encryption secret value veya hash review ekranına yazılmaz. Build başlamadan önce host-side işlem ile OTP/eFuse/lifecycle/hardware enforcement sınırı tekrar gösterilir.

### İnsan-okunur Result View

Application, ROM, Inspector, Key Center ve Negative Tests sonuçları raw JSON kutusu yerine ortak `HumanResultView` üzerinden gösterilir:

- PASS / FAIL / PARTIAL / NOT_CHECKED durum badge'i;
- kısa işlem özeti;
- kontrol tablosu;
- share-safe output filename bilgisi;
- `Kanıtlar / Kanıtlamaz` paneli;
- ham JSON yalnız `Teknik Ayrıntı` sekmesinde.

Bu katman workflow sonucunu değiştirmez; yalnız presentation modelidir.

### Image Anatomy

Inspector'a read-only görsel image map eklendi. Parsed artifact'a göre:

- X.509 certificate;
- appended plaintext payload veya ciphertext;
- ROM combined image için parsed component listesi

byte boyutlarına göre görselleştirilir. Load address, missing offset, core/host ID veya target behavior tahmin edilmez.

### Guided error UX

Ana GUI workflow'larında yalnız `ExceptionType: message` göstermek yerine:

- **Ne oldu?**
- **Neden olabilir?**
- **Ne yapabilirsiniz?**
- açılabilir **Teknik ayrıntı**

formatı kullanılır. File-not-found, permission ve invalid-input sınıfları için özel yönlendirme vardır. Exact address/ID/OID/key formatı source olmadan uydurulmaz.

### Negative Test sonucu

Single ve automatic suite sonuçları kullanıcıya test case tablosu halinde gösterilir. Original source'un değişmediği ayrı kontrol olarak görünür; mutasyon output'u yalnız test copy'dir.

### Result Center

Current result ve session history insan-okunur özet kullanır. Ham JSON kaybolmaz; secondary technical detail / explicit export olarak korunur.

## Güvenlik sınırı

Alpha6 aşağıdaki işlemleri eklemez:

- OTP/eFuse/customer-key programming;
- HS-FS → HS-SE transition;
- permanent debug/security write;
- hardware application authentication/decryption execution;
- customer Root of Trust enforcement claim.

Key generation synthetic/non-production/unprovisioned/offline-only sınıfındadır.

## QA durumu

- Pure-Python regression: PASS
- presentation/anatomy/error model tests: PASS
- Python compile: PASS
- wheel build/install smoke: release QA sırasında kaydedilir
- real PySide6 window render/screenshot QA: bu environment'ta PySide6 yoksa `NOT EXECUTED`
- Linux/Windows standalone clean-machine QA: ayrıca yapılmalıdır
