# Doğrulama raporları

`securectl report`, `inspect` ve `verify` sonuçlarını daha kolay okunabilen Markdown raporlarına dönüştürür. Bu komut image üzerinde değişiklik yapmaz.

## Tek dosya

```bash
securectl report image firmware.appimage.hs \
  --output firmware-report.md \
  --json firmware-report.json
```

Markdown raporunda dosya ve certificate hash'leri, image türü, TISCI kullanım biçimi, certificate boyutu, DER-SPKI fingerprint'i ve host-side kontroller yer alır.

JSON çıktısı isteğe bağlıdır ve aynı bilgilerin machine-readable karşılığını taşır.

## Birden çok dosya

```bash
securectl report batch \
  tiboot3.bin \
  application.appimage.hs \
  debug.der \
  --output secure-image-summary.md \
  --json secure-image-summary.json
```

Toplu rapor yalnız komutta açıkça verilen dosyaları okur. Dizinleri kendiliğinden taramaz. Böylece aynı klasörde bulunabilecek private key, MEK veya başka hassas dosyaların yanlışlıkla işlenmesi önlenir.

Her dosya için aşağıdaki sonuçlardan biri gösterilir:

- `PASS`: desteklenen host-side kontroller tamamlandı ve hata bulunmadı.
- `PARTIAL`: bazı kontroller target bilgisi veya desteklenmeyen bir alan nedeniyle yapılamadı.
- `FAIL`: doğrulama hatası bulundu.
- `ERROR`: dosya secure image/certificate olarak okunamadı.

## Yorumlama sınırı

Raporlarda certificate signature kontrolü, certificate içindeki public key ile matematiksel tutarlılığı gösterir. Bu public key'in hedef AM64x cihazında provision edilmiş customer Root of Trust ile eşleştiğini göstermez.

Benzer şekilde host-side integrity sonucu:

- OTP/eFuse durumunu,
- HS-FS → HS-SE geçişini,
- customer Root of Trust enforcement'ını,
- hardware application authentication/decryption enforcement'ını

kanıtlamaz. Bunlar ayrı target-side doğrulama gerektirir.
