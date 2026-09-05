# Negatif testler

Bu bölüm, secure image üzerinde yapılan kontrollü değişikliklerin doğrulama kontrolleri tarafından nasıl yakalandığını gösterir. Testler yalnız dosya kopyaları üzerinde çalışır; kaynak image değiştirilmez.

## Kullanım

Tek bir test üretmek için:

```bash
securectl negative signature <IMAGE> --output <COPY>
securectl negative tbs <IMAGE> --output <COPY>
securectl negative payload <SIGNED_APP> --output <COPY>
securectl negative ciphertext <ENCRYPTED_APP> --output <COPY>
securectl negative component <ROM_IMAGE> --component-index 1 --output <COPY>
```

Image türüne uygun testleri toplu çalıştırmak için:

```bash
securectl negative suite <IMAGE> --output-dir negative-tests
```

## Testlerin anlamı

### `signature`

Certificate içindeki `signatureValue` alanının son byte'ında tek bit değiştirilir. `TBSCertificate` ve certificate sonrasındaki data aynı kalır. Normal RSA certificate'ta embedded public key ile yapılan signature kontrolünün `FAIL` vermesi beklenir.

Bu test payload integrity kontrolünü değiştirmez. Application image içinde `.1.34` SHA2-512 değeri payload ile eşleşmeye devam edebilir.

### `tbs`

`TBSCertificate.serialNumber` bir artırılır ve mevcut `signatureValue` aynen korunur. Böylece certificate DER olarak parse edilebilir kalırken imzalanmış içerik değişmiş olur. Signature kontrolünün `FAIL` vermesi beklenir.

Certificate sonrasındaki payload/ciphertext değiştirilmediği için image-integrity hash'i ayrı olarak geçmeye devam edebilir. Bu sonuç certificate signature doğrulaması ile image data integrity kontrolünün farklı kontroller olduğunu gösterir.

### `payload`

Yalnız signed application/generic data için kullanılır. Certificate sonrasındaki plaintext payload kopyasında tek byte değiştirilir. Certificate byte'ları aynı kalır.

Beklenen sonuç:

- certificate signature kontrolü: değişmez;
- `.1.34` SHA2-512 payload binding: `FAIL`.

### `ciphertext`

Yalnız encrypted+signed application/generic data için kullanılır. Ciphertext kopyasında tek byte değiştirilir; certificate değiştirilmez.

Beklenen sonuç `.1.34` içinde certificate'a bağlanan ciphertext SHA2-512 değerinin artık eşleşmemesidir. Bu test decryption yapmaz ve MEK kullanmaz.

### `component`

ROM combined image içindeki seçilen component'ın orta byte'ında tek bit değiştirilir. Certificate ve diğer component'lar aynı kalır.

Beklenen sonuç yalnız değiştirilen component'ın certificate içindeki SHA2-512 değeriyle eşleşmemesidir. `suite` ROM image için tanımlı tüm component'ları ayrı kopyalarda tek tek sınar.

## Çıktı kaydı

Her test JSON çıktısında şunları verir:

- kaynak dosyanın SHA-256 değeri;
- test kopyasının SHA-256 değeri;
- değiştirilen alan veya byte offset'i;
- kaynak dosyanın değişmediği kontrolü;
- `securectl verify` sonucu;
- beklenen hatanın görülüp görülmediği.

`negative suite` ayrıca `negative_test_report.json` dosyasını oluşturur.

## Sınırlar

Bu testler host üzerinde dosya ve X.509 yapısını doğrular. Target cihazdaki customer Root of Trust, hardware authentication/decryption enforcement veya HS-SE davranışını kanıtlamaz.

Wrong-MEK testi bu komut grubunda yapılmaz; bu test simetrik secret kullanımını ve decryption sonucunun ayrıca değerlendirilmesini gerektirir. Toolkit secret değerini rapora veya test dosyasına yazmaz.
