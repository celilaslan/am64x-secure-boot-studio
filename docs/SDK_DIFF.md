# SDK source karşılaştırması

`securectl sdk diff`, iki MCU+ SDK/configuration source setini değiştirmeden karşılaştırır. Amaç yalnız dosya hash'lerinin değişip değişmediğini görmek değil; Secure Boot akışında kullanılan belirli configuration ve tool davranışlarında anlamlı fark olup olmadığını da göstermektir.

Araç bir SDK sürümünün güvenli olduğunu otomatik olarak ilan etmez. İzlenen alanlarda fark bulunmasa bile dosya SHA-256 değeri değişmişse manuel source review önerilir.

## Kullanım

Tek bir dosya rolünü karşılaştırmak için:

```bash
securectl sdk diff \
  --old-devconfig <OLD_SDK>/devconfig/devconfig.mak \
  --new-devconfig <NEW_SDK>/devconfig/devconfig.mak
```

Birden fazla rol birlikte verilebilir:

```bash
securectl sdk diff \
  --old-label 12.00.00.27 \
  --new-label <NEW_VERSION> \
  --old-devconfig <OLD_DEVCONFIG> \
  --new-devconfig <NEW_DEVCONFIG> \
  --old-app-makefile <OLD_APPLICATION_MAKEFILE> \
  --new-app-makefile <NEW_APPLICATION_MAKEFILE> \
  --old-sbl-makefile <OLD_SBL_MAKEFILE> \
  --new-sbl-makefile <NEW_SBL_MAKEFILE> \
  --old-app-tool <OLD_APP_SIGNER> \
  --new-app-tool <NEW_APP_SIGNER> \
  --old-rom-tool <OLD_ROM_SIGNER> \
  --new-rom-tool <NEW_ROM_SIGNER> \
  --report sdk-diff.json
```

Her rol için `old` ve `new` dosyasının birlikte verilmesi gerekir. Toolkit SDK dizinlerini tahmin ederek otomatik dosya seçmez.

## Karşılaştırılan alanlar

`devconfig.mak` için:

- `DEVICE_TYPE`
- `ENC_ENABLED`
- `ENC_SBL_ENABLED`
- `APP_SIGNING_KEY` routing durumu
- `APP_ENCRYPTION_KEY` routing durumu

Application Makefile için:

- `appimage_x509_cert_gen.py` consumer bağlantısı
- `ENC_ENABLED`
- `APP_SIGNING_KEY`
- `APP_ENCRYPTION_KEY`
- `--enc`
- `--enckey`

SBL Makefile için:

- `rom_image_gen.py` consumer bağlantısı
- `ENC_SBL_ENABLED`
- `BOOTIMAGE_CERT_KEY`
- `APP_ENCRYPTION_KEY`
- `--sbl-enc`
- `--enc-key`
- `--debug` / `DBG_FULL_ENABLE`

Application signer için:

- `--authtype`, `--enc`, `--enckey`
- AES-256-CBC ve OpenSSL raw-key kullanım işaretleri
- SHA-512
- application encryption OID `.1.4`
- image-integrity OID `.1.34`
- Load OID `.1.35`
- Boot OID `.1.33`
- IV/random-string ve `-nopad` implementation işaretleri
- kurulu 12.00.00.27 signer'da gözlenen `v_TEST_IMAGE_KEY_DERIVE_SALT = "0000"` marker'ı

ROM signer için:

- `--sbl-enc`, `--enc-key`, `--debug`
- SYSFW inner certificate ve BoardCfg seçenekleri
- AES-256-CBC, SHA-512 ve OpenSSL raw-key kullanım işaretleri
- combined-image OID `.1.9`
- SBL encryption OID `.1.10`
- IV/random-string ve `-nopad` implementation işaretleri

## Sonuç sınıfları

`IDENTICAL`
: İki dosyanın SHA-256 değeri aynıdır; dosyalar byte-for-byte aynıdır.

`MAPPED_SECURITY_BEHAVIOR_CHANGED`
: Toolkit'in izlediği configuration/tool özelliklerinden en az biri değişmiştir. Source review gerekir.

`CONTENT_CHANGED_NO_MAPPED_SECURITY_CHANGE`
: Dosyanın SHA-256 değeri değişmiştir fakat izlenen alanlarda fark bulunmamıştır. Bu sonuç değişikliğin güvenlik açısından önemsiz olduğu anlamına gelmez; manuel review önerilir.

## Secret veriler

Karşılaştırma raporu private key, MEK veya literal key değerini göstermez. Source/config içinde olası private-key material veya raw key literal görülürse yalnız dosya rolü, taraf (`old`/`new`) ve finding türü raporlanır.

## Çalıştırılmayan işlemler

`securectl sdk diff`:

- `make` veya build çalıştırmaz,
- signing/encryption yapmaz,
- key dosyalarını kullanmaz,
- target cihaza bağlanmaz,
- OTP/eFuse yazmaz,
- debug unlock veya lifecycle değişikliği yapmaz.

Bu nedenle sonuç bir SDK migration incelemesini hızlandırır; yeni sürümün target üzerinde doğru veya güvenli çalıştığını tek başına kanıtlamaz.

## Studio alpha9 semantic diff görünümü

GUI old/new source text'ini yan yana dökmez. Her role için `classification`, review seviyesi, SHA change durumu ve mapped semantic field değişiklikleri gösterilir. `APP_SIGNING_KEY` / `APP_ENCRYPTION_KEY` gibi configured key alanlarında literal host path kullanıcı arayüzüne taşınmaz. `CONTENT_CHANGED_NO_MAPPED_SECURITY_CHANGE` sonucu güvenli/önemsiz değişiklik anlamına gelmez; manuel review önerisi korunur.
