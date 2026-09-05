# Kullanım Kılavuzu

Bu belge `securectl` komutlarının ayrıntılı kullanımını açıklar. Komutların tam seçenek listesi için `securectl --help` ve ilgili alt komutun `--help` çıktısı kullanılabilir.

## Kurulum

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Test araçlarını da kurmak için:

```bash
pip install -e '.[dev]'
```

## Hızlı başlangıç

```bash
securectl inspect <IMAGE_OR_CERTIFICATE>
securectl verify <IMAGE_OR_CERTIFICATE>
securectl cert new app --output app.yaml
securectl cert validate app.yaml
securectl key signing <LOCAL_KEY_OR_CERTIFICATE> --purpose application
securectl key mek <LOCAL_MEK_FILE>
securectl provision new --output provision.yaml
securectl provision preflight provision.yaml
securectl revision key-matrix
securectl revision swrev --context tiboot3 --reference 2 --certificate 3
securectl boardcfg new --output security-boardcfg.yaml
securectl boardcfg check security-boardcfg.yaml
securectl sdk lint --devconfig <SDK>/devconfig/devconfig.mak ...
securectl sdk diff --old-app-tool <OLD_APP_SIGNER> --new-app-tool <NEW_APP_SIGNER>
securectl errata list --revision 2.0 --category security
securectl errata check --revision 2.0 --device-state hs-fs --flow full-combined --outer-rsa degenerate
securectl data new --output data.yaml
securectl data build data.yaml --key <PRIVATE_SIGNING_KEY_PATH> --output data.secure
securectl report image <IMAGE> --output verification-report.md
securectl report batch <IMAGE1> <IMAGE2> --output verification-summary.md
securectl gui
securectl build app ...
securectl build rom ...
```

Tüm komutlar için:

```bash
securectl --help
securectl cert --help
```

## Image ve certificate inceleme

`securectl inspect`, dosyanın başındaki DER X.509 certificate'ı ayırır ve desteklenen TI extension'larını okur. Application/generic data, ROM combined image, Secure Debug certificate ve tanınan Keywriter extension ailelerini ayırt edebilir.

Desteklenen başlıca alanlar:

- `.1.3` System Firmware Software Revision Extension
- `.1.4` System Firmware Encryption Extension
- `.1.8` System Firmware Debug Extension
- `.1.9` ROM extended boot information
- `.1.33` System Firmware Boot Extension
- `.1.34` System Firmware Image Integrity Extension
- `.1.35` System Firmware Load Extension
- seçili Keywriter `.1.67-.1.81` alanları

Encryption ve Keywriter içindeki key/IV/random-string gibi hassas byte değerleri çıktıya yazılmaz. Yalnız boyut, revision, OID ve benzeri yapısal bilgiler gösterilir.

## Image doğrulama

`securectl verify`, certificate signature ile payload/ciphertext integrity kontrollerini ayrı ayrı yapar.

Application/generic data için örnek kontroller:

- certificate içindeki public key ile signature consistency
- `.1.34` image size
- SHA2-512 payload/ciphertext binding
- `.1.35` Load Extension yapısı
- Boot Extension kullanılıyorsa reserved alanlar ve reset-vector genişliği
- encryption metadata uzunlukları ve AES block alignment

ROM combined image için `.1.9` içindeki component boyutları ve SHA2-512 değerleri ayrı ayrı kontrol edilir. `.1.9` ile legacy `.1.1/.1.2` extension'larının birlikte bulunması hata olarak raporlanır.

Secure Debug certificate için `.1.3` ve `.1.8` varlığı, UID uzunluğu, `debugType` yapısı ve core listelerinin temel biçimi kontrol edilir. Target cihazdaki active customer key, SOC UID, Security Board Configuration ve runtime izinleri host üzerinde doğrulanamayacağı için bu bölüm `PARTIAL` kalabilir.

## Negatif testler

`securectl negative`, kaynak image'ı değiştirmeden ayrı bir test kopyası üretir ve yapılan değişikliğin mevcut doğrulama kontrolleri tarafından yakalanıp yakalanmadığını gösterir.

Tüm testler kopya üzerinde çalışır. Kaynak dosyanın SHA-256 değeri işlemden önce ve sonra kontrol edilir; mevcut bir çıktı dosyasının üzerine yazılmaz.

Signed application için:

```bash
securectl negative signature app.secure --output app.neg-signature
securectl negative tbs app.secure --output app.neg-tbs
securectl negative payload app.secure --output app.neg-payload
```

Encrypted application için payload yerine ciphertext testi kullanılır:

```bash
securectl negative ciphertext app.appimage.hs --output app.neg-ciphertext
```

ROM combined image için belirli bir component değiştirilebilir:

```bash
securectl negative component tiboot3.bin \
  --component-index 1 \
  --output tiboot3.neg-component-1
```

Image türüne uygun testlerin tamamını tek seferde çalıştırmak için:

```bash
securectl negative suite <IMAGE> --output-dir negative-tests
```

Suite sonunda `negative_test_report.json` oluşturulur. Signature/TBSCertificate testlerinde certificate signature kontrolünün, payload/ciphertext testlerinde `.1.34` SHA2-512 binding'in, ROM component testlerinde ise ilgili component SHA2-512 kontrolünün beklenen şekilde hata vermesi aranır.

Ayrıntılar için `docs/NEGATIVE_TESTS.md` dosyasına bakılabilir.

## Doğrulama raporları

Tek bir secure image veya certificate için Markdown raporu üretmek için:

```bash
securectl report image <IMAGE> \
  --output verification-report.md \
  --json verification-report.json
```

Birden çok dosyayı tek tabloda özetlemek için:

```bash
securectl report batch <IMAGE1> <IMAGE2> <IMAGE3> \
  --output verification-summary.md \
  --json verification-summary.json
```

Raporlarda dosya/certificate SHA-256 değerleri, image türü, TISCI kullanım biçimi ve `verify` kontrollerinin sonucu bulunur. Toplu komut dizin taraması yapmaz; yalnız açıkça verilen dosyaları işler.

`PASS`, host-side kontrollerin geçtiğini gösterir. Customer Root of Trust provisioning veya hedef cihazdaki authentication/decryption enforcement sonucu değildir.

Ayrıntılar için `docs/REPORTS.md` dosyasına bakılabilir.

## X.509 certificate işlemleri

### Application profile oluşturma

```bash
securectl cert new app --output app.yaml
```

Oluşan YAML dosyasında payload yolu, load address ve gerekiyorsa Boot Extension alanları doldurulur. Toolkit processor ID, load address veya reset vector tahmin etmez.

Profile kontrolü:

```bash
securectl cert validate app.yaml
```

OpenSSL config üretmek için:

```bash
securectl cert render app.yaml --output app.cnf
```

Signed-only application certificate ve `certificate || payload` dosyası üretmek için:

```bash
securectl cert build app.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output app.der \
  --package app.secure
```

Bu komut TISCI System Firmware profile'ındaki SWREV, Image Integrity ve Load extension'larını üretir; Boot Extension yalnız profile'da açıkça etkinleştirilirse eklenir. Encrypted application image üretimi doğrudan bu komutla yapılmaz; kurulu TI `appimage_x509_cert_gen.py` aracı `securectl build app` üzerinden kullanılır.

### Secure Debug certificate

```bash
securectl cert new debug --output debug.yaml
securectl cert validate debug.yaml
securectl cert build debug.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output debug.der
```

Profile içinde SOC UID, certificate revision, debug privilege ve core listeleri açıkça doldurulur. Certificate üretmek JTAG açma işlemi değildir; toolkit `TISCI_MSG_OPEN_DEBUG_FWLS` çağırmaz ve target üzerinde debug policy değiştirmez.

### ROM profile

```bash
securectl cert new rom --output rom.yaml
securectl cert validate rom.yaml
```

ROM combined certificate/image üretimi yeniden uygulanmaz. Gerçek üretim, kurulu SDK'nın `rom_image_gen.py` aracıyla `securectl build rom` üzerinden yapılır.

### Keywriter preflight profile

```bash
securectl cert new keywriter --output keywriter.yaml
securectl cert validate keywriter.yaml
```

Bu profile yalnız public DER key bilgileri ile `KEYCNT`/`KEYREV` gibi secret olmayan metadata kabul eder. SMPK/BMPK public DER için RSA-4096 ve SHA2-512 hesabı kontrol edilebilir. Private key, SMEK veya BMEK değeri profile alınmaz; OTP/eFuse programlama yapılmaz.

### Certificate açıklama

```bash
securectl cert explain <CERTIFICATE_OR_IMAGE>
```

Bu komut certificate türünü ve önemli extension alanlarını kısa bir metin olarak gösterir.

Ayrıntılar için `docs/CERTIFICATES.md` dosyasına bakılabilir.

## Anahtar kontrolleri

Signing key'in public özelliklerini ve application/ROM encryption için kullanılan MEK text dosyasının formatını image üretmeden önce kontrol etmek için `securectl key` kullanılabilir.

```bash
securectl key signing <LOCAL_KEY_OR_CERTIFICATE> --purpose application
securectl key compare <LOCAL_PRIVATE_KEY> <PUBLIC_KEY_OR_CERTIFICATE>
securectl key mek <LOCAL_MEK_FILE>
```

Signing key kontrolü RSA key size ve public DER-SPKI SHA-256 fingerprint'i gösterir; private key içeriğini veya private-key hash'ini raporlamaz. `application` ve `keywriter` amaçlarında doğrulanmış RSA-4096 gereksinimi uygulanır. `rom` için key-size kuralı başka akışlardan taşınmaz ve sonuç bu bölümde `NOT_CHECKED` kalabilir.

MEK kontrolünde değer veya hash yazdırılmaz. AES-256 için 64 hexadecimal karakter kontrol edilir. Kurulu OpenSSL 3.5.6'nın 63/65 hex girdilerini warning ile kabul edebilmesi nedeniyle toolkit bunları geçerli format saymaz.

Ayrıntılar için `docs/KEYS.md` dosyasına bakılabilir.

## HS-FS → HS-SE provisioning hazırlık kontrolü

Toolkit, OTP/eFuse yazımı yapmadan provisioning girdilerini önceden kontrol edebilir. Önce secret içermeyen bir YAML dosyası oluşturulur:

```bash
securectl provision new --output provision.yaml
```

Bu dosyada `KEYCNT`, `KEYREV`, SMPK/BMPK public DER girdileri ve istenirse SWREV alanları doldurulur. Ardından:

```bash
securectl provision preflight provision.yaml
```

Kontroller şunları kapsar:

- `KEYCNT=1` için SMPK seti, `KEYCNT=2` için SMPK + BMPK seti tutarlılığı
- `KEYREV <= KEYCNT` ve active-key context kontrolü
- SMPK/BMPK public DER dosyalarının RSA-4096 olması
- SMPKH/BMPKH adaylarının exact DER byte'ları üzerinden SHA2-512 hesabı
- profile'a eklenmişse SWREV değerlerinin non-zero olması
- isteğe bağlı local SMEK/BMEK text dosyalarının AES-256 raw-hex format kontrolü

SMEK/BMEK kontrolü yapılacaksa secret dosya yolu yalnız komut girdisi olarak verilir; değer, path ve hash rapora kaydedilmez:

```bash
securectl provision preflight provision.yaml \
  --smek <LOCAL_SMEK_FILE> \
  --bmek <LOCAL_BMEK_FILE> \
  --report provision-report.json
```

`PASS`, yalnız offline girdilerin birbirleriyle tutarlı olduğunu gösterir. Araç OTP Keywriter çalıştırmaz, eFuse programlamaz, `KEYREV`/`SWREV` yazmaz ve HS-FS → HS-SE geçişi yapmaz. TI FEK ile Keywriter firmware'in aynı Keywriter package'ından olması gereken eşleşme de package girdileri olmadan otomatik doğrulanmaz.

Ayrıntılar için `docs/PROVISIONING.md` dosyasına bakılabilir.

## KEYREV ve SWREV kontrolü

`securectl revision`, revision alanlarını target'a yazmadan belirli kuralları karşılaştırmak için kullanılır.

KEYCNT/KEYREV durumlarını görmek için:

```bash
securectl revision key-matrix
```

Belirli bir durumu kontrol etmek için:

```bash
securectl revision key --keycnt 2 --keyrev 1
securectl revision key --keycnt 2 --keyrev 1 --target-keyrev 2
```

İkinci komut yalnız `KEYCNT=2` ile `KEYREV=2` hedef durumunun tutarlı olduğunu gösterir. `KEYREV` yazma işleminin hedef cihazda izinli veya uygulanabilir olduğunu söylemez ve hiçbir TISCI/eFuse write çağrısı yapmaz.

SWREV karşılaştırması image/certificate türüne göre yapılır. Örneğin ROM `tiboot3.bin` için:

```bash
securectl revision swrev \
  --context tiboot3 \
  --reference 3 \
  --certificate 2
```

Bu örnekte certificate revision değeri bootloader eFuse SWREV değerinden düşük olduğu için yalnız SWREV kuralı açısından `REJECT_BY_SWREV` sonucu alınır. Aynı komut `boardcfg` ve Secure Debug revision eşiği için de kullanılabilir.

Application/generic data bağlamında toolkit eski image'ın target üzerinde reddedileceğini varsaymaz. TISCI 12.00.02 bu certificate türlerinde SWREV için mevcut ek enforcement davranışı tanımlamadığından sonuç `NO_CURRENT_ENFORCEMENT_MODELED` olarak gösterilir.

Keywriter SWREV alan boyutlarını görmek için:

```bash
securectl revision swrev-info
```

Ayrıntılar için `docs/REVISION.md` dosyasına bakılabilir.

## Security Board Configuration kontrolleri

Security BoardCfg içindeki Secure Debug ve Extended OTP policy alanlarını target'a göndermeden kontrol etmek için:

```bash
securectl boardcfg new --output security-boardcfg.yaml
securectl boardcfg check security-boardcfg.yaml
```

Secure Debug certificate'ın `allow_jtag_unlock`, `allow_wildcard_unlock`, `min_cert_rev` ve `jtag_unlock_hosts` policy'siyle uyumunu değerlendirmek için:

```bash
securectl boardcfg debug-policy security-boardcfg.yaml \
  --certificate debug.der \
  --transport tisci \
  --host-id <HOST_ID> \
  --soc-uid <64_HEX_SOC_UID> \
  --jtag-efuse enabled
```

Extended OTP `write_host` alanının revision-write policy'sini kontrol etmek için:

```bash
securectl boardcfg revision-writer security-boardcfg.yaml --host-id <HOST_ID>
```

Bu komutlar BoardCfg'yi target'a göndermez, debug unlock yapmaz ve `TISCI_MSG_WRITE_SWREV`/`TISCI_MSG_WRITE_KEYREV` çağırmaz. `POLICY_ALLOWS_REQUEST` sonucu yalnız verilen BoardCfg policy girdilerinin isteğe izin verdiğini gösterir; active customer Root of Trust veya target kabulü ayrıca doğrulanmalıdır.

Ayrıntılar için `docs/BOARDCFG.md` dosyasına bakılabilir.

## SDK security configuration kontrolü

`devconfig.mak`, application/SBL Makefile ve kurulu signing script zincirini değiştirmeden incelemek için:

```bash
securectl sdk lint \
  --devconfig <SDK>/devconfig/devconfig.mak \
  --app-makefile <APPLICATION_MAKEFILE> \
  --sbl-makefile <SBL_MAKEFILE> \
  --app-tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --rom-tool <SDK>/source/security/security_common/tools/boot/signing/rom_image_gen.py
```

Linter `ENC_ENABLED` ile application signer zincirini, `ENC_SBL_ENABLED` ile ROM/SBL encryption zincirini ayrı kontrol eder. Makefile içinde olası raw key/MEK değeri veya doğrudan yazılmış key argümanı görülürse değeri göstermeden uyarı verir.

Production amacıyla kontrol yapılacaksa:

```bash
securectl sdk lint ... --intent production
```

Bu durumda full debug seçeneği görülmesi hata sayılır. İstenirse daha önce alınmış `make -pn` çıktısı `--make-db` ile read-only incelenebilir; toolkit `make` komutunu kendisi çalıştırmaz.

Ayrıntılar için `docs/SDK_LINT.md` dosyasına bakılabilir.

## SDK source karşılaştırması

İki SDK veya iki source setindeki Secure Boot ile ilgili değişiklikleri karşılaştırmak için:

```bash
securectl sdk diff \
  --old-label 12.00.00.27 \
  --new-label <NEW_VERSION> \
  --old-devconfig <OLD_DEVCONFIG> \
  --new-devconfig <NEW_DEVCONFIG> \
  --old-app-tool <OLD_APP_SIGNER> \
  --new-app-tool <NEW_APP_SIGNER> \
  --old-rom-tool <OLD_ROM_SIGNER> \
  --new-rom-tool <NEW_ROM_SIGNER>
```

Karşılaştırma yalnız hash farkına bakmaz; `ENC_ENABLED`, `ENC_SBL_ENABLED`, signer CLI seçenekleri, AES-256-CBC/SHA-512 işaretleri ve ilgili TI OID'leri gibi izlenen alanlardaki değişiklikleri de ayrı gösterir. Dosya değiştiği halde bu alanlarda fark görülmezse değişiklik otomatik olarak güvenli kabul edilmez; manuel source review önerilir.

Private key veya MEK değeri rapora yazılmaz. `sdk diff` build/signing çalıştırmaz ve target üzerinde işlem yapmaz.

Ayrıntılar için `docs/SDK_DIFF.md` dosyasına bakılabilir.

## Silicon errata kontrolü

AM64x/AM243x Errata Rev. J içindeki Boot advisories'i silicon revision'a göre listelemek için:

```bash
securectl errata list --revision 2.0
securectl errata list --revision 1.0 --category security
securectl errata list --revision 2.0 --boot-mode uart
```

Secure Boot ve ROM güvenliğiyle doğrudan ilişkili `i2413`, `i2415`, `i2418` ve `i2423` için kullanım koşulları ayrıca değerlendirilebilir:

```bash
securectl errata check \
  --revision 2.0 \
  --device-state hs-fs \
  --flow full-combined \
  --outer-rsa degenerate
```

Araç, advisory'nin revision ve verilen kullanım bağlamıyla eşleşip eşleşmediğini gösterir. Bu sonuç bir arızanın kök nedenini otomatik olarak belirlemez. `i2413` için HS-FS combined image ve outer RSA türü, `i2418` için normal boot flow'da certificate info varlığı, `i2415` için specific redundant/backup boot topolojisi ve `i2423` için HS-FS external-emulator/debug erişim bağlamı ayrı değerlendirilir.

`errata check` target'a erişmez, register yazmaz, TIFS isteği göndermez, debug unlock yapmaz ve OTP/eFuse değiştirmez. Ayrıntılar için `docs/ERRATA.md` dosyasına bakılabilir.

## Generic binary authentication ve encryption

Firmware olarak boot edilmeyecek bir binary dosyayı System Firmware generalized authentication biçiminde hazırlamak için `securectl data` kullanılabilir. Bu kullanımda `.1.3` SWREV, `.1.34` Image Integrity ve `.1.35` Load extension'ları üretilir; `.1.33` Boot Extension özellikle eklenmez.

```bash
securectl data new --output data.yaml
securectl data validate data.yaml
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output data.secure
```

Encryption istenirse profile'da etkinleştirilir ve local MEK yalnız build/verify anında verilir:

```bash
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --mek <LOCAL_MEK_FILE> \
  --output data.secure

securectl data verify data.secure \
  --mek <LOCAL_MEK_FILE> \
  --original <ORIGINAL_DATA>
```

Encrypted generic data üretiminde TISCI 12.00.02 biçimindeki 16-byte IV, 32-byte randomString, `iterationCnt=0`, 32-byte zero salt ve AES-256-CBC kullanılır. `.1.34` SHA2-512 değeri plaintext'e değil ciphertext'e bağlanır. Secret key, IV veya randomString byte değerleri rapora yazılmaz.

Bu komutlar `TISCI_MSG_PROC_AUTH_BOOT` çağırmaz. Host-side doğrulama target üzerindeki customer Root of Trust veya hardware decryption enforcement sonucu değildir. Ayrıntılar için `docs/GENERIC_DATA.md` dosyasına bakılabilir.

## Masaüstü arayüzü

Image/certificate inceleme, doğrulama ve tek dosya Markdown raporu için:

```bash
securectl gui
```

GUI private key veya MEK kabul etmez ve target üzerinde işlem çalıştırmaz. Ayrıntılar için `docs/GUI.md` dosyasına bakılabilir.

## Kurulu TI araçlarıyla secure image build

### Application

```bash
securectl build app \
  --tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --input <APP_MCELF> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_APPIMAGE>
```

Encryption için ayrıca:

```text
--enckey <ENCRYPTION_KEY_PATH>
```

### ROM combined image

```bash
securectl build rom \
  --tool <SDK>/source/security/security_common/tools/boot/signing/rom_image_gen.py \
  --sbl-bin <SBL_BIN> \
  --sysfw-bin <SYSFW_BIN> \
  --sysfw-inner-cert <SYSFW_INNER_CERT> \
  --boardcfg-blob <BOARDCFG> \
  --sbl-loadaddr <SOURCE_VERIFIED_VALUE> \
  --sysfw-loadaddr <SOURCE_VERIFIED_VALUE> \
  --bcfg-loadaddr <SOURCE_VERIFIED_VALUE> \
  --swrv <EXPLICIT_VALUE> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_IMAGE>
```

`--debug` ve `--sbl-enckey` yalnız açıkça verilirse kullanılır. Mevcut output dosyasının üzerine otomatik yazılmaz.

Her iki build komutunda:

```text
--dry-run       girdileri kontrol eder, TI tool'u çalıştırmaz
--post-verify   üretimden sonra bağımsız host-side verify çalıştırır
```

## Build kayıtları

Build sırasında output yanında şu dosyalar oluşturulur:

```text
<output>.build.log
<output>.build-record.json
```

Kayıtlarda kullanılan TI tool'un ve secret olmayan girdilerin kimliği bulunur. Private/symmetric key yolları ve key dosyalarının hash değerleri kaydedilmez. Upstream tool'un `stdout`/`stderr` içeriği de kalıcı log'a yazılmaz; yalnız byte sayısı ve SHA-256 değeri tutulur.


# v2 Studio hızlı başlangıç

GUI dependency ayrı tutulur:

```bash
pip install '.[gui]'
securestudio
```

Environment discovery:

```bash
securectl environment --sdk-root <SDK_ROOT>
```

Project workspace:

```bash
securectl project init <PROJECT_DIR> --name "AM6442 Secure Boot"
```

Development key set:

```bash
securectl key generate set --profile development --output-dir <EMPTY_DIR>
```

GUI'de Home -> Environment -> Project -> Keys -> Secure Application -> Image İnceleme -> Sonuçlar akışı kullanılabilir. v2 alpha2 GUI yüzeyinde OTP/eFuse, HS-FS→HS-SE veya permanent debug/security action sunmaz; Phase 5/6 offline workflow ekranları da artık gerçek backend binding kullanır.
