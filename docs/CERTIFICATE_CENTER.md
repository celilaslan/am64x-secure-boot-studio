# AM64x Secure Boot Studio — Certificate Center

Bu belge `2.0.0-alpha26` Certificate Center kapsamını ve güvenlik sınırlarını açıklar.

## 1. Amaç

Certificate Center, AM64x secure-boot çalışmasında kullanılan X.509 nesnelerini tek bir generic sertifika gibi ele almaz. Aşağıdaki context'ler ayrı tutulur:

- ROM / RBL combined-image certificate
- Application / generalized-auth certificate
- Secure Debug certificate
- Generic Data certificate
- OTP Keywriter provisioning certificate

Aynı ASN.1/X.509 taşıyıcısını kullanmaları aynı consumer, extension seti veya güvenlik kararı anlamına gelmez.

## 2. Kullanıcı akışları

### Yeni Certificate

GUI üzerinden Application veya Secure Debug certificate sıfırdan oluşturulabilir. Create akışı beş adımlı wizard olarak sunulur: `Kimlik -> TI Alanları -> Signing Key -> Çıktı -> Kontrol`. Alpha24 ile `Software Revision`, X.509 Subject/Kimlik alanlarından ayrılarak `TI Alanları` adımına taşınmıştır. Subject alanları kullanıcı tarafından tek tek doldurulur:

- Country (`C`)
- State / Province (`ST`)
- Locality (`L`)
- Organization (`O`)
- Organizational Unit (`OU`)
- Common Name (`CN`)
- Email

Subject bir signing key, public-key hash veya Root of Trust değildir.

Certificate mechanics görünür biçimde belirtilir:

- Issuer = Subject (self-signed X.509)
- serial number = cryptographic-random
- public key = seçilen RSA-4096 signing key'in public tarafı
- certificate signature = RSA + SHA-512
- Basic Constraints = `CA=true`, TI template davranışıyla uyumlu
- validity = kullanıcı tarafından gün cinsinden seçilir

### Application certificate

GUI şu alanları yönetir:

- Subject
- payload/application file
- Software Revision
- System Firmware Image Integrity (SHA2-512 + payload size, otomatik)
- System Firmware Load Extension
  - destination address
  - `auth_type` low byte: authentication/copy mode `0`, `1`, `2`
  - `auth_type` upper byte: destination Host ID (`copy_as_host`)

TISCI wire-formatında bunlar iki ayrı extension değildir; aynı `auth_type` INTEGER alanının iki parçasıdır. Studio GUI'deki iki kullanıcı seçimini tek `auth_type` değerine birleştirir.
- optional System Firmware Boot Extension
  - boot core
  - config flags set/clear
  - reset vector
  - field-valid

Target-specific address/core/flag/Host ID değerleri Studio tarafından tahmin edilmez.

Encrypted application için generic builder kullanılmaz. AES-256-CBC, IV, randomString, encryption extension ve ciphertext SHA-512 binding davranışı kurulu TI `appimage_x509_cert_gen.py` workflow'una delegate edilir.

### Secure Debug certificate

GUI şu alanları yönetir:

- Subject
- Software Revision / certificate revision
- 32-byte SOC UID
- optional wildcard UID seçimi
- source-backed debug privilege `0..5`
- non-secure processor ID listesi
- secure processor ID listesi

Hiçbir core seçilmeyecekse `0xFF` no-core encoding'i kullanılır. Processor ID değerleri Studio tarafından tahmin edilmez.

Secure Debug certificate üretmek target JTAG unlock değildir. Active customer key, SOC UID/wildcard policy, minimum certificate revision, Security BoardCfg ve runtime authorization ayrıca target-side koşullardır.

## 3. Explorer / Doğrulama

DER, PEM ve certificate+payload image okunabilir.

Gösterilen public metadata:

- classification/context
- Subject
- Issuer
- serial number
- validity dates/state
- public key type/size
- DER-SPKI SHA-256 developer fingerprint
- signature algorithm OID/hash
- Basic Constraints
- TI extension OID listesi
- decoded source-backed TI extension alanları

Host-side verification:

- certificate signature mathematical self-consistency
- mandatory/context extension checks
- payload/ciphertext varsa declared size/hash binding
- Load/Boot/Debug structure checks
- ROM combined component hash/size checks when component bytes are present

Standalone Application/ROM certificate seçildiğinde accompanying payload/component bytes yoksa ilgili payload/hash kontrolleri `NOT_CHECKED` olur; yokluğu yanlışlıkla integrity `FAIL` sayılmaz.

Host-side verification target customer Root of Trust veya hardware enforcement kanıtı değildir.

## 4. Yeniden Üret / Reissue

Signed X.509 byte'ları doğrudan düzenlenmez. Subject veya extension değiştirilecekse:

1. existing certificate parse edilir,
2. desteklenen alanlar yeni profile'a taşınır,
3. kullanıcı alanları düzenler,
4. Application için payload yeniden seçilir,
5. yeni certificate üretilir,
6. yeni certificate yeniden imzalanır ve doğrulanır.

Original certificate değiştirilmez.

## 5. Export ve key association

Desteklenen işlemler:

- DER export
- PEM export
- certificate içinden public DER-SPKI export
- certificate public key ↔ private signing key public tarafı match

Private key değeri veya secret path public export'a taşınmaz.

## 6. Certificate Compare

İki public certificate şu başlıklarda karşılaştırılır:

- context/classification
- Subject
- Issuer
- serial
- validity
- SPKI fingerprint
- signature algorithm
- Basic Constraints
- extension OID setleri

Bu işlem private key veya MEK gerektirmez.

## 7. Project Certificate Library

Aktif Project Workspace altında public certificate kopyaları:

`public/certificates/`

altında tutulabilir.

Library metadata'sı:

- name
- context
- Subject
- validity state/end
- size
- certificate SHA-256
- SPKI SHA-256

Aynı certificate SHA-256 ile duplicate ekleme engellenir. Private key, MEK veya secret path Library'ye alınmaz. Library girdisini kaldırmak external/original certificate'ı silmez.

## 8. ROM certificate context

ROM combined image outer certificate application certificate ile aynı template değildir. Studio generic editor ile ROM certificate üretmeye çalışmaz; official ROM workflow / `rom_image_gen.py` kullanılır. Certificate Center generated ROM image/certificate'ı inspect/verify edebilir.

## 9. Generic Data context

Generic Data workflow System Firmware Integrity + Load ve seçilirse Encryption semantics ile ayrı workflow olarak tutulur. Certificate Center generated public certificate/image'ı inspect/verify/library işlemlerine alabilir.

## 10. OTP Keywriter context

Keywriter provisioning certificate application/debug certificate değildir. Same-release kaynaklar customer key bilgilerinin protected X.509 extension'larda taşındığını, TI FEK + Keywriter package eşleşmesini ve SMPK/BMPK signing ilişkisini tanımlar.

Studio shared-board policy nedeniyle:

- production/customer secret istemez veya kaydetmez,
- OTP/eFuse programming çalıştırmaz,
- HS-FS -> HS-SE geçişi çalıştırmaz,
- KEYREV veya permanent security state değiştirmez.

Certificate Center Keywriter certificate'ı inspect edebilir ve provisioning-preparation workflow'a yönlendirir. Full production Keywriter certificate generation/execution, exact installed matching Keywriter package/tool resolution + dedicated authorized device/runbook olmadan "complete/executable" olarak ilan edilmez.

## 11. Genel PKI scope dışı alanlar

CSR, enterprise CA hierarchy, CRL ve OCSP genel X.509/PKI kavramlarıdır. Version-locked AM64x Secure Boot kaynakları bunları bu self-signed secure-image/debug/vendor certificate workflow'unun parçası olarak tanımlamadığı için Studio AM64x akışına uydurmaz.

## 12. Security claim boundary

Certificate oluşturmak veya host üzerinde doğrulamak şunları kanıtlamaz:

- hardware application-auth enforcement
- hardware application-decryption enforcement
- customer Root of Trust enforcement
- OTP/eFuse provisioning
- HS-FS -> HS-SE transition
- permanent debug/security state
- application rollback enforcement

Bu ayrımlar GUI result boundary ve report katmanlarında korunur.
