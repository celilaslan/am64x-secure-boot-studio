# X.509 certificate işlemleri

AM64x Secure Boot akışında tek bir X.509 formatı yoktur. ROM combined image, System Firmware application/generic authentication, Secure Debug ve OTP Keywriter farklı extension setleri kullanır. Toolkit bu bağlamları ayrı tutar.

## Application / generic data certificate

TISCI 12.00.02 System Firmware profile'ında kullanılan temel alanlar:

```text
.1.3   System Firmware Software Revision Extension
.1.34  System Firmware Image Integrity Extension
.1.35  System Firmware Load Extension
.1.33  System Firmware Boot Extension        (gerekiyorsa)
.1.4   System Firmware Encryption Extension  (encryption varsa)
```

`securectl cert build` signed-only application için `.1.3`, `.1.34` ve `.1.35` üretir. Boot Extension profile'da açıkça etkinleştirilirse `.1.33` de eklenir.

`.1.34` içinde hash algoritması SHA2-512'dir ve `imageSize` payload byte sayısını taşır. `.1.35` içindeki `destAddr` 64-bit big-endian olarak kodlanır. `auth_type` lower byte'ta mode, sonraki byte'ta `copy_as_host`, üst 16 bit'te reserved alan taşır.

Signed-only package:

```text
DER X.509 certificate || payload
```

Encrypted application için toolkit kendi encryption formatını üretmez. Kurulu `appimage_x509_cert_gen.py`, `securectl build app --enckey ...` üzerinden çağrılır.

## Boot Extension

`.1.33` içindeki başlıca alanlar:

```text
bootCore
configFlags_set
configFlags_clr
resetVec
fieldValid
rsvd1
rsvd2
rsvd3
```

Processor ID, flag ve reset-vector değerleri profile'a kullanıcı tarafından exact SoC/API kaynağına göre girilir. Toolkit bu değerleri tahmin etmez.

## Secure Debug certificate

TISCI Secure Debug akışı iki extension bekler:

```text
.1.3  Software Revision
.1.8  Debug Extension
```

Debug Extension alanları:

```text
debugUID
debugType
coreDbgEn
coreDbgSecEn
```

`debugType` alt 16 bit'te debug privilege, üst 16 bit'te reserved alan taşır. Toolkit reserved alanın sıfır olmasını ve privilege değerinin TISCI 12.00.02'deki `0..5` aralığında olmasını kontrol eder.

`coreDbgEn` ve `coreDbgSecEn` processor ID byte'larının birleşimidir. Hiçbir core seçilmeyecekse TISCI dokümanındaki `0xFF` no-core işareti kullanılabilir.

All-zero SOC UID ancak profile'da `wildcard_uid: true` açıkça seçilirse kabul edilir. Bu seçim target BoardCfg'nin wildcard unlock'a izin verdiği anlamına gelmez.

Certificate üretmek target üzerinde debug açmaz. Gerçek kabul; active customer key, eFuse public-key hash, certificate revision, SOC UID, Security Board Configuration ve runtime izinleriyle birlikte değerlendirilir.

## ROM combined certificate

ROM certificate yapısı System Firmware application certificate'ından farklıdır. Toolkit bu yapıyı yeniden üretmek yerine kurulu SDK `rom_image_gen.py` aracını kullanır.

`securectl cert new rom` yalnız gerekli girdilerin doldurulmasını kolaylaştıran bir profile oluşturur. Gerçek image üretimi `securectl build rom` ile yapılır.

## Keywriter certificate preflight profile

`securectl cert new keywriter`, Keywriter certificate tarafında kullanılacak secret olmayan public-key metadata'sını önceden kontrol etmek için basit bir profile oluşturur. `KEYCNT=1` SMPK setini, `KEYCNT=2` ise SMPK + BMPK setlerini gerektirir; `KEYREV`, `KEYCNT` değerinden büyük olamaz. `KEYCNT=0` için numeric `KEYREV` üretilmez.

TISCI 12.00.02 Key Writer için SMPK/BMPK public key'ler RSA-4096 olmalıdır. SMPKH/BMPKH bağlamında ilgili DER public key üzerinde SHA2-512 kullanılır.

Private SMPK/BMPK, SMEK veya BMEK değeri bu profile'a alınmaz. Daha geniş HS-FS → HS-SE hazırlık kontrolü, optional SWREV ve local SMEK/BMEK format kontrolü için `securectl provision preflight` kullanılır. OTP Keywriter çağrısı ve eFuse programlama hiçbir iki komutta da yapılmaz.

## Certificate doğrulama sınırı

`securectl verify`, certificate içindeki public key ile signature consistency kontrolü yapabilir. Bu, target cihazdaki active customer Root of Trust ile eşleşmeyi tek başına kanıtlamaz.

Benzer şekilde payload/ciphertext hash kontrolü certificate signature kontrolünden ayrıdır.
