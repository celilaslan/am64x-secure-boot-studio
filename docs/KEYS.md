# Anahtar kontrolleri

`securectl key`, signing key ve application/ROM encryption için kullanılan MEK dosyalarını image üretmeden önce kontrol etmek için kullanılır. Bu komutlar anahtar değerlerini veya private/symmetric key hash'lerini raporlamaz.

## Signing key kontrolü

```bash
securectl key signing <LOCAL_KEY_OR_CERTIFICATE> --purpose application
```

Girdi PEM/DER private key, public key veya X.509 certificate olabilir. Private key verilirse yalnız public tarafı türetilir. Çıktıda:

- key türü ve RSA olup olmadığı,
- RSA key size,
- public exponent bilgisi,
- DER-SPKI SHA-256 fingerprint,
- seçilen kullanım için doğrulanabilen key-size gereksinimi

gösterilir.

`application` için TISCI 12.00.02 System Firmware authentication akışı RSA-4K imza doğrulamasını destekler. `keywriter` için aynı sürüm Key Writer yalnız 4096-bit RSA SMPK/BMPK desteği tanımlar. `rom` seçiminde toolkit bu iki kaynaktaki kısıtı ROM signer'a otomatik genellemez; exact ROM/SDK gereksinimi ayrıca doğrulanmalıdır.

Public DER-SPKI dosyası gerekiyorsa:

```bash
securectl key signing <LOCAL_KEY_OR_CERTIFICATE> \
  --purpose application \
  --public-der-output public.der
```

Üretilen dosya public material'dir. Private key dosyası değiştirilmez.

## Private/public eşleşmesi

```bash
securectl key compare <LOCAL_PRIVATE_KEY> <PUBLIC_KEY_OR_CERTIFICATE>
```

Private key'in public tarafı DER-SPKI biçiminde türetilir ve reference public key/certificate ile SHA-256 fingerprint üzerinden karşılaştırılır. Private key'in kendisi veya hash'i raporlanmaz.

Bu fingerprint, Keywriter provisioning sırasında kullanılan `SMPKH/BMPKH` değeri değildir. `SMPKH/BMPKH`, TISCI 12.00.02 Key Writer bağlamında corresponding public DER verisi üzerinde SHA2-512 olarak tanımlanır.

## MEK format kontrolü

```bash
securectl key mek <LOCAL_MEK_FILE>
```

Kurulu MCU+ SDK 12.00.00.27 signing araçları encryption-key text'ini OpenSSL `-K` seçeneğine iletir. AES-256 için tam key 32 byte, yani 64 hexadecimal karakterdir.

Toolkit şu kontrolleri yapar:

- dosya ASCII text olarak okunabiliyor mu,
- yalnız hexadecimal karakterlerden oluşuyor mu,
- trimmed içerik tam 64 hex karakter mi,
- dosyada 64 hex karakter dışında ek whitespace var mı.

Tam 64 hexadecimal karakter ve ek whitespace olmayan dosya `PASS` olur. Örneğin sonundaki newline nedeniyle içerik trim edildiğinde 64 hex karakter kalıyorsa sonuç `PARTIAL` verilir; değer otomatik düzeltilmez.

Bu ek sıkılık bilinçlidir. Projede incelenen OpenSSL 3.5.6 davranışında 63 ve 65 hex karakterlik `-K` girdileri hata yerine warning ile kabul edilmiştir. Toolkit bu durumu güvenli bir key formatı olarak kabul etmez.

MEK değeri, MEK hash'i ve private key hash'i JSON çıktısına yazılmaz.

## Şifreli private key

Preflight passphrase istemez veya kaydetmez. Şifreli private key doğrudan kontrol edilemiyorsa public key veya certificate kullanılır. Certificate üretim/build aşamasındaki key yönetimi kurumun secret-management yöntemine göre ayrıca ele alınmalıdır.

## v2 — Synthetic key generation

v2 yalnız development/test ve offline provisioning rehearsal için local key generation sunar:

```bash
securectl key generate signing --role application --output-dir <EMPTY_DIR>
securectl key generate mek --role application --output-dir <EMPTY_DIR>
securectl key generate set --profile development --output-dir <EMPTY_DIR>
```

Offline customer-key hierarchy çalışması için, gerçek provisioning yapmadan:

```bash
securectl key generate set --profile provisioning-test --backup --output-dir <EMPTY_DIR>
```

Davranış:

- RSA signing key: RSA-4096, public exponent 65537;
- MEK/SMEK/BMEK test material: exact 256-bit / 64 hexadecimal karakter;
- secret dosyalar POSIX üzerinde `0600`, public DER/manifest `0644` oluşturulur;
- mevcut dosyanın üzerine yazılmaz;
- key material önce geçici dosyada stage edilir, mevcut `preflight_signing_key()` / `preflight_mek()` ile doğrulanır ve sonra final ada atomik olarak taşınır;
- `keyset-manifest.json` secret value/hash/path veya secret filename içermez;
- SMPK/BMPK public DER için hesaplanan SHA-512 değeri public provisioning **candidate** bilgisidir; target provisioning execution değildir.

Üretilen material her zaman:

`development/test / synthetic / non-production / unprovisioned / offline-only`

olarak sınıflandırılır.
