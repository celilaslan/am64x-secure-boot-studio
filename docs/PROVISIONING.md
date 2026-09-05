# HS-FS → HS-SE provisioning hazırlık kontrolü

`securectl provision`, gerçek provisioning işlemini çalıştırmadan önce customer key ve revision girdilerinin temel tutarlılığını kontrol eder.

Bu bölüm yalnız host-side hazırlık içindir. OTP Keywriter çalıştırılmaz, eFuse yazılmaz ve cihaz lifecycle durumu değiştirilmez.

## Profile oluşturma

```bash
securectl provision new --output provision.yaml
```

Oluşan profile örneği:

```yaml
type: hsfs_to_hsse_preflight
mode: offline_only
key_count: 1
key_revision: 1
smpk_public_der: ./smpk-public.der
bmpk_public_der: null
swrev:
  sysfw: null
  sbl: null
  boardcfg: null
```

Private key veya SMEK/BMEK değeri YAML dosyasına yazılmaz.

## KEYCNT ve KEYREV

TISCI 12.00.02 Key Writer tanımına göre:

- `KEYCNT=1`: SMPK seti kullanılır.
- `KEYCNT=2`: SMPK ve BMPK setleri bulunur.
- `KEYREV`, `KEYCNT` değerinden büyük olamaz.

Security X.509 tanımında `KEYREV=1` SMPK/SMEK, `KEYREV=2` ise BMPK/BMEK active-key context'ini seçer.

HS-FS → HS-SE hazırlık profile'ında `KEYCNT=0` kabul edilmez; bu değer customer root-key seti bulunmayan durumu ifade eder.

## Public key kontrolü

SMPK ve gerekiyorsa BMPK için DER public key dosyaları kullanılır. Araç:

1. DER dosyasını public key olarak parse eder.
2. RSA olduğunu kontrol eder.
3. TISCI 12.00.02 Key Writer için 4096-bit şartını kontrol eder.
4. Exact DER byte'larının SHA2-512 değerini hesaplar.

Bu SHA2-512 değeri SMPKH/BMPKH provisioning girdisinin hazırlanmasında kullanılan public hash'tir. `securectl key signing` tarafından gösterilen DER-SPKI SHA-256 fingerprint ile aynı amaçta değildir.

## SMEK ve BMEK format kontrolü

Secret değerler profile'a konmaz. İstenirse yalnız local dosya üzerinden format kontrolü yapılabilir:

```bash
securectl provision preflight provision.yaml \
  --smek <LOCAL_SMEK_FILE>
```

Backup set kullanılıyorsa:

```bash
securectl provision preflight provision.yaml \
  --smek <LOCAL_SMEK_FILE> \
  --bmek <LOCAL_BMEK_FILE>
```

Bu kontrolde yalnız AES-256 için beklenen raw-hex biçim değerlendirilir. Secret değer, secret dosya yolu ve secret hash rapora yazılmaz.

## SWREV

`swrev.sysfw`, `swrev.sbl` ve `swrev.boardcfg` alanları isteğe bağlıdır. Profile'da bir SWREV değeri verilirse araç bunun sıfırdan büyük olmasını ister.

TISCI Key Writer, SWREV kullanımını optional tanımlar ve revision kontrolü kullanılacaksa başlangıç değerinin non-zero olması gerektiğini belirtir. eFuse'daki double-redundancy encoding bu toolkit tarafından üretilmez.

## JSON raporu

```bash
securectl provision preflight provision.yaml \
  --report provision-report.json
```

Rapor şu tür bilgileri içerir:

- `KEYCNT` / `KEYREV`
- active-key context
- public DER RSA key size
- SMPKH/BMPKH için SHA2-512
- SWREV kontrol sonucu
- SMEK/BMEK format kontrolünün sonucu, yapılmışsa
- çalıştırılmayan target işlemlerinin açık durumu

Rapor private/symmetric key içeriği, MEK değeri, secret path veya secret hash içermez.

## Sonuçların anlamı

`PASS`, yalnız verilen offline girdilerin toolkit'in kontrol ettiği kurallarla tutarlı olduğunu gösterir.

Şunları göstermez:

- OTP/eFuse programlamanın başarılı olacağını,
- cihazın HS-SE durumuna geçtiğini,
- customer Root of Trust'ın cihazda enforce edildiğini,
- application authentication/decryption enforcement'ın donanımda doğrulandığını.

TISCI Key Writer ayrıca TI FEK ile Keywriter firmware'in aynı Keywriter package'ından olması gerektiğini belirtir. Package dosyaları verilmediği sürece bu eşleşme `NOT_CHECKED` olarak kalır.

## SWREV alan genişlikleri

Provisioning preflight, Key Writer 12.00.02 alan genişliklerini dikkate alır:

- `SWREV-SBL`: 96 bit encoded / 48 bit tek kopya
- `SWREV-SYSFW`: 96 bit encoded / 48 bit tek kopya
- `SWREV-BOARDCONFIG`: 128 bit encoded / 64 bit tek kopya

Toolkit yalnız verilen integer değerin bu tek-kopya genişliğine sığıp sığmadığını kontrol eder. eFuse double-redundancy bit encoding'i üretilmez.
