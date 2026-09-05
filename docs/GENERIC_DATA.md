# Generic binary için authentication ve encryption

`securectl data`, firmware olarak boot edilmeyecek bir binary dosyayı System Firmware'in generalized authentication kullanımına uygun biçimde hazırlamak ve host üzerinde kontrol etmek için kullanılır.

Bu kullanımda `TISCI_MSG_PROC_AUTH_BOOT` yine authentication/decryption hizmetini sağlar; fakat certificate içinde System Firmware Boot Extension bulunmaz. Bu nedenle başarılı security kontrollerinden sonra processor configuration uygulanması beklenmez. Target üzerindeki API çağrısı bu toolkit tarafından yapılmaz.

## Profile oluşturma

```bash
securectl data new --output data.yaml
```

Örnek profile:

```yaml
type: generic_data
subject:
  common_name: AM64x Authenticated Data
  organization: Example Project
input: calibration.bin
software_revision: 1
load:
  dest_addr: 0x0000000000000000
  auth_mode: 1
  copy_as_host: 0
encryption:
  enabled: false
valid_days: 3650
```

`dest_addr`, `auth_mode` ve `copy_as_host` değerleri kullanım bağlamına göre açıkça verilmelidir. Toolkit bu değerleri işlemci, Host ID veya memory map bilgisinden tahmin etmez.

TISCI 12.00.02 Load Extension için `auth_mode` alt byte'ında `0`, `1` ve `2` değerlerini tanımlar. Toolkit bunları sırasıyla `normal_copy_to_dest_addr`, `in_place_no_move` ve `in_place_variant` olarak raporlar. Diğer değerler kabul edilmez.

Profile kontrolü:

```bash
securectl data validate data.yaml
```

Generic data profile, Boot Extension alanı kabul etmez. Boot Extension eklemek authenticated processor boot davranışını ifade edeceği için bu komut grubunda hata olarak değerlendirilir.

## Signed generic data package

```bash
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --certificate data.der \
  --output data.secure
```

Üretilen dosya:

```text
DER X.509 certificate
        +
original binary
```

Certificate içinde şu System Firmware extension'ları bulunur:

- `.1.3` Software Revision
- `.1.34` Image Integrity
- `.1.35` Load

`.1.33` Boot Extension eklenmez.

`.1.34` içindeki hash SHA2-512'dir ve certificate arkasına eklenen binary üzerinde hesaplanır.

## Encrypted + signed generic data package

Profile içinde:

```yaml
encryption:
  enabled: true
```

ayarlanır ve build sırasında local MEK dosyası verilir:

```bash
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --mek <LOCAL_MEK_FILE> \
  --certificate data.der \
  --output data.secure
```

MEK dosyası tam 64 hexadecimal karakter olmalıdır. Değer, path veya hash çıktıya kaydedilmez.

Encryption sırası:

```text
input binary
 -> 16-byte hizaya kadar zero padding
 -> 32-byte randomString ekleme
 -> 16-byte IV ile AES-256-CBC
 -> ciphertext
 -> SHA2-512(ciphertext)
 -> X.509 certificate + ciphertext
```

TISCI 12.00.02 biçimine göre `.1.4` Encryption Extension içinde:

- IV: 16 byte
- randomString: 32 byte
- `iterationCnt`: 0
- `salt`: 32 byte zero

kullanılır. IV ve randomString değerleri JSON veya terminal çıktısında gösterilmez.

Bu bağımsız generic-data üreticisi, TISCI 12.00.02'de tarif edilen 32-byte zero salt biçimini kullanır. MCU+ SDK 12.00.00.27 içindeki application signer üzerinde gözlenen daha kısa salt davranışı buraya kopyalanmaz.

Zero padding de TISCI metnindeki "length is a multiple of 16" kuralına göre uygulanır. Girdi zaten 16-byte hizalıysa ek zero-padding byte'ı eklenmez. Kurulu SDK application signer'da gözlenen aligned-input edge-case davranışı bu bağımsız generic-data üreticisinin kuralı olarak alınmaz.

## Doğrulama

Signed package:

```bash
securectl data verify data.secure --original calibration.bin
```

Encrypted package:

```bash
securectl data verify data.secure \
  --mek <LOCAL_MEK_FILE> \
  --original calibration.bin
```

Kontroller iki katmanda yapılır. Önce genel `securectl verify` kontrolleri çalışır: certificate signature consistency, `.1.34` image size/SHA2-512 binding ve `.1.35` yapısı. Ardından generic-data kuralları kontrol edilir: Boot Extension bulunmaması, SWREV varlığı ve encrypted package için TISCI 12.00.02 encryption metadata biçimi.

MEK verilirse ciphertext host üzerinde açılır. Decrypted veri terminale veya dosyaya yazılmaz. Araç yalnız şu sonuçları karşılaştırır:

- decrypted son 32 byte == certificate `randomString`
- `--original` verilmişse ilk N byte == original binary
- aradaki padding byte'ları == zero

Yanlış MEK ile AES-CBC işleminin teknik olarak tamamlanması başarılı decryption kanıtı sayılmaz; randomString ve original-data kontrolleri başarısız olmalıdır.

MEK verilmeden encrypted package doğrulanırsa ciphertext integrity kontrol edilebilir ancak decryption correctness doğrulanamaz; sonuç bu nedenle `PARTIAL` olabilir.

## Güvenlik sınırı

Bu komutlar host tarafında package üretir ve inceler. Aşağıdaki işlemleri yapmaz:

- `TISCI_MSG_PROC_AUTH_BOOT` mesajı gönderme
- target memory'ye veri yükleme
- customer Root of Trust enforcement doğrulama
- hardware decryption enforcement doğrulama
- OTP/eFuse/customer key provisioning
- HS-FS -> HS-SE geçişi

Dolayısıyla host-side `PASS`, target üzerindeki authentication/decryption kabulünün kanıtı değildir.
