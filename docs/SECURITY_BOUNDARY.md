# Güvenli kullanım sınırları

- Private/symmetric key, MEK veya passphrase içeriği raporlara yazılmaz.
- Build kayıtlarında private/symmetric key path ve hash değerleri tutulmaz.
- Public certificate, public DER-SPKI fingerprint ve image hash değerleri kaydedilebilir.
- `securectl key` MEK değerini veya hash'ini yazdırmaz; signing private key için yalnız public tarafı raporlanır.
- Şifreli private key preflight sırasında passphrase istenmez veya kaydedilmez.
- `inspect`, encryption ve Keywriter alanlarında key/IV/random-string byte değerlerini göstermez.
- Certificate signature doğrulaması ile payload/ciphertext integrity doğrulaması ayrı kontrollerdir.
- Embedded public key ile signature doğrulaması target cihazın aynı key'e güvendiğini kanıtlamaz.
- Confidentiality, integrity, authenticity ve freshness/rollback birbirinden ayrı güvenlik özellikleridir.
- Toolkit OTP Keywriter veya eFuse programlama çalıştırmaz.
- Toolkit HS-FS → HS-SE lifecycle geçişi yapmaz.
- Toolkit Secure Debug certificate üretebilir ancak target üzerinde debug unlock çağrısı yapmaz.
- Kalıcı debug/security değişikliği veya fiziksel saldırı işlemi içermez.

- Negatif testler yalnız ayrı kopyalar üzerinde çalışır; kaynak image üzerinde byte değişikliği yapılmaz.
- Payload/ciphertext/component mutation testleri secret key kullanmadan integrity kontrolünü sınar.
- `securectl provision` yalnız offline hazırlık kontrolü yapar; `KEYCNT`, `KEYREV` veya SWREV değerlerini target'a yazmaz.
- Provisioning preflight sırasında local SMEK/BMEK verilirse yalnız format kontrol edilir; secret değer, path ve hash rapora kaydedilmez.
- SMPKH/BMPKH için hesaplanan SHA2-512 değerleri public DER key material'ından türetilir ve secret olarak sınıflandırılmaz.

- `securectl revision` yalnız offline karşılaştırma yapar; `TISCI_MSG_WRITE_KEYREV`, `TISCI_MSG_WRITE_SWREV`, OTP/eFuse write veya lifecycle değişikliği çağırmaz.
- KEYREV hedef durumu `PASS` olsa bile runtime write yetkisi/uygulanabilirliği `NOT_CHECKED` kalır.
- Application/generic SWREV için target rollback enforcement sonucu çıkarılmaz; bu projede application SWREV enforcement doğrulanmamıştır.

- `securectl boardcfg` yalnız Security BoardCfg policy değerlerini offline değerlendirir; BoardCfg'yi target'a göndermez.
- `POLICY_ALLOWS_REQUEST`, Secure Debug işleminin target tarafından kabul edildiği anlamına gelmez; active SMPK/BMPK trust ve eFuse public-key-hash eşleşmesi ayrıca doğrulanmalıdır.
- `boardcfg revision-writer` yalnız `write_host` eşleşmesini gösterir; `TISCI_MSG_WRITE_SWREV` veya `TISCI_MSG_WRITE_KEYREV` çalıştırmaz.
- `write_host` değerinin secure proxy thread'e map olduğu exact SoC Host ID kaynağı olmadan doğrulanmaz.

- `securectl sdk lint` SDK/config/source dosyalarını read-only inceler; `make`, signing script'i veya target işlemi çalıştırmaz.
- Linter olası private-key/raw-MEK bulgusunun içeriğini veya key path'ini raporlamaz; yalnız dosya rolü ve satır numarası bildirir.
- `DEVICE_TYPE` değeri yalnız build selector olarak değerlendirilir; fiziksel GP/HS-FS/HS-SE lifecycle sonucu çıkarılmaz.
- `ENC_SBL_ENABLED=yes` tek başına SBL encryption'ın gerçekten çalıştırıldığını kanıtlamaz; consumer branch ve gerçek build ayrıca değerlendirilmelidir.

- `securectl data` generalized authentication package üretir ancak `TISCI_MSG_PROC_AUTH_BOOT` mesajı göndermez ve target memory'ye veri yüklemez.
- Generic-data encryption sırasında MEK, IV ve randomString byte değerleri rapora yazılmaz; decrypted payload dışarı verilmez.
- Encrypted generic-data için host-side randomString/payload doğrulaması hardware decryption enforcement kanıtı değildir.
- Generic-data SWREV alanı certificate'a eklenir; application/generic-data rollback enforcement bu toolkit tarafından target üzerinde doğrulanmış sayılmaz.

## v2 local key generation sınırı

Studio'nun key generator'ı yalnız synthetic/non-production material üretir. Bu özellik production/customer key custody çözümü değildir ve HSM/PKCS#11 yerine geçmez.

- Private RSA ve symmetric key değerleri stdout/JSON/session/share-safe report içine yazılmaz.
- Secret key hash'leri raporlanmaz.
- Secret path'ler project metadata veya keyset manifest'e yazılmaz.
- `keyset-manifest.json` yalnız public fingerprint/hash, algorithm/format ve non-execution marker'ları içerir.
- `SMPK/BMPK` role seçimi yalnız format/role-aware offline hazırlıktır; OTP/eFuse write yapmaz.
- `SMEK/BMEK` üretimi provisioning'in gerçekleştiği veya customer Root of Trust'in enforce edildiği anlamına gelmez.
