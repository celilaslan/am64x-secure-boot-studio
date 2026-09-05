# Mimari

`securectl`, AM64x Secure Boot çalışmasında tekrar eden host-side işlemleri tek komut satırı aracı altında toplar. Modüller aynı güvenlik kavramlarını paylaşır ancak farklı image/certificate türlerini birbirine karıştırmaz.

## Ana modüller

- `inspect`: DER X.509 certificate sınırını ve desteklenen TI extension alanlarını okur.
- `verify`: certificate signature ile payload/ciphertext/component integrity kontrollerini ayrı yapar.
- `cert`: application ve Secure Debug certificate profile'larını doğrular ve desteklenen certificate'ları üretir.
- `build`: kurulu TI `appimage_x509_cert_gen.py` ve `rom_image_gen.py` araçlarını kontrollü biçimde çağırır.
- `negative`: kaynak image'ı değiştirmeden signature, TBSCertificate, payload, ciphertext veya ROM component test kopyaları üretir.
- `key`: signing key/public key özelliklerini ve MEK text formatını secret değerleri raporlamadan kontrol eder.
- `provision`: HS-FS -> HS-SE provisioning girdilerini OTP/eFuse yazımı yapmadan kontrol eder.
- `revision`: KEYCNT/KEYREV durumlarını ve kaynakta tanımlanan SWREV karşılaştırmalarını offline değerlendirir.
- `boardcfg`: Secure Debug ve revision-write policy alanlarını target'a göndermeden kontrol eder.
- `sdk lint`: `devconfig.mak`, Makefile ve signing-tool consumer zincirlerini read-only inceler.
- `sdk diff`: iki SDK/source setindeki security açısından anlamlı değişiklikleri karşılaştırır.
- `errata`: AM64x/AM243x Rev. J Boot advisories'i silicon revision ve kullanım bağlamına göre filtreler.
- `data`: boot edilmeyecek generic binary'leri TISCI generalized authentication biçiminde signed veya encrypted+signed olarak hazırlar ve host üzerinde doğrular.
- `report`: `inspect` ve `verify` sonuçlarını tek dosya veya açıkça verilen dosya grubu için okunabilir Markdown/JSON raporuna dönüştürür.
- `gui`: image/certificate inceleme, doğrulama ve tek dosya raporu için read-only masaüstü arayüzü sağlar.

## Certificate ve image zincirlerinin ayrılması

ROM combined image ile System Firmware tarafından tüketilen application/generic-data certificate aynı format değildir. ROM combined image üretimi kurulu `rom_image_gen.py` üzerinden yürütülür. Application build akışında kurulu `appimage_x509_cert_gen.py` kullanılabilir.

`securectl data` ise TISCI'nin generalized authentication kullanımını ayrı bir akış olarak ele alır. Bu package içinde `.1.3` SWREV, `.1.34` Image Integrity ve `.1.35` Load extension'ları bulunur; `.1.33` Boot Extension bulunmaz. Encryption etkinse `.1.4` eklenir. Boot Extension'ın olmaması, `TISCI_MSG_PROC_AUTH_BOOT` isteğinin processor boot yerine generic authentication amacıyla kullanılacağını ifade eder.

## Encryption davranışı

Kurulu SDK application signer ile `securectl data` aynı şey değildir.

Application build için toolkit TI signer'ı çağırabilir ve installed source davranışını değiştirmez. Generic-data modülü ise TISCI 12.00.02 dokümanındaki biçimi doğrudan uygular:

```text
binary
 -> zero padding (yalnız gerekiyorsa)
 -> 32-byte randomString
 -> AES-256-CBC / 16-byte IV
 -> ciphertext
 -> SHA2-512(ciphertext)
 -> signed X.509 + ciphertext
```

Generic-data `.1.4` extension'ında `iterationCnt=0` ve 32-byte zero salt kullanılır. IV, randomString ve MEK değerleri kullanıcı çıktısına yazılmaz.

## Doğrulama sonucu

Certificate içindeki public key ile signature doğrulaması certificate'ın matematiksel tutarlılığını gösterir. Target cihazdaki active customer Root of Trust eşleşmesi ayrı kontroldür.

Payload/ciphertext SHA2-512 doğrulaması certificate signature kontrolünden ayrıdır. Encrypted generic-data package için MEK verilirse decrypted son 32 byte'ın certificate `randomString` alanıyla eşleşmesi de kontrol edilir. `--original` verilirse original payload ve zero-padding yapısı ayrıca karşılaştırılır. Decrypted içerik dosyaya veya terminale yazılmaz.

ROM combined image'da her component kendi declared size/hash bilgisiyle doğrulanır.

## Secret bilgilerin işlenmesi

Private key veya symmetric key içeriği rapora yazılmaz. `securectl key` private key için yalnız public DER-SPKI bilgisi türetir; MEK için değer/hash raporlamadan format kontrolü yapar. Build wrapper key path'lerini kalıcı kayıtlardan çıkarır. `inspect`, encryption ve Keywriter alanlarında key/IV/random-string byte değerlerini göstermeden yalnız yapısal bilgileri raporlar.

`securectl data` da private-key/MEK path veya değerini build sonucuna kaydetmez ve decrypted payload'ı dışarı vermez.

`securectl report batch` dizin taraması yapmaz. Yalnız komutta açıkça verilen image/certificate dosyalarını okur; rapor JSON dosyasında local source path saklamaz.

## v2 Studio katmanları

v2 migration sırasında legacy core modülleri import compatibility için yerinde tutulur. Yeni katmanlar:

```text
legacy/core modules
      │
      ├── services/
      │    environment / project / claim_boundary / secret_policy / source_registry / session
      │
      ├── workflows/
      │    application / inspect / keys
      │
      └── gui/ (PySide6 optional)
           Home / Environment / Project / Application / Inspector / Keys / Negative / Reports
```

`WorkflowResult` GUI ve gelecekteki report/session katmanı için ortak status sözlüğü kullanır: `PASS`, `FAIL`, `PARTIAL`, `NOT_CHECKED`, `INFO`, `WARN`, `ERROR`.

GUI, `securectl` komutlarını shell subprocess olarak çağırmaz. Python backend/workflow fonksiyonlarını doğrudan kullanır. TI image/certificate generation logic'i yeniden implement edilmez; kurulu TI signing scriptleri kullanılmaya devam eder.


## Alpha10 Project Workspace output policy

Project Workspace generated non-secret/public outputs için `outputs/`, `public/`, `negative-tests/`, `reports/` ve `sessions/` alanlarını kullanır. `sessions/activity.jsonl` compact workflow history, `sessions/artifacts.jsonl` ise generated artifact index'idir. Project içi paths relative tutulur; external output yalnız basename olarak persist edilir. Private key/MEK generation project içine yönlendirilmez.
