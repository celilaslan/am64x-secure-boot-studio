# AM64x Secure Boot Studio v2.0 — GUI/UX ve Teknik Mimari Blueprint

**Temel paket:** `AM64x_Secure_Boot_Toolkit_v1.0.0`  
**Hedef:** Mevcut host-side Secure Boot yeteneklerini, AM64x konusunda yeni bir kullanıcının dahi komut satırı bilmeden güvenli biçimde kullanabildiği Türkçe masaüstü uygulamasına dönüştürmek.  
**Ana ilke:** **Kolay kullanım + zor yanlış kullanım.**  
**Varsayılan çalışma biçimi:** offline-first, host-side, non-destructive.  
**Donanım/provisioning sınırı:** OTP/eFuse/customer-key write, HS-FS→HS-SE transition ve kalıcı debug/security değişikliği bu GUI'nin normal işlem yüzeyi değildir.

---

## 1. Neden bu çalışma yapılmalı?

Mevcut toolkit'in backend'i yalnız bir image viewer değildir. v1.0.0 kodunda zaten şu yetenekler vardır:

- secure image / DER X.509 inspection;
- certificate signature ve payload/ciphertext/component integrity doğrulaması;
- kurulu TI SDK `appimage_x509_cert_gen.py` ile application build;
- kurulu TI SDK `rom_image_gen.py` ile ROM combined-image build;
- application ve Secure Debug certificate profile üretimi/doğrulaması;
- controlled negative-test copy üretimi;
- signing key ve MEK preflight;
- HS-FS→HS-SE provisioning girdileri için offline preflight;
- KEYCNT/KEYREV ve SWREV simulation;
- Security Board Configuration policy kontrolleri;
- MCU+ SDK security lint ve source diff;
- AM64x/AM243x Rev. J errata değerlendirmesi;
- generalized authentication için generic-data package üretimi/doğrulaması;
- Markdown/JSON raporlama.

Buna karşılık mevcut `gui.py`, Tkinter üzerinde yalnız şu akışı sunar:

```text
Dosya seç -> İncele / Doğrula / Rapor Kaydet
```

Dolayısıyla v2.0'ın ana işi yeni cryptographic logic yazmak değil; mevcut backend'i anlaşılır **workflow**'lara dönüştürmek, key generation gibi eksik birkaç çekirdek yeteneği eklemek ve bütün sistemi güvenli bir masaüstü UX altında birleştirmektir.

---

## 2. Ürünün adı ve konumu

Kullanıcıya görünen ürün adı:

> **AM64x Secure Boot Studio**

CLI adı korunur:

```text
securectl
```

Böylece iki kullanım yolu olur:

```text
                    AM64x Secure Boot Core
                              |
                  +-----------+-----------+
                  |                       |
            securectl CLI          Secure Boot Studio
             automation /             GUI / guided
                 CI                     desktop
```

GUI, CLI'yi shell subprocess olarak çağırmamalıdır. CLI ve GUI aynı Python service/workflow katmanını kullanmalıdır.

---

## 3. Kullanıcı profilleri

### 3.1 Yeni başlayan

Şunu bilir:

- bir `.mcelf` / image dosyası var;
- “imzalamak”, “şifrelemek” veya “doğrulamak” istiyor;
- X.509 OID, `ENC_ENABLED`, `TISCI_MSG_PROC_AUTH_BOOT`, `rom_image_gen.py` gibi ayrıntıları henüz bilmiyor.

GUI bu kullanıcıyı teknik terim bombardımanına tutmamalıdır.

### 3.2 Projeyi öğrenen mühendis/stajyer

Akışı öğrenmek ve sonuçların ne anlama geldiğini görmek ister. Görsel image anatomy, certificate explorer, “Bu kontrol neyi kanıtlar?” ve source trace özellikleri bu profile yöneliktir.

### 3.3 Uzman kullanıcı

Exact OID, tool, profile, SWREV, load address, build record, source diff gibi bütün ayrıntılara erişmek ister. **Uzman Modu** ile gizli olmayan teknik ayrıntılar açılır.

### 3.4 CI/otomasyon kullanıcısı

GUI değil `securectl` kullanır. GUI geliştirmesi CLI'yı zayıflatmamalı veya kırmamalıdır.

---

## 4. İki katmanlı kullanım modeli

Uygulamanın sağ üstünde sürekli bir mod seçici bulunur:

```text
[ Rehberli Mod ]   [ Uzman Modu ]
```

### Rehberli Mod

- görev bazlı soru sorar;
- yalnız gerekli alanları gösterir;
- güvenli default'ları kullanır;
- kullanıcıya tool adı/OID yazdırmaz;
- her adımda kısa açıklama verir;
- yanlış state/flow kombinasyonunu erkenden engeller.

### Uzman Modu

Aynı workflow'un ayrıntı drawer'ını açar:

- exact TI tool;
- certificate extension OID'leri;
- SWREV;
- load address;
- component metadata;
- build record;
- source mapping;
- raw, fakat secret-safe teknik log metadata'sı.

Rehberli Mod ile Uzman Modu iki ayrı engine değildir. Aynı workflow state'ini farklı ayrıntı seviyesinde gösterir.

---

## 5. Ana gezinme yapısı

Sol navigation bar:

```text
AM64x Secure Boot Studio

  Ana Sayfa
  Proje
  Secure Application
  ROM Image
  Image İnceleme
  Certificate
  Keys
  Negatif Testler
  SDK Kontrolü
  Errata
  Provisioning Hazırlığı
  Revision
  Security BoardCfg
  Generic Data
  Sonuçlar ve Raporlar
  Öğren

  Ayarlar
  Hakkında / Kaynaklar
```

Yeni başlayan kullanıcı bütün menüyü kullanmak zorunda değildir. Ana Sayfa görev kartları doğru bölüme yönlendirir.

---

## 6. Ana Sayfa — “Ne yapmak istiyorsunuz?”

İlk ekran komutlara göre değil kullanıcının amacına göre düzenlenir.

```text
+------------------------------------------------------------------+
| AM64x Secure Boot Studio                                         |
|                                                                  |
| Device context: AM6442 | HS-FS | SDK 12.00.00.27 | READY         |
|                                                                  |
| Ne yapmak istiyorsunuz?                                          |
|                                                                  |
| [ Secure Application Oluştur ]   [ Image Doğrula ]               |
| [ Image / Certificate İncele ]   [ Key Hazırla ]                 |
| [ ROM Combined Image ]           [ Negatif Test Yap ]            |
| [ SDK'yi Kontrol Et ]            [ Provisioning Hazırlığı ]      |
|                                                                  |
| [ Ne yapacağımı bilmiyorum — bana yol göster ]                   |
|                                                                  |
| Son proje: AM6442 Test Workspace                                 |
| Son işlem: encrypted+signed application verification — PASS      |
+------------------------------------------------------------------+
```

### “Bana yol göster” karar ağacı

Örnek soru zinciri:

1. Elinizde hazır bir secure image var mı?
2. Yeni bir application mı oluşturmak istiyorsunuz?
3. İçeriğin gizli olması gerekiyor mu?
4. Cihaz üzerinde provisioning mi planlıyorsunuz, yoksa yalnız host-side hazırlık mı?
5. Hedefiniz ROM combined image mı application image mı?

Cevaplara göre kullanıcı doğru workflow'a yönlendirilir.

Bu ekranın amacı kullanıcıya “hangi `securectl` komutunu kullanmalıyım?” sorusunu hiç sordurmamaktır.

---

## 7. Sürekli görünen Device Context Bar

Secure Boot'taki önemli hataların çoğu yanlış lifecycle/context varsayımından çıkar. Bu nedenle ana pencerenin üst kısmında küçük, sürekli görünür bir context bar bulunur:

```text
AM6442 | Silicon SR2.0 | HS-FS | MCU+ SDK 12.00.00.27 | TISCI 12.00.02
```

Tıklanınca genişler:

```text
Device                         AM6442
Silicon revision               SR2.0
Lifecycle                      HS-FS
Customer Root of Trust         NOT PROVISIONED / NOT ASSUMED
Secure Boot enforcement        NOT ASSUMED
Hardware auth validation       NOT EXECUTED
Hardware decrypt validation    NOT EXECUTED
```

### State seçimi

Kullanıcı state'i elle “HS-SE” seçebilir ancak GUI bunu hardware discovery sonucu gibi göstermemelidir. Alan etiketi:

> **Çalışma bağlamı / kullanıcı tarafından seçildi**

Donanımdan source-backed bir read-only detection gelecekte eklenirse bunun kaynağı ayrıca gösterilir.

---

## 8. İlk Açılış — Environment Setup Wizard

İlk çalıştırmada GUI doğrudan ana ekrana atlamaz. 2–3 dakikalık environment wizard çalışır.

### 8.1 Otomatik kontroller

```text
Python                         ✓
cryptography                   ✓
asn1crypto                     ✓
PyYAML                         ✓
GUI runtime                    ✓
MCU+ SDK                       ✓ 12.00.00.27
appimage_x509_cert_gen.py      ✓
rom_image_gen.py               ✓
OpenSSL                        ✓ 3.5.6
```

SDK location otomatik bulunamazsa kullanıcı yalnız SDK root directory seçer. GUI signing tool path'lerini kendisi çözer.

### 8.2 Version compatibility

Known baseline ile aynıysa:

```text
Validated project baseline detected
MCU+ SDK 12.00.00.27
```

Farklıysa:

```text
Farklı SDK sürümü bulundu.

Bu toolkit'in project baseline'ı 12.00.00.27'dir.
Yeni sürüm otomatik olarak eşdeğer kabul edilmeyecek.

[ Read-only SDK Compare çalıştır ]
[ Devam et, compatibility UNKNOWN olsun ]
```

### 8.3 Environment sonucu

Tek “READY” yerine kapsamlı sonuç:

```text
Host tooling          READY
TI application signer FOUND
TI ROM signer         FOUND
SDK compatibility     BASELINE MATCH
Hardware state        NOT CHECKED
```

---

## 9. Project Workspace

GUI'yi gerçek bir çalışma uygulaması yapan ana özelliklerden biri project workspace'tir.

Örnek:

```text
AM6442_Test_Project/
  project.am64xstudio
  inputs/
  outputs/
  public/
  reports/
  tests/
  sessions/
```

### 9.1 Project metadata'da tutulabilecekler

- device family;
- selected lifecycle context;
- silicon revision;
- selected SDK root;
- public artifact filenames;
- public DER fingerprint;
- non-secret workflow preferences;
- report paths;
- generated artifact hashes;
- last session state.

### 9.2 Project metadata'da tutulmayacaklar

- private key content;
- private key hash;
- MEK content;
- MEK hash;
- passphrase;
- seed;
- production/customer secret;
- secret environment-variable dump;
- secret command-line history;
- default olarak persistent secret absolute path.

Secret file bir workflow için seçildiğinde GUI bunu yalnız aktif session context'inde tutar ve UI'da dosya adını bile gerekmedikçe maskeler.

---

## 10. Drag & Drop Smart Inspector

Kullanıcı image/certificate dosyasını pencereye sürükleyip bırakabilmelidir.

Backend `inspect_artifact()` classification sonucuna göre otomatik yönlendirme yapılır.

Örnek:

```text
Dosya analiz edildi

Tür: encrypted+signed application/generic data
Certificate: DER X.509
Encryption extension: PRESENT
Image Integrity extension: PRESENT
Appended payload: 51328 bytes

[ Image Anatomy'yi Aç ] [ Host-side Verify ] [ Rapor ]
```

ROM combined image ise ROM ekranı, Keywriter certificate ise provisioning-inspection ekranı açılır.

### Kritik sınır

`encrypted+signed application/generic data` classification tek başına application ile generalized-authentication ayrımını her zaman çözmeyebilir. GUI `tisci_request_semantics` ve Boot/Load extension bağlamını kullanmalı; çözülmeyen durumda **“tam tür belirlenemedi”** demelidir.

---

## 11. Secure Application Wizard

Bu v2.0'ın ana workflow'udur.

### Step 1 — Girdi

```text
Application / MCELF
[ ................................................ ] [ Seç ]

Input hash   otomatik hesaplanır
Input size   gösterilir
```

GUI dosya suffix'ine kör güvenmez; build zinciri için beklenen format/role açıklaması gösterilir.

### Step 2 — Koruma biçimi

```text
Uygulama nasıl hazırlanacak?

( ) Signed only
(•) Encrypted + signed
```

Açıklama:

- **Signed:** authenticity/integrity chain için certificate kullanır.
- **Encrypted + signed:** bunlara ek olarak confidentiality sağlar.

“Encryption = integrity” gibi yanlış çağrışım yapılmaz.

### Step 3 — Signing key

Kullanıcı üç seçenek görür:

```text
[ Mevcut development/test key seç ]
[ Yeni synthetic development key oluştur ]
[ External key provider — future ]
```

Seçim sonrası otomatik preflight:

```text
RSA private key               PASS
RSA bits                      4096
Public fingerprint            <public SPKI SHA-256>
Target purpose                application
```

Private key content/path rapora gitmez.

### Step 4 — Encryption key

Encryption seçilmişse:

```text
[ Mevcut development/test MEK seç ]
[ Yeni synthetic MEK oluştur ]
```

Preflight:

```text
ASCII raw hex                 PASS
64 hexadecimal characters    PASS
AES-256                       PASS
Extra whitespace              NONE
```

### Step 5 — Tool resolution

Rehberli Mod:

```text
TI application signing tool   READY
```

Uzman Modu:

```text
Tool: appimage_x509_cert_gen.py
Tool identity: SHA-256 ...
Authtype: 1
Encryption: --enc y --enckey <REDACTED>
```

### Step 6 — İşlem Önizleme

Build düğmesinden önce son güvenlik özeti:

```text
Yapılacak işlem

Input       hello_world.mcelf
Signing     RSA-4096 development/test
Encryption  AES-256-CBC enabled
Generator   installed TI appimage_x509_cert_gen.py
Post verify enabled

Bu işlem:
✓ host üzerinde yeni image üretir
✓ source input'u değiştirmez
✗ OTP/eFuse yazmaz
✗ HS-FS -> HS-SE geçişi yapmaz
✗ hardware/customer enforcement kanıtlamaz

[ Dry Run ]                [ Image Oluştur ]
```

### Step 7 — Progress

Long-running operations UI thread'i bloklamaz.

```text
1 Input preflight             ✓
2 Key preflight               ✓
3 TI generator                ✓
4 Artifact parse              ✓
5 Certificate verification    ✓
6 Image integrity             ✓
7 Report                      ●
```

### Step 8 — Sonuç

```text
HOST-SIDE RESULT

Image generation             PASS
X.509 parse                  PASS
Certificate signature        PASS
Image/ciphertext integrity   PASS
Encryption metadata          PASS

Hardware application auth    NOT VERIFIED
Hardware decryption          NOT VERIFIED
Customer Root of Trust       NOT VERIFIED
```

Tek büyük yeşil “SECURE” etiketi kullanılmaz.

---

## 12. Key Center ve Key Generation

v2.0'a geçmeden önce veya v2.0 core içinde `keygen.py` eklenmelidir.

### 12.1 Ekran yapısı

```text
Keys

Development / Test
  Application Signing Key    VALID / NOT SET
  Application MEK            VALID / NOT SET

Provisioning Preparation
  SMPK                        PUBLIC CHECK / NOT SET
  BMPK                        PUBLIC CHECK / NOT SET
  SMEK                        FORMAT CHECK / NOT SET
  BMEK                        FORMAT CHECK / NOT SET
```

### 12.2 Generate menüsü

```text
Yeni Key Oluştur

Type
  Application signing
  Application MEK
  SMPK test/preparation
  BMPK test/preparation
  SMEK test/preparation
  BMEK test/preparation
```

Production/customer context seçilirse GUI açıkça local synthetic generation ile production key management'ı eşitlemez.

### 12.3 Development set

Tek tıkla:

```text
Application signing RSA-4096
Application MEK 256-bit
```

üretilir, ardından bağımsız `keycheck` çalışır.

### 12.4 Secret-safe file behavior

- private/symmetric output restrictive permission ile oluşturulur;
- existing file overwrite varsayılan olarak reddedilir;
- “Force overwrite key” düğmesi sunulmaz;
- generation yarıda kalırsa partial secret file cleanup yapılır;
- manifest yalnız public/non-secret metadata içerir.

### 12.5 Public identity card

Signing key için:

```text
Algorithm              RSA
Size                   4096
Public exponent        65537
DER-SPKI SHA-256       ....
```

SMPK/BMPK provisioning preparation için ayrı:

```text
Public DER SHA-512 candidate   ....
Classification                OFFLINE PREPARATION
Provisioned                   NO
```

DER-SPKI SHA-256 developer fingerprint ile provisioning SHA-512 aynı alan gibi gösterilmemelidir.

---

## 13. Image Anatomy

Bu ekran hem eğitim hem debugging için önemli olacaktır.

### 13.1 Application image

```text
+---------------------- Certificate -----------------------+
| Subject | Public Key | Signature | TI Extensions         |
|  .1.3 SWREV                                             |
|  .1.4 Encryption                                       |
|  .1.34 Image Integrity --------------------------+       |
|  .1.35 Load                                     |       |
+--------------------------------------------------|-------+
                                                   |
                      SHA-512 binding              |
                                                   v
+-------------------- Appended Payload / Ciphertext --------+
| size: ...                                                |
| SHA-512: ...                                             |
+----------------------------------------------------------+
```

### 13.2 ROM combined image

```text
+------- X.509 -------+
| ext_boot_info       |
+---------------------+
| SBL                 |
+---------------------+
| SYSFW               |
+---------------------+
| SYSFW Inner Cert    |
+---------------------+
| BoardCfg            |
+---------------------+
```

Her component kartında:

- type;
- offset;
- size;
- declared SHA;
- calculated SHA;
- MATCH / MISMATCH.

### 13.3 Hover/Click explanation

Kullanıcı `.1.34` üstüne geldiğinde:

```text
System Firmware Image Integrity Extension

Bu alan payload/ciphertext hash ve size bilgisini taşır.
Certificate signature kontrolünden ayrı bir doğrulamadır.
```

---

## 14. Certificate Explorer

Tree view:

```text
Certificate
  Identity
    Subject
    Issuer
  Public Key
  Signature
  TI Extensions
    Software Revision
    Encryption
    Debug
    Boot
    Image Integrity
    Load
    ROM Boot Information
    Keywriter Extensions
```

Sağ panel:

```text
Official name
OID
Decoded values
Applicable context
Who consumes it?
What it proves
What it does not prove
Source
```

### 14.1 Certificate context ayrımı

GUI aynı “X.509” kelimesi altında şu dört bağlamı özellikle ayırır:

1. ROM combined-image certificate → ROM/RBL
2. Application / generalized-auth certificate → System Firmware/TIFS
3. Keywriter provisioning certificate → OTP Keywriter
4. Secure Debug certificate → System Firmware debug authorization

Bir certificate type'ın alanını diğerine taşımaya çalışmak UI validation error olmalıdır.

---

## 15. “Bu neyi kanıtlar?” paneli

Her result ekranının kalıcı alt paneli:

```text
Bu sonuç neyi gösteriyor?
✓ certificate parse edildi
✓ embedded public key ile signature matematiksel olarak doğrulandı
✓ actual payload/ciphertext hash certificate değeriyle eşleşti

Bu sonuç neyi göstermiyor?
✗ embedded public key'in target üzerinde active customer Root of Trust olduğunu
✗ hardware application authentication enforcement'ı
✗ hardware decryption enforcement'ı
✗ OTP/eFuse provisioning'i
```

Bu panel generic hardcoded metin olmamalı; workflow sonucuna göre programatik oluşturulmalıdır.

---

## 16. “Neden?” açıklamaları

PASS/FAIL/NOT_CHECKED sonuçlarının yanındaki `?` düğmesi kısa teknik açıklama açar.

Örnek wrong-MEK:

```text
Decrypt process exit 0 verebilir.
Bu tek başına correct key kanıtı değildir.
Doğrulama decrypted payload ve certificate randomString eşleşmesine bakar.
```

Örnek embedded-key signature:

```text
Bu kontrol certificate'ın kendi public key'i ile matematiksel tutarlılığını gösterir.
Public key'in target eFuse customer Root of Trust ile eşleştiğini göstermez.
```

Açıklamalar local kaynak paketinden gelir; kullanıcıya AI-generated belirsiz açıklama olarak sunulmaz.

---

## 17. Negatif Testler — güvenli kontrollü kopyalar

Kullanıcıya “hex editor aç ve byte değiştir” denmemelidir.

Ekran:

```text
Negatif Test Oluştur

Source image   application.hs
Source hash    ....

Test
  Certificate signature byte
  TBSCertificate byte
  Payload byte
  Ciphertext byte
  ROM component byte

[ Test Kopyası Oluştur ve Doğrula ]
```

### Güvenlik davranışı

- source image read-only kalır;
- mutation yalnız yeni hash'li copy üzerinde yapılır;
- source hash işlemden önce/sonra kontrol edilir;
- output source ile aynı dosya olamaz;
- test sonucu expected vs actual gösterir.

### Görsel karşılaştırma

```text
                           ORIGINAL      MODIFIED
Certificate parse             PASS           PASS
Certificate signature         PASS           PASS
Ciphertext SHA-512            PASS           FAIL  <-- expected
Overall host-side             PASS           FAIL
```

---

## 18. ROM Image Wizard

ROM flow application wizard'dan kesin biçimde ayrılır.

### Inputs

- SBL binary
- SYSFW binary
- BoardCfg blob
- optional SYSFW inner certificate
- load addresses
- SWREV
- signing key
- optional SBL encryption key
- debug option

### Rehberli Mod davranışı

GUI load address/ID gibi değerleri tahmin etmez. Project profile veya inspected installed source'tan exact değer yoksa:

```text
Bu alan için doğrulanmış değer bulunamadı.
Exact SDK/build source üzerinden çözülmeden build başlatılamaz.
```

### Debug warning

`DBG_FULL_ENABLE` gibi development-oriented debug setting seçilmişse production çağrışımı yapan yeşil “secure” sonucu verilmez.

### ROM anatomy + post verify

Build sonrası component hash'leri ayrı ayrı doğrulanır ve combined-image view açılır.

---

## 19. SDK Inspector

Bu ekran `sdk_lint.py`'nin görsel karşılığıdır.

### 19.1 Configuration cards

```text
Device configuration
DEVICE_TYPE             HS
ENC_ENABLED             no
ENC_SBL_ENABLED         yes
```

### 19.2 Consumer-chain graph

Application:

```text
ENC_ENABLED
   -> application Makefile
   -> --enc y / --enckey
   -> appimage_x509_cert_gen.py
```

ROM/SBL:

```text
ENC_SBL_ENABLED
   -> SBL Makefile
   -> --sbl-enc / --enc-key
   -> rom_image_gen.py
```

UI açıkça:

> `ENC_ENABLED` ve `ENC_SBL_ENABLED` aynı artifact layer'ı kontrol etmez.

### 19.3 Source identity

Uzman Modu:

- source file hash;
- line match summary;
- detected option;
- unresolved mapping.

Generated output elle edit önerilmez.

---

## 20. SDK Compare / Upgrade Assistant

İki SDK source set'i seçilir:

```text
Baseline SDK  12.00.00.27
Candidate SDK 12.xx.xx.xx
```

Karşılaştırılır:

- `devconfig.mak`;
- application Makefile;
- SBL Makefile;
- `appimage_x509_cert_gen.py`;
- `rom_image_gen.py`.

UI yalnız security açısından ilgili farkları öne çıkarır:

```text
Encryption option mapping          SAME
Application integrity hash input   CHANGED
Encryption OID                     SAME
Salt behavior                      CHANGED
SBL encryption invocation          SAME
```

Yeni SDK'yı otomatik olarak “validated” yapmaz.

---

## 21. Errata Advisor

Kullanıcı context'ten gelen:

- silicon revision;
- device state;
- boot mode;
- boot flow;
- outer RSA type;
- certificate-info presence;
- external emulator context

bilgileriyle yalnız ilgili advisories'i görür.

Örnek kart:

```text
i2413 — Boot: HS-FS ROM boots corrupted ROM boot image
Relevance: HIGH
Applies: SR1.0 / SR2.0
Context match: HS-FS

[ Neden ilgili? ] [ Source ]
```

Errata Advisor otomatik workaround uygulamaz; source-backed öneri/uyarı gösterir.

---

## 22. Provisioning Hazırlığı

Bu bölümün adı bilinçli olarak **“Provision Device” değil “Provisioning Hazırlığı”** olmalıdır.

### 22.1 Lifecycle view

```text
HS-FS
  |
  |  customer root key set provisioning
  |  OTP Keywriter
  v
HS-SE
```

Büyük durum etiketi:

```text
OFFLINE PREPARATION ONLY
OTP/eFuse write is NOT provided here.
```

### 22.2 Key set cards

```text
Primary customer set
  SMPK public material      VALID / MISSING
  SMPKH candidate           READY / NOT READY
  SMEK                      FORMAT VALID / MISSING

Backup customer set
  BMPK ...
  BMEK ...
```

### 22.3 KEYCNT / KEYREV

`revision.py` ile aynı ekranda proposed configuration simüle edilir.

### 22.4 Keywriter certificate inspection

Mevcut bir Keywriter certificate kullanıcı tarafından verildiyse inspection yapılabilir. Secret encrypted fields'in raw byte değerleri GUI'de açılmaz.

### 22.5 İleride dedicated-device execution eklenirse

Normal build UI'dan ayrı bir plugin/privileged mode olmalıdır ve şu koşullar olmadan açılmamalıdır:

- dedicated device;
- written authorization;
- key owner;
- peer review;
- secret-management process;
- verified runbook.

v2.0 release bu execution'u içermez.

---

## 23. Revision Simulator

### KEYREV

```text
Current model
KEYCNT       ...
KEYREV       ...
Target       primary / backup

Result       VALID / INVALID / NOT VERIFIED
```

GUI bu simulation'ı eFuse write ile karıştırmaz.

### SWREV

Context seçilir:

- SBL/ROM;
- SYSFW;
- Board Configuration;
- Secure Debug;
- application (yalnız exact source'da desteklenen iddia sınırıyla).

```text
Reference revision    5
Certificate revision  3
Result                WOULD_REJECT / WOULD_ACCEPT / NOT_DEFINED
```

Unsupported/generalized context'te tahmin yapılmaz.

---

## 24. Security BoardCfg Editor

Raw YAML ilk kullanıcı arayüzü olmamalıdır.

Form alanları:

```text
Secure Debug Policy
  Wildcard UID                    OFF
  Minimum certificate revision   ...
  Allowed hosts                  ...

Revision-write policy
  Authorized write host          ...
```

Altta:

```text
[ Teknik YAML Önizleme ]
[ Profile Kaydet ]
[ Policy Kontrol Et ]
```

GUI source-backed alanları yalnız supported profile schema üzerinden düzenler.

---

## 25. Secure Debug Assistant

Mevcut certificate + BoardCfg backend'iyle yeni bir birleşik workflow yapılabilir.

Adımlar:

1. Secure Debug certificate inspect/create;
2. SOC UID input/validation;
3. certificate SWREV;
4. debug privilege;
5. secure/non-secure core selection;
6. BoardCfg policy evaluation;
7. transport choice (`TISCI` / `JTAG`) yalnız documentation/simulation context;
8. result.

Sonuç:

```text
Certificate structure        PASS
BoardCfg policy              PASS
SOC UID rule                 PASS
JTAG eFuse state             UNKNOWN
Target debug authorization   NOT VERIFIED
```

“Unlock JTAG” default action olarak sunulmaz.

---

## 26. Generic Data Assistant

Application boot ile generalized authentication ayrımı öğrenmesi zor olduğundan GUI bunu ayrı görev olarak gösterir.

```text
Generic Data Protection

Input binary
Signing
Optional encryption
Load/auth mode
Package build
Host-side verify
```

Açıklama:

> Boot Extension yoksa `TISCI_MSG_PROC_AUTH_BOOT` processor boot yerine generalized authentication bağlamında kullanılabilir.

Decrypted data GUI output/log'a yazılmaz.

---

## 27. Evidence / Session Center

Kullanıcı her komutu tek tek not almak zorunda kalmamalıdır.

Session timeline:

```text
10:42 Environment check          PASS
10:44 Signing key preflight      PASS
10:45 MEK preflight              PASS
10:46 TI application build       PASS
10:46 X.509 parse                PASS
10:47 Signature check            PASS
10:47 Ciphertext integrity       PASS
```

Her entry:

- operation;
- non-secret input name/hash;
- tool identity;
- execution state;
- output hash;
- expected/actual;
- result;
- source reference.

### Export

```text
[ Markdown ] [ JSON ] [ HTML ]
```

Rapor export edilmeden önce **Secret Scan** otomatik çalışır.

```text
Secret-content scan       PASS
Secret-path scan          PASS
```

---

## 28. Share-Safe Report Mode

Rapor iki profil sunabilir:

### Technical report

Public hash/OID/tool identity gibi bütün teknik ayrıntılar bulunur.

### Share-safe report

- machine-specific path'ler normalize edilir (`<HOME>`);
- secret path'ler hiçbir zaman yazılmaz;
- public artifact hash'leri korunur;
- exact claim boundary korunur.

Bu özellikle ekran görüntüsü/Jira/staj raporu gibi kullanımlarda hata riskini azaltır.

---

## 29. Source Trace Panel

Önemli her açıklamanın yanında:

```text
[ Kaynağı Göster ]
```

olmalıdır.

Örnek source card:

```text
TISCI 12.00.02 — System Firmware Authentication and Decryption Requests
Topic: authentication sequence
Local source: TISCI-04...

Summary:
1 public-key integrity
2 certificate authentication
3 image-data integrity
4 optional decryption
5 decrypted-result correctness
```

Source panel web bağlantısına bağımlı olmamalı; toolkit'in source registry'si local reference metadata taşıyabilmelidir.

### Source priority

UI yardım metinleri şu sıraya göre çözülür:

1. installed SDK source / Makefile / verbose build;
2. same-release SDK/TISCI;
3. silicon errata;
4. TRM/datasheet.

Exact value yoksa “doğrulanmadı” gösterilir.

---

## 30. Learn Mode

Ana menüde ayrı bir “Öğren” alanı olabilir; fakat normal workflow'u ders uygulamasına dönüştürmemelidir.

Kısa konular:

- RBL / SBL / SYSFW nedir?
- GP / HS-FS / HS-SE farkı;
- ROM certificate vs application certificate;
- signing vs integrity vs encryption;
- MPK / MEK;
- SMPK/BMPK ve SMEK/BMEK;
- `ENC_ENABLED` vs `ENC_SBL_ENABLED`;
- certificate signature vs payload hash;
- host-side verification vs hardware enforcement.

Her konu 30–90 saniyelik kısa kartlardan oluşur.

---

## 31. 5 Dakikalık Demo Workspace

İlk kez kullanan kişi için:

```text
[ Örnekle Öğren ]
```

Demo:

1. synthetic development signing key oluşturur;
2. synthetic MEK oluşturur;
3. bundled küçük test payload seçer;
4. offline package üretir;
5. inspect eder;
6. verify eder;
7. copy üzerinde bir-byte negative test yapar;
8. PASS → expected FAIL farkını gösterir.

Demo üretim/customer key veya hardware kullanmaz.

---

## 32. Hata Mesajı Tasarımı

Backend exception doğrudan kullanıcıya fırlatılmamalıdır.

Kötü:

```text
CalledProcessError exit status 1
```

İyi:

```text
Image oluşturulamadı

Signing key preflight tamamlanamadı.

✓ Dosya bulundu
✗ Private RSA key olarak okunamadı
○ RSA-4096 kontrol edilmedi

[ Key'i Kontrol Et ] [ Teknik Ayrıntı ]
```

### Hata katmanları

1. kısa kullanıcı mesajı;
2. “nasıl düzeltilir?” önerisi;
3. teknik detail drawer;
4. source link;
5. redacted internal error metadata.

---

## 33. Dry Run ve Change Preview

Build workflow'larında `Dry Run` bir expert-only gizli seçenek olmamalı; güvenli preview olarak sunulmalı.

```text
Dry Run

Would run:
TI application signer
Input: hello_world.mcelf
Signing key: supplied / REDACTED
MEK: supplied / REDACTED
Output: hello_world.secure

No tool executed.
```

Provisioning-related form'larda “what would change?” paneli bulunur ancak v2.0 target write yapmaz.

---

## 34. Background Worker ve Cancel modeli

Qt UI thread'i hiçbir zaman build/hash/SDK diff sırasında bloklanmamalıdır.

Önerilen yapı:

```text
QMainWindow
  -> ViewModel / Workflow Controller
      -> Job Manager
          -> QThreadPool / QRunnable
              -> core service function
```

Cancel davranışı:

- read-only hash/scan jobs: güvenle cancel;
- external TI subprocess: terminate/kill policy kontrollü;
- secret output yazımı sırasında atomicity korunmalı;
- output oluşmuşsa incomplete/unknown olarak işaretlenmeli, otomatik PASS verilmemeli.

---

## 35. Qt / PySide6 seçimi

### Öneri

**PySide6 (Qt 6)**.

Neden:

- wizard ekranları;
- tree/table modelleri;
- drag & drop;
- rich status widgets;
- background worker entegrasyonu;
- accessibility;
- high-DPI;
- Linux/Windows masaüstü paketleme;
- gelecekte chart/anatomy custom widget'ları.

Tkinter mevcut basit GUI için yeterlidir fakat v2.0 kapsamındaki stateful workflow'lar için sürdürülebilir değildir.

### Dependency modeli

Base CLI mümkün olduğunca hafif kalmalıdır:

```toml
[project.optional-dependencies]
gui = ["PySide6>=6.x"]
```

CLI-only install GUI dependency istememelidir.

---

## 36. Önerilen yeni package mimarisi

Mevcut çekirdek fonksiyonlar korunur, katmanlar netleştirilir:

```text
src/am64x_secure_toolkit/

  core/
    inspect.py
    verify.py
    certificate.py
    build.py
    negative.py
    keycheck.py
    keygen.py
    provision.py
    revision.py
    boardcfg.py
    sdk_lint.py
    sdk_diff.py
    errata.py
    generic_data.py
    reporting.py

  services/
    environment.py
    sdk_resolver.py
    project.py
    secret_policy.py
    source_registry.py
    result_explainer.py
    session.py

  workflows/
    application.py
    rom.py
    inspect.py
    keys.py
    negative.py
    provisioning.py
    debug.py
    generic_data.py

  gui/
    app.py
    main_window.py
    navigation.py
    state.py
    jobs.py
    theme.py
    resources/
    widgets/
    pages/
      home.py
      environment.py
      project.py
      application.py
      rom.py
      inspector.py
      certificate.py
      keys.py
      negative.py
      sdk.py
      errata.py
      provisioning.py
      revision.py
      boardcfg.py
      generic_data.py
      reports.py
      learn.py

  cli.py
```

### Geçiş kuralı

İlk refactor'da bütün modülleri fiziksel olarak `core/` altına taşımak zorunlu değildir. Önce service/workflow API oluşturulabilir; import compatibility korunur. Büyük dosya hareketi yalnız regression testleri sağlam olduğunda yapılmalıdır.

---

## 37. GUI backend mapping — mevcut v1.0.0

| GUI özelliği | Mevcut backend |
|---|---|
| Smart Inspect | `inspect_artifact()` |
| Host-side Verify | `verify_artifact()` |
| Application Build | `build_app()` |
| ROM Build | `build_rom()` |
| Certificate Create | `build_certificate()` |
| Certificate Explain | `explain_certificate()` |
| Negative Test | `create_negative_variant()` |
| Negative Suite | `run_negative_suite()` |
| Signing key check | `preflight_signing_key()` |
| MEK check | `preflight_mek()` |
| Key compare | `compare_key_material()` |
| Provisioning preflight | `provision_preflight()` |
| KEYREV simulation | `simulate_key_revision()` |
| SWREV simulation | `simulate_swrev()` |
| BoardCfg check | `check_boardcfg_profile()` |
| Debug policy | `evaluate_debug_policy()` |
| Revision writer policy | `evaluate_revision_writer()` |
| SDK lint | `lint_sdk_security()` |
| SDK diff | `compare_sdk_security()` |
| Errata | `list_errata()` / `check_errata()` |
| Generic data build | `build_generic_data()` |
| Generic data verify | `verify_generic_data()` |
| Image report | `write_image_report()` |
| Batch report | `write_batch_report()` |

Yeni core fonksiyonlar:

| Yeni özellik | Yeni servis/core |
|---|---|
| Key generation | `keygen.py` |
| Environment auto-discovery | `environment.py` / `sdk_resolver.py` |
| Project workspace | `project.py` |
| Session/evidence timeline | `session.py` |
| Source trace | `source_registry.py` |
| Result explanation | `result_explainer.py` |
| Share-safe export scan | `secret_policy.py` |

---

## 38. Workflow Service standardı

GUI her backend fonksiyonunun özel JSON shape'ini bilmemelidir. Ortak workflow result modeli gerekir.

Örnek:

```python
WorkflowResult(
    status="PASS | FAIL | PARTIAL | NOT_CHECKED | ERROR",
    operation="application_build",
    summary="...",
    checks=[...],
    outputs=[...],
    claims=[...],
    non_claims=[...],
    sources=[...],
    safe_details={...},
)
```

Böylece:

- CLI JSON aynı modeli serialize eder;
- GUI aynı modeli kartlara çevirir;
- report engine aynı modeli Markdown/HTML yapar;
- `PASS/PARTIAL/NOT_CHECKED` anlamları ekranlar arasında değişmez.

---

## 39. Status dili

Teknik sonuçlar için sabit küçük sözlük:

```text
PASS          doğrulandı / beklenen kontrol geçti
FAIL          kontrol başarısız
PARTIAL       bazı kontroller yapılamadı
NOT_CHECKED   bu kapsamda doğrulanmadı
INFO          bilgi
WARN          dikkat, hard failure değil
ERROR         işlem teknik hata nedeniyle tamamlanamadı
```

“SUCCESS” ile “SECURE” eş anlamlı kullanılmaz.

---

## 40. Claim Boundary Engine

GUI'nin farklı yerlerinde aynı güvenlik uyarılarının hardcoded kopyaları bulunmamalıdır.

Merkezi bir rule engine/result-explainer şu context'i alır:

```text
operation
image classification
device state
checks actually executed
hardware executed?
provisioning executed?
```

ve otomatik olarak:

```text
Verified
Not verified
Not executed
Not applicable
```

listelerini üretir.

Örneğin host-side encrypted application verification PASS olduğunda hiçbir ekran “hardware decryption verified” yazamaz.

---

## 41. Secret Policy Engine

Bütün GUI/service katmanlarında aynı policy uygulanmalıdır.

### Yasak output sınıfları

- private key content;
- symmetric key / MEK;
- secret hash;
- seed/passphrase;
- decrypted secret payload;
- persistent secret path;
- full external-tool stdout/stderr if sensitive content risk exists.

### İzin verilenler

- public certificate;
- public DER-SPKI;
- public fingerprint;
- artifact hash;
- tool hash;
- masked metadata;
- secret supplied: yes/no.

### Clipboard

Secret key/MEK için “Copy” düğmesi sunulmamalıdır. Generated development MEK kullanıcıya bir kez gösterilecekse bile tercih edilen davranış dosyaya güvenli yazıp değeri UI'ya basmamaktır.

---

## 42. File Safety Engine

Bütün output üretimlerinde ortak kurallar:

1. input ve output aynı dosya olamaz;
2. output existing ise explicit non-secret overwrite policy gerekir;
3. key files için overwrite default olarak yasak;
4. negative tests yalnız copy üzerinde;
5. generated output elle düzeltme önerilmez;
6. source input işlem sonrası hash ile kontrol edilebilir;
7. output hash session'a kaydedilir.

---

## 43. UI tasarım dili

### Dil

- Ana dil Türkçe.
- Official English adlar korunur: `Secure Boot`, `System Firmware`, `Board Configuration`, `Build`, `register`, `X.509`, `Root of Trust`, `Keywriter`, `Secure Debug`.
- Gereksiz yapay Türkçeleştirme yapılmaz.

### Görsel dil

- sade;
- kart tabanlı;
- teknik ama “IDE kalabalığı” gibi değil;
- PASS/FAIL yalnız renkle anlatılmaz; ikon + metin kullanılır;
- kırmızı yalnız gerçek failure/unsafe action için;
- lifecycle ve claim boundary sürekli görünür.

### Renk bağımlılığı

Accessibility için:

```text
✓ PASS
✗ FAIL
! WARN
? NOT CHECKED
```

ikonları renk olmadan da anlamlıdır.

---

## 44. Keyboard ve accessibility

- Tab order mantıklı;
- tüm işlemler keyboard ile erişilebilir;
- screen reader-friendly labels;
- high-DPI scaling;
- font size ayarı;
- light/dark/system theme;
- status yalnız renk ile iletilmez;
- long hash alanlarında copy button yalnız public data için.

---

## 45. Paketleme ve çalıştırma

Kullanıcı hedefi “Python projesi kurmayı bilmek” olmamalıdır.

### Development

```text
pip install -e .[gui,dev]
securectl gui
```

### Release

Tercih:

- Linux AppImage / portable bundle;
- Windows installer veya portable executable;
- CLI wheel ayrıca korunur.

Paketleme aşamasında bundled TI SDK veya TI proprietary binary/tool kopyalanmaz; kullanıcı kendi kurulu SDK'sını seçer.

---

## 46. Test stratejisi

### 46.1 Mevcut regression

v1.0.0 testlerinin tamamı geçmeye devam etmelidir.

### 46.2 Yeni core testleri

- key generation;
- environment discovery;
- project serialization secret scan;
- claim boundary result generation;
- source registry;
- share-safe report.

### 46.3 GUI/ViewModel testleri

`pytest-qt` önerilir.

Test örnekleri:

- Home task card doğru workflow açıyor;
- Application Wizard signed-only ve encrypted+signed state'i;
- invalid key ile Build düğmesi disabled;
- wrong device context yanlış claim üretmiyor;
- secret path session export'a düşmüyor;
- negative test source'u değiştirmiyor;
- background error UI thread'i çökertmiyor;
- cancel partial output'u PASS saymıyor;
- NOT_CHECKED doğru görünür;
- drag/drop doğru classifier'ı çağırıyor.

### 46.4 UI snapshot yerine semantic test

Pixel-perfect screenshot testleri ana güvenlik testi olmamalıdır. Asıl kontrol:

- doğru state;
- doğru enable/disable;
- doğru backend call;
- doğru redaction;
- doğru claim boundary.

---

## 47. Güvenlik regresyon testleri

Aşağıdaki invariant'lar CI'da özel test olmalıdır:

```text
private key value never in WorkflowResult
MEK value never in WorkflowResult
secret path never in BuildRecord
negative source hash unchanged
host PASS never implies hardware enforcement PASS
HS-FS never silently becomes customer-enforced state
OTP/eFuse action unavailable in normal GUI
```

---

## 48. Telemetry / internet politikası

Varsayılan release **offline-first** olmalıdır.

- telemetry default OFF;
- analytics zorunlu değil;
- secret/artifact upload yok;
- web lookup otomatik değil;
- source help local çalışır.

Gelecekte “check latest TI docs” özelliği eklenirse explicit user action ve ayrı network indicator gerekir.

---

## 49. Ayarlar

Ayarlar ekranı sade tutulur:

```text
Appearance          System / Light / Dark
Language            Türkçe
Default workspace   ...
SDK root             ...
Expert details       Default closed/open
Auto post-verify     ON
Auto safe-report     ON
Network features     OFF
```

Secret key default path gibi ayarlar bulunmaz.

---

## 50. Source-backed teknik sınırlar

GUI tasarımı aşağıdaki AM64x/TISCI ayrımlarını bozmayacaktır:

- HS-FS, customer keys provision edilmeden önceki state'tir ve customer secure-boot enforcement varsayılmaz.
- HS-SE, customer key provisioning sonrası secure-boot enforcement bağlamıdır.
- Application signing/encryption akışı System Firmware/TIFS certificate context'indedir.
- ROM combined-image ve application certificate template/tool zinciri farklıdır.
- `ENC_ENABLED` application encryption; `ENC_SBL_ENABLED` ROM/SBL encryption katmanını kontrol eder.
- encrypted application için ciphertext SHA-512 image-integrity binding certificate signature verification'dan ayrıdır.
- `TISCI_MSG_PROC_AUTH_BOOT` authentication + optional decryption hizmeti sağlar; host-side doğrulama bunun target enforcement sonucu değildir.
- Secure Debug X.509 certificate, secure boot certificate'ından farklı bağlamdır.
- Keywriter provisioning X.509, normal application image certificate'ından farklıdır.
- provisioning write işlemi irreversible class'tadır ve normal GUI workflow'u değildir.

---

## 51. Özellikle yapılmayacak tasarımlar

### 51.1 “Her şeyi tek düğmede yap”

```text
[ MAKE DEVICE SECURE ]
```

olmayacak.

### 51.2 “Build PASS = Secure”

olmayacak.

### 51.3 Secret'ı form içinde sürekli gösterme

olmayacak.

### 51.4 Tool seçeneklerini tahmin etme

exact source yoksa değer “unknown/unverified” kalacak.

### 51.5 Generated TI output'u otomatik patch etme

olmayacak.

### 51.6 Negative test'i original üzerinde yapma

olmayacak.

### 51.7 GUI içine doğrudan OTP/eFuse burn akışı

v2.0 kapsamında olmayacak.

---

## 52. Önceliklendirme — MUST / SHOULD / COULD / LATER

### MUST — v2.0 release için

1. PySide6 shell ve navigation
2. Environment Wizard
3. Project Workspace
4. Device Context Bar
5. Home guided task selection
6. Smart Inspect + Image Anatomy
7. Host-side Verify UI
8. Secure Application Wizard
9. Key Center + development key generation
10. ROM Image Wizard
11. Certificate Explorer
12. Negative Tests UI
13. SDK Inspector
14. Errata Advisor
15. Provisioning Preparation (offline only)
16. Result “ne kanıtlar / ne kanıtlamaz” paneli
17. Session/Report Center
18. secret-safe shared services
19. background jobs
20. regression + GUI tests

### SHOULD

21. SDK Compare assistant
22. Security BoardCfg form editor
23. Revision simulator
24. Generic Data assistant
25. Secure Debug assistant
26. source trace panel
27. Learn Mode
28. share-safe HTML report
29. demo workspace

### COULD

30. command palette (`Ctrl+K`)
31. recent projects
32. public artifact compare
33. project template library
34. printable workflow diagram
35. UI-integrated source search

### LATER / ayrı scope

36. HSM / PKCS#11 provider
37. hardware read-only device detection
38. dedicated-device reversible validation plugin
39. authorized provisioning execution plugin
40. multi-SoC support

---

## 53. Uygulama aşamaları

### Phase 0 — Baseline lock

- v1.0.0 package hash/test baseline kaydet;
- bütün current tests çalıştır;
- module/function inventory çıkar;
- current CLI behavior regression contract olarak sabitle.

### Phase 1 — Core cleanup + common result model

- `WorkflowResult`;
- error/redaction model;
- claim boundary service;
- secret policy;
- source registry skeleton.

GUI'ye geçmeden bu katman tamamlanmalı.

### Phase 2 — Key generation + environment discovery

- `keygen.py`;
- safe file creation;
- automatic preflight;
- SDK resolver;
- tool identity;
- environment model.

### Phase 3 — Qt shell

- main window;
- navigation;
- theme;
- project/context state;
- background job manager;
- generic PASS/FAIL/check widgets.

### Phase 4 — Core user workflows

Sıra:

1. Home
2. Environment
3. Inspector/Verify
4. Application Wizard
5. Key Center
6. Report Center

Bu noktada GUI günlük kullanım için anlamlı olur.

### Phase 5 — Secure Boot genişleme

- ROM Wizard;
- Certificate Explorer;
- Negative Tests;
- SDK Inspector;
- Errata.

### Phase 6 — Advanced offline security tools

- Provisioning Preparation;
- Revision;
- BoardCfg;
- Secure Debug;
- Generic Data;
- SDK Compare.

### Phase 7 — Learn/source polish

- source trace;
- Learn Mode;
- demo workspace;
- help/error explanations.

### Phase 8 — Packaging / final QA

- Linux bundle;
- Windows bundle;
- install/uninstall;
- no-SDK behavior;
- no-network behavior;
- secrets scan;
- accessibility;
- high-DPI;
- clean-machine smoke tests.

---

## 54. Minimum kullanılabilir release (MVP) ne olmalı?

MVP'yi çok küçültürsek kullanıcı yine CLI'ya dönmek zorunda kalır. Gerçek MVP:

```text
Environment
Project
Application build
Key generation/check
Inspect
Verify
Negative test
Report
```

Bu sekiz alan birlikte tamamlandığında yeni başlayan kullanıcı application host-side workflow'unu baştan sona GUI'de yapabilir.

ROM/provisioning/SDK advanced sayfaları ikinci milestone olabilir.

---

## 55. Definition of Done — v2.0

v2.0 tamamlanmış sayılabilmesi için:

1. Yeni kullanıcı SDK root dışında machine path yazmadan application workflow yapabilmeli.
2. Yeni kullanıcı command line kullanmadan signed-only image oluşturabilmeli.
3. Yeni kullanıcı command line kullanmadan encrypted+signed image oluşturabilmeli.
4. Development signing key + MEK GUI'den secret-safe üretilebilmeli.
5. Generated image otomatik post-verify edilebilmeli.
6. ROM combined-image akışı GUI'den gerçekleştirilebilmeli.
7. Image/certificate drag-drop ile classify/inspect edilebilmeli.
8. Negative tests source'u değiştirmeden GUI'den çalışabilmeli.
9. Current toolkit'teki bütün v1.0.0 host-side yetenekler GUI'den erişilebilir veya bilinçli olarak “expert/CLI only” diye açıklanmış olmalı.
10. Normal GUI içinde OTP/eFuse irreversible action olmamalı.
11. Secret value/hash/path rapor, session, JSON veya UI log'una sızmamalı.
12. Host-side PASS hiçbir yerde hardware/customer enforcement PASS olarak sunulmamalı.
13. Baseline CLI regression testleri PASS olmalı.
14. GUI semantic tests PASS olmalı.
15. Clean Linux/Windows environment smoke test tamamlanmalı.

---

## 56. En iyi kullanıcı deneyiminin örnek akışı

Yeni başlayan kullanıcı programı ilk kez açar:

```text
1 Secure Boot Studio açılır
2 Environment Wizard SDK'yi bulur
3 “Yeni Proje” seçilir
4 Device = AM6442, context = HS-FS
5 Ana Sayfa -> Secure Application Oluştur
6 MCELF seçilir
7 “Encrypted + signed” seçilir
8 “Development key set oluştur” denir
9 Key generation + preflight PASS
10 Build preview gösterilir
11 TI signer çalışır
12 Post-verify çalışır
13 Image Anatomy açılır
14 “Bu neyi kanıtlar?” paneli okunur
15 İstenirse one-byte ciphertext negative test yapılır
16 Share-safe report üretilir
```

Bu akışta kullanıcı şu komutları veya kavramları bilmek zorunda kalmaz:

```text
--enc y
--enckey
--authtype
.1.4
.1.34
openssl dgst
DER boundary
```

Ancak “Teknik Ayrıntılar” açıldığında bunların tamamını görebilir ve öğrenebilir.

---

## 57. Son karar

Bu proje için önerilen yön basit bir Tkinter ekranını büyütmek değildir.

Doğru hedef:

> **Mevcut AM64x Secure Boot backend'ini görev bazlı, kaynak izlenebilir, secret-safe ve claim-aware bir masaüstü uygulamasına dönüştürmek.**

En güçlü fark yaratacak üç özellik:

1. **Rehberli workflow'lar:** kullanıcı komut değil hedef seçer.
2. **Görsel teknik açıklama:** Image Anatomy + Certificate Explorer + source trace.
3. **Güvenlik anlamını doğru gösterme:** her sonuçta “ne doğrulandı / ne doğrulanmadı”.

Bunların üzerine Key Center, SDK Inspector, controlled negative tests, provisioning preparation ve report/session sistemi eklendiğinde toolkit yalnız bir script koleksiyonu değil, AM64x Secure Boot için gerçek bir **Secure Boot Studio** olur.

---

## 58. Blueprint'in dayandığı mevcut proje bileşenleri

### Toolkit v1.0.0 kodu

- `src/am64x_secure_toolkit/gui.py`
- `cli.py`
- `inspect.py`
- `verify.py`
- `build.py`
- `certificate.py`
- `negative.py`
- `keycheck.py`
- `provision.py`
- `revision.py`
- `boardcfg.py`
- `sdk_lint.py`
- `sdk_diff.py`
- `errata.py`
- `generic_data.py`
- `reporting.py`
- mevcut test suite

### AM64x / TISCI kaynak ailesi

- MCU+ SDK 12.00.00.27 Secure Boot guide
- MCU+ SDK 12.00.00.27 Security Related Tools
- TISCI 12.00.02 Signing binaries for Secure Boot
- TISCI 12.00.02 Security X.509 Certificate
- TISCI 12.00.02 Authentication and Decryption Requests
- TISCI 12.00.02 Processor Boot Management
- TISCI 12.00.02 Key Writer
- TISCI 12.00.02 Secure Debug
- TISCI 12.00.02 Security Board Configuration
- AM64x/AM243x TRM Rev. J
- AM64x/AM243x Errata Rev. J
- frozen Day-6/7/8 host-side evidence ve project technical document

