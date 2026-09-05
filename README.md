# AM64x Secure Boot Studio / Toolkit

**Current development release: `2.0.0-alpha26`**

Alpha21 introduces the AM64x-focused **Certificate Center** for from-scratch Subject entry, Application/Secure Debug certificate creation, inspect/verify/export/reissue/compare and public Project Certificate Library workflows.

AM64x/AM6442 Secure Boot çalışmalarında kullanılan image, X.509 certificate, key ve SDK yapılandırmalarını hazırlamak, incelemek ve doğrulamak için geliştirilmiş Python araç seti ve rehberli masaüstü uygulamasıdır. Toolkit, Texas Instruments MCU+ SDK içindeki `rom_image_gen.py` ve `appimage_x509_cert_gen.py` araçlarının yerine geçmez; bu araçlarla yürütülen işlemlerin çevresine ek kontrol ve doğrulama katmanı sağlar.

Current Studio development build: `2.0.0-alpha26` (real-host visual QA in progress; final release not declared).

Araç seti şu teknik sürümler esas alınarak geliştirilmiştir:

- MCU+ SDK `12.00.00.27`
- SYSFW/TISCI `12.00.02`
- AM64x/AM243x TRM Rev. J
- AM64x/AM243x Errata Rev. J

## Başlıca özellikler

- Secure image ve DER X.509 certificate inceleme
- Certificate signature ile payload/ciphertext integrity kontrollerini ayrı doğrulama
- Application ve ROM image üretiminde kurulu TI SDK araçlarını kontrollü çağırma
- Comprehensive **Certificate Center**: Application ve Secure Debug certificate'larını Subject (`C/ST/L/O/OU/CN/email`) dahil GUI'den sıfırdan oluşturma, profile/config üretme, DER/PEM export, metadata/validity/SPKI inceleme, certificate↔private-key eşleşmesi, compare, clone/reissue ve Project Certificate Library
- Application/Generic/ROM/Secure Debug/Keywriter certificate context'lerini birbirinden ayıran source-backed yönlendirme; encrypted application için resmi TI `appimage_x509_cert_gen.py`, ROM için `rom_image_gen.py`, Keywriter için provisioning-preparation boundary korunur
- Kontrollü negatif test kopyaları üretme
- RSA signing key ve AES-256 MEK format kontrolleri
- Synthetic/non-production RSA-4096 ve AES-256 key generation
- PySide6 tabanlı rehberli Secure Boot Studio workflow
- MCU+ SDK/environment auto-discovery ve Project Workspace
- HS-FS → HS-SE için offline provisioning hazırlık kontrolü
- KEYREV ve SWREV kurallarını target'a yazmadan değerlendirme
- Security Board Configuration policy kontrolleri
- `devconfig.mak`, Makefile ve signing araçları için SDK security lint/diff kontrolleri
- AM64x Boot/Security errata filtreleme ve koşul kontrolü
- Generic binary için generalized authentication ve optional encryption package üretimi
- Markdown/JSON doğrulama raporları
- Image inceleme, doğrulama ve raporlama için rehberli masaüstü arayüzü
- Offline-by-design runtime policy; telemetry/auto-update/SDK download yok
- Release secret/path hygiene scanner ve standalone packaging recipe’leri
- Local-only recent Project/preferences, share-safe Diagnostics ve explicit beta-readiness gate

## Certificate Center

`Certificate Center`, AM64x secure-boot bağlamındaki public X.509 yaşam döngüsünü tek yerde toplar:

- **Yeni Certificate:** Application veya Secure Debug için Subject alanlarını formdan doldurma; SWREV/validity ve source-backed TI extension alanlarını yönetme.
- **Explorer / Doğrula:** DER, PEM veya certificate+payload image inceleme; Subject/Issuer/public key/signature/TI OID alanları ve host-side verification.
- **Yeniden Üret / Export:** Signed certificate byte'larını elle değiştirmek yerine existing certificate'tan yeni profile oluşturma; DER/PEM/SPKI export ve certificate↔private-key match.
- **Certificate Library:** Project altında yalnız public certificate kopyalarını, fingerprint/context/validity metadata'sıyla düzenleme. Private key, MEK veya secret path Library'ye alınmaz.
- **Karşılaştır:** İki certificate'ın Subject/Issuer, validity, serial, SPKI, signature ve extension-set farklarını karşılaştırma.
- **Context routing:** ROM/Application/Generic Data/Secure Debug/Keywriter aynı certificate template'i kabul edilmez. Encryption metadata'sı/ciphertext binding resmi TI application signer'a; ROM combined certificate resmi ROM signer'a; Keywriter provisioning ise offline preparation sınırına yönlendirilir.

Standart enterprise PKI özellikleri olan CSR/CA hierarchy/CRL/OCSP, version-locked AM64x Secure Boot kaynaklarında bu self-signed TI secure-image/debug akışının parçası olarak tanımlanmadığı için Studio bunları vendor akışına uydurmaz.

## Kurulum

Python `3.10` veya üzeri gereklidir.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

Kaynak kod üzerinde geliştirme ve test için:

```bash
pip install -e '.[dev]'
pytest -q
```

GUI dahil geliştirme kurulumu:

```bash
pip install -e ".[dev,gui]"
```

CLI-only install PySide6 gerektirmez.

## Hızlı kullanım

Bir image veya certificate'ı incelemek için:

```bash
securectl inspect <IMAGE_OR_CERTIFICATE>
```

Host üzerindeki signature ve integrity kontrollerini çalıştırmak için:

```bash
securectl verify <IMAGE_OR_CERTIFICATE>
```

Okunabilir bir doğrulama raporu oluşturmak için:

```bash
securectl report image <IMAGE> --output verification-report.md
```

Application certificate profile oluşturmak için:

```bash
securectl cert new app --output app.yaml
securectl cert validate app.yaml
```

Kurulu TI application signer ile image üretmek için:

```bash
securectl build app \
  --tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --input <APP_MCELF> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_APPIMAGE> \
  --post-verify
```

Masaüstü arayüzünü açmak için:

```bash
pip install ".[gui]"
securestudio
# veya
securectl gui
```

Synthetic development key set üretmek için:

```bash
securectl key generate set --profile development --output-dir <EMPTY_DIR>
```

Environment kontrolü:

```bash
securectl environment --sdk-root <SDK_ROOT>
```

Release hygiene kontrolü:

```bash
securectl release-scan <RELEASE_ROOT>
securectl network-policy
securectl diagnostics --output diagnostics.md
securectl beta-readiness --source-root <SOURCE_PACKAGE>
```

Tüm komutlar:

```bash
securectl --help
```

## Güvenli kullanım

Toolkit private key, MEK veya passphrase içeriğini kalıcı raporlara yazmak üzere tasarlanmamıştır. Build kayıtlarında secret key yolları ve key dosyalarının hash değerleri tutulmaz. Negatif testler yalnız ayrı dosya kopyaları üzerinde çalışır.

`verify`, `provision`, `revision`, `boardcfg`, `errata` ve benzeri host işlemlerinin başarılı olması, hedef cihazda customer Root of Trust veya HS-SE enforcement'ın doğrulandığı anlamına gelmez. Toolkit OTP/eFuse programlamaz, HS-FS → HS-SE geçişi yapmaz ve target üzerinde permanent debug/security değişikliği uygulamaz.

Ayrıntılı sınırlar için `docs/SECURITY_BOUNDARY.md` dosyasına bakın.

## Dokümantasyon

- `docs/KULLANIM.md` — tüm komutların ayrıntılı kullanımı
- `docs/ARCHITECTURE.md` — modüller ve veri akışları
- `docs/CERTIFICATES.md` — X.509 certificate işlemleri
- `docs/CERTIFICATE_CENTER.md` — Certificate Center: sıfırdan Subject girişi, create/inspect/verify/export/reissue/compare/library
- `docs/NEGATIVE_TESTS.md` — negatif testler
- `docs/KEYS.md` — signing key ve MEK kontrolleri
- `docs/PROVISIONING.md` — HS-FS → HS-SE provisioning hazırlık kontrolü
- `docs/REVISION.md` — KEYREV/SWREV kontrolleri
- `docs/BOARDCFG.md` — Security Board Configuration kontrolleri
- `docs/SDK_LINT.md` ve `docs/SDK_DIFF.md` — SDK source/configuration kontrolleri
- `docs/ERRATA.md` — silicon errata kontrolleri
- `docs/GENERIC_DATA.md` — generic binary authentication/encryption
- `docs/REPORTS.md` — doğrulama raporları
- `docs/GUI.md` — Secure Boot Studio masaüstü arayüzü
- `docs/GUI_UX_BLUEPRINT_v2.0.md` — v2 GUI/UX blueprint
- `docs/IMPLEMENTATION_QA_ALPHA21.md` — alpha21 Certificate Center implementation baseline
- `docs/IMPLEMENTATION_QA_ALPHA23.md` — alpha22 beginner-onboarding/start-screen polish regression / release QA
- `docs/STUDIO_V2_ALPHA11.md` — historical alpha11 beta-hardening / diagnostics / local-state kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA11.md` — alpha11 regression / beta-readiness QA
- `docs/STUDIO_V2_ALPHA10.md` — historical alpha10 onboarding / Project-aware output kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA10.md` — alpha10 regression / onboarding-workspace UX QA
- `docs/STUDIO_V2_ALPHA9.md` — historical alpha9 workflow-history / advanced UX kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA9.md` — historical alpha9 regression / persistent-history QA
- `docs/STUDIO_V2_ALPHA8.md` — historical alpha8 visual-semantic polish kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA8.md` — historical alpha8 regression / visual-semantic QA
- `docs/STUDIO_V2_ALPHA7.md` — historical alpha7 product-polish implementation kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA7.md` — historical alpha7 regression / product-polish QA
- `docs/STUDIO_V2_ALPHA5.md` — historical alpha5 implementation kapsamı
- `docs/IMPLEMENTATION_QA_ALPHA4.md` — Phase 8 local QA / release-readiness sınırı
- `docs/STUDIO_V2_ALPHA2.md` — historical alpha2 implementation kapsamı
- `docs/STUDIO_V2_ALPHA1.md` — historical alpha1 implementation kapsamı
- `docs/BASELINE_V1_LOCK.md` — v1.0.0 regression baseline
- `docs/BUILD_ORCHESTRATION.md` ve `docs/BUILD_RECORD.md` — TI build wrapper ve build kayıt biçimi
- `docs/SOURCES.md` — teknik kaynak eşlemesi
- `docs/TESTLER.md` — otomatik test ve paket kontrol özeti
- `examples/` — doldurulabilir örnek YAML profilleri ve komut örnekleri

## Teknik kaynaklar

Toolkit'teki AM64x/TISCI kuralları, sürüme özgü resmi TI kaynaklarına ve projede incelenen kurulu MCU+ SDK source dosyalarına dayandırılmıştır. Kaynakların hangi modülde kullanıldığı `docs/SOURCES.md` içinde özetlenmiştir.


## v2.0.0-alpha3 guided learning

Studio now includes **Bana Yol Göster**, **Source Trace**, **Öğren**, a result **Neden?** panel and a **5 Dakikalık Demo**. The demo is explicitly educational / synthetic / non-production / unprovisioned and NOT_TARGET_READY; exact target values are not invented.


## v2.0.0-alpha5 GUI completeness + semantic hardening

Alpha5, Phase 8 release hazırlığının yanında beginner-facing GUI completeness audit uygular:

- **Rehberli Mod / Uzman Modu**: temel ekranlar ve advanced offline/security ekranları ayrılır.
- Key Center artık generation yanında existing signing/MEK preflight ve private/public match sunar.
- Negative Tests artık single mutation + automatic suite + ROM component mutation sunar.
- Reports artık current result, in-memory share-safe session history, single-image Markdown ve batch report üretir.
- Certificate ekranı Explorer yanında application/debug profile create/validate/render/build akışlarını sunar.
- Inspector drag-and-drop ile read-only inspect açabilir.
- Errata GUI değerleri backend canonical enum'larıyla ortak `ui_contract` üzerinden kilitlenmiştir.


Alpha4 adds high-DPI/accessibility preparation, explicit no-SDK/offline behavior, release secret/path scanning and standalone packaging recipes. Cross-platform release readiness is **PARTIAL** until real PySide6 render and clean Linux/Windows standalone smoke tests are executed.


## v2.0.0-alpha7 product polish

Alpha7, alpha6'nın insan-okunur result ve Application Wizard temelini ileri taşır. ROM Combined Image artık adım-adım wizard'dır; Certificate Explorer tree/detail görünümünde certificate context, consumer, OID, decoded value, claim sınırı ve source'u birlikte gösterir. Key Center application ve provisioning key rollerini görsel olarak ayırır ve public identity metadata'sını secret-safe biçimde sunar. Ana Sayfa Environment / Project / Son İşlem kartları ve açıklamalı task cards ile dashboard olarak çalışır.


## v2.0.0-alpha8 visual semantic polish

Alpha8, advanced ekranları aynı beginner-readable görsel dile taşır. SDK Inspector application ve ROM/SBL encryption consumer chain'lerini ayrı diagram lane'lerinde gösterir; Provisioning, KEYREV/SWREV ve Security BoardCfg ekranları semantic flow + human result görünümünü kullanır. Certificate Explorer seçilen extension'ı Image Anatomy üzerinde ilgili blokla ilişkilendirir. Her result check satırında source-aware **Neden?** açıklaması vardır. Studio hiçbir missing target ID/address/offset'i tahmin etmez ve offline/host-side sonucu hardware enforcement'a yükseltmez.


## v2.0.0-alpha9 advanced UX + project history

Alpha9 Secure Debug ve Generic Data ekranlarını raw JSON'dan çıkarıp ortak semantic flow + human result sistemine taşır. SDK Compare old/new source pair'lerini role-based side-by-side semantic diff olarak gösterir. Project Workspace aktifken workflow sonuçları secret/full-host-path içermeyen compact `sessions/activity.jsonl` history'ye yazılır; Reports içindeki Project History sekmesinden tekrar okunabilir. Bu persistence hardware evidence üretmez ve secret custody mekanizması değildir.


## v2.0.0-alpha11 beta-hardening + diagnostics

Alpha11, local-only preferences/recent Project akışı, share-safe Diagnostics ekranı/CLI komutu ve gerçek Qt/standalone QA için execution harness’leri ekler. Dependency veya harness varlığı release evidence sayılmaz; real Qt visual QA ve Linux/Windows clean-machine doğrulaması çalıştırılmadan release readiness `PARTIAL` kalır.

## v2.0.0-alpha10 onboarding + Project-aware workflow

Alpha10, Studio'yu ilk kez kullanan biri için **Environment → Project → Workflow** sırasını görünür hale getirir. Project aktif olduğunda Application/ROM/Negative Test/Report ekranları kontrollü project-relative output önerir; bu yalnız öneridir ve existing output overwrite edilmez. Generated non-secret/public output'lar `sessions/artifacts.jsonl` içinde relative/basename-only referans + optional SHA-256 ile indekslenir. Secret-generating key output Project Workspace içine yazılamaz; yalnız public DER export `project/public/` altına yönlendirilebilir. Source-level beta UX audit gerçek Qt render yerine geçmez; real PySide6/standalone QA hâlâ pending'dir.

## v2.0.0-alpha13 Home/Dashboard visual polish

Alpha12 is a focused real-Linux screenshot-driven polish pass. The Home page now uses compact context chips, concise Environment/Project/Last Operation cards and six beginner-facing primary tasks. Advanced tools remain accessible from Expert Mode instead of being duplicated on the Home dashboard. Card text backgrounds are explicitly transparent to avoid disabled-input-like grey strips on Linux desktop styles, and status-bar messages are kept short. Security execution boundaries are unchanged.


### Alpha13 visual QA note

Environment results now default to a human-readable overview; exact paths, hashes and raw discovery JSON remain available under **Teknik Ayrıntılar**.

## v2.0.0-alpha14 Project Workspace visual polish

Alpha14, real-Linux Project Workspace screenshot QA sonucuna göre create/open state ile active-project dashboard'u birbirinden ayırır. Aktif proje yokken beginner görünümü yalnız proje klasörü, proje adı, device/silicon/lifecycle context, create/open action'ları ve kompakt Son Projeler alanını gösterir. Proje açıldığında Workspace Özeti, Üretilen Dosyalar ve share-safe İşlem Geçmişi dashboard'u görünür. Secret value/path ve full host path project history/artifact index içine yazılmaz.
