# Changelog

## 2.0.0-alpha26

- Real Windows alpha25 Step 2 visual-QA patch for Certificate Center → Application TI fields.
- Added live fail-closed `Devam` gating: Application Step 2 cannot proceed until Payload/application, source-verified Destination Address, Yükleme davranışı and source-verified Destination Host ID are all explicitly provided.
- Added `*` markers to the required Application TI fields and a compact note explaining that target-specific values must come from source-verified context; Studio does not guess them.
- The disabled `Devam` button exposes a contextual tooltip identifying the next missing required field.
- Retained the independent `_validate_create_step` checks so live UI gating is not the sole correctness control.
- Applied the same live readiness mechanism consistently to CN, Secure Debug UID/wildcard, Signing Key and DER output steps without changing certificate encoding or TI security semantics.
- No TI extension encoding, cryptographic, provisioning, lifecycle, debug, hardware-enforcement, target-address, Host-ID or rollback semantics changed.
- Real Windows alpha26 Step 2 visual QA remains pending; project final completion is not declared.

## 2.0.0-alpha25

- Real Windows alpha24 Step 2 visual-QA polish for Certificate Center → Application TI fields.
- Replaced raw `auth_type — copy mode` / `auth_type — Host ID` labels with beginner-facing `Yükleme davranışı` and `Destination Host ID`; exact byte packing is preserved behind a collapsed technical panel.
- Application mode choices now explain Normal copy and in-place behavior without presenting raw enum values as the primary UI language.
- Simplified the encrypted-application notice and retained delegation to the installed TI `appimage_x509_cert_gen.py` flow.
- Renamed `destAddr / Destination address` to `Destination Address` in Guided UI; exact source/build verification remains required and Studio still does not guess the value.
- Renamed the optional boot checkbox to `Processor boot bilgilerini ekle` and added context help that it is only needed when the certificate is used to boot a core.
- No TI extension encoding, cryptographic, provisioning, lifecycle, debug, hardware-enforcement, or target-value semantics changed.
- Real Windows alpha25 Step 2 visual QA remains pending; project final completion is not declared.


## 2.0.0-alpha24

- Real Windows alpha23 Step 1 visual-QA patch for Certificate Center → New Certificate.
- Moved `Software Revision` out of `1 · Subject / Kimlik` into `2 · TI Alanları` so TI security metadata is not presented as X.509 identity information.
- Kept `Geçerlilik süresi (gün)` in Step 1 because it is host-side X.509 validity metadata.
- Added an explicit note that Software Revision is TI certificate metadata, not Subject/Kimlik, and does not by itself prove target rollback enforcement.
- No certificate-generation, cryptographic, TI-extension encoding, provisioning, lifecycle, debug, or hardware-enforcement semantics changed.
- Real Windows alpha24 Step 1/Step 2 visual QA remains pending; project final completion is not declared.

## 2.0.0-alpha23

- Reworked Certificate Center → New Certificate into a five-step guided wizard based on real Windows alpha22 screenshots.
- Separated Subject, TI fields, signing key, outputs and final review to remove the long single-scroll first-use form.
- Marked Common Name (CN) as required while keeping other Subject fields optional.
- Corrected Application Load UI wording so TISCI `auth_type` is shown as one INTEGER carrying copy mode in the low byte and Host ID in the upper byte.
- Collapsed certificate mechanics and optional export outputs by default.
- Final review does not render private-key paths.
- Target-specific addresses/core IDs/Host IDs remain source-verified user inputs; Studio does not guess them.
- Real Windows alpha23 visual QA remains `PENDING_SCREENSHOT`; project final completion is not declared.


## 2.0.0-alpha22

- Polished the Certificate Center start page after the first real Windows visual review of alpha21.
- Simplified the first-use copy and made the six primary certificate actions explicit for a beginner.
- Renamed `Yeniden Üret / Export` to `Yeni Sürüm / Export`; the start card now uses `Yeni Sürüm Oluştur` instead of mixed `Reissue` wording.
- Moved scope/security-detail text behind a collapsed `Teknik sınırlar ve güvenlik notları` control so the initial page is not dominated by PKI terminology.
- Removed CSR/CA/CRL/OCSP terminology from the first-use surface; the AM64x source boundary remains enforced in the implementation and documentation.
- The result-boundary panel stays hidden until a Certificate Center operation actually publishes a result.
- `Uzman Profile` is hidden in Guided Mode and remains available in Expert Mode.
- No certificate generation, signing, TI-extension, key, provisioning, lifecycle, debug, or hardware-enforcement semantics changed.
- Local regression: **229 tests PASS**.
- Real Windows alpha22 Certificate Center visual QA remains `PENDING_SCREENSHOT`; project final completion is not declared.

## 2.0.0-alpha21

- Reworked `Certificate Explorer` into a comprehensive **Certificate Center** for AM64x version-locked certificate workflows.
- Added from-scratch GUI creation for Application and Secure Debug certificates, including manual `C/ST/L/O/OU/CN/email` Subject fields, SWREV, validity duration and context-specific TI extension inputs.
- Added explicit certificate mechanics visibility: self-signed Issuer policy, cryptographic-random serial, RSA-4096 public key, RSA/SHA-512 signature and TI-template `CA=true` Basic Constraints.
- Added DER/PEM metadata support, validity state, days remaining, public-key metadata and standalone PEM host-side verification. Standalone certificate verification now returns `NOT_CHECKED` rather than a false payload-integrity failure when the accompanying payload/ciphertext is absent.
- Added certificate clone/reissue workflow: signed certificate bytes are never edited; fields are copied into a new profile and a new certificate is signed.
- Added certificate DER/PEM export, public DER-SPKI export, certificate↔private-key match and public Project Certificate Library with duplicate-certificate detection.
- Added certificate-to-certificate semantic compare for Subject/Issuer, serial, validity, SPKI, signature algorithm and TI extension sets.
- Added CLI management commands for metadata/export/public-key/match/clone/compare/library in addition to existing new/validate/render/build/explain.
- Added explicit context routing: encrypted Application certificates remain delegated to installed TI `appimage_x509_cert_gen.py`; ROM combined certificates to `rom_image_gen.py`; Keywriter remains provisioning-context/offline preparation and does not expose OTP/eFuse execution.
- Added source-level UX contracts for manual Subject entry, reissue-not-byte-edit, certificate context separation and compare.
- Regression: **226 tests PASS** in the final full regression suite.
- Real Linux Certificate Center visual QA remains `PENDING_REAL_LINUX_SCREENSHOT`; alpha21 is not declared final/beta release-ready on that basis.



## 2.0.0-alpha20

- Hardened Application build execution against host paths containing spaces by running the TI `appimage_x509_cert_gen.py` tool inside an isolated staging directory with short relative aliases.
- Application input uses a non-secret alias; signing private key and MEK use hardlink/symlink aliases only. Studio does not copy secret key material as a fallback.
- TI signer temporary files no longer use the installed SDK tool directory as the default working directory; transient files stay inside the isolated staging directory and are cleaned after execution.
- Generated output is published to the requested destination only after successful TI-tool execution, with an independent no-overwrite guard.
- Added bounded in-memory failure diagnostics: stderr/stdout excerpts are redacted for known secret paths and MEK text, exposed only in runtime Technical Details, and never persisted to build logs or build records.
- Removed persisted stdout/stderr hashes because an upstream tool could unexpectedly echo secret material; only stream byte counts are retained.
- Added regression coverage for TI-like shell-fragile path handling with spaces, staging cleanup, non-copying secret aliases, diagnostic redaction and no-persistence behavior.
- Regression after patch: 219 tests PASS.
- The original alpha19 TI signer failure is not retroactively reclassified; real Linux retry with alpha20 remains required to verify whether space-containing host paths were the actual root cause.

## 2.0.0-alpha19

- Real-Linux screenshot-driven Secure Application Step 3 output UX patch.
- Removed the example `application.appimage.hs` placeholder so the GUI no longer teaches a build-context-specific suffix as a default.
- Guided copy now uses `Çıktı` terminology and a natural no-project message.
- Active Project Workspace output suggestions are shown explicitly as project-relative `outputs/<name>` references with a compact restore action.
- Studio-generated application project suggestions now use descriptive suffix-free names (`*_signed_secure_application` / `*_encrypted_secure_application`) rather than implying an official TI output suffix.
- Step 3 navigation now fails closed for an existing output path or an output equal to the input; the execution layer retains its independent no-overwrite check.
- No signing, encryption, OTP/eFuse, lifecycle, debug, or hardware-enforcement semantics changed.
- Real Linux visual acceptance for Secure Application Step 3 remains pending until the alpha19 screenshot is reviewed.



## 2.0.0-alpha18

- Real-Linux screenshot-driven Secure Application Step 2 guided-UX patch.
- Replaced the ambiguous encryption checkbox with explicit mutually-exclusive `Yalnız imzala` and `Şifrele + imzala` choice cards.
- Signing private-key and MEK paths are retained only in internal runtime state; GUI surfaces show a signing-key basename/status and a generic MEK-selected status rather than full secret paths.
- Added inline development/test key guidance with a compact `Test key set'i oluştur` action instead of a full-width Key Center navigation button.
- The MEK selector is hidden unless encryption is selected, and Step 2 gating now requires selected secret files to still exist as regular files.
- Simplified host-side/provisioning safety copy without changing signing, encryption, OTP/eFuse, lifecycle, debug, or hardware-enforcement semantics.
- Real Linux visual acceptance for Secure Application Step 2 remains pending until the alpha18 screenshot is reviewed.


## 2.0.0-alpha17

- Real-Linux screenshot-driven Secure Application Step 1 interaction patch.
- `Devam` is now gated by an existing regular Application file, not merely non-empty text.
- Step 1 validation reports a guided missing-file error if a typed/removed path is invalid.
- Primary-action disabled styling now has explicit QSS specificity, so a disabled `Devam` is visibly grey instead of retaining the blue primary appearance.
- No signing, encryption, provisioning, lifecycle, debug, or hardware-enforcement semantics changed.
- Real Linux visual acceptance for Step 1 remains pending until the alpha17 screenshot is reviewed.


## 2.0.0-alpha16

- Real-Linux screenshot-driven Secure Application Step 1 UX patch.
- Guided Mode now shows a compact SDK status card instead of a manual SDK-root field; manual override remains available in Expert Mode.
- The Application file must be selected before `Devam` is enabled; later wizard steps apply the same required-field gating.
- Step 1 copy is simplified for beginners and normal UI terminology uses `Çıktı` instead of `Output`.
- Real Linux visual acceptance for this patched Application Step 1 remains pending until a user screenshot is reviewed.

## 2.0.0-alpha15

- Real-Linux active Project dashboard screenshot QA patch.
- Brand-new active projects now show a compact `Henüz işlem yapılmadı` empty state instead of large empty artifact/history panels.
- Workspace file counts are presented as five compact summary cards rather than a table.
- `Üretilen Dosyalar` and `İşlem Geçmişi` panels appear only when corresponding records exist.
- Active-project safety copy was simplified while preserving the no-secret/no-full-host-path persistence boundary.
- Project recent-list wording now uses `yerel ayarlar` instead of reader-facing `local preferences`.
- No provisioning, eFuse, lifecycle, permanent-debug, or hardware-enforcement execution was added.

## 2.0.0-alpha12

- Home/Dashboard real-Linux screenshot QA patch: compact context chips, simplified status cards and six-task beginner dashboard.
- Removed input-like grey text strips by explicitly keeping labels transparent inside cards.
- Quick Start language shortened and the primary action no longer spans the full dashboard width.
- Last-operation and status-bar text now stay concise; technical detail remains on the relevant page.
- Navigation spacing/selection styling polished and Home bottom clipping risk reduced with a compact 3-column task layout.
- Security claim boundary remains unchanged; no irreversible provisioning/debug execution was added.

## 2.0.0-alpha11

- Local-only preferences eklendi: Rehberli/Uzman modu, device context ve son Project Workspace listesi yeniden açılışta korunabilir.
- Recent project listesi yalnız local config içindir; share-safe export/report içine full host path taşımaz. POSIX preferences file mode `0600` olarak yazılır.
- Yeni `Hakkında / Diagnostics` GUI sayfası eklendi. Secret value/hash/path, username, hostname ve full host path içermeyen JSON/Markdown diagnostic export üretir.
- Yeni `securectl diagnostics` ve `securectl beta-readiness` komutları eklendi.
- Beta readiness gerçek Qt render ve Linux/Windows clean-machine testlerini yapılmış saymaz; dependency presence execution evidence olarak kabul edilmez.
- `tools/qt_visual_qa.py` offscreen page render/screenshot harness'i eklendi; human visual QA ayrı `NOT_EXECUTED` gate olarak korunur.
- `tools/standalone_smoke.py` ve `securestudio --smoke-test` packaged runtime smoke kontratı eklendi.
- Beta UX/safety source audit kapsamı 22 GUI sayfasına çıktı.
- Alpha11 regression: **189 tests PASS**.
- Build ortamında PySide6/PyInstaller bulunmadığı için real Qt render ve clean-machine standalone execution hâlâ `NOT EXECUTED`; release readiness `PARTIAL`.

## 2.0.0-alpha10

- Beginner onboarding için Ana Sayfa'ya environment → project → first workflow sıralı **Hızlı Başlangıç** modeli eklendi.
- Project Workspace artık Application/ROM wizard'larına project-relative output önerisi verir; kullanıcı isterse manuel output seçebilir ve existing output sessizce overwrite edilmez.
- Negative Test ve Reports ekranlarına project `negative-tests/` ve `reports/` output önerileri eklendi.
- Key Center, secret-generating key output'un Project Workspace içine yazılmasını engeller; public-only DER export için `project/public/` önerisi sunar.
- Project Workspace'e share-safe `sessions/artifacts.jsonl` Generated Artifact Index eklendi. Project içi path'ler relative, external output'lar basename-only tutulur; generated public/output SHA-256 kaydı desteklenir.
- Project create UI device / silicon revision / lifecycle context alanlarını açıkça gösterir.
- Environment/Errata/Provisioning/Revision/BoardCfg/Demo error UX ortak `Ne oldu / Neden / Ne yapabilirsiniz / Teknik ayrıntı` guided error akışına geçirildi.
- Source-level beta UX/safety consistency audit eklendi (`tools/beta_ux_audit.py`) ve Phase 8 QA'ya bağlandı. Audit gerçek Qt render testinin yerine geçmez.
- Reporting workflow sonuçları project artifact index için explicit generated-output contract taşır.
- Alpha10 regression: **181 tests PASS**.
- Gerçek PySide6 render ve Linux/Windows clean-machine standalone testleri bu build ortamında hâlâ `NOT EXECUTED`; release readiness `PARTIAL`.

## 2.0.0-alpha9

- Secure Debug Assistant, raw JSON yerine source-boundary-aware FlowDiagramWidget + HumanResultView yapısına taşındı.
- Secure Debug GUI/backend transport drift'i düzeltildi; canonical `tisci` / `sec-ap` contract kullanılıyor ve eski invalid standalone `jtag` GUI enum'u kaldırıldı.
- Generic Data profile/build/verify akışları generalized-authentication diagramı + insan-okunur result görünümüne taşındı; target `TISCI_MSG_PROC_AUTH_BOOT` her zaman ayrı NOT EXECUTED sınırında tutulur.
- SDK Compare role-based side-by-side semantic diff görünümü aldı; mapped security field before/after değerleri görünürken configured key host path'leri gösterilmez.
- Project Workspace persistent share-safe `sessions/activity.jsonl` workflow history aldı; secret value/path, full host path ve arbitrary technical JSON session log'a yazılmaz.
- Reports ekranına persistent Project History sekmesi eklendi; in-memory Session History ile project-backed history ayrıldı.
- `NOT_APPLICABLE` durumunun insan-okunur sunumu eklendi.
- Alpha9 regression: 172 tests PASS.

## 2.0.0-alpha8

- SDK Inspector'a ENC_ENABLED ve ENC_SBL_ENABLED consumer zincirlerini ayrı lane olarak gösteren görsel flow diagram eklendi.
- Provisioning Preparation, KEYREV/SWREV ve Security BoardCfg ekranları ortak FlowDiagramWidget + HumanResultView yapısına taşındı.
- Certificate Explorer alanları Image Anatomy bloklarıyla bağlandı; ilgili extension seçilince certificate/payload/ciphertext/ROM component bölümü vurgulanıyor.
- Bütün HumanResultView kontrol satırlarına durumdan bağımsız çalışan `Neden?` açıklaması eklendi; özel source mapping olan kontroller source ID de gösteriyor.
- SDK production-review ve SWREV sbl/sysfw/generic-data gibi GUI/backend enum drift'leri canonical `ui_contract` değerleriyle düzeltildi.
- `attach_claims` artık operation kimliğini result'a bind ederek advanced ekranların insan-okunur başlıklarını tutarlı hale getiriyor.
- Pure-Python `workflow_visuals` semantic model katmanı eklendi; diagramlar secret value/path/hash veya source-backed olmayan target ID/address üretmiyor.
- Alpha8 regression: 164 tests PASS.

## 2.0.0-alpha7

- ROM Combined Image ekranı gerçek step-by-step wizard yapısına taşındı: components → security → source-backed target values → output → review → result.
- Certificate Explorer tree/detail görünümüne geçirildi; certificate context, consumer, OID, decoded value, claim sınırı ve source birlikte gösteriliyor.
- Key Center'a Application / SMPK / BMPK / MEK / SMEK / BMEK rollerini ayıran görsel rol kartları ve public identity paneli eklendi.
- Home ekranı Environment / Project / Son İşlem durum kartları ve açıklamalı task cards ile dashboard haline getirildi.
- Certificate semantics için pure-Python `certificate_explorer_model`, key role contract için `key_roles` service eklendi.
- Alpha7 regression: 156 tests PASS.

## 2.0.0-alpha6

- Secure Application ekranı beş adımlı gerçek wizard'a dönüştürüldü.
- Ortak insan-okunur `HumanResultView` eklendi; raw JSON secondary `Teknik Ayrıntı` sekmesine taşındı.
- Inspector'a parsed byte boyutlarından üretilen read-only Image Anatomy görünümü eklendi.
- GUI hataları `Ne oldu / Neden olabilir / Ne yapabilirsiniz / Teknik ayrıntı` formatına geçirilmeye başlandı.
- Application, ROM, Key Center, Negative Tests ve Reports insan-okunur result modelini kullanıyor.
- Negative Test single/suite sonuçları controlled-change ve original-source-unchanged kontrolleriyle tablo haline getirildi.
- Result Center current/history görünümü sadeleştirildi; share-safe JSON explicit export olarak korundu.
- Presentation/anatomy/error contract testleri eklendi.
- Regression: 152 tests PASS.
- Real Qt render ve standalone clean-machine checks environment dependency nedeniyle hâlâ NOT EXECUTED.

## 2.0.0-alpha5

- Rehberli Mod / Uzman Modu navigation contract eklendi; guided mode beginner workflow'larını sadeleştiriyor.
- Key Center'a existing signing/public/certificate preflight, MEK strict-format check ve private/public comparison eklendi.
- Negative Tests ekranına automatic suite ve ROM component mutation eklendi.
- Reports ekranına share-safe in-memory session history, single-image Markdown ve batch report üretimi eklendi.
- Certificate Explorer'a application/debug profile create/validate/OpenSSL-render/DER-build araçları eklendi.
- Image Inspector drag-and-drop read-only inspect desteği aldı.
- Errata GUI seçenekleri canonical backend değerleriyle ortak pure-Python UI contract üzerinden eşlendi; eski invalid GUI enum drift'i giderildi.
- GUI capability/errata semantic contract testleri eklendi.
- Regression: 147 tests PASS.
- Gerçek Qt render ve standalone clean-machine testleri environment dependency nedeniyle hâlâ NOT EXECUTED.

## 2.0.0-alpha4

- Added Phase 8 local hardening: high-DPI/accessibility/keyboard navigation improvements.
- Added explicit no-SDK fail-closed UX and offline runtime network policy.
- Added `securectl network-policy` and release secret/path scanner.
- Added Linux/Windows PyInstaller packaging recipes and Linux desktop entry.
- Added Phase 8 local QA runner.
- Full regression: 143 tests passed.
- Release readiness remains PARTIAL because real Qt render and clean Linux/Windows standalone smoke are not executed in this environment.

## 2.0.0-alpha3

- Added guided decision tree ("Bana Yol Göster").
- Added source-priority registry and Source Trace GUI.
- Added short source-backed Learn Mode cards.
- Added Result Center "Neden?" explanations for known checks.
- Added self-contained educational demo workspace with explicit NOT_TARGET_READY boundary.
- Kept irreversible OTP/eFuse/lifecycle/debug execution out of the GUI.
- Full regression: 135 tests passed.

# Sürüm notları

## v2.0.0a1 — Secure Boot Studio başlangıcı

- PySide6/Qt tabanlı yeni Studio shell'i eklendi; GUI dependency base CLI'dan ayrıldı.
- `securestudio` launcher ve `securectl gui` korundu.
- ortak `WorkflowResult`, claim-boundary ve secret-policy servisleri eklendi.
- MCU+ SDK/environment auto-discovery eklendi.
- secret path saklamayan Project Workspace eklendi.
- synthetic/non-production RSA-4096 signing key generation eklendi.
- strict 256-bit / 64-hex MEK generation eklendi.
- development ve offline provisioning-test key-set generation eklendi.
- key outputs exclusive/atomic oluşturulur; existing secret dosya overwrite edilmez.
- generation sonrası mevcut signing/MEK preflight kontrolleri otomatik çalıştırılır.
- Home, Environment, Project, Secure Application, Inspector, Keys, Negative Tests ve Reports GUI sayfaları bağlandı.
- v1.0.0 baseline archive SHA-256 ve `109 passed` regression contract kaydedildi.

Bu alpha gerçek OTP/eFuse programming, HS-FS→HS-SE transition, customer Root of Trust enforcement veya hardware enforcement iddiası eklemez.

## v1.0.0

İlk kararlı Toolkit paketi; image/certificate inceleme-doğrulama, TI SDK build wrapper'ları, negative tests, key preflight, offline provisioning/revision/boardcfg/SDK/errata/generic-data ve read-only Tkinter GUI içeriyordu.

## 2.0.0-alpha2

- Bound Phase 5 GUI workflows: ROM Wizard, Certificate Explorer, SDK Inspector/Compare and Errata Advisor.
- Bound Phase 6 offline workflows: Provisioning Preparation, Revision Simulator, Security BoardCfg, Secure Debug policy and Generic Data.
- Removed Phase 5/6 placeholder navigation entries.
- Added ROM workflow service with key/MEK preflight and explicit non-execution semantics for dry-run.
- Added build-level private-key requirement for application/ROM signing workflows.
- Expanded result claim-boundary descriptions for new offline workflows.
- Added semantic GUI-source and ROM workflow tests.
- Regression result: 128 tests PASS.

## 2.0.0-alpha13

- Real-Linux Environment screen QA patch.
- Replaced raw-JSON-first Environment results with a beginner-first Overview tab.
- Added human-readable MCU+ SDK, Python, OpenSSL, application signer, ROM signer and `devconfig.mak` status cards.
- Moved exact paths, SHA-256 values and machine-readable discovery metadata to a secondary `Teknik Ayrıntılar` tab.
- Added a useful empty state before discovery and a masked `<HOME>` SDK discovery hint after automatic resolution.
- Kept environment readiness claims conservative: host/build readiness does not imply hardware/customer enforcement.

## 2.0.0-alpha14

- Real-Linux Project Workspace screenshot QA patch.
- Proje oluşturma/açma ve aktif proje dashboard durumları ayrı ekran state'lerine bölündü; aktif proje yokken boş history/index tabloları gösterilmez.
- Beginner-facing metinler sadeleştirildi: `Proje Çalışma Alanı`, `Proje klasörü`, `İşlem Geçmişi`, `Üretilen Dosyalar`.
- `Yeni Proje Oluştur` primary action yapıldı; `Mevcut Projeyi Aç` secondary action olarak ayrıldı.
- Son Projeler empty-state eklendi ve normal görünümde full host path gösterimi kaldırıldı.
- Aktif project dashboard'a Secure Application / Image İnceleme / Raporlar quick actions eklendi.
- `sessions/activity.jsonl` gibi internal storage ayrıntıları beginner görünümünden kaldırıldı; secret/full-host-path saklama sınırı korunuyor.
- Proje klasörü seçilmeden accidental current-working-directory project creation davranışı engellendi; klasör seçimi explicit hale getirildi.
