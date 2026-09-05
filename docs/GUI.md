# AM64x Secure Boot Studio GUI

Studio GUI PySide6/Qt tabanlıdır ve CLI ile aynı Python backend servislerini kullanır. GUI shell komut satırı üretip `securectl` subprocess'i çalıştırmaz; ilgili backend/workflow fonksiyonlarını doğrudan çağırır.

## Çalıştırma

```bash
pip install 'am64x-secure-toolkit[gui]'
securestudio
```

veya:

```bash
securectl gui
```

PySide6 kurulu değilse CLI çalışmaya devam eder; GUI launch açık hata verir.

## alpha2'de bağlı workflow'lar

- Home guided navigation
- Environment setup/discovery
- Project workspace
- Secure Application Wizard
- ROM Combined Image Wizard
- Image Inspect + Verify
- Certificate Explorer
- Key Center + synthetic key generation
- Controlled-copy Negative Tests
- SDK Inspector + SDK Compare
- Errata Advisor
- Provisioning Preparation — offline only
- KEYREV / SWREV Simulator
- Security BoardCfg inspector
- Secure Debug policy assistant — no unlock execution
- Generic Data assistant
- Results / share-safe JSON

## Safety boundary

GUI aşağıdaki target-changing işlemleri sunmaz:

- OTP/eFuse/customer-key programming
- HS-FS -> HS-SE lifecycle transition
- permanent debug/security changes
- Secure Debug/JTAG unlock send
- target-side `TISCI_MSG_PROC_AUTH_BOOT` execution

ROM load address, Host ID, OID/tool option gibi source-sensitive değerler GUI tarafından tahmin edilmez. Gerekli alanlar exact source/build context'ten kullanıcı tarafından sağlanır veya environment resolver tarafından yalnız gerçekten bulunan tool path olarak çözülür.


## Alpha8 visual semantic layer

- SDK Inspector, `ENC_ENABLED` ve `ENC_SBL_ENABLED` consumer chain'lerini ayrı flow diagram lane'lerinde gösterir.
- Provisioning, Revision ve Security BoardCfg advanced ekranları ortak semantic diagram + HumanResultView kullanır.
- Certificate Explorer alanları Image Anatomy ile ilişkilidir; relevant block parsed artifact yapısına göre vurgulanır.
- HumanResultView içindeki her check satırında `Neden?` aksiyonu bulunur. Known checks source-backed explanation, unknown/future checks conservative status-aware explanation gösterir.
- GUI labels backend enum değerlerinden ayrıdır; canonical values `services/ui_contract.py` içinde tutulur.

## Alpha9 workflow/history layer

- Secure Debug ve Generic Data ekranları raw JSON yerine `FlowDiagramWidget + HumanResultView` kullanır.
- Secure Debug transport seçenekleri backend ile aynı canonical `tisci / sec-ap` contract'ından gelir; TISCI Host ID alanı context-aware enable/disable edilir.
- SDK Compare role-based side-by-side semantic diff gösterir; mapped security changes before/after incelenebilir, configured key host path'leri görünmez.
- Project Workspace aktifken her workflow sonucu compact/share-safe `sessions/activity.jsonl` event'i olarak kalıcı kaydedilir.
- Reports içindeki `Session History` yalnız current process memory'sidir; `Project History` project-backed kalıcı history'dir.
- Persistent event log secret value/path, full host path veya arbitrary technical JSON taşımaz; output path yerine yalnız filename tutulur.


## Alpha10 onboarding ve Project-aware output

- Ana Sayfa `Hızlı Başlangıç` Environment → Project → first workflow önerisini state'e göre günceller.
- Application ve ROM wizard'ları Project aktifse `outputs/` altında deterministic output önerir; user override mümkündür.
- Negative Tests `negative-tests/`, Reports `reports/`, public-only DER export `public/` altında project-relative öneri kullanabilir.
- Secret-generating key output Project Workspace içine yazılamaz; böylece shareable workspace ile secret custody alanı birbirinden ayrılır.
- Project Generated Artifact Index yalnız project-relative/basename-only output referansı, size ve public/generated artifact SHA-256 tutar. Secret path/value/hash tutmaz.
- Advanced page error handling ortak guided error modeliyle normalize edilmiştir.
- `tools/beta_ux_audit.py` GUI source contract drift'ini kontrol eder; gerçek Qt render/accessibility QA yerine geçmez.

## Hakkında / Diagnostics (alpha11)

`Hakkında / Diagnostics` sayfası environment ve beta-release durumunu share-safe biçimde özetler. Export edilen JSON/Markdown içinde secret value/hash/path, username, hostname veya full host path bulunmaz. `PySide6 available` veya `PyInstaller available` yalnız dependency availability bilgisidir; real Qt render veya clean-machine validation sonucu değildir.

Project ekranındaki **Son Projeler** listesi farklıdır: yalnız kullanıcının kendi bilgisayarındaki local preferences dosyasında kolaylık amacıyla tutulur ve share-safe export kapsamına girmez.
