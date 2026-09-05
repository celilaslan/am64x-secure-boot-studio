# AM64x Secure Boot Studio v2.0.0-alpha10

Alpha10 yeni AM64x hardware/provisioning execution işi değildir. Amaç beginner onboarding, Project Workspace ile workflow output organizasyonu ve beta öncesi GUI consistency hardening'dir.

## Ana değişiklikler

1. **Hızlı Başlangıç** state-aware onboarding: Environment → Project → first workflow.
2. Application ve ROM wizard'ları Project aktifse `outputs/` altında deterministic output önerir; user override mümkündür, existing output overwrite edilmez.
3. Negative Tests ve Reports project `negative-tests/` / `reports/` output önerilerini kullanabilir.
4. Key Center secret-generating output'un shareable Project Workspace içine yazılmasını engeller; public-only DER `public/` altında tutulabilir.
5. `sessions/artifacts.jsonl` Generated Artifact Index eklendi. Project içi output path project-relative, external output basename-only kaydedilir. Existing generated public/output dosyada size + SHA-256 indekslenebilir.
6. Project create UI device, silicon revision ve lifecycle context'i açık seçime taşır.
7. Environment, Errata, Provisioning, Revision, Security BoardCfg ve Demo error handling ortak guided error modeline geçirildi.
8. `services/ux_audit.py` + `tools/beta_ux_audit.py` source-level GUI consistency/safety audit eklendi ve Phase 8 QA'ya bağlandı.

## Safety boundary

- OTP/eFuse/customer-key provisioning: NOT EXECUTED
- HS-FS → HS-SE transition: NOT EXECUTED
- Permanent debug/security change: NOT EXECUTED
- Hardware/customer Root of Trust enforcement: NOT VERIFIED
- Secret value/hash Project history/artifact index'e yazılmaz.
- Source-level UX audit gerçek Qt render/accessibility testi değildir.
