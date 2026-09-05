# Otomatik testler

## v2.0.0a10 — current local QA

- Full regression: **181 passed**.
- Onboarding Environment → Project → workflow routing contract: PASS.
- Project output suggestion / project-relative path policy: PASS.
- Project artifact index + external basename-only path hygiene: PASS.
- Secret-generating key output Project Workspace guard: PASS.
- Application/ROM/Negative/Reports Project-aware GUI source contract: PASS.
- Beta UX/safety source audit: PASS / 21 pages / 0 findings.
- Python compile: PASS.
- Phase 8 local QA must include beta UX audit.

Phase 8 release-readiness sınırı değişmez: gerçek PySide6 render ve clean Linux/Windows standalone smoke çalıştırılmadığı için `PARTIAL` olarak kalır.

## v1.0.0 baseline

- archive SHA-256: `4bbf815e6f0b39e230515ffe577148cba3bb411a900c55e15ed0db3ee66d5511`
- baseline: `109 passed`


## v2.0.0a2

Alpha2 GUI binding ve ROM workflow genişlemesinden sonra final package öncesi full regression sonucu: `128 passed`.

Ek semantic testler Phase 5/6 GUI modüllerinin mevcut olduğunu, main navigation içinde placeholder kalmadığını ve irreversible execution action label'larının eklenmediğini kontrol eder. ROM workflow testleri dry-run'ın execution PASS sayılmadığını, explicit load-address değerlerinin korunup secret key path'in redacted kaldığını ve build operation için private key gereksinimini doğrular.

Build container'ında PySide6 kurulu olmadığı için gerçek Qt window render smoke testi `NOT EXECUTED`; GUI modülleri `compileall`/AST semantic kontrollerinden geçmiştir.

## v2.0.0a1

Ek test sınıfları:

- RSA-4096 key generation / public DER / permissions
- strict 64-hex MEK generation
- provisioning-test primary/backup distinctness
- overwrite refusal
- keyset manifest secret-safety
- environment resolver
- Project Workspace metadata
- WorkflowResult / claim boundary / secret sanitizer
- GUI facade import without PySide6
- application workflow dry-run semantics

Final alpha1 regression sonucu paket üretilmeden hemen önce yeniden çalıştırılır ve package manifest ile birlikte kaydedilir.
