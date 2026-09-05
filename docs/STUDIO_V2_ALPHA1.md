# AM64x Secure Boot Studio v2.0.0a1

Bu alpha, GUI/UX Blueprint'in Phase 0–4 başlangıç implementation'ıdır.

## Tamamlanan çekirdek parçalar

- v1.0.0 regression baseline lock
- ortak `WorkflowResult` modeli
- centralized claim-boundary service
- secret-policy sanitizer
- source-registry skeleton
- SDK/environment resolver
- secret-path tutmayan Project Workspace
- synthetic RSA-4096 signing-key generation
- strict 256-bit / 64-hex MEK generation
- atomic/exclusive file creation ve overwrite refusal
- generation sonrası mevcut key preflight'larının yeniden kullanılması
- PySide6 optional GUI facade ve `securestudio` launcher
- Home / Environment / Project / Application / Inspector / Keys / Negative / Reports sayfaları

## Bilinçli olarak henüz tamamlanmayan GUI binding'leri

- ROM Wizard
- full Certificate Explorer
- SDK Inspector / Compare
- Errata Advisor
- Provisioning Preparation UI
- Revision / BoardCfg / Secure Debug / Generic Data UI
- production packaging smoke tests

Bu backend'lerin v1.0.0 fonksiyonları kaldırılmamıştır. Alpha1, onları sonraki GUI phase'lerine taşımak için shell/state yapısını hazırlar.
