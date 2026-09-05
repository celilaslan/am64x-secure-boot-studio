# AM64x Secure Boot Studio v2.0.0-alpha5

## Amaç

`alpha5`, mevcut backend yeteneklerini beginner-facing GUI içinde daha eksiksiz ve yanlış kullanımı daha zor hale getiren bir **GUI completeness + semantic hardening** milestone'udur. Day-8/9/10 teknik proje işlerini tekrar etmez; yeni toolkit scope'udur.

## Yeni GUI davranışı

### Rehberli Mod / Uzman Modu

Studio varsayılan olarak **Rehberli Mod** açılır. Application, inspect/verify, key, negative test, reports, environment/project ve learn/demo akışları görünür. ROM, provisioning, BoardCfg, Secure Debug, SDK/Errata, Generic Data ve revision gibi advanced host-side/offline araçlar **Uzman Modu** altında görünür. Explicit advanced navigation isteği mode'u expert'e geçirir.

### Key Center

- synthetic/non-production generation;
- existing RSA signing/public/certificate preflight;
- strict 64-hex AES-256 MEK format check;
- private/public material DER-SPKI comparison.

Secret value/hash raporlanmaz; target provisioning/enforcement sonucu çıkarılmaz.

### Negative Tests

- single signature/TBSCertificate/payload/ciphertext mutation;
- ROM component mutation;
- image classification'a göre automatic negative suite.

Original source değiştirilmez.

### Reports

- current share-safe result;
- son 50 sonucu yalnız in-memory sanitize edilmiş history olarak gösterme;
- single-image Markdown + optional JSON;
- explicit file list ile batch Markdown + optional JSON.

### Certificate Tools

Explorer'ın yanında application/debug profile template, validation, OpenSSL config render ve DER certificate build GUI'den yapılabilir. ROM/Keywriter certificate bağlamı bu generic profile builder'a karıştırılmaz.

### Drag & Drop Inspector

Local file Inspector ekranına bırakıldığında yalnız read-only inspect otomatik çalışır. Verify ayrıca kullanıcı tarafından seçilir.

### Errata semantic contract

GUI label'ları okunabilir kalırken backend'e giden değerler tek `services/ui_contract.py` kaynağında canonical enum'larla tutulur. Alpha4'teki `boot/security`, `rom-combined/application`, `customer`, `missing` gibi backend'in kabul etmediği bazı GUI değerleri kaldırılmıştır.

## QA

- Python compile: PASS
- Regression: `147 passed`
- Pure-Python GUI/backend semantic contract tests: PASS
- PySide6 gerçek window render: NOT EXECUTED (bu environment'ta PySide6 yok)
- PyInstaller standalone bundle: NOT EXECUTED (bu environment'ta PyInstaller yok)
- OTP/eFuse / HS-FS→HS-SE / hardware enforcement execution: NOT EXECUTED
