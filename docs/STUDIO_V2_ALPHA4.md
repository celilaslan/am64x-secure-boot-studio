# AM64x Secure Boot Studio v2.0.0-alpha4

## Amaç

`alpha4`, GUI/UX blueprint Phase 8'in **yerel olarak doğrulanabilen** kısmına odaklanır: accessibility/high-DPI hazırlığı, no-SDK/no-network davranışı, release secret/path hygiene ve standalone packaging recipe'leri.

Bu sürüm **final v2.0 değildir**. Real PySide6 window render, Linux standalone binary ve Windows clean-machine smoke testleri bu build ortamında tamamlanmadığından release readiness `PARTIAL` kalır.

## Eklenenler

- Qt high-DPI fractional scaling policy ve daha okunabilir ortak tema.
- Minimum pencere boyutu, keyboard shortcuts ve accessibility name/description metadata.
- Environment ekranında SDK bulunmadığında açık fail-closed açıklaması.
- Runtime network policy: telemetry, auto-update, SDK download ve remote key service yok.
- `securectl network-policy` komutu.
- `securectl release-scan <ROOT>` accidental private-key/MEK/user-home-path taraması.
- Release scanner secret value/hash'i findings içine yazmaz.
- Linux ve Windows için PyInstaller packaging recipe'leri.
- Linux `.desktop` dosyası.
- `tools/phase8_qa.py` yerel Phase 8 smoke/hygiene denetimi.
- Phase 8 testleri.

## Güvenlik sınırı

Bu geliştirmeler hiçbir şekilde:

- OTP/eFuse programlama,
- HS-FS → HS-SE transition,
- customer Root of Trust enforcement,
- permanent debug/security write,
- hardware application-auth/decryption enforcement

çalıştırmaz veya doğrulanmış saymaz.

Standalone packaging başarısı da Secure Boot security verification anlamına gelmez.

## Yerel acceptance sonucu

- Full pytest regression: `143 passed`
- no-SDK fail-closed smoke: `PASS`
- runtime network policy: `PASS`
- source-tree network client import scan: `PASS`
- release secret/path scan: `PASS`
- Phase 8 local QA: `PASS`
- Phase 8 release readiness: `PARTIAL`

## Bu ortamda tamamlanmayanlar

- PySide6 gerçek pencere render: `NOT EXECUTED`
- Linux PyInstaller standalone build: `NOT EXECUTED`
- Windows standalone build/smoke: `NOT EXECUTED`
- clean Windows install/uninstall: `NOT EXECUTED`

Neden: build container'da PySide6/PyInstaller yoktu; dependency indirme denemesi network/DNS olmadığı için tamamlanamadı. Bu eksikler PASS olarak yorumlanmaz.
