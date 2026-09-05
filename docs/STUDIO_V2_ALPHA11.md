# AM64x Secure Boot Studio v2.0.0-alpha11

Alpha11 bir özellik-yığma sürümü değil; beta öncesi **local state, diagnostics ve gerçek GUI/standalone QA hazırlığı** turudur.

## Kullanım kolaylığı

- Rehberli/Uzman modu ve device context local preferences içinde korunur.
- Son açılan Project Workspace'ler local-only listede tutulur ve Project ekranından tekrar açılabilir.
- Recent project path'leri yalnız local preferences içindir; share-safe report/diagnostic export'a full host path olarak girmez.
- Preferences dosyası POSIX üzerinde restrictive `0600` mode ile yazılır.

## Share-safe Diagnostics

Yeni `Hakkında / Diagnostics` GUI sayfası ve CLI komutu:

```bash
securectl diagnostics
securectl diagnostics --sdk-root <SDK_ROOT> --output diagnostics.md
```

Diagnostic çıktı şunları içerir:

- toolkit/Python/platform sürümleri;
- dependency availability;
- SDK version/compatibility ve signer presence;
- offline network policy;
- Project varsa yalnız non-sensitive dashboard özeti;
- explicit beta/release blockers.

Şunlar özellikle dahil edilmez:

- private/symmetric secret value;
- secret hash;
- secret path;
- full host path;
- username/hostname.

## Beta readiness

Yeni:

```bash
securectl beta-readiness --source-root <SOURCE_PACKAGE>
```

Gerçek Qt render ve standalone clean-machine validation yapılmadan release readiness PASS sayılmaz. PySide6/PyInstaller'ın yalnız kurulu olması execution evidence değildir.

## Gerçek Qt QA hazırlığı

`tools/qt_visual_qa.py` PySide6 bulunan ortamda bütün Studio sayfalarını offscreen render edip screenshot ve machine-readable report üretmek üzere eklendi. Bu test runtime/render kırılmalarını yakalar; insan görsel QA'sının yerine geçmez.

Standalone paket için `tools/standalone_smoke.py` ve `securestudio --smoke-test` kontratı eklendi. Bu da tek başına clean-machine release kanıtı değildir.

## Güvenlik sınırı

Alpha11 OTP/eFuse programlama, HS-FS→HS-SE transition, customer Root of Trust enforcement veya permanent debug/security write eklemez. Host-side/toolkit beta hazırlığıdır.
