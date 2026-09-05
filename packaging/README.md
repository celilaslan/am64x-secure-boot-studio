# Standalone packaging

Bu klasör Phase 8 standalone packaging recipe'lerini taşır.

- Linux: `packaging/build_linux.sh`
- Windows: `packaging/windows/build_windows.ps1`
- PyInstaller spec: `packaging/pyinstaller/securestudio.spec`

## Güvenlik ve doğrulama sınırı

Standalone build, Secure Boot doğrulaması değildir. Release adayı dağıtılmadan önce:

1. clean OS environment'da build/install/uninstall smoke test;
2. gerçek PySide6 window render ve temel navigation smoke;
3. `securectl release-scan <RELEASE_ROOT>`;
4. full pytest regression;
5. package manifest doğrulaması

gereklidir.

Studio runtime'da internet/telemetry/update-check gerektirmez. SDK veya Python package kurulumu, Studio'nun runtime network davranışından ayrı environment setup işlemidir.

Bu repository/build ortamında Windows executable'ın Linux üzerinde üretildiği veya smoke-tested olduğu varsayılmaz.

## Alpha11 runtime smoke / visual QA

PySide6 bulunan gerçek GUI ortamında source tree üzerinden otomatik offscreen render:

```bash
PYTHONPATH=src python tools/qt_visual_qa.py <OUTPUT_DIR>
```

Bu bütün Studio sayfaları için screenshot üretir ve `qt_visual_qa.json` yazar. `automated_render=PASS`, insan visual review yerine geçmez.

Standalone executable üretildikten sonra:

```bash
python tools/standalone_smoke.py <PATH_TO_SECURESTUDIO_EXECUTABLE>
```

Bu komut packaged runtime'ın `securestudio --smoke-test` yolunu çalıştırır. Tek başına clean-machine release acceptance değildir; Linux ve Windows için ayrı gerçek host doğrulaması gerekir.
