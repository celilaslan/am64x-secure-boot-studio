# AM64x Secure Boot Studio 2.0.0-alpha27

Bu sürüm, standart application kullanımını CCS/MCU+ SDK secure build akışı etrafında birleştirir.

## Kullanıcı akışı

1. Environment kontrol edilir ve MCU+ SDK bulunur.
2. Project Workspace içinde target lifecycle seçilir: GP, HS-FS veya HS-SE.
3. **CCS / Secure Application** ekranında CCS proje ya da Debug/Release build klasörü seçilir.
4. Studio uygun makefile'ı ve mevcut build çıktılarını otomatik bulur.
5. **Studio ile Secure Build Et** MCU+ SDK make/signer zincirini lifecycle'a uygun ayarlarla çalıştırır.
6. Üretilen `.appimage.hs_fs` veya `.appimage.hs` otomatik bulunur; certificate ve image host üzerinde doğrulanır.

Kullanıcı `.mcelf` dosya adını, `DEVICE_TYPE`, `APP_SIGNING_KEY`, `ENC_ENABLED` veya application X.509 alanlarını bilmek zorunda değildir. Standart application certificate, MCU+ SDK'nın TI signer adımı tarafından build sırasında oluşturulur.

## Lifecycle eşlemesi

- **HS-FS:** `DEVICE_TYPE=GP`; key seçilmezse MCU+ SDK development key'i kullanılır. İstenirse kullanıcı development/test key'i seçebilir veya Studio içinde üretebilir.
- **HS-SE:** `DEVICE_TYPE=HS`; cihazdaki provision edilmiş Customer Root of Trust ile eşleşen signing key zorunludur.
- **GP:** `DEVICE_TYPE=GP`; üretilen image hardware secure enforcement kanıtı değildir.

## Güvenlik sınırı

- Global `devconfig.mak` ve CCS proje ayarları değiştirilmez.
- Private key ve MEK yolları proje metadata'sına kaydedilmez.
- Seçilen secret dosyalar build sırasında geçici, nötr adlı bir dizine kopyalanır; make tamamlanınca geçici dizin silinir.
- Studio OTP/eFuse yazmaz, HS-FS → HS-SE transition yapmaz ve key'in cihazda provision edildiğini varsaymaz.

## Doğrulama durumu

- Otomatik testler: `269 passed`.
- Gerçek Windows + CCS 20.4.0 + MCU+ SDK 12.00.00.27 secure build denemesi kullanıcı hostunda yapılacaktır.
- Container ortamında `libEGL.so.1` bulunmadığı için yeni ekranın offscreen screenshot render'ı çalıştırılamadı; scroll sözleşmesi ve GUI kaynak testleri PASS durumundadır.
