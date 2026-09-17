# AM64x Secure Boot Studio 2.0.0-alpha28

Alpha28 günlük işi tek bir akışta toplar: CCS application projesi → lifecycle'a uygun secure application → isteğe bağlı SBL/combined boot image → UART UniFlash planı → OSPI boot doğrulama yönergesi.

## Lifecycle modeli

| Fiziksel kart | Üretim hedefi | Build | Karta yazma |
|---|---|---|---|
| HS-FS | HS-FS | `DEVICE_TYPE=GP`; SDK development key kullanılabilir | İzinli |
| HS-FS | HS-SE | `DEVICE_TYPE=HS`; customer private key gerekir | Kapalı; çevrimdışı paket |
| HS-SE | HS-SE | `DEVICE_TYPE=HS`; customer private key gerekir | Yalnız Customer RoT durumu doğrulanmışsa |
| HS-SE | HS-FS | Çevrimdışı hazırlanabilir | Kapalı; lifecycle uyuşmazlığı |

Studio hiçbir durumda OTP/eFuse yazmaz veya HS-FS → HS-SE transition çalıştırmaz.

## Application ve combined image

Application certificate/image, CCS/MCU+ SDK projesinin `makefile_ccs_bootimage_gen` zinciriyle üretilir. Tam paket seçildiğinde SBL CCS projesi de aynı resmi project recipe üzerinden build edilir. Manuel Certificate Center ve ROM formu gelişmiş entegrasyon/inceleme işleri için korunur; normal CCS kullanıcısının `.mcelf`, X.509 alanı, load address veya `DEVICE_TYPE` girmesi gerekmez.

## Karta yükleme

Studio kurulu SDK'nın lifecycle'a uygun default OSPI config'ini kaynak kabul eder, flash-writer/boot image ve application offset'lerini buradan çözer ve geçici bir config üretir. SDK dosyaları değiştirilmez. OSPI yazma, onay kutusu ve son uyarı diyaloğu olmadan çalışmaz.

Başarılı yazma sonrası gerçek kabul testi:

1. kartı OSPI boot moduna alın;
2. reset/power-cycle yapın;
3. application UART çıktısını gözleyin.

CCS/JTAG Debug, host-side certificate verification veya UniFlash exit `0` tek başına gerçek secure boot kanıtı değildir.

## Windows açılışı

Repo kökündeki `studio.cmd` ilk kullanımda `.venv` ortamını hazırlar. Sonraki güncellemelerde `git pull` ve `studio.cmd` yeterlidir; venv aktivasyonu gerekmez.
