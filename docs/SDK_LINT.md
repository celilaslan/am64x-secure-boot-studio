# SDK security configuration kontrolü

`securectl sdk lint`, MCU+ SDK içindeki security ile ilişkili configuration ve consumer zincirlerini dosyaları değiştirmeden inceler.

Amaç; `devconfig.mak` içinde görülen değişkenlerin application ve ROM/SBL Makefile'larında doğru araçlara bağlanıp bağlanmadığını, signing script seçeneklerinin beklenen yapıda bulunup bulunmadığını ve build dosyalarında açık bir key/MEK değeri bırakılıp bırakılmadığını kontrol etmektir.

Araç `make`, signing script'i veya target işlemi çalıştırmaz.

## Temel kullanım

```bash
securectl sdk lint \
  --devconfig <SDK>/devconfig/devconfig.mak \
  --app-makefile <APPLICATION_MAKEFILE> \
  --sbl-makefile <SBL_MAKEFILE> \
  --app-tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --rom-tool <SDK>/source/security/security_common/tools/boot/signing/rom_image_gen.py
```

Tam zincir verildiğinde aşağıdaki ilişkiler aranır:

```text
ENC_ENABLED
  -> application Makefile
  -> appimage_x509_cert_gen.py
  -> --enc / --enckey

ENC_SBL_ENABLED
  -> SBL Makefile
  -> rom_image_gen.py
  -> --sbl-enc / --enc-key
```

`ENC_ENABLED` ile `ENC_SBL_ENABLED` aynı ayar olarak yorumlanmaz.

## Development ve production kontrolü

SBL Makefile'da `DBG_FULL_ENABLE` veya eşdeğer `--debug` kullanımı ayrıca kontrol edilir.

Development için:

```bash
securectl sdk lint ... --intent development
```

Production için:

```bash
securectl sdk lint ... --intent production
```

TI SDK dokümantasyonu full debug seçeneğinin development amacıyla etkin olduğunu ve production'a geçilirken kaldırılması gerektiğini belirtir. Bu nedenle production intent ile full debug görülürse linter sonucu `FAIL` olur.

## Önceden alınmış Make database çıktısı

Bir Makefile'daki tanım, build sırasında kullanılan son değerle aynı olmayabilir. İstenirse daha önce alınmış bir `make -pn` çıktısı read-only olarak linter'a verilebilir:

```bash
securectl sdk lint ... --make-db make-db.txt
```

Toolkit `make -pn` komutunu kendisi çalıştırmaz. Bunun nedeni Makefile parse sırasında `$(shell ...)` veya recursive Make davranışlarının yan etki oluşturabilmesidir.

`make-db.txt` içinden şu değişkenler hedefli olarak okunur:

```text
DEVICE_TYPE
ENC_ENABLED
ENC_SBL_ENABLED
APP_SIGNING_KEY
APP_ENCRYPTION_KEY
```

Key değişkenlerinde gerçek path veya değer çıktıya yazılmaz. Yalnız boş/dolu durumu veya güvenli bir Make variable referansı raporlanır.

## Secret kontrolü

Linter configuration/Makefile içinde aşağıdaki durumları arar:

- private-key PEM marker'ı,
- key/MEK bağlamında 64-hex raw değer,
- Make recipe içinde doğrudan yazılmış `--key`, `--enckey` veya `--enc-key` girdisi.

Bulunan secret adayının içeriği veya path'i rapora yazılmaz; yalnız dosya rolü ve satır numarası bildirilir.

## Kaynak dosya kimliği

Proje sırasında kullanılan MCU+ SDK 12.00.00.27 dosyalarının SHA-256 değerleri karşılaştırma amacıyla toolkit içinde tutulur. Bir dosyanın SHA-256 değeri farklıysa bu tek başına hata sayılmaz; yalnız sürüme özgü daha önce doğrulanmış davranışların yeniden kontrol edilmesi gerektiğini gösterir.

Bu karşılaştırma özellikle şunlar için yapılır:

- `devconfig.mak`
- incelenen application Makefile
- incelenen `sbl_uart` Makefile
- `appimage_x509_cert_gen.py`
- `rom_image_gen.py`

## Sonuçların anlamı

`PASS`, verilen dosyalarda linter'ın kontrol ettiği configuration ve consumer ilişkilerinin tutarlı olduğunu gösterir.

`PARTIAL`, tam zincirin verilmediğini veya ek inceleme gerektiren bir durum bulunduğunu gösterir.

`FAIL`, beklenen consumer zincirinin bulunamadığı, production/full-debug çakışması olduğu, resolved key girdisinin eksik olduğu veya olası secret material bulunduğu anlamına gelir.

Bu sonuçların hiçbiri physical device lifecycle, customer Root of Trust, Secure Boot enforcement veya hardware decryption sonucu değildir.
