# Secure image build

Toolkit, MCU+ SDK 12.00.00.27 içindeki signing araçlarını değiştirmeden çağırır.

## Rehberli CCS / Secure Boot Paketi

Normal kullanımda manuel `securectl build` parametreleri yerine Studio'daki **Secure Boot Paketi** ekranı kullanılır. Bu ekran:

- fiziksel kart lifecycle'ını üretim hedefinden ayırır;
- HS-FS için `DEVICE_TYPE=GP`, HS-SE için `DEVICE_TYPE=HS` seçer;
- CCS application projesinin ve isteğe bağlı SBL projesinin kendi make/post-build tarifini çalıştırır;
- application ve boot image çıktılarını lifecycle suffix'ine göre ayırır;
- SDK'nın `default_sbl_ospi_hs_fs.cfg` veya `default_sbl_ospi_hs.cfg` dosyasındaki flash offset'lerini okuyarak UART UniFlash planı kurar.

Global `devconfig.mak` veya CCS project metadata'sı değiştirilmez. Private key/MEK yalnız geçici stage üzerinden make işlemine verilir ve yolu kalıcı rapora yazılmaz.

HS-SE artifact HS-FS makinede çevrimdışı hazırlanabilir; bu durum karta deploy edilebilirlik anlamına gelmez. Studio fiziksel lifecycle ile hedef eşleşmedikçe veya HS-SE Customer RoT durumu doğrulanmadıkça flash çalıştırmaz.

OSPI yazma OTP/eFuse yazma değildir, ancak mevcut flash içeriğini değiştirir ve bu nedenle iki aşamalı kullanıcı onayı ister. UniFlash exit `0`, ROM/TIFS authentication sonucunu tek başına kanıtlamaz; kart OSPI boot modunda resetlenip UART çıktısı gözlenmelidir.

## Application image

```bash
securectl build app \
  --tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --input <APP_MCELF> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_APPIMAGE>
```

Encrypted+signed image için ayrıca:

```text
--enckey <ENCRYPTION_KEY_PATH>
```

Bu durumda wrapper TI araca `--enc y --enckey ...` iletir.

## ROM combined image

```bash
securectl build rom \
  --tool <SDK>/source/security/security_common/tools/boot/signing/rom_image_gen.py \
  --sbl-bin <SBL_BIN> \
  --sysfw-bin <SYSFW_BIN> \
  --sysfw-inner-cert <SYSFW_INNER_CERT> \
  --boardcfg-blob <BOARDCFG> \
  --sbl-loadaddr <SOURCE_VERIFIED_VALUE> \
  --sysfw-loadaddr <SOURCE_VERIFIED_VALUE> \
  --bcfg-loadaddr <SOURCE_VERIFIED_VALUE> \
  --swrv <EXPLICIT_VALUE> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_IMAGE>
```

Load address, SWRV, debug seçimi veya SBL encryption kararı toolkit tarafından üretilmez. `--debug` ve `--sbl-enckey` yalnız açıkça verilirse kullanılır.

## `--dry-run`

Girdileri ve command yapısını kontrol eder, TI generator'ı çalıştırmaz.

## `--post-verify`

Image üretildikten sonra bağımsız `verify` kontrolü çalışır. Generator exit `0` verse bile verify sonucu `FAIL` ise build genel sonucu `PASS` olmaz.

Toolkit mevcut output dosyasının üzerine yazmaz.
