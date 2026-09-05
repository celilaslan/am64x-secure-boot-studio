# Secure image build

Toolkit, MCU+ SDK 12.00.00.27 içindeki signing araçlarını değiştirmeden çağırır.

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
