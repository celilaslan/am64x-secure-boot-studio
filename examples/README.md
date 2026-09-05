# Örnek kullanım

Bu dizinde secret içermeyen örnek profile dosyaları bulunur:

- `application_profile.yaml`
- `debug_profile.yaml`
- `provisioning_profile.yaml`
- `security_boardcfg.yaml`
- `generic_data.yaml`

Placeholder değerler gerçek proje/SoC bilgileriyle doğrulanmadan kullanılmamalıdır. Bu pakette private key, MEK veya production/customer secret bulunmaz.

## Application certificate profile

```bash
securectl cert new app --output app.yaml
# app.yaml içindeki payload ve load alanlarını doldur
securectl cert validate app.yaml
securectl cert render app.yaml --output app.cnf
```

Test amacıyla oluşturulmuş local RSA-4096 signing key ile signed-only package üretmek için:

```bash
securectl cert build app.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output app.der \
  --package app.secure
```

## Secure Debug profile

```bash
securectl cert new debug --output debug.yaml
# SOC UID / revision / privilege / core listelerini doldur
securectl cert validate debug.yaml
```

Bu işlem target üzerinde debug açmaz.

## Application build dry-run

```bash
securectl build app \
  --tool <SDK>/source/security/security_common/tools/boot/signing/appimage_x509_cert_gen.py \
  --input <APP_MCELF> \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output <OUTPUT_APPIMAGE> \
  --dry-run
```

ROM combined image örneklerinde load address ve SWRV değerleri yalnız exact SDK/SoC kaynağından veya gerçek build recipe'den alınmalıdır.

## Provisioning preflight

```bash
securectl provision new --output provision.yaml
# KEYCNT, KEYREV ve public DER girdilerini doldur
securectl provision preflight provision.yaml \
  --report provision-report.json
```

Bu komut yalnız host-side hazırlık kontrolüdür; OTP/eFuse yazımı veya HS-FS → HS-SE geçişi yapmaz.

## Revision kontrol örnekleri

```bash
securectl revision key-matrix
securectl revision key --keycnt 2 --keyrev 1 --target-keyrev 2
securectl revision swrev --context tiboot3 --reference 3 --certificate 2
securectl revision swrev-info
```

## Security BoardCfg policy örneği

```bash
securectl boardcfg new --output security-boardcfg.yaml
securectl boardcfg check security-boardcfg.yaml
securectl boardcfg debug-policy security-boardcfg.yaml --certificate debug.der --transport sec-ap --soc-uid <64_HEX_SOC_UID> --jtag-efuse enabled
```

Host ID veya SOC UID gibi target'a özgü değerler toolkit tarafından tahmin edilmez.

## Generic binary authentication

```bash
securectl data new --output data.yaml
# input, load ve encryption alanlarını kullanım bağlamına göre doldur
securectl data validate data.yaml
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --output data.secure
```

Encryption etkinleştirilmişse MEK yalnız komut girdisi olarak verilir:

```bash
securectl data build data.yaml \
  --key <PRIVATE_SIGNING_KEY_PATH> \
  --mek <LOCAL_MEK_FILE> \
  --output data.secure
```

Bu package Boot Extension içermez ve target üzerinde `TISCI_MSG_PROC_AUTH_BOOT` çağrısı yapmaz.

