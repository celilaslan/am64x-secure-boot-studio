# Security Board Configuration kontrolleri

`securectl boardcfg`, Security Board Configuration içindeki Secure Debug ve Extended OTP policy alanlarını target'a göndermeden kontrol eder.

## Profile oluşturma

```bash
securectl boardcfg new --output security-boardcfg.yaml
```

Şablonun ilgili bölümü:

```yaml
type: security_boardcfg_policy
secure_debug:
  subhdr_magic: '0x42AF'
  allow_jtag_unlock: 0
  allow_wildcard_unlock: 0
  allow_debug_level_rsvd: 0
  rsvd: 0
  min_cert_rev: 0
  jtag_unlock_hosts: [0, 0, 0, 0]
extended_otp:
  subhdr_magic: '0x4081'
  write_host: null
```

Toolkit exact Host ID veya debug policy değeri seçmez. Bu alanlar kullanılan BoardCfg kaynağından veya hedef sistem tasarımından alınmalıdır.

## Policy alanlarını kontrol etme

```bash
securectl boardcfg check security-boardcfg.yaml
```

Kontrol edilen başlıca kurallar:

- Secure Debug Unlock subheader magic: `0x42AF`
- `allow_jtag_unlock`: yalnız `0` veya `0x5A`
- `allow_wildcard_unlock`: yalnız `0` veya `0x5A`
- `allow_debug_level_rsvd = 0`
- `rsvd = 0`
- `min_cert_rev`: 32-bit unsigned değer
- `jtag_unlock_hosts`: tam dört adet 8-bit Host ID
- `jtag_unlock_hosts` içinde `128`: TISCI requester host wildcard
- Extended OTP subheader magic: `0x4081`
- `write_host`: 8-bit Host ID; wildcard `128` burada geçersizdir

`write_host` değerinin gerçekten secure proxy thread'e map olduğu, SoC'ye ait exact Host ID kaynağı olmadan doğrulanmaz.

## Debug certificate ile policy'yi birlikte değerlendirme

Bir Secure Debug certificate'ın BoardCfg tarafından izin verilen runtime akışla uyumunu görmek için:

```bash
securectl boardcfg debug-policy security-boardcfg.yaml \
  --certificate debug.der \
  --transport tisci \
  --host-id <HOST_ID> \
  --soc-uid <64_HEX_SOC_UID> \
  --jtag-efuse enabled
```

Sec-AP için:

```bash
securectl boardcfg debug-policy security-boardcfg.yaml \
  --certificate debug.der \
  --transport sec-ap \
  --soc-uid <64_HEX_SOC_UID> \
  --jtag-efuse enabled
```

Değerlendirme şu ayrımı korur:

- `REJECT_BY_POLICY`: verilen BoardCfg/runtime koşullarından en az biri isteği reddeder.
- `POLICY_ALLOWS_REQUEST`: verilen policy girdileri isteğe izin verir; bu target kabulü değildir.
- `INDETERMINATE`: SOC UID, JTAG eFuse durumu veya TISCI requester Host ID gibi gerekli bir target bilgisi verilmemiştir.

`POLICY_ALLOWS_REQUEST`, active SMPK/BMPK trust, eFuse public-key-hash eşleşmesi veya System Firmware'in certificate'ı target üzerinde kabul ettiğini kanıtlamaz.

### UID ve wildcard

`allow_wildcard_unlock = 0x5A` ise BoardCfg, debug certificate içindeki UID'nin target SOC UID ile eşleşmesi şartını atlayabilir. Wildcard kapalıysa araç karşılaştırma yapabilmek için `--soc-uid` ister; değer verilmezse sonuç `INDETERMINATE` olur.

### TISCI requester Host ID

`jtag_unlock_hosts[4]` TISCI üzerinden debug unlock isteği gönderebilecek host'ları sınırlar. Listede `128` varsa tüm requester host'lar için wildcard policy uygulanır. `Sec-AP` değerlendirmesinde bu liste uygulanmaz.

### JTAG eFuse önkoşulu

Secure Debug dokümanına göre JTAG connectivity eFuse tarafında kapalıysa runtime unlock adımları etkili olmaz. Araç bu durumu yalnız kullanıcı tarafından verilen `--jtag-efuse enabled|disabled|unknown` bilgisiyle değerlendirir; eFuse okumaz.

## SWREV/KEYREV write_host kontrolü

Extended OTP `write_host` alanının belirli bir requester host ile eşleşmesini kontrol etmek için:

```bash
securectl boardcfg revision-writer security-boardcfg.yaml --host-id <HOST_ID>
```

TISCI 12.00.02 Security Board Configuration, `TISCI_MSG_WRITE_SWREV` ve `TISCI_MSG_WRITE_KEYREV` işlemlerini yalnız `write_host` için yetkilendirir. Bu komut yalnız BoardCfg policy karşılaştırması yapar; TISCI mesajı göndermez ve OTP/eFuse yazmaz.

## Kapsam

Bu modül:

- gerçek BoardCfg binary layout offset'lerini tahmin etmez,
- BoardCfg'yi target'a göndermez,
- `TISCI_MSG_OPEN_DEBUG_FWLS` çağırmaz,
- `TISCI_MSG_WRITE_SWREV` veya `TISCI_MSG_WRITE_KEYREV` çağırmaz,
- eFuse veya kalıcı debug ayarı değiştirmez.
