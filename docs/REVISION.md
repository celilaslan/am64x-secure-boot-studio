# KEYREV ve SWREV kontrolü

Bu bölümdeki komutlar target cihazda herhangi bir revision alanı yazmaz. Amaç, TISCI 12.00.02'de açıkça tanımlanan durum ve karşılaştırma kurallarını host üzerinde kontrol etmektir.

## KEYCNT ve KEYREV

Key Writer 12.00.02 alan anlamları:

- `KEYCNT=0`: customer root-key set yok
- `KEYCNT=1`: SMPK seti mevcut
- `KEYCNT=2`: SMPK ve BMPK setleri mevcut
- `KEYREV` en fazla `KEYCNT` olabilir
- `KEYREV=1`: SMPK/SMEK context
- `KEYREV=2`: BMPK/BMEK context

Geçerli durumları görmek için:

```bash
securectl revision key-matrix
```

Belirli bir durum:

```bash
securectl revision key --keycnt 2 --keyrev 1
```

Hedef bir KEYREV durumunun yalnız alan ilişkileri açısından mümkün olup olmadığını görmek için:

```bash
securectl revision key \
  --keycnt 2 \
  --keyrev 1 \
  --target-keyrev 2
```

`target-keyrev` sonucu bir write izni değildir. Araç runtime `TISCI_MSG_WRITE_KEYREV` çağrısı yapmaz; hedef cihazın board configuration, host authorization veya OTP durumunu incelemez.

## SWREV karşılaştırmaları

Aynı SWREV alanı her certificate türünde aynı sonucu doğurmaz. Toolkit bu nedenle context seçilmesini zorunlu tutar.

### tiboot3.bin

```bash
securectl revision swrev \
  --context tiboot3 \
  --reference 3 \
  --certificate 2
```

`certificate < reference` ise ROM SWREV kuralı açısından `REJECT_BY_SWREV`; eşit veya yüksekse `ACCEPT_BY_SWREV` sonucu verilir. Bu sonuç yalnız revision gate içindir; signature veya image integrity sonucu değildir.

### BoardCfg

```bash
securectl revision swrev \
  --context boardcfg \
  --reference 4 \
  --certificate 4
```

Reference, configuration SWREV eFuse değerini temsil eder. Certificate revision daha düşükse SYSFW revision kontrolü açısından reject beklenir.

### Secure Debug

```bash
securectl revision swrev \
  --context debug \
  --reference 5 \
  --certificate 6
```

Reference, Security Board Configuration içindeki `min_cert_rev` eşiğidir. Eşiği geçmek yalnız revision kontrolünü karşılar; certificate signature, SOC UID, requested debug privilege ve host policy kontrollerinin yerine geçmez.

### Application / generic data

```bash
securectl revision swrev \
  --context application \
  --reference 5 \
  --certificate 1
```

TISCI 12.00.02 authentication dokümanı SWREV extension'ı mandatory olarak tanımlar ancak bu sürümde parsing/validation sonrasında ek bir işlem uygulanmadığını belirtir. Bu yüzden toolkit application için eski revision değerini `REJECT` diye etiketlemez ve `NO_CURRENT_ENFORCEMENT_MODELED` sonucu verir.

## Key Writer SWREV alanları

```bash
securectl revision swrev-info
```

Kaynakta verilen boyutlar:

| Alan | eFuse encoded alan | Tek kopya |
|---|---:|---:|
| `SWREV-SBL` | 96 bit | 48 bit |
| `SWREV-SYSFW` | 96 bit | 48 bit |
| `SWREV-BOARDCONFIG` | 128 bit | 64 bit |

Key Writer double redundancy kullanıldığını belirtir. Toolkit bu bilgiye göre provisioning profile'daki integer aralığını kontrol eder; eFuse bit dizisini oluşturmaz.

## Ne yapılmaz?

Bu modül:

- `KEYREV` veya `SWREV` yazmaz,
- OTP/eFuse programlamaz,
- HS-FS → HS-SE geçişi yapmaz,
- revision `PASS` sonucunu tam boot/debug authorization sonucu saymaz,
- application rollback enforcement'ı doğrulanmış gibi göstermez.
