# Silicon errata kontrolü

`securectl errata`, AM64x/AM243x **SPRZ457J Rev. J** errata belgesindeki Boot advisory kayıtlarını troubleshooting sırasında daha hızlı ilişkilendirmek için kullanılır.

Araç iki farklı iş yapar:

```bash
securectl errata list ...
securectl errata check ...
```

`list`, Errata Table 1-2 içindeki Boot advisory indexini filtreler. `check` ise Secure Boot/ROM/security açısından doğrudan önemli olan seçilmiş kayıtların documented koşullarını verilen kullanım bilgileriyle karşılaştırır.

## Advisory listesini filtreleme

```bash
securectl errata list --revision 2.0
securectl errata list --revision 1.0 --category security
securectl errata list --revision 2.0 --boot-mode uart
```

`matrix_applicable_to_revision=true`, yalnız ilgili advisory'nin Errata Rev. J matrix'inde seçilen silicon revision için `YES` olarak listelendiğini ifade eder. Mevcut karttaki bir hatanın o advisory'den kaynaklandığını göstermez.

## Secure Boot / ROM değerlendirmesi

Örnek HS-FS combined image kontrolü:

```bash
securectl errata check \
  --revision 2.0 \
  --device-state hs-fs \
  --flow full-combined \
  --outer-rsa degenerate
```

### i2413 — HS-FS combined image integrity

Errata, HS-FS combined image non-degenerate RSA outer certificate ile hazırlandığında ROM'un TIFS component integrity kontrolünü atlayabildiğini belirtir. TI workaround'u outer X.509 certificate için **RSA degenerate key** kullanmaktır.

Toolkit sonucu:

- `RISK_CONDITION_MATCH`: HS-FS + combined image + non-degenerate RSA bilgileri verilmiş.
- `WORKAROUND_CONDITION_SATISFIED`: HS-FS + combined image + degenerate RSA bilgileri verilmiş.
- `POTENTIALLY_APPLICABLE`: gerekli bağlamın bir kısmı bilinmiyor.

Bu workaround customer authenticity veya provisioned Root of Trust kanıtı değildir.

### i2415 — xSPI primary / UART backup authentication failure

Errata belirli bir **HS-SE** failure sequence'i tanımlar: redundant address destekleyen xSPI/OSPI primary boot, redundant offset'te tam ROM boot image yerine yalnız TIFS/SYSFW image ve ardından UART backup.

```bash
securectl errata check \
  --revision 2.0 \
  --device-state hs-se \
  --flow redundant-backup \
  --primary-boot ospi \
  --backup-boot uart \
  --redundant-content tifs-only
```

TI workaround'u redundant offset'te yalnız TIFS/SYSFW certificate/image yerine **tam boot certificate/image** bulundurmaktır.

### i2418 — Certificate Info yokluğunda Secure ROM panic

Bu advisory, **Full Combined Image dışındaki normal boot flow** için tanımlanır. Extended info veya Legacy info bulunmaması Secure ROM panic/infinite-loop koşullarından biridir.

```bash
securectl errata check \
  --revision 2.0 \
  --flow normal \
  --certificate-info absent
```

Toolkit certificate info varlığını kullanıcı tarafından verilen bağlam olarak değerlendirir. Address translation failure veya ROM hash-computation failure durumunu host üzerinde kanıtlamaz.

### i2423 — HS-FS debug/firewall erişim sınırı

Errata, HS-FS ROM'un secure assets içeren **FWL 33 ve 66** için debug restriction'ı firewall region'ın tamamına uygulayabildiğini belirtir. Bu durum external emulator ile initial flash programming gibi erişimleri etkileyebilir. Workaround bağlamında ihtiyaç duyulan firewall'ın açılması için TIFS/SYSFW gerekir.

```bash
securectl errata check \
  --revision 2.0 \
  --device-state hs-fs \
  --external-emulator yes
```

Araç firewall açma isteği göndermez ve herhangi bir debug/security state değişikliği yapmaz.

## Çıktının yorumu

`errata check` içindeki `assessment` alanları troubleshooting yardımıdır:

- `RISK_CONDITION_MATCH`: verilen bilgiler advisory'nin documented risk koşuluyla eşleşiyor.
- `WORKAROUND_CONDITION_SATISFIED`: verilen bilgiler documented workaround koşuluyla uyumlu.
- `APPLICABLE_TO_ACCESS_CONTEXT`: advisory selected access context ile doğrudan ilişkili.
- `POTENTIALLY_APPLICABLE`: gerekli girdilerin bir kısmı bilinmiyor.
- `OUTSIDE_DOCUMENTED_CONTEXT`: verilen kullanım, advisory'nin documented condition'ından farklı.

Bu sonuçlardan hiçbiri tek başına root-cause tespiti değildir. Önce dosya/image kimliği, certificate parse/signature, payload/component hash, load ve boot configuration kontrolleri yapılmalıdır.

## İşlem sınırı

Bu modül yalnız local veri ve sabit Errata Rev. J eşleştirmesi kullanır:

```text
target access       NO
OTP/eFuse           çalıştırılmaz
debug unlock        çalıştırılmaz
lifecycle change    yapılmaz
```
