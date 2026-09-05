# Build kayıt dosyası

`securectl build app` ve `securectl build rom`, üretilen image'ın yanında makine tarafından okunabilir bir JSON kayıt dosyası oluşturur:

```text
<output>.build-record.json
```

Kayıtta şu bilgiler bulunur:

- toolkit sürümü ve UTC zamanı
- build işleminin türü
- secret yolları gizlenmiş komut
- çalışma dizini ve Python sürümü
- kullanılan TI signing tool'un boyutu ve SHA-256 değeri
- secret olmayan girdi dosyalarının boyutu ve SHA-256 değerleri
- signing/encryption key'in sağlanıp sağlanmadığı
- process exit code ve çalışma süresi
- output boyutu ve SHA-256 değeri
- `stdout`/`stderr` için yalnız byte sayısı ve SHA-256
- kullanıldıysa `post_verify` sonucu

Signing ve encryption key girdileri için key içeriği veya key dosyasının hash'i kaydedilmez. Upstream signing tool'un `stdout` ve `stderr` metni de kalıcı log'a yazılmaz; yalnız boyut ve SHA-256 bilgisi tutulur.

Bu kayıt, bilgisayarda yapılan build işleminin izlenebilirliğini sağlar. Hedef cihazın image'ı authenticate veya decrypt ettiğini göstermez.
