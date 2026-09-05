# Teknik kaynaklar

Toolkit aşağıdaki sürümlerle eşleştirilmiştir:

- AM6442 / AM64x
- MCU+ SDK `12.00.00.27`
- SYSFW/TISCI `12.00.02`
- AM64x/AM243x TRM Rev. J

## Birincil kaynaklar

| Konu | Kaynak | Toolkit'teki kullanım |
|---|---|---|
| Secure image signing/encryption | TISCI 12.00.02, *Signing binaries for Secure Boot on HS Devices* | Image Integrity, Load, SWREV, optional Boot/Encryption sırası |
| System Firmware X.509 | TISCI 12.00.02, *Security X509 Certificate Documentation* | `.1.3`, `.1.4`, `.1.8`, `.1.33`, `.1.34`, `.1.35` ve Keywriter OID şemaları |
| Authentication/decryption | TISCI 12.00.02, *System Firmware Authentication and Decryption Requests* | SHA2-512 integrity, Load Extension ve optional AES-256-CBC davranışı |
| Secure Debug | TISCI 12.00.02, *Secure Debug User Guide* | Debug + SWREV zorunluluğu, SOC UID, `debugType`, core listeleri ve target policy ayrımı |
| OTP Keywriter | TISCI 12.00.02, *Key Writer* | RSA-4096 SMPK/BMPK, DER public-key SHA2-512, KEYCNT/KEYREV alanları |
| ROM combined image | AM64x/AM243x TRM Rev. J | `.1.9` component yapısı ve legacy extension ayrımı |
| SDK signing araçları | MCU+ SDK 12.00.00.27, *Security Related Tools* ve installed scripts | `rom_image_gen.py`, `appimage_x509_cert_gen.py`, `--enc y --enckey` |
| Negatif doğrulama testleri | Projede yürütülen application signing ve encrypted application host-side testleri | Certificate signature, TBSCertificate, payload/ciphertext ve ROM component değişikliklerinin birbirinden bağımsız kontrol edilmesi |
| Signing key preflight | TISCI 12.00.02 Authentication and Decryption Requests; Key Writer | System Firmware RSA-4K desteği, Key Writer RSA-4096 SMPK/BMPK kısıtı, public-key kontrolleri |
| MEK format preflight | Kurulu MCU+ SDK 12.00.00.27 signer source incelemesi + OpenSSL 3.5.6 runtime probe | AES-256 için 64-hex key formatı; 63/65 hex warning ile kabul edildiği için strict local kontrol |
| HS-FS → HS-SE provisioning preflight | TISCI 12.00.02, *Key Writer* + *Security X509 Certificate Documentation* | `KEYCNT`/`KEYREV`, RSA-4096 SMPK/BMPK, DER SHA2-512 SMPKH/BMPKH, optional SWREV ve offline-only sınırı |
| KEYREV / SWREV offline kontrolü | TISCI 12.00.02, *Key Writer* + *Security X509 Certificate Documentation* + *Secure Debug User Guide* | KEYCNT/KEYREV geçerli durumları; `tiboot3.bin`, BoardCfg ve debug revision karşılaştırmaları; application rollback sınırı |
| Security BoardCfg policy kontrolü | TISCI 12.00.02, *Security Board Configuration* + *Secure Debug User Guide* | `allow_jtag_unlock`, `allow_wildcard_unlock`, `min_cert_rev`, `jtag_unlock_hosts[4]`, Secure Debug magic `0x42AF`, Extended OTP magic `0x4081`, `write_host` ve runtime debug/revision-write policy değerlendirmesi |
| SDK security configuration lint | MCU+ SDK 12.00.00.27 `devconfig.mak`, incelenen application/SBL Makefile ve installed signing script source mapping | `DEVICE_TYPE`, `ENC_ENABLED`, `ENC_SBL_ENABLED`, `APP_SIGNING_KEY`, `APP_ENCRYPTION_KEY`, application `--enc/--enckey`, ROM/SBL `--sbl-enc/--enc-key` ve development full-debug kontrolü |
| SDK source karşılaştırması | Aynı source mapping ve kurulu SDK davranışları | İki source setinde configuration routing, signer options, AES-256-CBC/SHA-512 işaretleri ve `.1.4/.1.9/.1.10/.1.33/.1.34/.1.35` OID varlıklarının read-only karşılaştırılması |
| Silicon errata kontrolü | AM64x/AM243x Processor Silicon Revision 1.0, 2.0 Errata, SPRZ457J Rev. J | Boot advisory revision indexi; `i2413`, `i2415`, `i2418`, `i2423` için documented koşul ve workaround bağlamının offline değerlendirilmesi |
| Generic binary authentication/encryption | TISCI 12.00.02, *System Firmware Authentication and Decryption Requests* + *Security X509 Certificate Documentation* + *Signing binaries for Secure Boot on HS Devices* | Boot Extension olmadan generalized authentication; `.1.3/.1.34/.1.35`, optional `.1.4`, SHA2-512 ciphertext binding, AES-256-CBC ve host-side decryption correctness kontrolü |

## Sürüme özgü notlar

- TISCI Authentication guide, application/generic authentication için SWREV'i mandatory ve önerilen minimum `1` olarak anlatır. Aynı sürümün Security X509 sample-template notunda binary authentication için Load + Image Integrity yeterli ifadesi bulunur. Toolkit SWREV'i kendi `cert build` application profile'ında üretir; başka bir certificate'ta SWREV yokluğunu `verify` sırasında tek başına hard-fail yapmaz.
- TISCI `.1.4` salt alanını 32-byte reserved zero olarak tanımlar. Kurulu SDK 12.00.00.27 application signer üzerinde daha kısa zero salt gözlemi bulunduğundan toolkit salt değerini değiştirmez ve yalnız uzunluğu raporlar.
- Keywriter Security X509 kaynağı `.1.73` Extended OTP alanını unsupported/reserved olarak işaretlerken Key Writer belgesi aynı alanı supported-field akışında listeler. Toolkit bu farkı kendiliğinden çözmez.
- Exact load address, processor/host ID, debug policy veya lifecycle değeri kaynaksız üretilmez.

- Key Writer, `SWREV-SBL` ve `SWREV-SYSFW` alanlarını 96 bit (48 bit without double redundancy), `SWREV-BOARDCONFIG` alanını 128 bit (64 bit without double redundancy) olarak tanımlar. Provisioning preflight bu tek-kopya genişliklerini kontrol eder; eFuse encoding üretmez.
- Security X509 kaynağı `tiboot3.bin` ve BoardCfg için certificate revision daha düşükse reject davranışını açıkça tanımlar. Secure Debug revision değeri ayrıca `min_cert_rev` eşiğine tabidir. Application/generic data için bu toolkit target rollback enforcement sonucu üretmez.
- Generic-data encryption üreticisi TISCI 12.00.02'de tanımlanan `salt[32] = 0` biçimini ve "16-byte multiple olana kadar zero padding" ifadesini doğrudan uygular. Bu nedenle input zaten 16-byte hizalıysa padding sayısı `0` olur. Kurulu SDK 12.00.00.27 application signer'daki 2-byte salt ve aligned-input'ta 16-byte padding gözlemleri bu bağımsız üreticiye kural olarak taşınmaz.
- Generic data üzerinde Boot Extension bulunmaması `TISCI_MSG_PROC_AUTH_BOOT` kullanımını generalized authentication olarak ayırır; toolkit target API çağrısını veya customer Root of Trust enforcement'ı çalıştırmaz.

