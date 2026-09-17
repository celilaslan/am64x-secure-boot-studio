# AM64x Secure Boot Studio v2.0.0-alpha25 — Application TI Fields Guided-UX QA

## Scope

Alpha25 is a focused Guided-Mode wording and information-density patch based on the real Windows alpha24 `2 · TI Alanları` screenshot.

## Change

- `auth_type — copy mode` is presented as `Yükleme davranışı`.
- `auth_type — Host ID` is presented as `Destination Host ID`.
- Exact `auth_type[7:0]` / `auth_type[15:8]` packing remains visible in a collapsed technical section.
- `destAddr / Destination address` is presented as `Destination Address`.
- The encrypted-application route is expressed in beginner-facing language while continuing to delegate to installed TI `appimage_x509_cert_gen.py`.
- `System Firmware Boot Extension ekle` is presented as `Processor boot bilgilerini ekle` with contextual help.

## Security boundary

- No target-specific address/core/Host ID is guessed.
- No OTP/eFuse/customer-key provisioning.
- No HS-FS -> HS-SE transition.
- No hardware authentication/decryption enforcement claim.
- No TI extension encoding or cryptographic behavior changed by this patch.
