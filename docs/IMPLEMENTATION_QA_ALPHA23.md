# AM64x Secure Boot Studio v2.0.0-alpha23 — Certificate Creation Wizard QA

## Scope

Alpha23 is a focused UI/interaction patch based on the real Windows screenshots of alpha22 Certificate Center → New Certificate.

The certificate backend, X.509/TI extension engine, cryptographic behavior and AM64x security boundaries are not redefined in this patch.

## Changes

- Replaces the long single-scroll create form with five guided steps:
  1. Kimlik
  2. TI Alanları
  3. Signing Key
  4. Çıktı
  5. Kontrol
- Common Name (CN) is visibly required; other Subject fields are optional.
- Certificate mechanics are collapsed by default.
- Application `auth_type` is presented according to TISCI semantics as one INTEGER composed from:
  - lower byte: copy/authentication mode (0/1/2)
  - upper byte: destination Host ID
- Signing key selection is isolated from public certificate metadata.
- DER output is required; optional PEM/Profile/OpenSSL/package outputs are collapsed by default.
- Final review masks private-key path and shows only selected/not-selected state.
- Step transitions gate the minimum required inputs without guessing target-specific address/core/host values.

## Security boundary

- No OTP/eFuse/customer-key provisioning.
- No HS-FS -> HS-SE transition.
- No hardware authentication/decryption enforcement claim.
- No target-specific address/core/Host ID guess.
- Private-key material/value is not displayed by the review UI.
