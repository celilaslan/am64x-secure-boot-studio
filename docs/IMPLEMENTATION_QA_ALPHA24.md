# AM64x Secure Boot Studio v2.0.0-alpha24 — Certificate Identity/TI Metadata Separation QA

## Scope

Alpha24 is a focused UI semantics patch based on the real Windows alpha23 `1 · Kimlik` screenshots.

## Change

- `Software Revision` is no longer shown inside `1 · Subject / Kimlik`.
- `Software Revision` is shown at the top of `2 · TI Alanları`.
- `Geçerlilik süresi (gün)` remains in Step 1 as host-side X.509 validity metadata.
- UI text explicitly states that Software Revision is TI certificate metadata, not X.509 Subject/Kimlik, and does not independently prove target rollback enforcement.

## Security boundary

- No OTP/eFuse/customer-key provisioning.
- No HS-FS -> HS-SE transition.
- No hardware authentication/decryption enforcement claim.
- No target-specific address/core/Host ID guess.
- No cryptographic or certificate encoding behavior changed by this patch.
