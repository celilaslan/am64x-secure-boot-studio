# Implementation QA — v2.0.0-alpha21

## Scope

Alpha21 adds the AM64x-focused **Certificate Center** while preserving the existing host-side claim boundary.

Implemented and regression-covered:

- manual X.509 Subject entry (`C/ST/L/O/OU/CN/email`);
- Application certificate create/build/verify profile flow;
- Secure Debug certificate create/build/verify profile flow;
- certificate metadata for DER/PEM and certificate+payload images;
- DER ↔ PEM export and public DER-SPKI export;
- certificate ↔ private signing key public-side match;
- clone/reissue workflow without editing signed certificate bytes;
- certificate semantic compare;
- public Project Certificate Library with duplicate SHA-256 rejection;
- Subject newline/control-character and malformed-email validation;
- explicit ROM/Application/Debug/Generic/Keywriter context separation.

## Final local regression

`226 passed`

## Security boundary

Certificate creation/verification does **not** prove target hardware authentication/decryption enforcement, customer Root of Trust enforcement, OTP/eFuse provisioning, HS-FS→HS-SE transition, permanent debug/security state, or application rollback enforcement.

Encrypted Application generation remains delegated to the installed TI `appimage_x509_cert_gen.py`; ROM combined generation remains delegated to `rom_image_gen.py`. Keywriter is inspect/offline-preparation context only unless a separately authorized exact-package provisioning workflow is established.

## Real-host status

- Linux Certificate Center human visual QA: `PENDING`
- Windows Certificate Center human visual QA: `PENDING`
- Windows clean-machine standalone bundle: `NOT EXECUTED`
- Project final completion: `NOT DECLARED`
