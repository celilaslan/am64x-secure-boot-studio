# Implementation QA — v2.0.0-alpha22

## Scope

Alpha22 is a focused Certificate Center first-use UX patch based on the real Windows alpha21 screenshot review. It does not change certificate cryptographic semantics or AM64x security claims.

Changes:

- beginner-focused start-page copy;
- explicit primary actions for Application, Secure Debug, existing certificate inspection, new-version creation, Certificate Library, and ROM/Keywriter/Generic Data contexts;
- `Yeni Sürüm / Export` terminology instead of mixed `Yeniden Üret / Reissue`;
- collapsible technical/security notes;
- empty result-boundary panel hidden until an operation produces a result;
- raw `Uzman Profile` tab hidden in Guided Mode and retained in Expert Mode.

## Local regression

`229 passed`

Phase-8 source QA: `PASS`

The local build environment does not provide PySide6/PyInstaller, therefore real Qt rendering and standalone executable smoke are not claimed by local automation.

## Real-host status

- Alpha21 Windows source-install launch/render: `OBSERVED`
- Alpha21 Certificate Center start page: `STRUCTURE PASS / UX PATCH REQUIRED`
- Alpha22 Windows Certificate Center visual QA: `PENDING SCREENSHOT`
- Windows standalone clean-machine bundle: `NOT EXECUTED`
- Linux alpha22 visual QA: `NOT EXECUTED`
- Project final completion: `NOT DECLARED`

## Security boundary

This UX patch does not prove hardware application authentication/decryption enforcement, customer Root of Trust enforcement, OTP/eFuse provisioning, HS-FS→HS-SE transition, permanent debug/security state, or application rollback enforcement.
