# Implementation QA — v2.0.0-alpha20

## Scope

Application TI-signer execution hardening after a real-Linux alpha19 encrypted+signed build reached `ti_signing_tool=FAIL` while signing-key and MEK preflights both passed.

## Changes

- Application builds execute `appimage_x509_cert_gen.py` inside an isolated staging directory using short relative aliases instead of user paths.
- Private signing key and MEK aliases use hardlink/symlink only; Studio does not copy secret key material as a fallback.
- Upstream signer temporary files are kept out of the installed SDK tool directory and staging is removed after execution.
- Generated output is published to the requested destination only after TI-tool success and through a no-overwrite publish guard.
- Failure diagnostics now expose a bounded redacted stderr/stdout excerpt in runtime Technical Details only.
- Failure excerpts are not written to build logs or build records.
- Persisted stdout/stderr hashes were removed; only byte counts are retained because upstream output could unexpectedly contain secret material.

## Regression

- Full regression: `219 PASS`.
- Added TI-like shell-fragile whitespace-path regression: `PASS`.
- Added secret diagnostic redaction/no-persistence regression: `PASS`.
- UX source audit: `PASS`.
- Release secret/path scan: `PASS`.

## Root-cause status

The alpha19 real-Linux failure is **not retroactively declared proven** to be a whitespace-path bug. Source behavior and the host path made that the leading hypothesis, and alpha20 removes that failure mode. A real Linux retry with the same MCELF/key/MEK is still required to classify the observed failure as resolved or to surface the sanitized exact upstream diagnostic.

## Claim boundary

No OTP/eFuse provisioning, HS-FS -> HS-SE transition, permanent debug/security change, hardware authentication/decryption enforcement, or customer Root of Trust enforcement was executed or added.

## Real Linux acceptance

Application encrypted+signed retry / alpha20: `PENDING_REAL_LINUX_RETRY`.
