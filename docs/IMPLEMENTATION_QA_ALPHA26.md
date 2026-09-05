# AM64x Secure Boot Studio v2.0.0-alpha26 — Certificate Step-2 Required-Field Gating QA

## Scope

Alpha26 is a focused interaction patch based on the real Windows alpha25 `2 · TI Alanları` screenshot. The underlying X.509/TI extension encoding is unchanged.

## Change

- `Payload / application`, `Destination Address`, `Yükleme davranışı` and `Destination Host ID` are visibly marked required in the Application certificate flow.
- `Devam` is disabled until all four required inputs are explicitly present.
- The button tooltip identifies the next missing field while disabled.
- Exact semantic validation still runs on transition; live readiness is only the first UI gate.
- Target-specific Destination Address/Host ID are never synthesized or silently defaulted.
- The same readiness helper keeps CN, Secure Debug UID/wildcard, signing key and DER output navigation fail-closed.

## Security boundary

- No target-specific address, Host ID, processor ID or boot flag is guessed.
- No OTP/eFuse/customer-key provisioning.
- No HS-FS -> HS-SE transition.
- No hardware authentication/decryption enforcement claim.
- No TI certificate extension encoding or cryptographic behavior changed by this patch.

## Real-host status

- Real Windows alpha25 screenshot identified the active-`Devam` UX problem.
- Real Windows alpha26 visual/interaction confirmation remains `PENDING_SCREENSHOT`.
- Project final completion remains `NOT DECLARED`.
