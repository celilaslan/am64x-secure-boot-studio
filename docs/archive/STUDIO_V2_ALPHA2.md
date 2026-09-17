# AM64x Secure Boot Studio v2.0.0-alpha2

## Scope

Alpha2 continues the v2.0 GUI/UX blueprint without re-running project Day-8/9/10 technical work. It is a new toolkit-development increment.

### Phase 5 bindings completed

- ROM Combined Image Wizard -> installed `rom_image_gen.py` via shared workflow service
- Certificate Explorer -> structured inspect + optional host verification + readable explanation
- Negative Tests -> existing controlled-copy page retained
- SDK Inspector -> `sdk_lint.py` binding
- SDK Compare -> `sdk_diff.py` binding
- Errata Advisor -> Rev. J list/context evaluation

### Phase 6 bindings completed

- Provisioning Preparation -> offline `provision_preflight()` only
- KEYREV / SWREV Simulator -> offline revision functions
- Security BoardCfg -> profile check + revision-writer authorization
- Secure Debug Assistant -> certificate + BoardCfg policy evaluation only
- Generic Data Assistant -> profile validate/build/verify

## Safety properties retained

- no OTP/eFuse write action
- no HS-FS -> HS-SE execution action
- no permanent debug/security write action
- no source SDK mutation
- no generated TI output patching
- negative tests remain copy-only
- secret fields use secret-style selectors and reports remain sanitized by the shared secret-policy layer
- ROM load addresses are user/source supplied; the GUI does not guess addresses/options
- build workflows require a private signing key rather than accepting public-only material for an operation that needs signing

## Verification

- full test suite: `128 passed`
- Python source compile: PASS
- real Qt render smoke test: NOT EXECUTED in the build container because PySide6 is not installed
- PySide6 remains an optional `gui` dependency; CLI does not require Qt
