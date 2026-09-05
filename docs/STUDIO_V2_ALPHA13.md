# AM64x Secure Boot Studio v2.0.0-alpha13

## Scope

Real-Linux Environment screen visual-QA patch.

## Main changes

- Environment default result is now human-readable instead of raw JSON.
- Added six status cards: MCU+ SDK, Python, OpenSSL, Application signer, ROM signer and devconfig.mak.
- Exact paths, hashes and discovery metadata remain available under **Teknik Ayrıntılar**.
- Added a useful pre-check empty state and masked active SDK hint.
- Build/environment readiness remains host-side only and does not claim hardware/customer enforcement.

## Visual acceptance state

- Home: real-Linux screenshot accepted on alpha12.
- Environment populated-state patch: source/regression tested; second real-Linux screenshot still required before visual acceptance.
