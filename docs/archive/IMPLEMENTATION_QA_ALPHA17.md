# Implementation QA — v2.0.0-alpha17

Focus: Secure Application wizard Step 1 real-Linux interaction-state patch.

Expected changes:

- `Devam` remains actually disabled until the Application field resolves to an existing regular file.
- A typed but missing path does not enable progression.
- Disabled primary actions have an explicit grey visual state and no longer retain the blue primary appearance.
- Step 1 validation gives a guided missing-file error if an invalid path is forced programmatically or becomes stale.
- Signing/encryption/provisioning/lifecycle/hardware claim boundaries are unchanged.

Automated regression target: `208 tests PASS`.

Real-Linux post-patch screenshot acceptance: `PENDING_REAL_LINUX_SCREENSHOT`.
