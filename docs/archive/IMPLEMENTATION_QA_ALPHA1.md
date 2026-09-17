# v2.0.0a1 Implementation QA

## Regression

- v1.0.0 baseline: `109 passed`
- v2.0.0a1 final source test run: `121 passed`
- v1.0.0 source archive SHA-256: `4bbf815e6f0b39e230515ffe577148cba3bb411a900c55e15ed0db3ee66d5511`

## Wheel

- file: `am64x_secure_toolkit-2.0.0a1-py3-none-any.whl`
- SHA-256: `ec3ab5c538fafc46a64614bbce51ad3a91d5b2b054c52683a4277a196d986ca8`
- wheel import / `securectl --version` / help smoke: PASS
- GUI facade without PySide6: graceful error path PASS

## GUI runtime sınırı

Build container'da PySide6 kurulu değildir ve network-disabled build environment nedeniyle dependency indirilememiştir. Bu nedenle actual Qt window render/screenshot smoke testi bu alpha üretim oturumunda **NOT EXECUTED**. GUI Python modules `compileall` ile syntax-check edilmiş, optional-import facade test edilmiş ve PySide6 dependency `[gui]` optional extra olarak paketlenmiştir.

## Security QA

- synthetic RSA-4096 generation + preflight: PASS
- strict 256-bit / 64-hex MEK generation + preflight: PASS
- POSIX secret file mode 0600: PASS
- existing output overwrite refusal: PASS
- provisioning-test primary/backup distinctness: PASS
- keyset manifest secret-name/value/hash exclusion: PASS
- claim-boundary regression: PASS
- secret-policy sanitizer: PASS
- application dry-run does not become execution PASS: PASS

No OTP/eFuse write, HS-FS→HS-SE transition, permanent debug/security change or hardware enforcement execution was added or performed.
