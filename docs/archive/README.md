# Archive — historical development records

This folder holds the development record of the project. The files are kept for
traceability, not as current documentation. **For current documentation, see
[`../`](../).**

Nothing here is a release claim. Each QA note records what was verified *at that
point in development*, under the limits stated in that note.

## Contents

| Prefix | What it is |
| --- | --- |
| `STUDIO_V2_ALPHA*.md` | Scope of work planned and implemented in each `2.0.0-alpha*` iteration. |
| `IMPLEMENTATION_QA_ALPHA*.md` | Regression / QA results recorded at the end of that iteration. |
| `BASELINE_V1_LOCK.md` | The `v1.0.0` regression baseline that `2.0` development started from. |
| `PACKAGE_MANIFEST.sha256` | SHA-256 manifest of the source package as of the alpha26 snapshot. It is a point-in-time artifact and is **not** regenerated on later commits, so it does not match current `HEAD`. |

A condensed, chronological summary of the same history — and the only version
history that is kept current — lives in [`../../CHANGELOG.md`](../../CHANGELOG.md).
