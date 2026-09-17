# AM64x Secure Boot Studio v2.0.0-alpha12

Alpha12 is a focused Home/Dashboard visual-polish patch derived from a real Linux PySide6 launch and screenshot review.

## Scope

- Compact device/SDK/security context chips in the top bar.
- Beginner-first Home dashboard with six primary tasks instead of duplicating the advanced tool catalogue.
- Environment / Project / Last Operation status cards moved before Quick Start.
- Shorter, more natural Quick Start language.
- Technical last-operation details removed from the Home card; they remain available on the relevant workflow/result page.
- Card text is explicitly transparent to avoid disabled-input-like grey strips under some Linux desktop styles.
- Navigation spacing/selection treatment polished.
- Bottom safety boundary retained as a compact, readable note.
- Status-bar workflow messages shortened.

## Security boundary

This release does not add OTP/eFuse writes, HS-FS → HS-SE transition execution, permanent debug/security writes, production secret management, or hardware enforcement claims.

## Visual QA state

A real Linux alpha11 window launch and screenshot exposed the Home issues addressed here. The alpha12 code patch is source/regression tested in the build environment, but the patched alpha12 Home screen still requires a second real-Linux screenshot review before the Home page is considered visually accepted.
