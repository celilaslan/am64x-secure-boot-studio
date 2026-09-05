# AM64x Secure Boot Studio v2.0.0-alpha14

## Scope

Real-Linux Project Workspace visual-QA patch.

## Main changes

- Project create/open state is separated from the active-project dashboard.
- Empty history/artifact tables are hidden until a project is active.
- Beginner-facing Project terminology is simplified.
- Recent-project normal display no longer exposes full host paths.
- Active-project dashboard adds Secure Application, Image Inspector and Reports quick actions.
- Explicit project-folder selection prevents accidental project creation in the current source directory.

## Security boundary

Project persistence remains share-safe: secret values, private/symmetric key paths and full host paths are not written to project activity/artifact records.

## Visual acceptance state

- Home: real-Linux accepted on alpha12.
- Environment: real-Linux accepted on alpha13.
- Project setup/dashboard patch: source/regression tested; real-Linux post-patch screenshots required before visual acceptance.
