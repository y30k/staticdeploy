# CI retirement evidence

## Verified GitHub state

- CI-01 (`legacy-baseline-qa`) and CI-02 (`scans-and-images`) completed successfully on merged pull requests #17 and #18.
- `master` branch protection requires those two GitHub Actions checks, requires resolved conversations, enforces rules for administrators, and disallows force pushes and branch deletion.
- The GitHub repository webhook inventory is empty.
- The repository has no checked-in CI configuration other than GitHub Actions workflows after this change.

## Retired checked-in coupling

- CircleCI configuration, README badge, contribution instructions, and Prettier exemption are removed.
- Codecov upload commands and dependencies are removed.
- Docker Hub tag/push commands, public npm `publishConfig`, tag-based release scripts, the legacy CLI image path, and CircleCI website variables are removed.
- Legacy documentation directs characterization users to local source builds rather than retired public artifacts.
- No replacement release or deployment workflow is introduced.

## External integration attestation

Maintainer attestation: this fork has never had CircleCI, Docker Hub, npm, Codecov, or website-publication connectivity; no corresponding project, webhook, credential, or publisher exists to disable or revoke. Consequently, no owner-side retirement action is required.

The DEC-01 record and the empty GitHub repository webhook inventory corroborate the absence of GitHub-side CircleCI coupling. GitHub Actions is the only CI system for this fork. This retirement does not authorize creation of replacement publication or deployment workflows.
