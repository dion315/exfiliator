# Change Control & Versioning

## Versioning schema

Exfiliator follows [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

- **MAJOR**: incompatible protocol/CLI changes (e.g., client JSON shape changes).
- **MINOR**: backwards-compatible feature additions such as new protocol tests or HTML sections.
- **PATCH**: bug fixes, documentation, or query updates that do not modify public behavior.

The canonical version string lives in `version.py` and is surfaced at runtime with `exfiliator_client.py --version` / `exfiliator_server.py --version`. Every merge that changes behavior must evaluate whether to bump PATCH, MINOR, or MAJOR.

## Change control workflow

1. **Open an issue / RFC** describing the requested feature or fix, including:
   - Use case, risks, affected protocols, and validation approach.
   - Any required configuration or documentation updates.
2. **Implementation branch**:
   - Branch from `main`.
   - Keep changes atomic; unrelated work belongs in separate branches.
   - Update `version.py` according to the impact (see above) and note the new version in `CHANGELOG.md` (future enhancement).
3. **Validation**:
   - Run `ruff check .`, `pytest`, and any manual protocol smoke tests relevant to the change.
   - For detection/content updates, paste screenshots or logs showing the new queries work.
4. **Pull request review**:
   - Link back to the issue/RFC.
   - Summarize risk, testing performed, and rollback plan.
   - Ensure `docs/`, `configs/`, and `queries/` stay synchronized with code changes.
   - **Mandatory:** Update the *Change Log* section in this file with a short description of the changes heading to `main` (one bullet per PR). CI/gatekeepers should block merges if the entry is missing.
5. **Approval & merge**:
   - Require at least one maintainer approval.
   - Squash or rebase to keep history linear.
   - Tag the merge commit with the version number (`git tag vMAJOR.MINOR.PATCH && git push --tags`).
6. **Post-merge tasks**:
   - Publish updated HTML reports or sample configs if applicable.
   - Notify stakeholders (SOC, blue-team) about new capabilities or detection content.

## Emergency hotfixes

For urgent fixes (security regressions, critical bugs):

- Branch from the latest release tag.
- Limit the change set to the bug fix and associated tests.
- Bump only the PATCH number.
- Document the incident and mitigation steps in the pull request for audit trails.

Following this lightweight process keeps Exfiliator auditable while still enabling rapid iteration for new protocol simulations and detection content.

## Change log (update this before merging to `main`)

- *2025-02-14* — Added automated QA & security GitHub workflows plus dev dependency manifests for lint/tests/audits.
- *2025-02-14* — Synced architecture/threat docs with the latest protocol coverage (DNS/Telnet/SMTP, mock-sensitive testing, detection content).
- *YYYY-MM-DD* — *<pending entry; describe feature/fix and PR # here>*
