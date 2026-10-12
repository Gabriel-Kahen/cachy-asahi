# Development and maintenance

Read `AGENTS.md`, `outline.md`, `docs/roadmap.md` and `manifests/packages.toml` before changing the project. `docs/orchestration.md` assigns exclusive file ownership for the current batch. The coordinator alone integrates shared manifest and release-policy changes.

## Reproduce and review

- Use Python 3.11+ for stdlib tooling. Read `docs/build-system.md` for the clean aarch64 builder contract and `docs/package-validation.md` for static versus executed checks. Do not install dependencies onto a shared host from a research/build script.
- Keep source revisions, licenses, notices, dependency transactions, installed paths and hooks reviewable. Original code/documentation is MIT. Excluded upstream source cannot inherit this grant.
- Use isolated paths for local smoke builds and record their architecture. Data-only host packaging does not complete the two-clean-ARM-build gate.
- Preserve source snapshots, package inventories, logs, checksums and build provenance. Inspect package ownership/configuration behavior, not only a successful compiler or package-manager exit code.
- Have another worker review the result. Add regression tests for actual validation failures; avoid tests that merely repeat an implementation detail. Never treat a synthetic fixture as real target evidence.
- Keep commits bounded to finished owned files. Coordinate shared Git operations and retain other workers' changes. Do not publish a release until all required evidence is accepted.

The static CI workflow exercises tooling and recipe inspection. It cannot certify ARM compilation, graphics, audio, speaker protection, suspend, recovery or optimization acceptance. Missing resources and failed packages stay visible in the status record.

## Bug reports

Include the exact Air model/size, base and overlay source revisions, installed package versions, execution context (physical/native, VM, emulated), reproducible steps, expected/actual behavior, frequency and whether it existed on the unmodified baseline. Attach sanitized logs and evidence checksums. Note recovery outcome and user-configuration differences. Do not include credentials, private signing material or device serial numbers.

## Release responsibilities

| Responsibility | Current implementation owner | Ongoing accountable maintainer |
| --- | --- | --- |
| Package inputs and source/license audits | Desktop and tools/defaults workers | Not assigned |
| Build/inspection CI and provenance | Build/validation worker | Not assigned |
| Exact-machine integration and regression checks | Coordinator, with target operator required | Not assigned |
| Signing custody, staging and recovery | Release worker designs tooling; no production signing identity exists | Not assigned |
| Guides, triage and contributor review | Coordinator | Not assigned |
| Controlled performance measurements | Performance worker prepares tooling; target operator required | Not assigned |

Agent chats are development capacity, not a permanently staffed maintenance service. Before a supported release, assign maintainers, signing custody and target operators; record backups and available validation machines.

For every dependency or upstream change, triage platform impact, rebuild the affected set in staging, exercise version-coupled desktop checks, retain the prior supported artifacts, and promote only after package and hardware gates. Handle urgent defects through withdrawal/fix and the documented trust/recovery process. Record the response and known limits rather than promising an unstaffed deadline.

The first supported release must be followed by another release through the same process, and an independent operator must exercise the installation guide. Until then, the maintenance and usability acceptance stages remain incomplete.
