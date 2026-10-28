# Maintained desktop seed93 authentication

October 15, 2026: the fresh `sqlite03` invocation passed all 93 selected archive
hash, detached-signature and package-metadata checks. The external command exited
naturally with status 0. Its final report records `verified_count=93`, no first
failure and no cancellation; its supervisor records verified child cleanup with
no cleanup uncertainty. This is input authentication, not installation or M2 validation.

The selected source is [2643e175](https://github.com/Gabriel-Kahen/cachy-asahi/commit/2643e1755d402399035976d1f12cd4e8296148bd).
The [runnable harness](https://github.com/Gabriel-Kahen/cachy-asahi/commit/599a8588767dcb5074f7f02646a4b49253c8c541)
uses profile `2f32684073cd945843a5685ca72d951435bb96c252d43344368193c5d3ca9155`.
The whole invocation retained its 1,800-second timeout and 10-second kill allowance.

The earlier `sqlite02` invocation verified 91 packages before zlib acquisition
failed. An exact copy of that pinned archive and signature was recovered from
[Archboot's October aarch64 release archive](https://archboot.com/src/release/aarch64/2026.10/).
Archboot is an alternate acquisition source. Both recovered files matched the
existing selected sizes and SHA256 hashes; no package identity changed. The new
run copied only selected public archive/signature bytes into a new private cache,
then repeated every signature check and metadata observation in a fresh isolated
GPG home. It reused no reports or GPG state.

Local retained output is
`artifacts/maintained-desktop-seed93-authentication-run-20261015-sqlite03/`, including
`invocation.json`, `process-result.json` and `work/reports/094.json`.
The report's historical `REPORTED_COMPLETE_PENDING_ROOT_ADMISSION` label is the
producer's original vocabulary; the observed successful command and 93 checks
are recorded here without introducing an additional admission framework.

This does not establish trust or compatibility for the entire 574-package set,
an Asahi package transaction, installed payload execution, a usable desktop,
physical 16KiB-page operation, either M2 Air size, or a supported release.
