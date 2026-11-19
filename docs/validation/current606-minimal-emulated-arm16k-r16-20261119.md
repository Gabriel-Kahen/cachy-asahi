# Current606 R16 accepted minimal desktop on emulated ARM with 16 KiB pages

The hosted minimal case passed on November 19 UTC. Run `44454333017`,
job `135325576270`, and its accepted Original join source commit
`229b143302608ca0a726f5618dc404fe11fcde74`. The native AArch64 runner
booted a generic emulated AArch64 guest with 16,384-byte pages. The guest
reported 606 packages and the separate controller image held 590.
[Minimal run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44454333017)

- Both installed-state scans matched all 606 package identities and versions,
  114,247 filesystem entries and 4,918,288,238 payload bytes. The verification
  finished its final database and root recheck after 585.7 seconds. Its
  snapshot SHA-256 is `be8522202bbeb7d7cd394776b094ab65f9e32d5241e074914451695fb1af3023`.
- The 15 original screenshots were reviewed for the expected Welcome views,
  terminal and file manager, stored DNS, Doctor and orphan results, deliberate
  failure and unavailability, cancellation and successful retry. Welcome8
  still displays its cancellation report-format warning. The separate
  Welcome9 correction is on Main. [Welcome9 change](https://github.com/Gabriel-Kahen/cachy-asahi/pull/593)
- The guest exited naturally, all 15 runtime cleanup records were verified,
  and the producer retired afterward. The independent Reader verified the
  current cleanup output receipts before projecting their command names and
  exit statuses into its existing order checks. The original archive and
  historical Reader remain available for replay.
- After R16 removed a redundant source verification, the hosted retention
  step completed in 64 seconds and retained all 248 evidence members. The
  original artifact is 27,516,886 bytes with SHA-256
  `c7edfd4e94a324beea6f69b8158c9177fe7ff51c61b897738fecda53b6a5221f`.
  [R16 source](https://github.com/Gabriel-Kahen/cachy-asahi/tree/229b143302608ca0a726f5618dc404fe11fcde74)

The matching overlay case passed from the same exact source after independent
minimal acceptance. Physical M2 validation, target power and performance
measurements, and stable release acceptance remain open.
[Overlay result](current606-overlay-emulated-arm16k-r16-20261119.md)
