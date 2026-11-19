# Current606 R16 accepted desktop pair on emulated ARM with 16 KiB pages

The minimal and overlay cases ran in order from source
`229b143302608ca0a726f5618dc404fe11fcde74`. The overlay started after
independent acceptance of the minimal case. Both hosted runs passed on
native AArch64 runners using emulated AArch64 guests with 16,384-byte pages.
Each guest held 606 packages. Each controller image held 590.
[R16 source](https://github.com/Gabriel-Kahen/cachy-asahi/tree/229b143302608ca0a726f5618dc404fe11fcde74)
· [Minimal result](current606-minimal-emulated-arm16k-r16-20261119.md)
· [Overlay run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44462779800)

The overlay run `44462779800`, job `135353310908`, independently passed
on November 19, 2026 UTC.

- The two installed-state scans matched the same 606 package identities and
  versions, 114,247 filesystem entries and 4,918,288,238 payload bytes.
  The final database and filesystem recheck finished at 632.7 seconds.
  The overlay snapshot SHA-256 is
  `e5b4794637925c7067a7b22828d6f78e3c2d38a680f885bfa74a67d7d8eef3a2`.
- All 15 overlay screenshots were reviewed alongside the separate 15 minimal
  frames. Welcome opened the terminal and file manager and displayed the
  stored DNS, Doctor and orphan results, unavailable and failed checks,
  cancellation and successful retry. Both Stop frames show the known
  Welcome8 report-format warning. The separate Welcome9 correction awaits
  its installed ARM desktop trial. [Welcome9 change](https://github.com/Gabriel-Kahen/cachy-asahi/pull/593)
- The guest exited naturally. All 15 runtime cleanup rows were verified
  before original producer cleanup. Independent replay checked the
  actual cleanup command output and resource identities before applying the
  historical order check.
- Retention completed in 63 seconds under the 120-second cap. The hosted
  export retained all 248 evidence members. Original artifact
  `14503288842` is 28,218,590 bytes with SHA-256
  `d1c9aaa378a5856b3e943d0d431bdbe48df97c9de47410309a5c702930921665`.

This closes the two emulated desktop cases for the exact R16 package set.
Physical M2 behavior, hardware acceleration, target performance and power,
and supported release acceptance remain open.
