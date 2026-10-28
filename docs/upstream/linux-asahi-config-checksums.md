# Submitted kernel source-checksum correction

The coordinator submitted [asahi-alarm/PKGBUILDs draft PR #99](https://github.com/asahi-alarm/PKGBUILDs/pull/99)
on October 12, 2026 at 05:40:58 UTC. At 05:50:17 UTC it was **OPEN, DRAFT,
NOT MERGED**, with one changed file and two checksum replacements. This is an
actual upstream contribution required by `outline.md` section 9; it does not
accept the platform, kernel build, hardware, performance or complete port.

The config update at `b6c99b08e5f6d9bad8e23b88db69570436471961` retained stale
SHA-256 and BLAKE2 entries in `linux-asahi/PKGBUILD`. Fresh primary API queries
and a clean upstream checkout confirmed the mismatch remained present at main
`1c6daffd905c1b8f76202949ed48b80a4759ab73`. No existing open checksum-fix PR
appeared in the complete small open-PR list inspected before submission.

Submitted commit: `d28ebe2abba533e12e4cd748cf1da65cce4f54de`.
Both checksum arrays now match the existing 240,666-byte config. The retained
262,965,559-byte kernel source archive matches both unchanged archive entries.
The coordinator and an [independent reviewer](../reviews/upstream-kernel-checksum-review.md)
recomputed all four hashes, checked the exact two-line diff and passed
`bash -n linux-asahi/PKGBUILD` without executing the recipe.

The PR explicitly records that kernel compilation and hardware testing were
not performed. No package was installed, kernel/config selected for a project
release, boot state changed or upstream main branch modified. Maintainer review
and merge are external outcomes; refresh the actual PR state before relying on
it. The older Hyprland evidence drafts remain unposted and have separate routing
records.
