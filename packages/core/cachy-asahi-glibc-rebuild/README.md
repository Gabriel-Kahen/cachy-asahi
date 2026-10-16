# Unselected project-owned GNU libc successor

`PKGBUILD.in` is a reviewable template. A complete exact GNU source tree remains
missing, so there is no executable PKGBUILD or completed source bundle. The null
archive SHA256 in `source-lock.json` is a hard prerequisite, never a checksum
waiver. Use the data-only materializer documented in
`../../../scripts/ci/glibc-owned-rebuild/README.md` after source recovery.

This deliberately separate package neither reconstructs the old held binary's
recipe nor resolves its source-correspondence gap. Its only runtime payload is
under the versioned private prefix recorded in the lock. No install hooks,
global loader/cache/locale changes, providers/replacements or inventory edits
are proposed. Build-pair, upstream tests, static ABI, runtime smoke, lifecycle,
M2 hardware and performance are all NOT RUN.

All source/patch dependencies, licensing, ordinary build commands, input bounds
and the explicit owned-container lane are recorded in the harness README and
source lock. Full GNU source license notices must travel with the eventual
source bundle. The six patch files retain their upstream regression coverage.
