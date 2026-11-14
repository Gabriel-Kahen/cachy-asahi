# Offline settings/session-lock pair verification

[`scripts/integration/desktop_session_lock.py`](../../scripts/integration/desktop_session_lock.py)
provides an explicit source CLI for the unselected settings 0.1.1-1 and
session-lock 0.1.0-1 pair. It leaves `desktop.py`, the accepted old recipe,
frozen inputs and private native/DesktopTools runtimes unchanged.

The checked-in source profile is
[`scripts/integration/profiles/desktop-session-lock011.json`](../../scripts/integration/profiles/desktop-session-lock011.json),
SHA256 `bed94f0ab252544cbaf1d5e666e7c4ac4564a7295e2ca15f34498aa9a32b10f6`.
Its schema has four top-level fields: `schema: 1`,
`profile: "hyprland011-session-lock010"`,
`qualification: "OFFLINE_PACKAGE_PREFIX_ONLY"` and `packages`.
Each of the two package-name keys contains an informational source commit,
the complete static `.PKGINFO` field/list expectations, and a `payload` mapping
from canonical relative paths to SHA256, byte count and numeric permission mode.
The settings mapping has exactly nine files; the helper mapping has four.

The caller supplies the reviewed profile digest and an independent expected
digest for each actual build archive. The profile can therefore be reused for
matching native builds with different build metadata; current x86 host archive
digests are not frozen as accepted native output. Package identity, versions,
license, dependencies, optional dependencies and build dependencies must match
the profile exactly. Build date and packager are allowed to vary with validated
shape; declared size must equal the exact payload byte total. Raw `.BUILDINFO`
and `.MTREE` are required ordinary archive metadata, not independently accepted
build provenance or a validated installed dependency transaction.

Archives are read as bounded ordinary files, checked against their supplied
digests, then parsed without extraction. Raw tar and Zstandard-compressed tar
are supported. On Linux, `/usr/bin/zstd` receives already-held compressed bytes
through an anonymous memfd; it never reopens the caller's archive pathname or
writes decompressed files. Input/output limits are 2 MiB per archive, 256 KiB
per member, 64 entries and ten seconds for decompression. Traversal, unexpected
members/directories, duplicates, links, special files, non-root archive owners,
unsafe modes and nonzero trailing data are refused.

The prefix must be an absolute, ordinary **payload-only staging directory**
containing exactly the thirteen files and their expected directories. It can
be assembled by the two actual unprivileged `package()` functions with that
temporary directory as `pkgdir`; this is not package installation. Prefix file
bytes/modes must match the verified archives. Descriptor-relative traversal
refuses symlinks, hardlinks, unexpected files/directories and changed inputs.
Prefix filesystem ownership is not treated as pacman ownership. Use quiescent
caller-controlled inputs; this is not protection against an adversarial actor
concurrently mutating arbitrary directories with the same UID.

The verifier also recognizes the exact audited Lua delta: one helper-backed
lock binding, one helper-backed suspend binding, and the unchanged pinned
baseline after reversing those edits. It checks the successor's provenance,
API revision, helper dependency bounds and retained auxiliary hashes. This is
an exact finite-template check, not a general Lua interpreter or compositor
parser. Payloads are never executed and no display, system bus or package
manager connection is made. Python isolated mode is required.

## Actual local invocation and result, 2026-11-14

The following source command passed on the existing x86_64 host after the two
real package functions assembled the temporary prefix. Both archive digests
are the final previously built host inputs, not native acceptance:

```sh
python -I -B scripts/integration/desktop_session_lock.py \
  --profile scripts/integration/profiles/desktop-session-lock011.json \
  --profile-sha256 bed94f0ab252544cbaf1d5e666e7c4ac4564a7295e2ca15f34498aa9a32b10f6 \
  --settings-package /tmp/cachy-asahi-settings011-release-source-host-ncv_fn0e/cachy-asahi-hyprland-settings-0.1.1-1-any.pkg.tar.zst \
  --settings-sha256 a2e7f87f952bfbee67c717e4611dd97a6447f548e56d0c079b5de44aeccd0931 \
  --session-lock-package /tmp/cachy-asahi-session-lock-final-host-3oqv04q_/cachy-asahi-session-lock-0.1.0-1-any.pkg.tar.zst \
  --session-lock-sha256 738f361830f0586dff28acd725b2865f3a95f0c1ab0d1cbc6517ede8d750a686 \
  --prefix /tmp/cachy-asahi-desktop-pair-prefix-9zdw1z1i/prefix
```

Result: exit 0, `desktop-session-lock-prefix-pass`, 13 exact payload files;
archive metadata/payload, audited binding delta and assembled prefix checks
all `PASS`. JSON is written only to stdout. Refusals return exit 2 with a
`refused` JSON object; the verifier has no output-directory/publisher mode.

`python -I -B -Werror::ResourceWarning scripts/integration/test_desktop_session_lock.py`
passes **29 tests**. Controls cover raw/Zstandard archives, source pins and
read-only behavior, supplied digest mismatch, missing helper/archive/payload,
metadata/version/dependency drift, changed helper, malformed source profiles,
duplicate/traversing/link/special/privileged archive entries, missing/extra/
changed/linked prefix files, wrong modes, changed Lua despite updated receipts,
decompression limits, trailing data, hostile environment, and source CLI
success/refusal. Neither these controls nor the successful actual assembly
executes a payload, locks a screen or requests sleep.

This is ready source verification for a later reviewed constructor to invoke.
It does not replace the existing container/runtime/dependency validation or
qualify a native build. Native ARM4K/16K builds, installed database ownership,
dependency resolution, actual desktop/locking/suspend behavior and M2 hardware
remain **NOT RUN**. No candidate selection or shared manifest changed.
