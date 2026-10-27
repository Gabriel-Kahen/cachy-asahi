# Three management-tool source-delivery profiles (2026-10-27)

Proposed extension to `scripts/release/recipe_source_delivery.py`, based on
21,108-byte PR285 SHA256
`75cf872cf4e178535c378ede16fb8037e027dd5ed0a52590409afc4673ef899c`.
Observed checkout: `89a423cb56f6500b4b81df47e63f0cfdb823b60b`. Exact recipe and
SRCINFO hashes select versions; the observed revision alone is not authority.

| Exact package | Local recipe sources | Bundle files including recipe/SRCINFO | Payload files | Bundle bytes |
| --- | ---: | ---: | ---: | ---: |
| cachy-asahi-orphans 0.1.0-2 | 6 | 8 | 5 | 71,680 |
| cachy-asahi-cache 0.2.0-1 | 5 | 7 | 4 | 81,920 |
| cachy-asahi-repository-runtime 0.1.0-1 | 9 | 11 | 8 | 112,640 |

Every source is flat, local and checksum-pinned in both the literal recipe and
SRCINFO. All three retain the same full project MIT grant (SHA256
`51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7`)
and their actual package NOTICE. No candidate requires source acquisition or a
new generated-file model. Every package payload is a direct source-byte copy;
Repository Runtime's loops expand to three documentation files and two notices.
Tests and checkers are delivered as sources even where they are not installed.

Orphans' five files are CLI 0755, README 0644, protection-floor.json 0644, and two
license/notice files 0644. Cache has CLI 0755, README 0644 and the two notices0644.
Runtime has no CLI: three pinned helpers 0644 under
`usr/share/cachy-asahi/repository-runtime/scripts/{client,release}/`, three
README/provenance/pins documentation files 0644, and two notices0644. Its unchanged
helper-pins and provenance maps agree on all 86,445 helper bytes. Cache/Orphans
have no source-provenance.json; their explicit required-source lists retain the
actual notices and, for Orphans, the protection floor.

The separately provided dependencies remain explicit: Python >=3.11 and pacman
for Cache/Orphans; Python >=3.11, gnupg, libarchive and pacman for Runtime. Their
library/program bytes are not bundled. This is finite original recipe-source
coverage, not transitive operating-system source delivery or release acceptance.

## Host results

Packet: `artifacts/development/management-tools-source-delivery-development-20261027/`.
`evidence/receipt.json` retains commands, interpreter SHA256, raw-log hashes,
per-source byte/hash maps and the pinned exclusive-child supervisor identity.
`actual-checkout/receipt.json` confirms bundles made directly from the actual
checked-out candidate trees match the independently qualified snapshots.

Python 3.14.7 host: **65/65 tests PASS**: 10 new management tests, 15 existing
original-recipe tests, 9 existing expanded-recipe tests and 31 existing transport
tests. Eight preexisting version profiles and their payload maps are unchanged;
legacy bundle checksums and Setup7's recorded checksum still pass. Tests cover
all 26 source/recipe/SRCINFO tamper cases, nine unsafe-node cases, all 17 payload
files with byte/mode/missing mutations, extras, 36 identity/dependency/BUILDINFO
mutations, canonical-tar checks and synthetic transport/export association.

All three actual source bundles verify, relocate/unpack and repack byte-identically.
Static recipe checks and Python source compilation pass. Relocated Cache and
Orphans `--help` execute successfully. Runtime's unchanged source checker passes
both the relocated recipe and an exact eight-file data-only stage; its helper
mains never execute. Eight supervised children all return raw exit0, complete
captured output, no signals and two complete empty group observations.

The first qualification attempt passed all 65 tests then stopped because the
Python audit guard rejected ctypes' import-time Python-process handle. The
corrected guard initializes ctypes before installing the guard; every later
library load, subprocess, socket, fork and signal request remains refused.
`evidence-attempt1/` preserves the failure. `evidence-attempt2/` is the intermediate passing run before adding explicit tested-code hashes to the receipt; only `evidence/` is final qualification.
These Python audit refusals are not a kernel sandbox.

## Reproduce

From a checkout containing this packet:

```sh
python -I -B artifacts/development/management-tools-source-delivery-development-20261027/qualify.py --output "$PWD/source-delivery-recheck"
python -I -B artifacts/development/management-tools-source-delivery-development-20261027/verify_checkout.py --checkout "$PWD" --output "$PWD/source-delivery-actual-recheck"
```

Both outputs must be absent. The first uses retained checksum-pinned source-only
inputs and temporary private checkout copies. The second reads the current three
canonical recipe directories and refuses drift from the qualified source maps.
All code and generated output used by this packet is private to it in the
recorded run. Applying the proposal and committing/CI dispatch remain Root's work.

## Evidence limits

No PKGBUILD is sourced and no recipe hook, makepkg, GPG, ALPM, native build or
package installation/removal is executed. Two original regression methods and
one expanded method that execute hooks or spawn unguarded actors are explicitly
omitted in the receipt. Full Cache/Orphans libalpm test suites are **NOT RUN**.
Their manifest host commands are deliberately limited to `--help`; those commands
do not establish runtime/package correctness. Runtime data staging is ordinary
file copying checked by the existing checker, not package() execution.

Archive-binding tests use synthetic uncompressed package data and grant no build
or installation evidence. Actual source bundles are unbound to a binary archive;
no release index is emitted. Native ARM, 16K, supported Asahi composition,
physical13/15-inch M2, performance, installation, legal and maintained-release
acceptance remain **NOT RUN / NOT ADMITTED**. No blocker was found for these three
finite source-delivery profiles; wider dependency-source delivery is separate.
