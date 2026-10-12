# Updater tool aliases: independent held-source review

**SOURCE-READY for coordinator rebinding and review of the resulting bootstrap.**
No material blocker was reproduced in this narrow correction. The historical
actual updater6 remains FAIL at `entry-controller/tool-resolution`; its private
offending tool/path/hash remains UNKNOWN. The correction and its fixtures do not
establish native compilation, package installation or hardware acceptance.

## Authenticated scope

Author hold receipt SHA256:
`d2ddf16998a30076ab59cfdc1db340a2a0ea58da1a75b0446d219dabc23c6419`.
Every referenced evidence file's bytes, hash, mode and regular-file type were
checked before use. The three held files and their primary copies matched:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `packages/tools/cachy-asahi-update/updater-native.py` |48749| `05788ac7490996794440d5856a1a1e8c62da717026744e0d0af41e42775346af` |
| `packages/tools/cachy-asahi-update/test-native.py` |98391| `0352ed24300fde10876391a0802872fd20194b6254cdc57e7afb7969c1bcd875` |
| `docs/workstreams/updater-tool-alias-correction.md` |5531| `0118100ed427084c99c09b5743cffd2d2e27acedc85fcbfd8d49555c95a60b36` |

All three modes are0644. Historical parent/test bytes were independently read
from Git commit `908636cf10298fce844cb5ad8944c0cb2261eae6`, not inferred from
current HEAD or copied author assertions. The old parent hash is
`99b7e58a325d48119af6987e163ccfd031e14e573bc43261ac04ce64bfdf03d1`;
the old test hash is
`45bac5849b9f7fa0e1c70267218df8bf0286453633216fed597051f17239dfec`.

The complete historical86-file closure was reconstructed from its exact Git
blobs/modes and ready64-package/eight-root metadata. It has4,194,759 source bytes.
All Git object hashes, SHA256 pins and modes verify. Exactly84 current rows match
those historical bytes: only the held parent/test differ. All62 other package
rows, eight root rows, recipes, inputs, worker guard and ready map remain
unchanged. The ready map still has historical SHA256
`9cb072d0935486a0c1bb8bc5a06937c98295c17f143af44f62ea2f1292542586`;
it does **not** currently admit the new two source hashes.

The independent AST comparison confirms that `tool_pins` is the sole changed
production definition. Other functions/classes, imports, constants, launch,
process/signal handling, timers, worker predicates, diagnostics, cleanup and
acceptance gates are identical. All75 original test-method bodies are identical;
eight new methods were added.

## Semantics and causal tests

An installed hardlink is a second pathname for the same inode. `Path.resolve`
keeps that hardlink's name while following symbolic links. The old parent ledger
treated a tar hardlink as a symbolic alias and selected the content member's
pathname. The unchanged worker therefore refuses that ledger even when hashes
agree. The correction preserves the installed symbolic resolution pathname and
uses a separate same-owning-archive hardlink chain solely to obtain regular
content bytes.

The independently captured74-file test cohort ran83 tests, zero failures/errors/
skips, exit0, with `-I -B -S` and ResourceWarnings as errors. No author capture
script or author namespace was executed in place. Existing launch/cancellation
tests use harmless Python controls and mocked Docker/build operations. No
Docker, compiler, GPG, installer, namespace or package actor ran in this review.
The first replay passed all83 but a nested harmless Python fixture emitted an
owned parent-module PYC because parent `-B` alone did not propagate to that
process. That cohort/cache is retained unchanged. A separate exact74-file copy
replayed the same83 tests with inherited `PYTHONDONTWRITEBYTECODE=1`, passed with
no skips and has zero PYC/cache directories. These are83 distinct tests replayed
twice, not166 distinct tests; only the clean second cohort supplies the final
source-copy disposition.

Thirteen additional independent records use tiny USTAR data and real private
filesystem hardlinks/symlinks. Both old and corrected **actual parent functions**
run against identical SHA-bound archives. The exact captured worker condition
and its unchanged `regular`/`digest` function AST run against only those owned
files, with the root path mapped to the private model; the complete worker and
its execution authority are never invoked.

- GCC-like hardlink plus cc→gcc: old path ledger refuses, corrected path ledger
  passes the unchanged condition; bytes/hashes match and filesystem inodes match.
- Hardlink content under `usr/lib` plus symbolic tool alias: the lazy library
  content path also has old-red/new-green behavior while retaining the installed
  `/usr/bin/gcc` pathname.
- Wrong installed resolved pathname or content hash still refuses.
- Hardlink cycle, missing target, hardlink-to-symlink, noncanonical target,
  special terminal, foreign/later-overlaid content and normalized duplicate
  selected member refuse.
- Ordinary regular/symbolic package overlay semantics remain supported in data
  fixtures; production input acquisition and signature checks are unchanged.

The copied83 suite additionally covers16/17-hop boundary, symbolic cycles,
absolute/traversal targets, directories, declared hardlink payload, oversized
regular data,200,000/200,001 headers and archive-hash drift. Selected member
duplicate checks are per archive; ordinary final regular/symbolic overlays across
archives remain allowed. Hardlink content must originate in its own authenticated
archive namespace and still be the exact final namespace record. No foreign
content lookup, arbitrary tool substitution, ledger waiver or type fallback is
introduced.

The exact15-tool schema is unchanged. Parent tool-content bound remains512MiB;
the worker's actual bound remains256MiB with hardlinks permitted through its
unchanged `singly_linked=False` call. A parent ledger alone cannot override that
worker bound or any other worker gate. No extra command/query/actor, timeout
renewal or success/cleanup weakening was found.

## Actual evidence and adoption limits

All15 retained updater6 public files were independently hash/length checked
against the root verification receipt
`e2b4e9e8e4c18d5c88de1f924bb27d5b7cdfa86e41ba285ce0a78e2503031fde`.
This is passive byte verification, not a replacement public-consumer replay.
The bound worker diagnostic records first failure `entry-controller` /
`tool-resolution`, compiler launch false, and FAIL. The outer terminal is FAIL;
cleanup and recovery are PASS with their original explicit authority limits.
No missing private ledger is reconstructed and no named tool is attributed as
the actual failure cause. The source-causal model explains a real defect without
rewriting that historical run or asserting that its next native attempt will
pass.

Root must prospectively update the two ready rows, source/stage/bootstrap binding
hashes and workflow registration, authenticate the resulting complete source
closure and commit it before actors. This review does not perform those edits or
grant execution. Installer namespace diagnosis `2b1176d8…` and adapter v11's
three held files remain unchanged. Publication, native compilation, installation,
16K/M2 compatibility and full-port acceptance remain NOT ACCEPTED here.

Independent evidence is under
`artifacts/reviews/updater-tool-alias-root-peer-20261012/`: captured74 source
cohort, captured historical86 Git closure, `capture.json`, `historical86-proof.json`,
both83-test logs/receipts, the first-copy cache observation, independent13-case
source/receipt and actual6 passive proof.
The final receipt binds this review, those results and the unchanged source holds.
