# Independent native LLVM Reader preparation

This is an independent offline Reader **implementation/preparation**, not an
operational Reader invocation or native result. It owns only
`scripts/port/llvm23-native-independent-reader/` and this document. The LLVM
candidate, native pipeline, shared inventory and workflows are unchanged.
All actual Source/ref/run/job/attempt/approval/authority/image/artifact/Reader
selectors and actual archive/decode/provider/code descriptors remain NULL in
`binding.TEMPLATE.json` until Root supplies authenticated operands.

The frozen expected Source comes from wrapper successor
`979e81bee2560d3780e2b0868de1896affc64cae`: **248 files / 40788233 bytes**, map
`b462bebb24a5dcf18aaecb5843b75cba0f6c3f89b920c313263abff91f7e7e33`, Git tree
`b6d4f3bcbfb7454b1760c3ff9f9910d734d8bece`. `pins.json` binds the exact policy
and critical source descriptors. The Source's `hosted/reader.py` was inspected as
code/data; it is neither imported nor invoked by this driver. The bounded tar
framing approach is adapted from that MIT-licensed implementation. Acceptance,
Source replay, ELF, package, ownership and retirement checks are independently
implemented. The driver uses standard-library Python 3.14+ only, without child
processes, Git commands, network clients, daemon access or source-code imports.

## Future Root operands

Root must authenticate the complete original provider artifact ZIP and raw
provider observations independently, then select this exact Reader code and
pins by SHA256 in a fresh external binding. Passing a status string or a local
binding's self-computed hash is not Root authentication. The binding's whole
SHA256 is an external operand; the driver does not create authority or discover
selectors. It consumes:

- The exact published Source as ordinary DATA, plus raw commit-object bytes.
  The commit object's Git SHA1 must equal the actual Source selector and name the
  expected tree. Every file's bytes/mode and Git blob are replayed; the complete
  tree, nested Original dependency map and hosted source-readback rows must join.
- The complete original artifact ZIP, with its externally authenticated whole
  byte count/SHA256 and artifact ID. No selective download/extraction or decoded
  summaries substitute for it. Every member is decoded, CRC-checked to EOF and
  hashed; symlinks/devices, duplicates, traversal and encryption refuse.
- A Root-pinned `provider.json` object containing raw `run`, `job`, `artifact`
  provider records. The run/job must be completed/successful, first-attempt manual
  dispatch on the exact Source/ref in `Gabriel-Kahen/cachy-asahi`. Artifact ID,
  name, expiration and workflow-run Source/run must join the same binding.
- Exact Root admission bytes: SHA256 equals `actual.approval`, scope/status,
  authority, Source/ref/map, holds and complete resource policy must match.
- Root-pinned full Original decode descriptor: `files`, total regular-file
  `bytes`, and SHA256 of canonical sorted/indented JSON plus final newline whose
  rows are `{relative_name: {"bytes": N, "sha256": H}}`. Directory entries do not
  count. This driver independently replays that complete descriptor. Decoded
  files are stored as nonexecutable DATA with mode 0400.
- Whole export and whole final package SHA256, bound independently by Root.
  Code and pins SHA256 are also mandatory; `actual.reader` identifies Root's
  selected Reader revision/role. All these actual operands are NULL here.

The operational entry is `reader.py`; its argument definitions are in `main()`.
No operational command was run during preparation. Root must provide an owned,
private existing output parent and a fresh absent output directory, outside the
Source tree. The proposal requires 20 GiB free DATA space / 10000 free inodes,
uses a 256 MiB address-space cap and 1800-second wall budget, and streams files
with bounded metadata. Package DATA requires Python 3.14 stdlib zstd; there is no
external decoder fallback. A shortfall or parse failure refuses, leaving no PASS
report. These are proposed Reader budgets, not measured actual-run sufficiency.

## Checks beyond the embedded reader

The independent reader binds the completed provider tuple, Root admission,
Source Git commit/tree, complete Original ZIP decode and frozen policy before
acceptance. It then checks the actual native **AArch64 / 4096-byte-page**
Rootful unremapped container domain: alarm UID/GID 1001, cap0, NoNewPrivs,
observed seccomp, process/init lineage and namespace/map continuity, read-only
root/inputs/source, writable work, safe fixed tmpfs, loopback-only interfaces,
8 GiB/no-swap/2 CPU/512-PID resource observations and matching Docker inspect.
The prior bubblewrap path remains uninvoked/unqualified.

Every required build, ownership and metadata command must have exact argv,
bounded duration, whole log hashes, natural direct exit, a held leader through
group inspection, final direct reap, no ownership loss and no forced cleanup.
CMake caches must agree with native GCC first-stage / private Clang runtime
stage, private prefix/lib and 16K linker flags. The ordinary makepkg invocation,
complete349 inventory, actual bootstrap tools/ALPM owners, signed257 payload
observations, exact original248+fixed8 input derivation, bootstrap proof/image
ownership and package BUILDINFO must agree.

The package is independently streamed as DATA. Every ELF is inspected directly:
LE AArch64, executable/shared PT_LOAD geometry suitable for 16K mapping,
contained private RPATH and matching package-owned LLVM SONAME dependencies.
Native ET_REL objects are allowed as relocatable DATA; mandatory tool paths must
still resolve to executable/DSO ELFs. Every symlink resolves without cycles or
escape. All payload paths stay within the fixed private prefix, with no global
providers/replacements/hooks. Complete archive ownership/modes/hashes must match
packaged provenance and the independently replayed checked-stage inventory;
only exact package metadata and eight pinned notice/provenance files may be
added after the checked stage. Static checks do not execute package code.

Natural finished actor/export status and all raw hosted-command retirements are
required. Exact owned container, volume and image removal/absence observations
are checked against their raw pinned stdout/stderr. Summary absence flags alone
are insufficient. Incomplete, OOM-killed, failed or forced observations refuse.
A final report would claim **Root-bound DATA parity only**, with
`native_acceptance=false`; it cannot establish independent-machine execution,
native16K behavior, M2 compatibility, signed installation/removal,
reproducibility, performance or release. All original4/source108 and existing
license/source/release holds remain unchanged.

## Fenced fixture controls and actual status

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover \
  -s scripts/port/llvm23-native-independent-reader -p 'test_*.py'
```

Tests call small helpers on explicitly synthetic ZIP/tar/package/ELF, Git-tree,
process and retirement fixtures. They never call Reader `main()`/`replay()`, use
actual Source/artifacts as Reader input, or produce an operational verdict.
Default NULL-binding refusal, whole decode drift, malformed JSON/FIFO/link
refusal, full Git-tree/readback shape, cap/page/mount tampering, forced retirement,
ELF architecture/alignment/RPATH/SONAME, native relocatables, symlink cycles and
private package ownership are covered. `validation.json` records actual checks.
There was no acquisition, daemon call, lease, actor, compiler, package execution,
operational Reader invocation, publication or dispatch.
