# Actual native setup4 scoped footprint: run38791777707

The optional footprint stage passed on the actual generic ARM587-package
composition with setup0.1.0-4 and updater4.4.2-2. It measured a scoped filesystem
copy; the result explicitly remains `whole_root_copy=false`, `copy_complete=false`
and `eligible=false`. Setup4's existing lifecycle completed afterward, restoring
setup0.1.0-3 while keeping updater4.4.2-2. Scoped cleanup passed. This does not
establish an immutable full-root update, auxiliary success or Apple hardware
acceptance.

## Retained evidence and source identity

[Run38791777707](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38791777707)
used the hosted `ubuntu-24.04-arm` runner. Product/caller source:
`ec014db3cc599793f1df5284a4dbcbd96305e0a6`; workflow:
`b8babebd4228d8c1b683bed54b8e9c96bd83809e`, on
`codex/full-composition-setup4-footprint-v1`. The retained provider checkout log
confirms the exact product commit. Workflow identity is the coordinator's frozen
identity; its local Git object was inspected with no remote query.

Root collected terminal [logs.zip](../../artifacts/development/full-composition-footprint-run38791777707/logs.zip) once. This review used only that ZIP
and local frozen Git objects: no network retrieval, recollection, dispatch,
rebuild, container/package/target execution or auxiliary-policy change.

- ZIP SHA256: `d327aaf991fe28f79458a77f0dd5bc661c9624b59720f6ef08cbed11baa344cb`;
  ZIP CRC check passed.
- Decoded exactly one `public` evidence block from
  `native/18_Retain bounded development composition metadata.txt`, lines19–3540.
  Compressed bytes200640, SHA256
  `7b21db80d879d99e25b0edeef41b85e8f5ca58395260eb4f3a2aaacbaced80e6`.
  Hash and byte count match the logged marker. All76 members are regular contained
  public files, totaling1,635,915 uncompressed bytes.
- The retained compressed public bundle is [public-evidence.tar.gz](../../artifacts/development/full-composition-footprint-run38791777707/public-evidence.tar.gz).
  Only the result, coordinator, footprint, package metadata and transaction log
  were materialized. [decoded-evidence.json](../../artifacts/development/full-composition-footprint-run38791777707/decoded-evidence.json) records actual
  marker lines and members; use that record if line wrapping changes.
- [result.json](../../artifacts/development/full-composition-footprint-run38791777707/public/result.json), [coordinator.json](../../artifacts/development/full-composition-footprint-run38791777707/public/coordinator.json),
  [setup4-footprint.json](../../artifacts/development/full-composition-footprint-run38791777707/public/setup4-footprint.json) and
  [transaction.log](../../artifacts/development/full-composition-footprint-run38791777707/public/transaction.log) are the selected original public bytes.
  Footprint JSON SHA256:
  `67312da336278aba118dca3cb0b373f894101a4b4d30892d25f64e42b6a7c56c`.
- The workflow hash-bound retained setup4 pair at69776 bytes, SHA256
  `1637452a84733fdf059d7dbc10c5b6dddd11c589c4f97ebb6a4655aedd12359f`,
  and checked64 regular build-1/build-2 members before extraction. This stage did
  not rebuild setup4 or fetch another run's logs.

The five helper/import files match the frozen adopted pins recorded in
[frozen-source-hashes.json](../../artifacts/development/full-composition-footprint-run38791777707/frozen-source-hashes.json). The result's sources name
the original ten-recipe source `a58fca33c4db5f2ab3ea6111f4d7842a932cc336`,
updater compiler `1aea667aec50a62ba0ab2dad44be24a4dc3bd098`, desktop builder
`8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2`, setup4 source
`98fecf28a3cde63a9dd7531501c2187825349310`, and updater-v2 source
`480053c0866a922138d85af2b9880fb0e10d7b2c`. These component identities differ
from the composition caller's product commit and the workflow commit.

## Checkpoints and source preservation

| Stage | Setup version | Updater version | Packages | Exact lock SHA256 |
| --- | --- | --- | ---: | --- |
| Initial checkpoint |0.1.0-3|4.4.2-2|587|`2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7`|
| Measured setup4 state |0.1.0-4|4.4.2-2|587|`dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac`|
| After explicit removal |absent|4.4.2-2|586|checked derived inventory|
| Reinstalled setup4 |0.1.0-4|4.4.2-2|587|same measured lock|
| Restored checkpoint |0.1.0-3|4.4.2-2|587|same initial lock|

Frozen lock contents confirm glibc2.43+r22+g8362e8ce10b2-2,
pacman7.1.0.r9.g54d9411-2 and linux-aarch64 7.2.10-1. Those generic package
identities do not establish an Asahi platform set.

The hook ran after the first setup4 installed dependency/payload checks and before
user/enrollment fixtures. Actual pacman-Q before/after and independently parsed
copied DB identities matched the measured587 lock. The wrapper also recorded
source `/var/lib/pacman/local` before/after equality:11,734,138 regular-file bytes,
2377 nodes, content/type/mode/UID/GID/link-record digest
`ab6ab91d2347f12432497d72aad843e9aba6cfff3acf09270963d06958edf786`.
Both `source_inventory_preserved` and `source_database_preserved` are true.

`source_root_mount_readonly=false`: the source was mutable. Preservation here
means per-file identity checks plus these stable source/copy inventory and DB
observations, not an atomic filesystem snapshot. Copy metadata includes content,
modes, UID/GID, symlinks and internal hardlinks; xattrs/timestamps are omitted.

## Actual measured scoped copy

Logical bytes count each regular-file directory entry, including hardlink names.
Allocated bytes below deduplicate regular-file inodes; they are filesystem
allocation observations, not a distribution image size or performance metric.

| Observation | Actual |
| --- | ---: |
| Scoped source entries visited after exclusions |124743|
| Copied/observed entries |124739|
| Regular-file logical bytes |4,927,246,493 (4.589GiB)|
| Allocated regular-file bytes, unique inodes |5,133,045,760 (4.781GiB)|
| Allocated bytes counting each directory entry |5,185,847,296|
| Largest regular file |173,387,392 bytes (165.355MiB)|
| Symlinks |14006|
| Hardlink entries / unique hardlinked inodes |2896 /1048|
| Sum of declared link counts for those inodes |2896|
| Broader copied `var/lib/pacman/` regular-file bytes / files |21,549,387 /1794|
| Free destination bytes at observation |76,125,491,200 (70.897GiB)|
| Free destination inodes at observation |18359932, known via statvfs|

The broader pacman-prefix bytes/files are not the same scope as the separate
source local-DB digest. The latter also counts directories as nodes.

The copy excluded16 runtime/mounted entries: dev, proc, run, sys, tmp;
etc/hostname, etc/hosts, etc/resolv.conf; inputs, out, measurement,
measurement-source; and the mounted footprint.py, lifecycle.py, runner.py and
setup4.py. Four special nodes were skipped. Thus both omissions and exclusions
remain visible; this is not a complete root clone.

## Finite budget and worker outcome

The selected data ceilings were8GiB logical bytes,500000 nodes,1GiB per file,
900 seconds for copy+observation, depth128 and64 unsupported examples. Actual
bytes were57.36% of the logical ceiling, nodes24.95% and largest file16.15% of
its ceiling. Capacity checking reserved10,654,711,808 future bytes and501024
inodes before copy allocation. The worker passed that check without an injected
inode fallback. Reported free capacity above is the later observation, not a
separately retained pre-copy free-capacity sample.

The exact-nonce local Docker volume and selected rw ext4/xfs/btrfs mount guard
passed; the exact filesystem type and volume name were not exported in the
public report. The private root-owned0700 workspace and read-only staged helper
source guards passed. Optional FSETID was confined to this measured caller.

Worker returncode0, termination `none`, phase `completed`, error_category `none`.
Supervisor ceiling960 seconds and1MiB combined captured output,2MiB public JSON
ceiling, and measured-container ceiling2400 seconds remained selected. These are
limits successfully avoided, not elapsed-time measurements. No per-copy duration,
throughput, benchmark or baseline comparison was retained; make no speed claim.

## Unsupported shapes and auxiliary boundary

Observation completed (`observation_complete=true`, footprint complete=true), but
unsupported observations keep `eligible=false`:

| Kind | Count | Detail retained |
| --- | ---: | --- |
| Hardlink observations |2896|64 bounded examples, all this category|
| Absolute-symlink observations |87|count only in the bounded public sample|
| Auxiliary-path observations |3|count; source checks three ldconfig spellings|
| Skipped special source nodes |4|count only; paths/types not retained|

The hardlink examples start with `usr/include/et/com_err.h` and
`usr/include/com_err.h`, followed by terminfo names such as
`usr/share/terminfo/l/la120` and `usr/share/terminfo/n/nsterm-256color`.
All64 sample slots were consumed by hardlinks. This is a bounded, unbalanced
sample, not a full unsupported-path inventory. It does not retain the87 absolute
link paths/targets, complete hardlink group membership/content, or the four
special-node paths/types.

Frozen observation code tests `usr/bin/ldconfig`, `usr/sbin/ldconfig` and
`sbin/ldconfig`; count3 is for path spellings/resolutions and does not mean three
independent binaries or executions. No executable/config/library identity/write
closure is exported by that count. The existing source audit still lacks the
assembled effective ld.so.conf includes, scan/hwcaps directories, relevant alias
targets, cache/temp-parent state and permitted SONAME/cache write changes.
The old574 archive declarations cannot fill that gap. No auxiliary-enabled
scaled update or separately supervised/accepted ldconfig result follows from this
measurement. Existing composition pacman success also cannot establish its
internal ldconfig success, because the audited libalpm callers ignore that status.

## Setup4 lifecycle and scoped cleanup truth

Composition result and nested coordinator composition agree byte-for-data.
Dependency checks passed with no waivers; payload ownership, installed FDK provider
load and native pyalpm import passed. Hooks were masked and package scriptlets
disabled. The installed setup4 trial reports all seven named checks passed:
read-only preview, repeated activation idempotency, edited-copy and existing-prefix
preservation, removal preserving user files, reinstall preserving user files,
and setup3 restoration preserving user files.

Installed TEST repository enrollment passed preview, apply, repeat and two disable
calls, with the original pacman.conf bytes and ALARM fingerprint preserved.
No repository network request occurred. Disable intentionally retained imported
TEST public trust in this disposable root; it did not claim to delete that trust.
The final exact587 checkpoint matches setup3+updater2, not the measured setup4
state. This is package/config lifecycle evidence in a disposable generic ARM
container, not target OS rollback, boot recovery or production enrollment.

Coordinator cleanup statusPASS, failures[] and footprint_volume_cleanup
PASS-absence-verified. Frozen cleanup removes/checks the owned container before
exact-name/label/local-identity volume removal and absence checking. It then
checks removal of selected newly created images, preserves the borrowed core
image, stops owned GPG agents and removes private trial files before saving its
PASS coordinator record. This establishes the script's scoped cleanup result;
it is not a global Docker/prune/host audit or a host-crash recovery guarantee.

Application sessions, Bluetooth transport, physical Apple stack/audio, M2/16KiB,
boot/suspend/recovery, production enrollment, immutable scaled update, release
acceptance and performance gains remain NOT RUN / NOT ESTABLISHED. No code or
new execution proposal is added by this retained-result review.
