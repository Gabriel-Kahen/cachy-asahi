# Actual shape run38807193872: scoped measurement, lifecycle and cleanup PASS

Retained evidence supports actual generic-ARM scoped measurement and setup4
lifecycle success, independently of the workflow SUCCESS label. The copy remains
incomplete/ineligible and no whole-root transaction, auxiliary permission, target
OS/M2 acceptance or performance gain is established.

## Evidence boundary and identity

Root collected `logs.zip` once. ZIP bytes3479032, SHA256
`c12530ed8b747fb610ecdb268cfc0d76816d416be338969b2b027c113a3b07d9`.
This review read only retained logs and local frozen Git sources; no fetch,
recollection, dispatch, package/native/container/target/network actor, Git mutation
or canonical edit. No original/package/source/binary evidence frame was decoded.

One public metadata block was decoded exactly once from
`native/18_Retain bounded development composition metadata.txt`, lines19–3547:
201016 compressed bytes, SHA256
`80846bb7d9a3d69149446ce00ea178720656174d5775ec7eab2339dc23b65bf6`.
Marker length/hash and selected ZIP member CRC pass. All76 members are contained
regular public files totaling1638571 file bytes; tar bytes1781760. Only six selected
metadata files were materialized. Existing export limits16MiB total files/8MiB compressed were retained; actual
1638571/201016 bytes remain below them. Other frame payloads were untouched. Saved
[public-evidence.tar.gz](../../artifacts/development/full-composition-footprint-run38807193872/review/public-evidence.tar.gz) and
[decoded-evidence.json](../../artifacts/development/full-composition-footprint-run38807193872/review/decoded-evidence.json) prevent a second decode.

Original selected bytes:[footprint](../../artifacts/development/full-composition-footprint-run38807193872/review/public/setup4-footprint.json),
[result](../../artifacts/development/full-composition-footprint-run38807193872/review/public/result.json),[coordinator](../../artifacts/development/full-composition-footprint-run38807193872/review/public/coordinator.json),
[transaction log](../../artifacts/development/full-composition-footprint-run38807193872/review/public/transaction.log),[packages](../../artifacts/development/full-composition-footprint-run38807193872/review/public/packages.json),
[retained setup4 summary](../../artifacts/development/full-composition-footprint-run38807193872/review/public/diagnostics/setup4-summary.json).
Footprint8778 bytes, SHA256
`9967d26fbcde8e4721b48d2b130e09574f487a8e851fe798b164605c838558c5`.
Selected hashes are retained in decoded-evidence.json.

Source `231667d06e11bb20a878ca1830dde6eb5b75c3aa`, workflow
`5ae4dbf3a839532bbe83206e1dab20fc85fd7f52`. Provider checkout log includes the exact
source SHA; frozen three-file source hashes and workflow SHA
`92e154a98ad178186909134f6d0025a8606ab0f9813bc481347d494ee6952978` match Root's
freeze. [source-audit.json](../../artifacts/development/full-composition-footprint-run38807193872/review/source-audit.json) records those checks and relevant
frozen owner code, not a new runtime permission object.

## Four observed specials: names and kinds complete

All four source skip samples are sockets, untruncated, with count4,
examples_complete=true, sample limit8 and path limit1024:

- `etc/pacman.d/gnupg/S.gpg-agent`
- `etc/pacman.d/gnupg/S.gpg-agent.browser`
- `etc/pacman.d/gnupg/S.gpg-agent.extra`
- `etc/pacman.d/gnupg/S.gpg-agent.ssh`

These are actual nofollow source observations in this run. None was copied,
opened as a stream or recreated. Socket PID, liveness, UID/GID and the particular
creator invocation were not exported. Names alone do not prove a live process.
These new observations do not identify the four unrecorded specials in old
run38791777707.

## Absolute-chain classes and bounded examples

All87 absolute-link observations are classified, absolute_classes_complete=true,
observation_complete=true. These are first-absolute-target prefix classes, not
final endpoint/dependency acceptance or proof that a runtime object was copied.

| Class | Actual count |
| --- | ---: |
| `usr-path` |44|
| `runtime-dev` |41|
| `runtime-proc` |1|
| `etc-path` |1|
| Total |87|

Absolute category examples are first8, all untruncated, each `target_class=usr-path`:

- `usr/share/X11/xkb`
- `usr/share/licenses/qt6-declarative`
- `usr/share/licenses/vim-runtime/license.txt`
- `usr/share/licenses/xz/COPYING.GPLv2`
- `usr/share/licenses/xz/COPYING`
- `usr/share/licenses/xz/COPYING.0BSD`
- `usr/share/licenses/systemd/MIT-0.txt`
- `usr/share/licenses/libmpdclient/BSD-2-Clause.txt`

examples_complete=false:these do not enumerate all87, the44 usr class members,
or the actual pathnames in the other three classes. No endpoint or raw link target
is retained. Existing global64 unsupported examples remain all hardlinks; shape
sampling now avoids their starvation of other categories.

Auxiliary paths are complete: `usr/bin/ldconfig`, `usr/sbin/ldconfig`,
`sbin/ldconfig`; all3 appear in the auxiliary category/examples_complete=true.
This establishes guard spellings, not their current inode/write closure or an
accepted auxiliary execution. Hardlinks2896 entries/1048 unique inodes/2896 sum
of declared counts; first8 hardlink examples are incomplete. Generic opt-in and
the pure resolver were not selected; default hardlink refusal remains.

## Scoped copy, preservation and budgets

| Observation | Actual |
| --- | ---: |
| Measured inventory |587, setup0.1.0-4/updater4.4.2-2|
| Source entries visited / copied nodes |124743 /124739|
| Logical regular bytes |4927246495 (4.589GiB)|
| Unique-inode allocated regular bytes |5133045760 (4.781GiB)|
| Allocated bytes counting each alias |5185847296|
| Largest file |173387392 bytes|
| Symlinks |14006|
| Pacman-prefix regular bytes/files |21549387 /1794|
| Source local-DB bytes/nodes |11734138 /2377|
| Post-copy free bytes/inodes |76125396992 /18359936, known statvfs|

Source local-DB before/after digest
`8e1ca471e279de32f9405792e6acc7a4c43df626bcad4873107d2c3036af9ab1`
matches the standalone footprint and nested result/coordinator summaries.
source_database_preserved=true and source_inventory_preserved=true. Actual and
copied exact587 lock is
`dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac`.
source_root_mount_readonly=false:checked per-file interval plus stable inventory/
local DB, not an immutable snapshot or exclusion of arbitrary writers.

Observation/footprint complete=true; copy_complete=false, eligible=false,
whole_root_copy=false, transaction_acceptance='NOT ESTABLISHED'. Source skipped
special count4 and default observation refusals hardlink2896/absolute87/auxiliary3
are explicit. Exclusions remain16:dev/proc/run/sys/tmp;etc/hostname/hosts/resolv.conf;
inputs/out/measurement/measurement-source;footprint.py/lifecycle.py/runner.py/setup4.py.
No omission or exclusion was silently admitted.

Held ceilings:8GiB logical,500000 nodes,1GiB/file,900s copy/observation, depth128,
64 original samples, shape8/category at1024 chars,4096 class work steps/40 links;
960s supervisor/1MiB combined capture,2MiB public JSON,2400s measured container;
workflow290min and composition180min. Before allocation demand10654711808 bytes
and501024 inodes remained mandatory, with unknown capacity refusal/no fallback.
Actual observation8778-byte public JSON is within its bound; worker returncode0,
termination none, phase completed, error_category none. These are successful limit
checks, not elapsed-time or throughput measurements. Precise preallocation free
sample and per-copy duration were not retained.

Existing mount/marker/isolation/signature guards passed:owned root0700 workspace,
readonly staged helpers, network-none disposable generic ARM container, dropped
capabilities plus existing FSETID preservation, exact-nonce local disk volume and
rw ext4/xfs/btrfs guard. Exact filesystem type/volume name were not public fields.
No new permission or generic internal-hardlink mode was activated.

## Lifecycle, enrollment and cleanup from actual metadata

result.json equals coordinator.composition. Both record PASS/completed,
PASS-no-waivers dependency checks, payload ownership PASS, native pyalpm import
and installed FDK load PASS, hooks MASKED and scriptlets DISABLED.

Initial/final setup3/updater2 checkpoint587 lock
`2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7`;
measured/reinstalled setup4/updater2 exact587 dbfe lock; explicit removal586;
setup3 restoration587. Retained setup4 pair MATCHED, source98fecf28..., package
SHA `c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a`;
new setup4 build NOT RUN. Root freeze binds the exact69776-byte/64-member pair.

All7 recorded checks pass:preview readonly, repeat idempotent, edited desktop copy
preserved, existing prefix preserved, user files preserved across removal,
reinstall and setup3 restoration. TEST-only enrollment preview/apply/repeat and
disable twice pass; original pacman.conf bytes and ALARM fingerprint preserved;
TEST public trust intentionally retained; repository network NOT USED. This is a
disposable generic fixture, not production enrollment or target rollback.

Coordinator cleanup PASS with failures[], exact footprint volume absence verified.
Frozen cleanup checks owned container absence before removing the exact
nonce/label/local volume; protects borrowed core image, removes selected newly
owned images, stops private TEST agents and removes private files before writing
coordinator metadata. No live daemon/resource query was performed by this review.
Current root-keyring socket liveness before cleanup was not separately measured.
No target installation/full updater transaction/hardware/app-session/Bluetooth/
release acceptance is claimed by these results.

## Comparison with old38791777707

[comparison.json](../../artifacts/development/full-composition-footprint-run38807193872/review/comparison.json) records same exact package identities/versions
and same14 initial project/addition archive hashes, same exclusions and unsupported counts,
same copied nodes/hardlinks/symlinks/largest file/allocated sizes/pacman-prefix totals.
Logical bytes increased2, from4927246493 to4927246495. The local-DB digest differs
between runs while its byte/node totals match; each run independently preserved
its own DB. No retained file-level evidence identifies the exact2-byte or digest
cause; do not claim bit-identical root state, elapsed-time comparison or gain.

New shape diagnostics fill the four current socket names/kinds and class-count
gap. They do not backfill old ephemeral names or all87 dependency chains. The
smallest next proposed correction is the owned keyring-agent lifecycle boundary
in [owner-scope-plan.md](../../artifacts/development/full-composition-footprint-run38807193872/review/owner-scope-plan.md), not another diagnostic bridge or an
eligibility waiver. That is source-only and has not been implemented or executed.
