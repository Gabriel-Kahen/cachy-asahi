# Local disposable payload transaction

This is the initial implementation of the missing payload operation identified
in the [installation gap review](../reviews/complete-install-software-gap-review.md).
It accepts synthetic signed packages and uses actual libalpm preparation and
commit in a private copied root. It is not a supported installation command,
an ARM transaction, a first-boot result, or M8 acceptance.

## Scope and invocation

The worker is `scripts/install/local_transaction.py`; the fixtures are
`scripts/install/test_local_transaction.py`. Original code is MIT-licensed.
Run as an ordinary Linux user on the observed x86_64 test host, with Python,
GnuPG, util-linux `unshare`, and the exact libalpm binary below available.
User, mount, PID and network namespaces and recursive read-only mount support
are mandatory; an unavailable prerequisite is a refusal.

```sh
python3 -I -B scripts/install/local_transaction.py \
  --worker-source-sha256 REVIEWED_WORKER_SHA256 \
  --contract /absolute/private-work/contract.json \
  --contract-sha256 CONTRACT_SHA256 \
  --output /absolute/private-work/evidence \
  --allow-disposable-payload-commit
```

`workspace` must be an existing, caller-owned directory with mode `0700`, with
no symlink ancestors. Its optional `system` directory supplies the inert seed;
otherwise the worker creates an empty seed. The output must be the fresh,
absent `workspace/evidence` path. The original seed is not the transaction root.
Keep the contract and inputs outside that output. Existing output is refused;
use a fresh workspace for another attempt.

The worker-source pin is supplied independently by the reviewed caller; it is
not an embedded digest of this script or authority derived by hashing whatever
currently occupies its path. The Python API requires the same
`worker_source_sha256` keyword. A missing or mismatched pin must refuse output
creation and child launch. The correction below is being source-tested before
another actual transaction is authorized.

The exact JSON contract has these fields, with no additional fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `scope` | `synthetic-fixture` |
| `workspace` | Absolute private directory |
| `architecture` | `x86_64`; package architecture may be `any` or `x86_64` |
| `before`, `after`, `protected`, `remove` | Complete name/version maps, with explicit removal identities |
| `add` | Name/version rows with `archive`, `signature`, and uppercase primary signing fingerprint `signer` |
| `keyring` | Public-only test certificate file reference |
| `timeout_seconds` | Integer from `1` through `1200` |
| `libalpm_sha256` | `da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888` |

Every file reference has exactly `path`, `size`, and lowercase SHA-256 `sha256`.
Input files must be regular, independently owned inodes without group/other
write permission; links and changed bytes are refused. Each input is at most
8 MiB and combined input bytes at most 32 MiB. Package maps contain at most
128 identities; filesystem/archive traversals have finite node and decoded-byte
bounds. Only gzip/xz fixture archives are accepted; the complete decompressed
tar stream, including headers and control files, is bounded before parsing.
The copied tree ceiling is 128 MiB. These are fixture limits, not a
capacity claim for the complete release.

`after` must equal the full declared add/remove result. Each protected package
must retain its exact version and cannot be added or removed. Test fingerprint
trust is local to the temporary GnuPG home; it establishes no production trust
or signing-key custody. The worker requires a valid SHA-2 detached signature
bound to the declared primary certificate, allowing a bound signing subkey.
`real-candidate` scope and any `--selection-sha256` are refused in this version.

## Operation and evidence

The parent first captures externally pinned worker bytes and the fixed runtime
bytes. Kernel-sealed memory files prevent write, growth, shrink and further seal
changes. The launchers verify their descriptor identities, seals, hashes and
the bound engine specification, then compile the same captured buffers; source
paths and adjacent bytecode caches are not execution inputs. The supervisor
runtime remains `8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`.
The parent captures package input bytes and the seed and supervises its owned
child. The child verifies its
namespace identities, mapping and PID, makes inherited mounts private and
read-only, and mounts a new temporary workspace. It exposes only the fixed
owned evidence directory for persistent output. Device access is restricted to
the standard null, zero, random and urandom nodes. Inputs are independently
copied and checked inside the namespace before use. No network namespace is
shared with the host. A native x86 syscall filter blocks outgoing socket IPC and
the io_uring APIs; GnuPG is invoked without agent autostart. Namespace privilege
is reduced after the required mounts so transaction code cannot undo the barrier.

The observed engine is `/usr/lib/libalpm.so.16.0.1`, version `16.0.1`, with the
SHA-256 above. The host reports CachyOS pacman `7.1.0.r9.g54d9411-4`, licensed
GPL-2.0-or-later; this identifies the observed local binary, not an audited ARM
build. The validation host used Python `3.14.7`, GnuPG `2.4.9` / libgcrypt
`1.12.4`, and util-linux `2.42.4`. Its database, GnuPG directory and log paths belong to the copied
root/workspace. The worker checks the actual complete starting inventory,
loads authenticated local packages, prepares the real transaction, and requires
the exact prepared add/remove maps before commit. Dependency, conflict and
database-lock checks remain enabled. The only suppression flags are `NOHOOKS`
and `NOSCRIPTLET`; unaudited `ldconfig` paths and aliases are refused. Libalpm's
[transaction API](https://man.archlinux.org/man/libalpm_trans.3.en) defines these
flags; hook behavior is documented in [alpm-hooks](https://man.archlinux.org/man/alpm-hooks.5).

After commit, the worker reopens the database, compares the complete installed
inventory, checks added payload bytes/types/modes/ownership/link targets and
package ownership lists, and compares protected package files. Persistent
evidence consists of the result, bounded logs, a copied system snapshot and
`installed-packages.lock`. The child publishes only a provisional result and
candidate lock. The parent independently checks the bounded exported tree,
package database, inventory, ownership, payload and protected files before final
publication. Accept only the final `PASS-disposable-payload-transaction` result,
CLI exit status `0`, and its verified installed lock together; a lock by itself
is not acceptance.
A failure may retain diagnostic
snapshot data; the authoritative result stays failed and no accepted lock is
retained. Discard a failed attempt; this worker does not recover a live system.

The parent supervises the child process group with a finite deadline and
cleanup. This matters because Python signal handlers can be delayed during a
long C call, as documented by [Python](https://docs.python.org/3/library/signal.html#execution-of-python-signal-handlers).

## Historical validation and current correction

The preceding worker was `5ef418929ddbe6e387626ac824f292197fb59a73950ef9b0983e4e9e4af7ee53`;
its test source was `9ace5f83d84fe37c5fce57563854e7fef8440ea01a8bb80e2d92430fe169ccb8`.
The author source review passed, followed by **38 checks with zero failures,
errors or skips** in the [finite-suite receipt](../../artifacts/install-local-transaction-20261012/tests/finite-suite-01.json).

| Evidence | Count and actual scope |
| --- | --- |
| Models | 19: contract/plan/inventory/link/keyring checks, mocked export corruption, deadline and late cancellation |
| Synthetic worker pipeline | 17 cases / 22 worker calls: 10 accepted commits, 9 expected FAIL and 3 expected REFUSED |
| Actual barrier | 1: outside writes `EROFS`, unchanged sentinel/host namespaces, guest file absent after exit, fixed evidence persisted; observed capabilities and IPC denials |
| Actual process timeout | 1: owned child started, deadline fired, child was reaped |

Eleven pipeline calls entered libalpm commit; ten committed successfully and
one was the expected file conflict. Successful cases cover a signed dependency
pair, a signature made by a bound subkey, upgrade with changed payload, removal
to an empty inventory, and an unrelated addition preserving protected versions
and files. Missing dependencies fail at actual prepare; foreign file conflicts
fail at actual commit. Signature, secret-certificate, escaping path, hardlink,
wrong starting inventory, protected upgrade/removal and declared-map failures
retain their distinct refusal/failure phases. Prepared-plan and post-install
inventory mismatch injection, export corruption and late cancellation are
**modeled**, not real package-manager fault injections.

The first tiny trial failed before libalpm/commit because the keyring guard
rejected ordinary GnuPG trust metadata. Its [failure receipt](../../artifacts/install-local-transaction-20261012/tests/first-signed-pair.json)
is preserved. The corrected guard rejects secret records/material, and the
[retry](../../artifacts/install-local-transaction-20261012/tests/signed-pair-retry-01.json)
and finite suite passed. The process-timeout case did not interrupt an actual
libalpm C commit; it verifies the reused supervisor with a real sleeping child.

Reproduce the test cases with:

```sh
python3 -I -B scripts/install/test_local_transaction.py
```

Historical tests generated fresh TEST keys in temporary homes and retained owned evidence
under `artifacts/install-local-transaction-20261012/tests/`. Corrected runs use
`artifacts/install-local-transaction-correction-20261012/tests/`; old receipts
remain unchanged. Tests never use the
host trust store or package database for a transaction. No ARM, full 624-package
transaction, M2 hardware, hook/scriptlet execution, first boot or production
installation acceptance has been established by this worker.

An [independent review](../reviews/local-install-transaction-root-review.md)
subsequently found two binding gaps: actual child launch reopened the worker
pathname without an enforced reviewed source pin; promotion and failure cleanup
could follow an output-directory replacement and leave renamed original PASS
authority behind. Its latter reproducer was modeled; the preceding cooperative
transaction results remain historical evidence, not proof that those gaps were
closed. The bounded correction captures externally pinned source bytes, binds
the worker/runtime pins into the child specification, and retains the original
evidence directory descriptor and identity through promotion and revocation.
Inherited `HOME` is preserved; GnuPG and temporary paths are explicit and private.
GnuPG uses the private homedir, `GNUPGHOME`, and `--no-options`; preserving
`HOME` does not authorize use of host trust or configuration.

The parent holds the original evidence directory and authoritative result/lock
file descriptors and identities. The child binds that directory, closes the raw
old-mount descriptor, reopens only the guest mount, and adopts the same initial
result/candidate inodes. It updates those provisional nodes in place. Parent
promotion records pending new inodes before atomic replacement and retains
retired authority through completion. Checked access requires caller ownership,
regular single-link files, mode `0600`, and matching device/inode identities.
Failure invalidates retained original, pending and retired authority through
their descriptors. Cleanup checks names against owned identities before unlink;
detected foreign names are preserved. The CLI retains custody through publication
checks, printing and failure fallback. Descriptor revocation can invalidate an
original inode after its pathname changes; CLI exit alone cannot repair stale
authority. These checks do not mechanically close POSIX check-to-rename or
check-to-unlink races against a concurrent directory writer.

The first correction was held at worker
`c3175e48de81942520d5a4ac63113fb5674c6232c8b78ffb4d3221b561aac1ca`
and tests
`74ef9e28e5cc8f86308f200934f207abe4d0fc36d15d5ba52352a287ccd948b8`.
[Thirty-five permitted controls](../../artifacts/install-local-transaction-correction-20261012/tests/models-source-controls-03.json)
passed with zero failures, errors or skips: **28 modeled controls and seven
harmless executable-source fixtures**. These cover missing/wrong external pins,
worker/runtime/spec binding, sealed-buffer mutation refusal, ignored source/PYC
replacement, preserved `HOME` value/absence, directory replacement, retained
node aliases, post-replacement publication failure and CLI revocation. Package
completion and failure are mocked; loader fixtures execute only owned marker
programs. No new namespace, package-manager or supervisor trial ran.

The first correction's source preflight command was:

```sh
python3 -I -B scripts/install/test_local_transaction.py \
  ContractTests ParentModelTests SourceLoaderTests
```

Its [focused peer review](../reviews/local-install-transaction-correction-root-review.md)
found two remaining defects: `KeyboardInterrupt` during final printing/disposal
could leave original PASS authority, and a foreign result inserted during staged
fsync could be replaced without a second identity check. The immutable first
correction checkpoint remains
`bc0af5408c081506257345c0afa408ad81834dd57458d7b092469286bdbc7d25`;
its 35-control receipt does not validate this follow-up.

The first narrow follow-up was held at worker
`55e7fa30c99731e242a531e83da94e583f94e9acffb70d875c96e7390ca5581a`
and tests
`80ee47f4c1675d42c61e9e773c5e2897055b1aece8851cfd24cdab66cc1ec48a`.
The CLI catches terminal `BaseException` before disposal. Disposal duplicates a
bounded custody loan before closing original descriptors under the unchanged
runtime's signal deferral, keeps the loan through handler restoration, and
revokes through it if close or restoration is interrupted. `Evidence.close()`
tracks partially closed descriptors. Callable `main()` retains one bounded loan
until caller disposal, the next invocation or process teardown; it does not
promise revocation after the final custody descriptor closes.

Writes now recheck the original destination after staged write/flush/fsync and
before replacement, refusing a detected foreign inode. Absent or untracked
destinations, including missing-result revocation fallback, use exclusive create.
This closes the deterministic staging and absent-create insertion controls;
POSIX replacement still has a residual identity-check-to-rename race. No atomic
compare-and-replace guarantee is claimed against an active concurrent writer.

[Thirty-two inert models](../../artifacts/install-local-transaction-correction-20261012/followup-01/tests/inert-models-01.json)
passed with zero failures, errors or skips and zero subprocess calls. They retain
the 28 modeled controls and add final-print interruption, final-close
interruption, staged-fsync foreign insertion and exclusive absent-result
insertion. Signing bytes in this run were structural inert fixtures; no GnuPG
invocation or authentication occurred. Seven executable-source fixtures are
**NOT RUN at this follow-up hold**. This run substituted inert signing fixtures
before selecting the contract and parent-model classes and blocked subprocess
entry points. Directly selecting those classes from the ordinary test CLI still
uses its GnuPG fixture setup; it is not the zero-subprocess procedure recorded
in this follow-up receipt.

The fresh [follow-up checkpoint](../../artifacts/install-local-transaction-correction-20261012/followup-01/checkpoint.json)
binds exact source, guide, model receipt and historical baseline hashes. No new
namespace, package-manager or supervisor trial ran. Focused peer acceptance of
that held source was still pending when the next review found the terminal gaps
below.

The [final-custody review](../reviews/local-install-transaction-final-custody-root-review.md)
subsequently reproduced default SIGTERM during printing and a buffered stdout
failure after `main()` returned zero. Both left modeled original PASS/lock
authority. Those harmless peer children were source/model processes, not
package transactions; their evidence and the first follow-up checkpoint
`bd84876ea8bc245b8915498b68b769ab0a71e9321fb23cbd1ca7cbadfdfdffe9`
remain unchanged.

The second terminal correction was held at worker
`09b340b57bc7d7b9671c9b9d521462b6486b2f6f14aebf78979eef1c0be1284d`
and tests
`312c3982085264668a3b93e0dd3c32a44877a68b19fe0214ba3e20a1e9086290`.
Direct `execute()` promotion now remains inside a custody guard. The guard uses
the unchanged pinned runtime's outer signal deferral around cancellation
handlers, then checks result/lock identity while that outer deferral is still
installed. Errors revoke retained authority before leaving the guard; signals
queued during its final restoration are routed to failure with custody held.
No substantive filesystem validation runs after the final guard restoration.

The CLI guard covers execution, success publication, final checks, disposal and
restoration. Terminal publication uses `print(..., flush=True)` and an explicit
stdout flush inside the failure/cancellation scope. A flush error revokes before
successful return; failure publication also installs cancellation handlers.
The bounded loan survives disposal and restoration, so queued soft signals can
invalidate the original receipt/locks. Keeping this loan does not keep signal
handlers installed after callable `main()` returns. Recovery is not promised
across arbitrary later caller actions, process teardown, uncatchable termination
or after the last custody descriptor closes. The residual POSIX check-to-rename
and check-to-unlink races described above remain.

[Thirty-eight inert models](../../artifacts/install-local-transaction-correction-20261012/followup-02/tests/inert-models-02.json)
passed with zero failures, errors or skips: the previous 32 plus six controls for
direct promotion SIGTERM handling, terminal publication SIGTERM handling,
explicit flush failure, disposal cancellation, inner restoration and final
deferral restoration. Installed signal handlers were invoked directly; pending
signals were modeled through `sigpending`/`sigwait`. Process entry points and
`kill`/`killpg` were blocked and uncalled. The exact runner was retained before
execution. No GnuPG invocation/authentication, executable loader fixture,
namespace, libalpm/package, supervision, real termination or pipe-failure child
ran in this author follow-up. Seven loader fixtures remain NOT RUN here.

The [second follow-up checkpoint](../../artifacts/install-local-transaction-correction-20261012/followup-02/checkpoint.json)
binds the final sources, guide, runner, 38-model receipt and preserved baseline.
That source remained held for independent terminal-publication peer review before
any new actual transaction actor. Historical passes do not validate revised source.

The [terminal-publication peer](../reviews/local-install-transaction-terminal-publication-root-review.md)
closed the SIGTERM/flush findings using harmless old/new children, but reproduced
a capsule-disposal gap: an interruption after the first sealed source descriptor
closed left a runtime capsule and direct-call PASS/lock authority. The old
post-guard `finally` loop did not retain remaining capsule ownership or enter the
earlier revocation handler. The peer receipt `c00f7152…`, its real harmless-child
proof and the `496852f3…` checkpoint remain unchanged; they are not current-source
transaction acceptance.

The third correction is held at worker
`cf8345f13ce6b44d516904b1ab01a76656200538277e36a55ecaab837ecdd088`
and tests
`83ce29af75f74734fcdff588cd67bf61364dd4fadef5aa8441e53d11de0dc5e4`.
Sealed source capsules now have at most two tracked leases, with provisional
ownership recorded before identity capture. Soft signals are deferred during
acquisition; up to three identity attempts either establish exact device/inode
custody or retain an explicitly unresolved lease. Source writing uses the tracked
descriptor directly, without an untracked temporary duplicate.

Capsule disposal runs inside the custody guard. It checks identities before
closing, tries at most three times per lease, and recognizes a close that took
effect before raising through subsequent descriptor checks. Remaining leases
are attempted despite `BaseException`. A detected reused foreign descriptor is
not closed. Any disposal fault still refuses success and revokes retained
receipt/lock authority. An earlier operation failure stays the first cause;
separate cleanup status records attempts, closed/changed leases and remaining
ownership. Persistent OS refusal or unresolved identity remains tracked and
blocks another `execute()` instead of accumulating source resources or
speculatively closing a possibly reused descriptor.

[Forty-one corrected inert models](../../artifacts/install-local-transaction-correction-20261012/followup-03/tests/inert-old-new-models-01.json)
passed with zero failures, errors or skips. Three added methods cover ten
disposal cases across direct `execute()` and callable `main()`: interruption
after actual close, modeled SIGTERM handling, one-shot close errors before/after
effect, and earlier export failure preservation. Corrected cases leave zero new
capsule descriptors and zero retained leases, restore handlers/masks, and retain
FAIL/no accepted lock authority. The old source's ten expected failing subcases
and observed leaks are recorded separately, then explicitly cleaned by their
fixture owner. Those red results are not relabeled as passing tests.

Eleven internal fully mocked source controls additionally pass for acquisition
bookkeeping, bounded persistent refusal, foreign descriptor reuse and first-cause
handling. A twelfth control retains the initially faulty acquisition prototype's
expected-red result. Persistent/unknown refusal cases intentionally retain
ownership; they are not leak-free integration cases. These source checks do not
replace the selected independent peer.
The exact integration runner was retained before execution. GnuPG, subprocess,
real signal delivery, namespace, libalpm/package, supervision, real children and
the seven executable loader fixtures were NOT RUN in this author correction.

The [third follow-up checkpoint](../../artifacts/install-local-transaction-correction-20261012/followup-03/checkpoint.json)
binds final source/test/guide bytes, corrected and red model evidence, internal
source review and preserved holds. Source remains frozen pending the same
independent peer before any actual actor. Bounded lease tracking does not promise
forceable cleanup under persistent OS errors, atomic behavior against an
uncooperative concurrent caller/writer, or revocation after all custody
descriptors close. Earlier cancellation, external-pin, HOME, sealed-loader and
POSIX race limits remain in force.

The original 17 pipeline cases, barrier and timeout tests are preserved, but
their reviewed pin is deliberately unset. They refuse before setup/probes.
The revised source must pass focused peer preflight before the coordinator
supplies a reviewed pin and authorizes another tiny actual transaction.
Historical 38-check results do not validate the corrected launch/custody path.
ARM and production policy are outside this correction.

The next production-capable step requires an adopted release selection, source
and distribution grants, authenticated package/key policy, an exact independently
verified baseline, ARM engine provenance, and reviewed first-boot/hook/service
behavior. The available 624-archive audit does not establish that the captured
installed image contains those payload bytes. The strict protected-Python
selection remains failed; an alternative package set has not been adopted.

The [Asahi installation route](../port/installation-route.md) retains Asahi's
Apple platform preparation and recovery boundaries. This payload worker makes
no APFS, ESP, firmware, bootloader, host package-database, service or physical
machine changes. Both M2 Air sizes still require the roadmap's integrated
installation, login, update and recovery evidence.
