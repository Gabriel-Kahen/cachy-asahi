# Disposable lifecycle peer review

Reviewed October 11, 2026. **Four actionable findings remain in the reviewed
runner: three P2 and one P3.** The 24 supplied portable tests pass. This is a
source review with mocked commands and temporary fixtures; it does not establish
successful native pacman transactions, signing trust, installed-image acceptance,
physical M2 support or performance. Only this review file was changed. No host
package, GPG trust, account, display, audio, device or container-install operation
was performed.

Scope: `scripts/integration/lifecycle.py`, its tests, original/derived fixture
contract generation, and the prospective installed-handoff adapter. A bounded
read-only subreview independently checked trust, isolation and process handling.
The integration coordinator retains implementation and final source-freeze
ownership; virtual GPU testing is outside this review.

## Findings requiring correction

### [P2] Nested and unexpected mounts bypass the isolation guard

`environment_guard()` (lines 118–125) checks the parent `/inputs`, `/runner` and
`/out` mount flags, then rejects mounts only beneath six system/home paths. It
does not reject a writable child beneath a read-only input/runner mount, an extra
output child, or arbitrary mounts beneath `/proc` and `/run`.

Starting with `test_lifecycle.probe()`, independently add each of these entries:

```python
probe["mounts"][path] = {"fs": "ext4", "options": ["rw"]}
environment_guard(probe)
```

Every tested `path` was accepted: `/inputs/baseline`, `/runner/lifecycle.py`,
`/out/lifecycle`, `/proc/self/status` and `/run/host-user.sock`. These are mocked
mount observations, not actual mounts. Parent read-only flags do not constrain
child mounts. The runner consequently cannot enforce its promised input/source
immutability or absence of exposed host runtime paths. A writable runner child
is especially relevant to the installed adapter's later subprocess invocation;
a substituted process-status mount can also undermine capability observations.

Reject all child mounts beneath the fixed input, runner and evidence roots,
regardless of read/write flags. Enumerate the legitimate Docker runtime mount
layout and reject unexpected mounts, including host socket paths, before input
reads or mutation. Add negative fixtures for both read-only and writable nested
mounts and for unexpected `/proc` and `/run` entries.

### [P2] Permitted/bounding capabilities and no-new-privileges are unchecked

`actual_environment()` (lines 97–108) records only `CapEff`.
`environment_guard()` (line 114) limits that set but neither observes nor limits
`CapPrm`, `CapBnd`, inheritable/ambient sets, or `NoNewPrivs`. The workstream's
proposed invocation requires `--security-opt=no-new-privileges` and a limited
capability set, but the runner does not verify that contract.

An otherwise valid probe with `CapPrm = CapBnd = 1 << 21` (SYS_ADMIN) and
`no_new_privileges = "0"` was accepted because those fields are ignored. This
fixture establishes the missing checks, not an executed privilege escalation.
An allowed effective set alone does not establish that a subprocess cannot
acquire broader privileges on execution.

Parse the actual process status, constrain all relevant capability sets to the
declared safe set, and require `NoNewPrivs=1`. Refuse absent/malformed observations
and add regressions for capabilities outside the effective set and NNP disabled.
The installed adapter imports this same guard and inherits the gap.

### [P2] Archive processing has no deadline or bounded child cleanup

`inspect_archive()` (lines 188–233) streams archive data and bounds individual
members to 8 MiB and aggregate declared file bytes to 32 MiB. It does not bound
member count, processing duration, decompressed stream bytes or decompressor
execution. Zero-size members and tar extension processing are not covered by
the declared-byte limit. The `finally` block reads stderr and calls `wait()` with
no timeout; it never terminates or kills the decompressor on parser failure.

A mocked zstd child emitting malformed tar bytes reproduced `ReadError`, then
`wait()` with no arguments and zero terminate/kill calls. No real decompressor
was launched. The unbounded stderr read/wait can prevent the original rejection
from becoming a completed FAIL receipt, and a cleanup exception can replace the
original parser error. The outer CI timeout is an emergency bound, not complete
runner evidence or child-cleanup handling.

Add deadlines, member/stream limits, bounded diagnostics and a dedicated process
group. Ensure cleanup terminates, then kills/reaps as needed, on every exit path
without replacing the original failure. Cover malformed input, stalled output,
many empty members, stderr saturation and timeout in safe fixtures.

### [P3] Command timeout loses evidence and leaves descendants unmanaged

`Lifecycle.command()` (lines 293–300) records its command receipt/log only after
`subprocess.run()` returns. A mocked `TimeoutExpired(..., output=b"fixture partial
stdout")` resulted in zero command receipts and no log, although partial output
was available. `capture_output=True` is also unbounded, and commands do not have
a new process group or explicit descendant cleanup.

On POSIX, `subprocess.run` kills and waits for its direct child on timeout; this
review does not claim that direct-child timeout is ineffective. It does not
provide the lifecycle's desired bounded descendant handling and retained failure
evidence. Write a receipt before execution, preserve bounded partial stdout/stderr
and timeout classification on failure, and terminate/reap the command group.
Test both direct failure and timed-out descendants with temporary/mock fixtures.

## Controls present in the source

| Area | Reviewed behavior | Acceptance limit |
| --- | --- | --- |
| Signed transaction | Pins archive and detached-signature bytes; pins a public certificate and sole primary fingerprint; verifies GPG status; dedicated nonce keyring; pacman requires local signatures | Real native GPG/pacman trust remains unexecuted by this reviewer |
| Transaction scope | Exactly four original and four changed upgrade packages; greater versions checked with vercmp; scoped data payloads; no links/special files/ELF/platform paths; scriptlets suppressed and base hook names masked | Actual signed archives and native transactions still need execution |
| Installed binding | Exact base-plus-overlay version inventory, complete package file lists, payload hashes, archive modes, root ownership and pacman Qk checks | Source checks and mock coverage do not demonstrate native installed results |
| User lifecycle | Installed helper under fresh/existing demoted users; read-only preview, repeat apply, existing prefixes/modes, external Fish/Zsh blocks, desktop copy/edit preservation, upgrade/remove/reinstall/deactivation and shell/base config preservation | Real fixture accounts and shell source behavior remain CI gates |
| Interruption | Actual installed helper code is instrumented to exit 75 immediately after a Fish atomic write; journal mode, read-only recovery preview and actual recovery are checked | This is a concrete planned interruption, not an executed native result here |
| Cleanup | Original account files/backups held in memory and restored with metadata/xattrs; fixture users/groups/homes/work/journals/keyring removed; original base keyring hashes checked | Successful-path cleanup is guarded; failed containers must be discarded by the controller |
| Original handoff | Required lifecycle gates must pass; upgrades removed; original versions and every original payload hash rechecked; original helper pin verified; successful cleanup precedes baseline_handoff_ready | A mocked successful finish is not an installed image |

The handoff adapter independently pins the contract and runner, requires the
lifecycle PASS/ready receipt with matching identity/version/payload maps, verifies
the actual inventory/payloads, removes signing and user/cache state, and verifies
the installed state again before its READY receipt. Its imported isolation guard
must be repaired before that receipt can support the stated boundary. This was
a prospective adapter source read, not a complete controller review or execution.

Raw account files and their hashes are not exported by the reviewed lifecycle
path; original base-keyring hashes remain internal. Helper journal contents and
user-home trees are not copied into public evidence. The prospective exporter
limits file/total sizes, refuses links and sensitive subtrees, and checks content
for private-key/credential patterns. This is defense in depth, not proof that an
arbitrary command's output can never contain a secret. Failure receipts remain
unready; this source does not promise complete in-container cleanup after every
failed lifecycle operation.

## Fixture and acceptance status

The fixture generator binds an accepted source commit and exact original recipe
file lock, creates separately labeled development upgrades with changed installed
payloads, preserves license/dependency/ownership metadata, retains recipe diffs
and original rollback expectations, and preserves the canonical original setup
helper pin. The lifecycle checks actual archive contents against the full contract
independently of those source expectations. The additional setup fixture input
is not an extra installed helper according to the reviewed recipe.

No generated, signed native original/derived archive set and completed lifecycle
contract was exercised in this review. Generator-to-contract reconciliation and
actual package/signature bytes therefore remain pending native integration.
Physical M2 checks remain **NOT RUN**. No graphics, boot, audio, suspend, device,
performance or M2 acceptance is implied by the portable tests or this review.

## Reproduction results and source identity

Both the immutable review snapshot and the later live source passed:

```text
python -m unittest discover -s scripts/integration -p test_lifecycle.py -v
Ran 24 tests; OK
```

Snapshot reproduction results: all five mount additions and the missing privilege
checks were accepted; timeout had no receipts/logs; malformed decompression ended
with unbounded `wait()` and no termination. Those additional tests used only
mocked commands and temporary files. Temporary retained evidence is below
`/tmp/cachy-lifecycle-review-_zn50qka`; it is local review evidence, not CI output.

| Input | SHA256 |
| --- | --- |
| lifecycle.py initial snapshot | `5ee385e6a7c06b0c4ef95ee54bdffef989dae71b60171653bd726674739a8f32` |
| lifecycle.py later live source | `d51049c2183e0a460e2e25b3ca6532589a0b1a653e641025ca90fb55813aea7d` |
| test_lifecycle.py | `01df055e4df1adc86ee989131be04c00df34eb5daaa3c03abe57aebaffcd4d2d` |
| fixtures.py | `0042c17f99e5ff2d3af02ba343786c860d2a9c4c698dd67da2862cc203a60824` |
| virtual-lifecycle.md | `699f18cf895a5f06a76d3079eea6cad838ce760b5fb018eadbaa24be4b321fee` |
| installed_handoff.py prospective read | `61bb5e13591df21ba343e8cd3132fe8aa9709dac71709265f4d82a02a8dd6967` |
| integration_export.py prospective read | `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c` |

The live runner differed by runtime fact reporting, fingerprint-row validation and
transaction config revalidation. Inspection confirmed those changes do not alter
the four findings; line references above use that later live source. Subsequent
edits require an explicit recheck against a new hash.
