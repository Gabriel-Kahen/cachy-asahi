# Software onboarding workstream

Scope: `scripts/integration/onboarding.py`, its tests, and this record only.
Source implementation complete and locally tested; disposable native ARM software journey **NOT RUN**.
Full upstream/macOS/Asahi installation, GUI/editor use, hardware and exact-M2
onboarding remain NOT RUN regardless of subsequent software results.

## Integration interface

The lifecycle coordinator supplies an already-installed **immutable ARM image**
and its reviewed complete sorted `pacman -Q` inventory. This worker does not
install/trust packages or create system accounts. Final frozen CLI:

```sh
python3 scripts/integration/onboarding.py \
  --image 'sha256:<installed-image-id>' \
  --expected-packages /absolute/installed-packages.lock \
  --expected-packages-sha256 <reviewed-lock-sha256> \
  --baseline-manifest /absolute/lifecycle.json \
  --baseline-manifest-sha256 <reviewed-native-baseline-manifest-sha256> \
  --source examples/development/hello.c \
  --source-sha256 <reviewed-original-source-sha256> \
  --output /absolute/new-onboarding-evidence
```

Reuse the existing native runner probe/image-pin rules. Execution requires native
Linux ARM plus a local ARM Docker daemon, never emulation or remote bind mounts.
Each journey gets a fresh named, network-disabled, capability-dropped,
no-new-privileges, read-only-root container; only a new evidence directory is
writable on the host. HOME/XDG/workspace live in owned disposable tmpfs; no host
home, account, service, socket or system directory is mounted or modified.

Container preflight verifies mounts/security/runtime identity, exact installed
inventory, all four original overlay packages, helper/template ownership and
required Python/Fish/Zsh/Vim/C compiler commands. Missing prerequisites fail with
diagnostics. The ordinary non-root journey uses PTY terminal/shell startup,
installed setup preview/apply/repeat/remove, guarded Fish/Zsh behavior, a scripted
editor operation on a copied C example, and the guide's exact compiler/run argv.
Raw command/output records and source/binary hashes distinguish this from a GUI
or complete target onboarding exercise.

`--baseline-manifest` reuses the lifecycle contract's `baseline` array: exactly
four records with `name`, exact `version`, native archive `sha256`, and complete
regular-file `payload_sha256` maps. The file may be the full reviewed lifecycle
JSON; this harness uses only the native baseline slice, never its upgrade fixture.
Installed versions, complete pacman file lists, root ownership/permissions and
every payload byte are checked independently before/after the user journey.

The retained actual native-builder lock from run `38189520114` contains
`vim 9.2.1164-2`, `vim-runtime 9.2.1164-2`, `nano 9.2-1`,
`gcc 16.1.1+r12+g301eb08fa2c5-1`, Fish and Zsh. Vim is an existing locked prerequisite,
not a proposed dependency extension; the runtime still fails if its executable
is absent. No installation is attempted. The fresh ordinary-user container also
runs frozen copies of the existing 40 setup and 19 release tests; skips, failures,
missing tools or unexpected test counts prevent SOFTWARE PASS. Those tests use
temporary homes and synthetic signing identities and do not certify release trust.

The CLI below is the final owner interface. No benchmark work or performance
claim is part of this task.

## Container and evidence boundaries

The inner runner requires the fresh nonce/image-ID environment contract, matching
ordinary UID/GID, aarch64 Linux, `/.dockerenv`, zero effective capabilities and
no-new-privileges. The root and inputs are read-only; `/tmp` is owned private
nosuid/nodev tmpfs; output is initially empty and user-owned. Only loopback exists.
Required proc/sysfs/tmpfs/devpts/mqueue/cgroup mounts have checked filesystem types
and flags. The explicit standard-Docker runtime/masked-path allowlist rejects
additional mounts even under unrelated names. Device nodes and runtime sockets
outside the permitted pseudo-device set are refused. Docker-managed host/resolver
files must be regular root-owned files without group/world writes.

Known OCI file masks may be writable null-device binds; these are accepted only
at the exact masked-file destinations, on tmpfs, with observed null-device major
1/minor 3. This narrow exception follows source inspection of
[upstream runc file/directory masking](https://github.com/opencontainers/runc/blob/main/libcontainer/rootfs_linux.go).
Unknown runtime masks or engine-specific mounts fail visibly; review their actual
facts before extending this explicit policy.

The host uses `--pull=never`, the inspected immutable image ID, network none,
read-only root, all capabilities dropped, no-new-privileges, non-root UID/GID and
CPU/memory/PID bounds. It mounts only the new snapshot and new artifacts directory;
no source checkout, real home, host account/system database, signing home, display,
audio, device or Docker socket is passed through. Existing native/image helpers
are imported read-only; the script disables source bytecode writes.

Command records are separated into `preflight-commands.json`,
`journey-commands.json` and `suites-commands.json` so one phase cannot overwrite
another. Each record contains exact argv/cwd/minimal environment, PTY/capture mode,
exit/error status, expected output, raw stdout/stderr filenames and timestamps.
The edited working copy and binary are copied into evidence with distinct hashes;
the source checkout is untouched. Host provenance captures image/entry/source/test
pins, native runner facts, Docker argv and owned-container cleanup. Failure
diagnostics remain in the selected evidence directory.

Signal handling defers cancellation until spawned process handles are assigned,
then runs original-process-group cleanup. Repeated TERM/INT during bounded cleanup
and evidence persistence cannot skip those blocks; cancellation is recorded as
failure. Group reap waits are bounded to one second, individual command limits
are 20 seconds (suite limit 90), and outer Docker removal is bounded to 30 seconds.
SIGKILL, OS stalls and detached subprocesses remain outside a cleanup guarantee;
workload/test source must be reviewed and must not launch persistent services.

## Actual local validation and diagnosed failures

October 11, 2026, x86_64 development host only:

```sh
python3 -m unittest discover -s scripts/integration -p 'test_onboarding.py' -v
python3 scripts/integration/onboarding.py --help
```

Final owner suite: **12 tests PASS**, 0.680 seconds reported by unittest. It includes
an actual 13-command PTY/helper/Fish/Zsh/Vim/compiler/run/removal **source fixture**
using only a fresh temporary home, copied original templates and the source helper.
That local fixture does not establish installed package or native ARM evidence.
Host/container orchestration tests are explicitly mocked. Other tests exercise
payload/version/type/mode and reviewed-input drift, unsafe mounts/resources,
strict skip reporting, literal argv, timeout evidence, acquisition-time SIGTERM,
and repeated cancellation during cleanup. No current mocked handoff test claims
an actual SOFTWARE PASS run.

The first real PTY fixture failed after 20.723 seconds at `zsh-after-remove`.
The missing startup file correctly exposed Zsh's first-use function, which waited
for input. Retained diagnostic excerpt from the bounded reproduction:

```text
Failure: step failed: zsh-after-remove; see recorded output/diagnostics
clear:echotc: no such capability: cl
zsh-newuser-install
(q), (0), (1) first-use menu
--- Type one of the keys in parentheses ---
```

The implementation now answers `0` **only after observing that exact prompt**,
records the prompt/response and proceeds with the fresh-shell removal assertion.
This selects Zsh's user-owned comment-only startup file; it does not silently
substitute or source another overlay configuration. PTY echo is disabled, and
assertion commands are argv rather than sent terminal text. No timeout was raised
to mask the failure. Source-changing aggregate failures at this step predate that
fix; the final owner suite exercises it end to end.

A new skip-reporting fixture also exposed non-JSON-serializable unittest objects;
reports now serialize test names/reasons and refuse skipped suites. Cancellation
testing exposed interruption before `Popen` assigned its child handle; signal
deferral closes that acquisition window. Independent source review additionally
found extra runtime binds and cancellation during cleanup; guard/cleanup fixes
and focused regressions address those findings. The final source is frozen for
coordinator aggregate/native testing; no benchmark reruns were performed.

## Guide corrections for their owners

| Existing document | Proposed correction exposed by the software path |
| --- | --- |
| `examples/development/README.md` | Explicitly start in the repository/workspace root; its relative source/build argv depends on that otherwise unstated CWD. Preserve an original source hash before a scripted working-copy editor change. |
| `docs/installation.md` | Show launching fresh `fish` or `zsh` after activation; setup does not switch the login shell. Explain that fresh Zsh can show its first-use wizard after a newly created managed `.zshrc` is removed. |
| `docs/setup-tooling.md` introduction | Its native-package-build NOT RUN sentence is stale relative to accepted native build evidence. Keep real Asahi installation and exact-M2 onboarding NOT RUN. |
| Full onboarding acceptance | Treat scripted Vim/PTY/container checks separately from an independent user's GUI editor/graphical terminal journey and lock/resume survival. |

Shared guides and root acceptance records were not edited by this worker.

## Remaining native handoff

CI/lifecycle owners supply the sanitized installed immutable baseline image,
reviewed complete installed lock and actual-native-archive-derived `baseline`
payload manifest. This worker's runner independently verifies every original
package version/file list/payload byte before executing the installed CLI, and
rechecks packages/payloads after the journey. The copied helper source used by the
40-test suite must byte-match the installed helper; production execution never
substitutes the checkout helper for `/usr/bin/cachy-asahi-setup`.

Actual execution of the whole journey plus 40 helper/19 release tests inside the
fresh native container remains **NOT RUN here**. The local x86 host cannot satisfy
the native guard. Retain actual native logs, sanitized receipts and observed
failures; coordinate source/lock freezes before running aggregates. SOFTWARE PASS
is limited to this disposable VM userspace path. It does not certify production
package trust, a supported endpoint, GUI usability, a full macOS/Asahi installation,
16K-page behavior, physical M2 onboarding, graphics/audio/power/suspend or performance.

Final source SHA-256 (after the passing owner suite):

```text
2aeb0bfdad5aec6bbc969b3c008a10fa9cfb3a91775d9969a48e78e284c0e560  scripts/integration/onboarding.py
04f83906f8f5bd5eb7d7a64985ecf668d0643956ab7aebd8e9d9aaf92ca9af07  scripts/integration/test_onboarding.py
```
