# Separate KSM diagnostic development lifecycle

Status: corrected source candidate passes **147 tests locally, no skips**: 42 contract, 55 worker (including four real temporary GPG checks) and 50 controller/boundary tests. The prior 137-test checkpoint remains historical: subsequent independent review reproduced source replacement and forged bytecode-cache execution through its worker loader. The current worker compiles captured verified bytes and binds every installed probe to one verified capture. It retains the original Docker/identity and cancellation fixes. Bounded independent source review and all ten targeted capture regressions passed at the final hashes; the coordinator owns acceptance. Actual native KSM build-pair consumption, container signing, installation and removal are **NOT RUN**. M2, Asahi, 16K hardware, management activation and performance remain **NOT RUN**. This adapter owns only `scripts/port/ksm-lifecycle/` and this report. The coordinator owns job wiring, source freezes, CI, Git and dispatch. This diagnostic foundation does not complete the port's five required workstreams or KSM management.

The coordinator's [native KSM build verification](../../artifacts/ci/38218102399/root-ksm-build-verification.json) records two equal native archives and distinct clean containers in job `38218102399`. That build evidence does not establish execution of this lifecycle adapter.

The adapter consumes the two accepted native `cachy-asahi-ksmctl` build directories. It does not build a replacement image or change the original four-package MIT signer, client adapter, 345-package lifecycle, or its acceptance criteria. KSM uses a separate short-lived DEVELOPMENT TEST identity and a separate disposable lifecycle container.

## Accepted inputs

Both build directories must contain their actual `provenance.json`, recipe inputs, artifact records and package archive. The contract requires native ARM provenance, network disabled, the same immutable image, distinct clean environments, the exact reviewed native-build command grammar and entry script, and the complete accepted builder lock. File reads refuse symlinks and are bounded. Archive parsing is data-only: xz/gzip are supported; zstd is refused.

`.BUILDINFO` must report the actual makepkg tool version `7.1.0`, while the accepted installed package version is `pacman 7.1.0.r9.g54d9411-2`. Those identities are separate: [upstream meson.build at the pinned revision](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/meson.build) sets project version `7.1.0`, which [makepkg uses](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/makepkg.sh.in); [ALARM packaging](https://github.com/archlinuxarm/PKGBUILDs/blob/fd636a0077db0efe900d67d4de910c0d270fc8c4/core/pacman/PKGBUILD) derives the package version from Git. The fixture uses the actual complete accepted 341-package lock and architecture assignments, and refuses a package-version string in the tool-version field.

The reviewed 15-file recipe map SHA-256 is `f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44`. Both build provenance files must match the caller's separately supplied SHA-256, including a second comparison against the bytes actually consumed. Archives, `.PKGINFO`, `.BUILDINFO` and complete payload metadata must compare equal across both builds.

The `.BUILDINFO` installed rows must match all 341 accepted package names and versions and use an `any` or `aarch64` suffix. The contract does not independently bind each row's architecture suffix to a per-package architecture map.

The only accepted package is `cachy-asahi-ksmctl` version `0.1.0-1`, architecture `any`, license `GPL-2.0-or-later`, dependency `python>=3.11`. An architecture declaration does not establish a native build. The archive must contain exactly these five regular, root-owned files, with the reviewed input hashes:

| Path | Mode |
| --- | --- |
| `usr/bin/cachy-asahi-ksmctl` | 0755 |
| `usr/share/doc/cachy-asahi-ksmctl/README.md` | 0644 |
| `usr/share/doc/cachy-asahi-ksmctl/source-provenance.json` | 0644 |
| `usr/share/licenses/cachy-asahi-ksmctl/NOTICE` | 0644 |
| `usr/share/licenses/cachy-asahi-ksmctl/LICENSE` | 0644 |

Only their finite ancestor directories and the required package metadata are allowed. Hooks, install scriptlets, links, protected paths, extra metadata identities, differing payload bytes and incomplete builder inventories are refused.

The native nonroot controller also requires the actual current GitHub commit/run environment, checksum-bound runner receipt, current full bootstrap receipt, complete 341-package inventory, refreshed current-input lock, immutable ARM image, explicitly supplied live local daemon ID, SHA-256 of the accepted `/usr/bin/docker` ELF and the accepted Unix socket's device/inode. Real/effective UID must match and be positive, as must real/effective GID, before Docker or caller input access. The accepted builder lock SHA-256 is `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`; refreshed current-input SHA-256 is `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`. Bootstrap/image/job/CLI/socket values come from the future executing job; an old completed job's bootstrap cannot stand in for its live image.

## Future same-job interface

The controller refuses a host architecture override, root coordinator, remote daemon, mutable image name, mismatched runner, changed input, reused public output path or an unreviewed source hash. The coordinator must bind both supplied build outputs to its executing job when selecting their provenance hashes.

```sh
python -B scripts/port/ksm-lifecycle/stage.py \
  --image "$KSM_IMAGE_ID" --daemon-id "$KSM_LOCAL_DAEMON_ID" \
  --docker-endpoint "$KSM_LOCAL_DOCKER_ENDPOINT" --docker-sha256 "$KSM_DOCKER_CLI_SHA256" \
  --docker-socket-device "$KSM_DOCKER_SOCKET_DEVICE" --docker-socket-inode "$KSM_DOCKER_SOCKET_INODE" \
  --source-commit "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" \
  --runner "$KSM_RUNNER_RECEIPT" --runner-sha256 "$KSM_RUNNER_SHA256" \
  --bootstrap "$KSM_BOOTSTRAP_RECEIPT" --bootstrap-sha256 "$KSM_BOOTSTRAP_SHA256" \
  --packages "$KSM_BUILDER_LOCK" --current-inputs "$KSM_CURRENT_INPUTS" \
  --source "$KSM_REVIEWED_SOURCE" \
  --stage-sha256 "$KSM_STAGE_SHA256" --worker-sha256 "$KSM_WORKER_SHA256" \
  --contract-source-sha256 "$KSM_CONTRACT_SHA256" \
  --approved-inputs "$KSM_APPROVED_MAP" \
  --build-1 "$KSM_BUILD_ONE" --build-1-provenance-sha256 "$KSM_BUILD_ONE_SHA256" \
  --build-2 "$KSM_BUILD_TWO" --build-2-provenance-sha256 "$KSM_BUILD_TWO_SHA256" \
  --output "$KSM_FRESH_PUBLIC_OUTPUT"
```

All variables are task-specific inputs, not defaults. The endpoint is explicit and restricted to `unix:///var/run/docker.sock` or `unix:///run/docker.sock`, matching the accepted runner. There is no ambient Docker context discovery. The coordinator must capture and authenticate the CLI SHA-256 and socket device/inode alongside the actual same-job daemon/runner evidence before invocation; the adapter independently checks those pins against live observations.

Every Docker request, including architecture/image queries, name lookup, create, inspect, start, removal and each separate name/ID absence query, crosses one checked execution boundary. It observes the accepted daemon before and after that request. Each CLI invocation, including the daemon-ID observations, checks the original UID/GID pair, CLI inode/metadata/bytes and retained socket inode/metadata before and after execution, including transport exceptions. CLI reads are bounded to 128 MiB and refuse links, special files and unsafe permissions. The checked ELF bytes are copied into a sealed anonymous memfd and executed through the retained descriptor; no PATH lookup or mutable pathname is used for execution. A real Unix-socket descriptor pins the accepted node identity. Descriptor disposal happens before the authoritative public receipt. Checked contract/helper bytes are also executed from captured snapshots. The controller copies only the five checksum-bound source files and accepted data into a private temporary directory.

The worker also compiles the exact verified BASE, GUARD and CONTRACT byte captures, without using a source-file loader or bytecode cache. Its module cache is keyed by absolute path and verified digest, preserving one shared BASE cancellation state across entry/guard aliases. CONTRACT execution consumes the source-map check's captured bytes. The signing guard directly invokes the captured GUARD's environment and guard functions; it preserves the frozen base helper's full protected-proc presence and accepted UID/eUID/eGID checks without invoking that helper's nested path loader. The external BASE and GUARD bytes are unchanged.

The installed probe captures its approved executable bytes and mode/UID/GID/link count from the same opened descriptor. All five CLI probes use that capture through a sealed inherited memfd and isolated Python; the fixture module compiles the same bytes. The wrapper preserves the original installed filename, `__name__` and `sys.argv[0]`. The descriptor closes before probe completion. Replacement of the installed pathname after capture or a timestamp/size-valid foreign `.pyc` cannot supply executed source to these consumers.

## Finite phases and boundaries

Signing runs nonroot with a read-only overlay root, no capabilities, NNP=1, no network, private IPC, two CPUs, 1 GiB memory with no additional swap, 64 PIDs, file-descriptor limit 256 and a private 256 MiB `/tmp` tmpfs. The only binds are read-only `/source` and dedicated `/out`. An ephemeral one-day Ed25519 primary signs exactly the accepted archive with SHA-256. Verification requires the exact full primary fingerprint, valid one-day expiry, expected TEST identity, no subkeys and no invalid/expired/revoked status. Only the detached signature, public certificate and sanitized worker receipt temporarily leave that container.

The second container is a disposable writable overlay, root inside the container, network off, private IPC, two CPUs, 2 GiB memory, 96 PIDs and the same descriptor/tmpfs bounds. Its exact effective/permitted/bounding mask is `0xcb`: CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID; inheritable and ambient sets are zero and NNP=1. It has no SYS_CHROOT, CAP_KILL, SYS_ADMIN, devices, Docker socket or host system mounts. Worker observations independently validate the actual UID, mounts, protections, standard devices, sockets and capabilities; no observation is rewritten to imitate another phase.

Pacman uses a private options-only config, private keyring/cache/log and `Required TrustedOnly` for the supplied local archive. A separate ephemeral certification primary locally certifies only the exact public signer. No repository is registered. Private HookDir basename masks preserve image-owned hook files; all package transactions use `--noscriptlet`. Positive pacman commands must have zero exit and clean ancillary diagnostics. Default-root libalpm skips its chroot call when the root is `/`, unlike the repository adapter's `/scratch/system`; no sixth capability is added to this KSM lifecycle.

The lifecycle checks the complete 341-package baseline, refuses preexisting payloads including dangling links and symlink ancestors, installs the signed package, verifies exactly 342 package rows and all five file hashes/modes/owners plus pacman ownership, probes as the original nonroot UID, removes, reinstalls, probes again and finally removes. Both removals require the complete original inventory and absent payload files. A user-owned mode-0600 fixture with fixed timestamp must retain its bytes and metadata across every transition. No `--nodeps`, overwrite, database-only operation or weakened signature setting is permitted.

The nonroot probe clears supplementary groups, has zero effective/permitted/inheritable/ambient capabilities and NNP=1; its bounded set remains `0xcb` because the parent has no SETPCAP. It checks installed help/version, refusal of unsupported management arguments, actual read-only status (success or explicitly unavailable interface), and in-memory fixture conversion of three shared pages at both 4K and 16K. Fixture conversion is not evidence of a 16K kernel or M2 hardware. No management action or sysfs write is attempted.

## Cleanup and public evidence

Both phases inspect the exact worker entrypoint, argument hash, source/output binds, labels, image, limits, environment, capabilities and network before execution and again after a clean stopped state. A create command's ambiguous failure still triggers owned-name inspection and disposal. Cleanup refuses an object whose nonce/contract/image labels differ. Successful daemon queries must prove both the owned name and known ID absent; failed transport is not proof of absence. Daemon drift prevents cleanup acceptance.

Cancellation is deferred across cleanup. Root may lack permission to signal a nonroot child without CAP_KILL; that produces controlled FAIL, with private cleanup still attempted, and requires confirmed controller container removal. No broader capability is added to accommodate cleanup. A worker cannot provide authoritative PASS without all phase checks and process/tmpfs cleanup, and the controller cannot provide PASS without confirmed container absence, removal of its private directory and descriptor disposal. Lifecycle receipt permissions are set before authoritative JSON is written and fsynced. Cancellation observed during chmod, fsync, final stream close or final deferral unwinding changes the durable receipt and return status to FAIL. Both finalizers catch cancellation raised while restoring the handler and reconcile remembered cancellation after their final deferral. The controller performs no post-persistence descriptor or private-directory disposal; a late cancellation rewrites the already disposed result as FAIL.

The entry wrappers also reconcile a caught SIGINT/KeyboardInterrupt while restoring the caller's handler, using the already completed report without replaying either phase. Acceptance requires both matching PASS receipts and clean worker/controller exits. For each signal, the controlled handler's scope ends when that signal's caller handler is restored: arbitrary termination after that point, including default SIGTERM, can stop an already completed process and cannot be diagnosed from its receipt alone.

The fresh public output retains only `receipt.json`: source/image/job/input hashes, curated package comparisons, full public signer fingerprint plus certificate/signature hashes, fixed check names/statuses, stopped state, attach byte count/hash and cleanup status. Raw command output, archive, signature, certificate, key homes and secret keys are not published or retained there. `private_artifacts_retained` stays true until private-directory absence is confirmed; a cleanup failure reports FAIL and retained private artifacts rather than claiming removal. Source fixtures explicitly identify their mocked Docker/package operations; real temporary GPG checks use private homes and do not modify default trust or install host packages.

## Validation still required

Portable tests cover strict package contracts, reviewed-byte loading, exact sandbox commands, typed failure receipts, cancellation, ambiguous create, ownership, changed daemon, name/ID absence, denied cross-UID cleanup, private artifact removal, GPG identity/signature/trust, preserved hooks and ownership/payload invariants. Real sealed-ELF/private-Unix-socket fixtures reject changed CLI bytes/inodes, changed sockets, wrong pins, FIFO paths and identity drift, including CLI drift after an operation and socket drift during a transport exception. Mocked daemon responses reproduce A→B→A, pre-start changes and changes between cleanup queries. Real file/chmod/fsync regressions cover the formerly unsafe lifecycle mode change and durable writer completion. Actual SIGTERM and SIGINT are also delivered during final handler restoration and after the controller writer returns inside its final deferral; both durable receipts must become FAIL/cancelled. These fixture cancellations require a nonzero worker return or a controller FAIL that its CLI maps to exit 1. No Docker daemon or native package transaction is invoked by these controller fixtures. A local full-suite pass is source/fixture evidence only.

The coordinator must independently review/freeze these new sources, wire the above interface to both real accepted KSM native builds, run both containers on the actual ARM job, inspect the complete receipt and confirm disposal before accepting R1/R5 lifecycle evidence. Full native execution, hardware compatibility, activation and measurements remain unfinished.

## Source handoff

The independent reviewer edited no files. CLI help, AST parsing and whitespace checks pass. Both adapter files bind the coordinator's intentionally refreshed original client stage SHA-256 `dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154`; that external change updates a test-fixture source pin and was not edited by this worker. The source guard remains `4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100`. No shared manifests, CI, Git or dispatch was changed by this adapter work.

The [held source checkpoint](../../scripts/port/ksm-lifecycle/source-checkpoint.json) binds these six files, this document, the 147-test receipt and the external helper pins. Its native-build pointer describes the coordinator's existing build verification, not execution of this adapter. The earlier [137-test checkpoint](../../scripts/port/ksm-lifecycle/source-checkpoint-137.json) retains its original hash and source map as historical evidence.

| New file | SHA-256 |
| --- | --- |
| `stage.py` | `be4a61ac4ed8efbf243e2be1a5211c4ad0553f7be13a26b64e3e655de73cbaee` |
| `test_stage.py` | `e34c99bb71f57748c5f171f08085ca4d0ab3846e26cbc48ca07e246730218332` |
| `contract.py` | `bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b` |
| `test_contract.py` | `13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258` |
| `worker.py` | `76a3e94f317bea79d1e2444630d719b8acaed6c6cb6427c0bb19beedbc4d6b83` |
| `test_worker.py` | `5e9bac1045407585f26c8819c9e4d283cae3044e1cefbebabc1f4c086e517aa8` |

## Disposition of the additional independent review

[The coordinator's independent review](../reviews/ksm-lifecycle-review.md) correctly rejected the earlier 107-test freeze. Its three reproduced findings were addressed by the inherited 127-test candidate. Transfer review then reproduced final-handler-restoration cancellation, cancellation remembered after the controller writer returned and caught caller-handler restoration; the 137-test candidate added those corrections and post-operation CLI/socket drift coverage. The current 147-test candidate adds ten loader/consumer regressions: same-size replacement after capture, a valid foreign bytecode-cache control, changed-pin/cache refusal, shared BASE cancellation state, same-descriptor metadata checks, the signing guard route, CONTRACT capture consumption and installed CLI/module probe captures. The [current test receipt](../../scripts/port/ksm-lifecycle/source-test-results.json) binds the actual current six source/test hashes; the [137-test receipt](../../scripts/port/ksm-lifecycle/source-test-results-137.json) and [135-test receipt](../../scripts/port/ksm-lifecycle/source-test-results-135.json) remain historical. This closure does not edit the coordinator's historical review, establish native execution, or authorize full-port acceptance.
