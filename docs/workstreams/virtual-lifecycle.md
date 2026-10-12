# Disposable native ARM package lifecycle workstream

Lifecycle peer-review corrections implemented and source refrozen; ready for coordinator review/native dispatch. Actual native execution remains pending. This worker has **not executed native package installation**. Current four development packages already have native build evidence in the shared inventory; Docker installation/user-fixture results and physical M2 acceptance remain different gates.

Owned files: `scripts/integration/lifecycle.py`, `scripts/integration/test_lifecycle.py`, this report only. No canonical setup source, other worker source, shared manifest, workflow or Git state was changed by this task.

## Frozen interface

Final refrozen runner SHA-256: `e408a540765ede2350a57abd311e8814d516ab379351fe28751a20250a3a8461`. Earlier e5ada216/f2b50246 snapshots are superseded.

Inside a **new named disposable native linux/arm64 Docker container**, invoke:

```sh
python3 /runner/lifecycle.py --execute-disposable-container --baseline-handoff \
  --contract /inputs/lifecycle.json --contract-sha256 ACTUAL_64_HEX \
  --output /out/lifecycle
```

`--baseline-handoff` must exactly match the reviewed contract's `baseline_handoff: true`. Omit it and set the contract false to end with the overlay removed instead. Default invocation without the explicit disposable execution switch refuses.

Set `CACHY_ASAHI_DISPOSABLE_LIFECYCLE` to the contract's fresh 32-hex nonce and `CACHY_ASAHI_IMAGE_ID` to its immutable image ID. Caller owns Docker orchestration and validates the **actual native daemon architecture**. An in-container aarch64 uname cannot independently attest that an external daemon is native rather than emulated; the caller's daemon observation remains a recorded contract input. Runtime architecture, kernel and page size are recorded separately. No physical-Mac hardware status is inferred.

Mount the integration directory read-only at `/runner`, all approved inputs read-only at `/inputs`, and only new evidence storage writable at `/out`. Root filesystem must be a new writable overlay. Use root **inside this disposable container**, `--cap-drop ALL` and only `--cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL --cap-add SETUID --cap-add SETGID`. Use `--init` for orphan reaping. Require `--security-opt=no-new-privileges`, `--network=none`; no devices, privileged mode, host namespaces or Docker socket. The image already contains Python 3.11+, pacman/pacman-key dependencies, `gpg`, `gpgconf`, `vercmp`, `zstd`, shadow account tools, Fish, Zsh, and all package dependencies. The runner downloads/installs no missing dependencies.

Guards require actual root-owned regular `/.dockerenv`, aarch64/root, loopback only, constrained effective capabilities, no exposed hardware/block devices or Docker socket, exact mount roles and no unexpected external mounts. Default Docker `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` mounts and expected kernel/device pseudo-filesystems are allowed; host-backed system/home/tmp mounts are refused. A separate `/tmp` tmpfs is permitted. Guards run before input reads/output creation and are re-observed before command/system-mutation execution; a supplied/cached claimed probe cannot arm a host command. These checks prevent ordinary host execution; they are not cryptographic Docker attestation against an administrator deliberately forging the environment.

## Exact contract schema 1

Root fields:

- `schema_version: 1`, `execution: "native-aarch64-disposable-docker"`, `allow_system_mutation: true`.
- `nonce`: fresh 32 lowercase hexadecimal characters; `image_id`: immutable `sha256:<64 lowercase hex>`; `daemon_arch: "aarch64"`; `source_commit`: accepted baseline project commit, 40 lowercase hex.
- `baseline_handoff`: boolean matching the CLI option.
- `public_cert: "signing/test-key.asc"`, `public_cert_sha256`: exact pinned SHA-256 of the **armored public certificate only**. Private certificates are refused. Expected `signing_key_fingerprint`: full 40-character uppercase primary fingerprint. Signing/private-key creation belongs to the separate isolated signer; the runner creates no private signing key.
- `pacman_conf: "pacman.conf"`, `pacman_conf_sha256`: exact read-only configuration below `/inputs`, re-pinned before each transaction.
- `baseline` and `upgrade`: each an array of the exact four package rows below; no omitted, duplicate or extra package.

Each package row has `name`, exact ALPM `version`, `archive` (relative below its stage directory, e.g. `baseline/name.pkg.tar.zst`), archive `sha256`, same-basename `.sig` `signature_sha256`, and a complete `payload_sha256` map of **all installed regular file paths** relative to `/`, excluding pacman root metadata. Paths must remain in that package's own template/doc/license subtree; setup alone may install `usr/bin/cachy-asahi-setup`. All archive/signature files must be regular, singly linked, checksum-matching inputs with no symlink path components. Original zst/xz/gz formats are accepted without recompression.

| Name | Required primary payload path |
| --- | --- |
| `cachy-asahi-hyprland-settings` | `usr/share/cachy-asahi/hyprland/hyprland.lua` |
| `cachy-asahi-fish-config` | `usr/share/cachy-asahi/fish/config.fish` |
| `cachy-asahi-zsh-config` | `usr/share/cachy-asahi/zsh/config.zsh` |
| `cachy-asahi-setup` | `usr/bin/cachy-asahi-setup` |

The baseline helper must be original accepted `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`. Upgrade fixtures must be **separately generated and reviewed**, have greater versions (checked with real `vercmp`), different archive bytes and changed primary template/helper bytes for every package. Reinstalling baseline bytes or changing only a notice is not an upgrade trial. Fixture source/version records remain caller-owned retained evidence, not production releases. Contract JSON rejects duplicate/nonfinite values; its complete bytes are pinned by the command's SHA-256.

The configuration is `[options]` only; duplicate/unknown options, includes/repository sections, optional/disabled signatures and other keyring paths are refused:

```ini
[options]
Architecture = aarch64
SigLevel = Required
LocalFileSigLevel = Required
HookDir = /builder-disabled-hooks
GPGDir = /tmp/cachy-asahi-lifecycle-keyring-NONCE_32_HEX
```

Replace the nonce with the exact contract value. Every existing base ALPM hook below `/usr/share/libalpm/hooks` or `/etc/pacman.d/hooks` must already have the builder's `/dev/null` mask in `/builder-disabled-hooks`; the runner refuses unmasked hooks. Project archives must contain no hooks/scriptlets, links, special files, ELF payloads, ownership/mode deviations, extra directories or paths outside their declared scope. Pacman operations use normal dependency checks and mandatory signature validation, with `--noscriptlet`; no `--nodeps`, `--overwrite`, recursive removal, repository synchronization or host package operation is present.

## Signing and evidence trust

After the complete actual-container guard, the runner verifies the public certificate's pinned bytes and GPG primary fingerprint before importing it into **only** the fresh private nonce-specific test keyring. It locally trusts that test public certificate for this disposable transaction; it does not import into or fall back to `/etc/pacman.d/gnupg` or any host/default HOME keyring. All eight archive/signature pairs receive real GPG verification with the expected primary signer and reject bad/expired/revoked/missing/duplicate valid statuses. Pacman's independent `SigLevel=Required` check uses the dedicated keyring. This internal test trust is not a production repository credential or stable trust bootstrap.

Package tar contents are streamed without extracting them by the inspector, compared with every reviewed payload hash, name/version/architecture/license, and narrow installed paths. A complete pre-install package inventory is captured. Actual transactions and installed `pacman -Ql`/`-Qk`, versions, bytes, modes and root ownership must match the expected inventory plus exactly the four overlay packages; dependency additions/updates outside that set fail.

`/out/lifecycle/result.json` records PASS/FAIL, input-contract hash, image/source identity, runtime facts, required checks, every command's exit/log and `hardware_status: "NOT RUN"`. Inventories and archive audits are retained. Logs contain public signatures/package data and known temporary fixtures, not original account DB contents or real user config. Evidence directory/result/logs are readable by the caller; no secret key is exported. Preflight host refusal produces no output directory. Existing output storage is rejected, and failed runs cannot report handoff-ready.

## Implemented real-container sequence

1. Verify both signed four-package sets and changed-primary upgrade versions/payloads; capture original ALARM keyring metadata and complete base package inventory. Refuse an image where the overlay is already installed.
2. Install baseline via pacman; verify exact inventory, installed bytes/modes/ownership/file lists.
3. Create only two temporary fixture users, with Bash unchanged as their login shell. Run the **installed** helper at `/usr/bin/cachy-asahi-setup` as these non-root users. Fresh preview writes nothing; fresh repeated activation is idempotent. Existing shell bytes/modes and base desktop rc remain intact.
4. Add known outside-block edits and an edited copied desktop config; install all four signed changed-package fixtures. Verify changed installed payloads/versions, refresh the unedited user's desktop copy, preserve the edited copy and shell customization.
5. Remove the actual packages; assert every package payload disappears, original base inventory remains, and all user config bytes/modes remain. Execute guarded Fish/Zsh startup in temporary homes while templates are absent. Reinstall actual upgrade packages and revalidate.
6. Deactivate fresh/existing profiles, preserving edited desktop/outside-block bytes and modes. Inject an actual child-process exit 75 after the installed helper's first atomic config operation for both activation and removal; preview stays read-only, journal is private, actual recovery completes all components. Edited internal Fish block survives repeated activation/removal; only explicit fixture repair permits its later removal.
7. Require the complete lifecycle gate set; remove upgrade fixtures and verify base inventory. In handoff mode reinstall **original baseline** archives and verify exact original versions/payloads/helper hash.
8. Remove fixture users/groups/homes/journals/mail spools and dedicated test keyring. Account DB/backup bytes, owners, modes and xattrs are retained only in memory and restored to their initial state. Newly generated account backup files are deleted only when absent initially and confirmed **not base-package-owned**; base ALARM package files/keyring/inventory are not sanitized away. User creation skips login-log initialization.
9. Revalidate the final baseline inventory/payloads after cleanup, then and only then emit `baseline_handoff_ready: true`, `handoff_package_versions` and complete `handoff_payload_sha256`. Without handoff, end with the four overlay packages absent and base inventory unchanged.

Caller may commit the named container only after exit 0, `status: "PASS"`, all checks PASS and `baseline_handoff_ready: true`. Use `clean-baseline-handoff-inventory.json` as the installed lock and bind the result/log hashes to the committed image ID. Rootfs handoff validation does **not** set OCI metadata: restore the original pinned image's USER/entrypoint/environment configuration explicitly when committing, rather than inheriting root test-execution overrides. No Docker/Git commit is performed by this runner. Failed runs must be discarded or inspected as failed test containers, never published as the clean baseline.

## Actual local validation and outstanding execution

`python3 -m unittest discover -s scripts/integration -p 'test_lifecycle.py' -v`: **37 passed**. Only temporary fixtures, mocked commands/GPG responses and pure environment/schema predicates were used. Tests cover host/cached-probe refusal, flags/nonce/image/native/root/network/caps/devices/mounts, signature config, pins/tampering, hostile archives, required changed main payloads, public-certificate import isolation/private-cert refusal, failed command/check evidence, cleanup gating and account-backup preservation. A mocked successful finalization is explicitly control-flow testing, not an ARM installation.

`python3 -m py_compile scripts/integration/lifecycle.py scripts/integration/test_lifecycle.py`: passed. An actual invocation with the execution switch on the present x86_64 host refused with `actual Docker marker required; host execution refused` (exit 1), before any input/package/output operation. No host pacman/useradd/GPG key creation ran.

An earlier directory-wide discovery also ran other workers' in-progress desktop/fixture tests and encountered their transient failures; this report claims only the owned lifecycle suite, and did not edit their files. CI integration of the new suite belongs to the coordinator/workflow owner.

Actual native ARM signature/import/package/user/upgrade/interruption/cleanup/handoff execution is **NOT RUN by this worker**, pending caller's preprovisioned image, real baseline/changed artifacts, ephemeral signatures/public certificate and pinned contract. Physical M2 Air installation, boot, audio/protection, graphics, suspend, recovery, performance and independent onboarding remain **NOT RUN** by this runner and require their own exact-model evidence.

## Final peer-review corrections and exact guard contract

The supplied review findings were reproduced/covered with safe fixtures and repaired before this refreeze. Current owned suite: **37 passing tests**; includes actual short-lived Python process/descendant/stderr saturation fixtures and bounded gzip inspection, with no host package/user/GPG trust operation.

Privilege observations now include `probe["privileges"]` with integer Linux `CapEff`, `CapPrm`, `CapBnd`, `CapInh`, `CapAmb`, `NoNewPrivs` keys. All five capability sets must be nonnegative subsets of the declared safe mask; NNP must be integer 1, and `caps` must match observed CapEff. CAP_KILL is now explicitly required to signal demoted test-user children; Docker must add it alongside CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID. Missing/malformed privilege observations and broader permitted/bounding/inheritable/ambient capabilities fail before mutation.

The guard requires `/proc`, `/sys`, `/dev` and exact path-specific roles; no mixed ro/rw parent flags. Kernel/dev entries (when mounted):

| Path | Filesystem / access / required security flags |
| --- | --- |
| `/proc` | proc / rw / nosuid,nodev,noexec |
| `/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`, `/proc/sysrq-trigger` | proc / ro / nosuid,nodev,noexec |
| `/sys` | sysfs / ro / nosuid,nodev,noexec |
| `/sys/fs/cgroup` | cgroup or cgroup2 / ro / nosuid,nodev,noexec |
| `/dev` | tmpfs / rw / nosuid |
| `/dev/pts` | devpts / rw / nosuid,noexec |
| `/dev/shm` | tmpfs / rw / nosuid,nodev,noexec |
| `/dev/mqueue` | mqueue / rw / nosuid,nodev,noexec |
| optional `/tmp` | tmpfs / rw / nosuid,nodev |

Exact Docker null masks `/proc/kcore`, `/proc/keys`, `/proc/latency_stats`, `/proc/timer_list`, `/proc/timer_stats`, `/proc/sched_debug`, `/proc/interrupts` permit tmpfs ro or rw only with observed non-symlink character device major/minor **1:3**. Exact directory masks `/proc/acpi`, `/proc/scsi`, optional `/proc/asound`, `/sys/firmware`, `/sys/devices/virtual/powercap` require read-only tmpfs plus observed non-symlink directory identity. These observations are `probe["mask_nodes"][PATH] = {"symlink": false, "kind": "char"|"directory", "device": [1,3]|null}`; actual_environment gathers them by lstat. Ext4 replacements, wrong sysfs/cgroup/devpts/mqueue roles, writable sysfs, missing security flags, arbitrary proc/run mounts and all child mounts under `/inputs`, `/runner`, `/out` (including read-only ones) fail. Positive fixtures cover the complete standard masked layout, including V6 cases.

Commands now receive a pre-execution JSON receipt, bounded 4 MiB stdout/1 MiB stderr, 180-second deadline, fresh process group and bounded TERM→KILL/direct-child reap. Logs/receipts retain partial output, timeout/limit/launch/exit classification and cleanup outcome; failure cannot publish handoff-ready. Tests prove TERM-ignoring forked descendants in that group are stopped. The scope is the owned group/direct child, not tracking arbitrary daemon escape; dedicated keyring agents receive their own successful-path cleanup and failed containers must be discarded.

Archive gzip/xz/zstd decoding drains both pipes under a 30-second deadline with at most 64 MiB decoded bytes and 1 MiB diagnostics. It completes bounded group cleanup before tar parsing. The complete decode/parse deadline, 4096 physical/logical member limits, bounded PAX/GNU extension headers (64 KiB each/1 MiB total), 8 MiB member and 32 MiB declared payload bounds prevent zero-size/metadata bombs. Parsing cannot perform an unbounded stderr read/wait or have a cleanup exception replace its original error. Safe regressions cover stalled output, saturated diagnostics, malformed tar, empty-member floods, stream/metadata limits, receipt retention and descendants.

Installation-route audit is a separate owned follow-up and does not hold this runner freeze. Canonical setup source remains unchanged at a6251142... . Shared manifests/Git/workflows and peer review files remained untouched by these repairs.
