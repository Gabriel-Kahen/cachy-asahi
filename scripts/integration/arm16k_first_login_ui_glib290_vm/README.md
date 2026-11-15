# Experimental ARM16K UI with explicit GLib 2.90 upgrade/rollback

Status: **Source/control and retained-material DATA tested; new preparation/VM
NOT RUN.** This separate operation is `arm16k-first-login-ui-glib290-vm-v1`.
It starts from the exact original 111-package raw, explicitly upgrades only
`glib2` from2.88.3-1 to2.90.1-1 alongside the unchanged172 additions, then removes
those172 and installs the original signed GLib archive to restore111 versions.
173 packages are touched; the installed total is283. The old UI family/172
manifest, raw, markers, failed trials, PAM/systemd/Asahi platform stay unchanged
at rest. This changes only an owned experimental guest after fresh Root admission.

## Why this exists

Root's prior 4GiB UI trial genuinely installed283 packages and passed all six
independent real-seat checks, but GTK import failed: libgtk-4.so.1 required
`g_timeout_source_new_ns`. The official [GLib API documentation](https://docs.gtk.org/glib/func.timeout_source_new_ns.html)
marks that function available since2.90. Actual ELF DATA also found missing
`g_markup_parse_context_get_attribute_position`. No observer or policy waiver
repairs this mismatch. That trial remains HOLD; GTK actions/logout/removal were
not accepted. Its counters measured no OOM; clean owned-helper reaping alone
does not establish natural QEMU closure or explain an earlier unmeasured SIGKILL.

A bounded retained lookup plus official intake found both real archives:

| Role | Version | Bytes | SHA256 |
| --- | --- | ---: | --- |
| Rollback |2.88.3-1|4892752|a1498d94c3ff5e52ea157a09bb55bceaa7f94e47ded7c74ac5611d0e0b9b5ec8|
| Upgrade |2.90.1-1|4972100|c0beb07e62117bf5adef1561580b7878742521a4caea1227bff76a2f894b9bd0|

Their original detached566B signatures have SHA256
44c300d59dcfe7b2a24c864e86bf7445dc9bee0689491da643c7f3288cb4d99b
and62000543b3101eb33a688ab7112f7f1f029585b831873d0e7c8b1575ddfeded3,
respectively. Both public-only gpgv checks genuinely returned0 for exact official
primary68B3537F39A313B3E574D06777193F152BDBE6A6. No private key, trust import,
production-current-trust or Root admission follows. Source/license declarations
and static binary facts do not establish complete corresponding-source/legal
acceptance. Current official intake used5 requests/5082106 body bytes, under the
12-request/32MiB/10minute limits; old originals were not changed.

The old archive's six provider ELFs exactly match the six original-rootfs GLib
libraries. The new package's six SONAMEs match; every old exported symbol remains.
All1515 strong g_* imports from actual GTK4.24.1 resolve against the new six,
including both measured misses. Both versions'18 ELF files pass the existing
static aarch64/16K LOAD checks. `glib_data_audit.py` recomputes these bounded DATA
joins on exact archives during preflight. Full transitive symbol-version/loader/
runtime compatibility remains NOT RUN; it is not invented as PASS.

Actual libalpm16.0.1 metadata prepare accepted173 targets with1319 final dependency
relations and zero errors/removals/questions/conflicts. After a modeled removal
of172, old-GLib downgrade preparation accepted one exact target and472 relations.
This is metadata evidence, not a real install/removal. Two earlier private-input
attempts omitted archive repository fields and crashed native preparation;
they are retained. Corrected input supplies the exact real FILENAME/CSIZE/hash
fields used by the existing planner. No shared libalpm/helper policy changed.

## Finite Source and runtime contract

`origin.json` pins parent d64569ee and every initial Source file. This is a
separate finite upper adapter; the lower reference/custody/kernel/tool inputs
remain pinned. No generic callback/process framework is introduced. It preserves
9 exact preparation binds,3GiB preparation memory and1.5GiB preparation physical cap,
5GiB/no-extra-swap boot memory,2GiB guest,2GiB overlay,2CPU/256PIDs,
7GiB minimum boot host availability/2GiB reserve,
RTC/current-UTC proof, public-only TEST trust, unsuppressed hooks, ordinary PAM/
active seat0/foregroundVT/real keyboard ACKs, GUI/edit preservation and natural
owned process retirement. Memory diagnostics and all6 independent checks remain
mandatory. The new actor is `ui_glib_actor.py`; boot validates that exact Cmd
before its explicit legacy projection. New marker is ui-glib290-attempt.json.

`compose.propose(original172_manifest)` emits a new173/rollback **proposal**,
with issuer/trust/Root review null, not an admission. `data/additions172-anchor.json`
binds every unchanged addition's exact archive and metadata. Only baseline GLib
ownership overlap is permitted; any other baseline change/collision refuses.
All baseline/new dependency edges are required. The new manifest must be
ARM16K_FIRST_LOGIN_UI_GLIB290_ADDITIONS_V1 with Root-reviewed closure status,
exact fixed rollback pair, complete173 material authentication, the pinned
`glib_material_contract`, new namespace and actual metadata proof. Root must
freshly fill public keys/project signatures/trust times; old authorities cannot
be retagged. Both authority allow flags and allow_glib_runtime_upgrade default
false; new public Source/preparation/boot fields remain null.

Guest install is an ordinary Required/TrustedOnly `pacman -U` over173 exact
archives. Qkk/analyzed ownership covers all173 before UI starts. New-GLib-owned
namespace hashes replace only their exact old-GLib-owned counterparts in the
post-install check; original PAM/udev/NM policy stays exact. After real GUI and
session corroboration, the fixed removal allowlist contains only the172 additions,
never GLib or another baseline package. Ordinary signature-required `pacman -U`
then restores2.88.3-1. Mandatory old-package Qkk/ownership uses a separate rollback
index and durable receipt subdirectory. Original namespace pins and111 versions
must match, new-only GLib paths must be absent, user edits preserved and sync-f
complete. Normal sysusers/cache effects are recorded; full-filesystem restoration
is not claimed. No nodeps/forced overwrite/hook suppression/GLib shim is used.

Root-only entrypoints, after separate complete admission:

```sh
python3 -I -B scripts/integration/arm16k_first_login_ui_glib290_vm/prepare.py \
  --allow-prepare-arm16k-ui-glib290 [same explicit pinned input flags as parent] \
  --authority NEW_GLIB290_AUTHORITY --authority-sha256 NEW_AUTHORITY_SHA \
  --output NEW_PRIVATE_PREPARATION
python3 -I -B scripts/integration/arm16k_first_login_ui_glib290_vm/boot.py \
  --allow-first-arm16k-ui-glib290-boot --prepared NEW_PREPARED \
  --prepared-sha256 NEW_PREPARED_SHA [pinned kernel/tool flags] \
  --authority NEW_GLIB290_BOOT_AUTHORITY --authority-sha256 NEW_BOOT_SHA \
  --output NEW_PRIVATE_BOOT
```

The brackets are explanatory placeholders, not runnable argv. Old prepared files
and markers refuse. Root alone may materialize/prepare/boot after fresh Source/
authority/resource review. New success status is
PASS_EMULATED_ARM16K_GLIB290_REAL_SEAT_UI_LIFECYCLE_ONLY, never native/M2/release.

## Checks actually run

The fenced suite covers inherited input/confinement/receipt/PAM/seat/GUI joins,
explicit173→283 counting, finite172 removal, exact-old rollback/version/hash,
all-baseline edges, immutable old172 proposal data, both missing symbols and old
export parity, ELF-table refusals, distinct actor and mandatory post-rollback
ownership/namespace/sync. Commands and actual counts are recorded in RESULTS.json.
Source DATA audit actually passed on old/new/GTK retained bytes; real four-file
pin/metadata gates passed. No new actor, daemon, lease, image, guest install,
preparation or boot ran. Normal ALPM upgrade/removal/rollback, full GTK journey,
native16K, M2/hardware/performance and release acceptance remain Root gates.


## Closed first GLib290 trial and console-frame successor

Root's first trial remains HOLD: JSONDecodeError Extra data at line2/column1,
char10191. The exact private UART is76105B SHA256
`a37a0673696c226e1b1dbf78f9e6a517e7b1d45d71841bb950c3957d4821290e`.
Lines746/750 delimit one nonce-bound SEAT_SESSION; line747 contains a complete
10190B JSON object, and line748 is an ANSI-prefixed systemd start-job status line.
The old decoder treated that diagnostic as JSON trailing data. All six seat checks
and283 installed packages were present, but NO UI_SESSION frame was retained.
GTK actions, normal removal, original-GLib rollback and normal logout are therefore
NOT ESTABLISHED. The old owned supervisor reported exit0/reaping/EMPTY_TWICE,
but retained QEMU stderr proves actor-issued SIGTERM; it was not a natural QEMU
closure. Owned-container absence remains a real separate cleanup fact.

The new adapter recognizes only line-boundary start-job diagnostics: finite red
SGR/reset/cursor sequences, six-character star indicator, at most2 jobs, bounded
minute/second timers and exact names or bounded ellipsized suffixes of the two
fixed UI fixture/observer unit descriptions. At most16 such lines fit one bounded
frame. Arbitrary text/ANSI/units, additional JSON, foreign/duplicate markers,
truncated payloads, nested/interleaved frames and interior-line injection refuse.
JSON bytes are not edited; a strict reconstructed seat frame goes through the
UNCHANGED frozen lower validator. The same syntax gate applies to the UI frame.
No semantic seat, policy, trust, rollback or acceptance predicate is waived.

`data/console-status-minimum.data` preserves only the exact observed118B status
line (including its cursor-return CR), marker nonce and a synthetic non-acceptance
JSON object. Its origin JSON pins the private original and exact10190B payload
hash; no private properties or credential data are committed. Source controls now
number71. A separate actual76105B UART DATA check passed the unchanged lower
validator after reconstruction and confirmed the original JSON bytes/hash match.
This is a codec check over a closed HOLD, not a replay or fresh guest success.
A new Source lock/publication/authority/nonce/preparation is still Root's scope.


Closed GLib290 r2 and natural private-session closure successor

Root's closed r2 remains HOLD. Actual client receipt522B SHA71fe9bb575c58189e9e3526a8e0adf643bb59f64c942f8ea6d187deb78565bf4 records launcher exit0/REAPED/EMPTY_TWICE/output-complete/no timeout but passed=false/signals=[SIGTERM]. GTK stderr and Xvfb log are empty. These facts do not establish GTK controls, removal, old-GLib rollback or full guest acceptance. Root's read-only extraction preserved originals; the initial conversion succeeded but its1.5GiB allocation postcheck held at1,764,077,568B. Root later read-only reused/compared that derivative without conversion replay.

The pinned supervisor begins retirement at leader terminal status, immediately signals a still-live original group/session member, and requires no signals for PASS. The retained receipt cannot identify which descendant was live. Do not attribute it to a particular daemon or claim the new adapter has repaired an actual guest.

The new local client launches a fresh reserved Python session leader, which starts exactly the original dbus-run-session/xvfb-run/GTK argv without a new session. The unchanged pinned helper owns that direct launcher through raw reap/output drain with an82s cap; any forced cleanup remains HOLD. The wrapper then read-only observes the reserved original group/session until leader-only twice, bounded by one3s deadline, without sending signals or reaping arbitrary children. Only then does it emit the original GTK stdout and exit naturally. Its outer unchanged90s group supervisor still must prove passed=true/signals=[]/EMPTY_TWICE. GTK probe/window.close(), policy, all controls, signed ALPM and rollback predicates are unchanged. No global or escaped-descendant absence is claimed.

New private0600/fsynced receipts are /home/builder/UI-runtime/{session-lifecycle.json,session.stdout,gui.stdout}. Lifecycle records the exact fixed argv, launcher retirement, remaining members with numeric identities and bounded process names, and bounded changed/final censuses. Each receipt<=128KiB; no environment, credentials, keys, pixels or user file contents are recorded. Existing UI_CLIENT_REPORT.json references raw stdout/lifecycle hashes, preserving output before any retirement assertion. Root may recover these fixed paths after a closed HOLD; private process properties should not be published. New constructor/source/authority/nonce preparation is required. Worker ran actor-fenced source controls only; actual successor GUI/session remains NOT RUN.


Closed r3 component progress and post-removal runtime successor

Root's closed r3 is still HOLD; the source successor below has not run in a guest. Its read-only extraction preserved original raw/overlay and all28 requested receipt associations. Actual UI_READY_FOR_REMOVAL1403B SHA802b1b856a0b5dd4d0b29d495570dbe41e5952b6d7330fa4a4b643b787016771 contains PASS_REAL_INSTALLED_GTK_CONTROLS: real X11/Cairo window, inspect/preview read-only, explicit apply, repeated apply preserving edit and a3MiB private pixel read/hash. GUI stdout839B SHAeb0c01adec92a390d8d3256d58a1409085d12437382e64bf20aa6a68c8f20ecb equals session stdout. Session-lifecycle1091B SHAf410d75e9574cd477719fe5396a06a9d29623e7b62d6b6405b693d83db1dccf3 records natural launcher exit0/no signals and leader-only twice; outer GUI exit0/REAPED/no signals/EMPTY_TWICE passed. GUI stderr and Xvfb log are empty. This establishes those emulated software components, not the whole lifecycle or target hardware.

Trusted normal172-package removal command177 passed exit0 (183B/046977a8db69665c2e4cee1ae89adb4512d084be8f5541e33829bde077df7f1a). Command178 failed sync-post-remove/syncfs-refusal (200B/352847945a2b9c5498640afead0665952f54bcb6ef80be0963214177dba09d79); its actual errno was not retained. Terminal-hold sync started only, final client report is absent, and no rollback/restored receipts exist. OldGLib rollback,111 restoration, final user recheck/logout/full acceptance are NOT established. UART ModuleNotFoundError masks the root failure; its exact missing module was not retained. Do not claim a measured syncfs cause or that the source correction already repairs it. Private actual receipts remain /dev/shm/cachy-asahi-ui-glib290-r3-failure-DATA-root-20261115-r1; Root canonical record Root-UI-glib290-failure-extract-r4. No public durability is implied.

The root observer previously loaded its failure schema and final-result module only after ordinary removal had deleted the Python package. It now loads exactly those two fixed Source validators at startup while the runtime is installed, then calls the same validation functions without dynamic loading after removal. The existing ctypes syncfs operation is bound once before the first installed-phase sync and retained; later sync boundaries use that same function/errno check without recreating CDLL/function objects. An unprepared binding or nonzero actual syncfs result still fails. No syscall, trust, ALPM, filesystem predicate or rollback order is waived.

Finite post-removal operation audit: root subprocess.run/timeout, JSON/writer, Path/stat/hash and ownership-Qkk parser paths are already exercised by installed checks; the user file-walk/hash function is now also exercised against the actual GUI hash map before READY and reused unchanged afterwards. Rollback ownership loads plain pinned JSON, not tar/gzip/build code. Original GLib rollback remains normal signed ALPM, followed by the same Qkk/new-only-path/original-payload/inventory/dependency/user/policy checks. This is targeted reuse of needed resident code, not blanket importing the standard library or keeping an extra package installed.

New bounded durable root diagnostics runtime-error-{sync-post-install,sync-post-remove,sync-post-rollback,sync-terminal-pass,sync-terminal-hold,root-stage}.json use the existing0700/0600/fsync Writer; they contain only nonce/stage/fixed operation/exception category/validated module identifier/numeric errno. They never include exception text, traceback, key/user/file contents or arbitrary paths. Root observer independently writes /var/lib/arm16k-virtio-seat/receipts/ui-observer-error.json with the same sanitized schema on failure; failed diagnostic persistence still cannot turn HOLD into PASS. Client failure metadata also retains a bounded module identifier/errno. These paths can be included in a future Root DATA-only receipt recovery if needed.

Source verification includes blocked-all-fresh-import controls for cached sync binding, preloaded failure/final semantic validators and primed user-file walk; real errno/unprepared binding/altered user files/failure-schema/refusal controls remain strict. Tests do not perform actual syncfs, installation, removal, foreign code execution or VM work. Root alone may admit fresh Source/public pins/authority/preparation/nonce and a new trial.


Closed r4 write-cap diagnosis and explicit resource successor

Root's r4 remains HOLD. Its inner report, not the outer wrapper's failed natural-exit assertion, supplies actual cleanup/seat facts. Root's32path DATA extraction passed originals-unchanged/owned-container-absence; new runtime diagnostics, final client/failure/restored receipts were absent. Its root stage is trusted-remove; command177 is only STARTED/exitnull (187B/24ea38d3f5d18256c816cd9100df2c21e8399571d3de6a25d3e2ff1b69ae1af7). Do not transfer r3's successful command177 exit0 to r4. GUI/session natural close remains separately established; full removal/rollback/restoration/logout did not pass.

The actual r4 UART first reports vda WRITE I/O errors and EXT4 warnings at191.988s (normalized line813), then additional failed writes. Its overlay file is exactly1073741824B, allocated1073680384B. The Source actor explicitly set RLIMIT_FSIZE soft=hard1GiB immediately before QEMU Popen, inherited by QEMU. Docker had no --ulimit override; the frozen command runtime's64MiB limit affects Docker CLI children, not the daemon-created actor. This reached binding and actual guest write errors establish an inadequate actor disk limit. The host write errno was not recorded; EFBIG is an inference, not a measured errno or sole quantified cause. Retained report3773B/ac51d70f7ac99f56aa54c5193d6a77711eb92fbbe482993412518775d2562ce5 and UART145056B/22fd1506fff07251884d01a0e4b7bfad63beb3b5ad4e13e8a117f2d10c7e0f78 remain unchanged.

All four closed GLib290 QEMU logs are76B/ca9072704259a241e682adf79f8ecde682e86d9163a23782581e010c84562b55 and state termination on signal15 frompid1(/usr/bin/python3). The actor sent SIGTERM on STOP/deadline before transferring wait ownership to the pinned supervisor. Therefore the old helper signals=[]/exit0/EMPTY_TWICE do not prove QEMU received no signals or exited naturally. Earlier wording implying natural actual-QEMU closure is withdrawn; reaping/owned-container absence remain valid. Frozen old code/results/trials are not rewritten.

The new local actor applies exactly2GiB RLIMIT_FSIZE (never raises an inherited lower hard limit), records actual actor limits and reserved child's /proc limits/start identity/SigIgn, and records QCOW file/allocated sizes under2GiB. New0600/fsynced actor-file-limits.json,qemu-file-limits.json,overlay-at-qemu-exit.json are bounded16KiB each. The Source keeps3GiB virtual raw geometry unchanged. File-offset limiting and final physical allocation checks are distinct; an oversize or missing proof refuses acceptance. The planned2GiB budget is not a claim that a new guest has completed it.

Every actor-issued SIGTERM attempt now records STOP/deadline/actor-cancel reason separately from supervisor signals. Such a signal or a child-diagnostic error makes natural_without_actor_signal=false and passed=false even if the unchanged helper later reports exit0/EMPTY_TWICE. The actor always transfers exclusive retirement ownership, including diagnostic refusal. Host reports retain these facts on HOLD and start guest_shutdown=NOT ESTABLISHED; only an actual QMP request after proved normal PAM logout gets that narrower description. No actual guest-poweroff or hardware claim follows.

Root approved5GiB memory=swap(no extra swap) for the boot owner:2GiB guest+2GiB tmpfs overlay+1GiB overhead, with hostMemAvailable>=7GiB including2GiB reserve. The new custody adapter verifies raw5GiB first and projects only memory/memory-swap plus the already reviewed actor Cmd into the unchanged frozen3GiB guard. All network/capability/mount/domain/CPU/PID/policy checks remain. Preparation memory remains3GiB.

Storage admission is staged, not a fictitious whole worst-case reservation: fresh preparation requires1.5GiB physical budget+2GiB reserve. After its actual physical bytes are known, fresh boot requires NEW available quota AND filesystem headroom>=6GiB+32MiB, excluding already charged preparation:2GiB overlay+2GiB future DATA conversion+2GiB reserve+32MiB non-overlay output slack. Root wrappers check ownUID quota; constructors enforce filesystem floors and measured output caps. If a full1.5GiB preparation leaves insufficient headroom, stop before boot. Before any later diagnosis Root independently re-admits2GiB conversion+2GiB reserve; no automatic conversion actor is launched.

Docker CLI log files are independently limited1MiB in their child process, QEMU output remains1MiB, and existing UART/frame bounds remain. Boot non-overlay allocated output is capped32MiB including a reserved512KiB final report. Preparation total allocated files are capped1.5GiB; all immutable materials/original111/accepted155/platform/PAM/kernel/trust/GUI/ordinaryALPM rollback predicates remain. Root's actual r4 preparation was996036608B including raw797597696B; these are observations, not new limits. Root may retain closed failed disks on HOME with whole hashes; no accepted reference retirement or worker deletion is assumed.

Tests model the actual1GiB boundary and unrecorded SIGTERM regression, bounded physical-file fixtures, exact2GiB actor/child limit proofs, staged admission, old4GiB/wrongswap refusal and log caps. No actual resource limits, guest/daemon/process actor, lease or network were used. New actor/source/authority/nonce/preparation/VM remain NOT RUN until Root's fresh admission.
