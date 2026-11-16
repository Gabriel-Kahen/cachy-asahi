# No-package boot/session metadata control

This family implements a public packet constructor, a separately Root-authorized
controller, and its cap0 rootless VM actor. **Source and MODEL validation only;
no actual control has run.** All operator templates leave Root choices and
acceptance unissued. The maintained family includes the exact metadata reader
and tests from author commit `c9ac118ec3308dbf042c15e2af216772a48d9525`.
`prepare.py --reader` snapshots that whole pinned source without importing it.
An API-compatible substitute with different bytes is refused. The reader is
12810 bytes / SHA256
`94a755ab24b940a809f53a78faf90a851ded9f14d28c0fdb9cf75f5e01c59f23`.

The production comparison is Source65 author commit
`57c0aa8ad61b8128cc7a224030bebbc759a41df3`, family
`09bd4c22062ca3b4c23019ff3564bd51c860d355`, 65 files/740759 bytes, lock10598 bytes /
SHA256 `9324c8e79374ba95e5b2ce37e389b3e5732cf6c079ca6857b35205932ad5a61a`.
Its production bytes and `image.preserve` remain unchanged. The maintained
65-file dependency has a test-only amendment: two intentional `pidfd_open`
models use explicit attribute creation, and a negative control verifies that
the original peer refuses an absent API before process-identity access. Only
`test_controls.py` and its regenerated `source.lock.json` differ from the author
family. The whole amended dependency is741718 bytes, tree
`60d81a3fec1110aa78ba691703fb7922ac7c490b`, lock10598 bytes / SHA256
`da1c8749a281b767f50ca696cf7818d1925aa852057d7de011b4c3ddd8eca75d`.
The adapter seal, public input template and packet comparison join that exact
whole dependency pin; A's three production helper pins remain byte-identical.
Case14 is consumed HOLD;
Root-reported guest PASS/natural exit0 and `/var` mtime drift supply context,
not acceptance or a proven creator. Nothing reenters case14.
This public branch starts directly at Main
`a246137c558001746a8e82f1e3f68720e2a02f8e`, which carried Source56. The
Source65 production upgrade and explicitly sealed test amendment satisfy both
the adapter and reader helper pins; no author branch history is merged.

## Runnable source interfaces

`contracts.py` supplies closed public schemas, canonical bounded nofollow JSON,
streaming stable-file pins and separate fresh Root authority/admission validators.
It does not authenticate a signer. The external admission is a required explicit
Root assertion that Root's outer CUSL/S wrapper supplies whole-process resource
and canonical exclusive custody enforcement. This adapter validates that exact
assertion and joins, while the outer wrapper owns the live lease/FD/conflict
protocol; the assertion alone is not independently verified live custody.

`prepare.py` reads only the filled public choices JSON, public reader source and
pinned Source code. It checks the synchronous `observe` API below using
AST parsing without importing the reader, then creates a fresh private snapshot:
`control-packet.json` and `raw_metadata.py`, each0400, directory0500. It never
reads a baseline, kernel, credentials, lease or image; invokes no process; and
performs no live quota sampling. The HOME profile's `prepare` output means this
constructor snapshot, not an image-preparation actor.

Root fills `operator-inputs.TEMPLATE.json` with fresh nonce, original baseline
nonce, exact case14 kernel/tool/reader pins, six actor tool pins, serial timing,
idle and finite resources. Known original baseline pins are fixed; no old-kernel
fallback or package material role exists. Root joins the filled choices to its
accepted baseline/kernel facts. The two public declarations are not evidence
created by this worker.

```sh
python3 -I -B scripts/integration/arm16k_no_package_control/prepare.py \
  --inputs /ROOT/FILLED/control-inputs.json \
  --source-lock-sha256 EXACT_NEW_SOURCE_LOCK_SHA256 \
  --reader /ROOT/REVIEWED/scripts/integration/arm16k_no_package_control/metadata_raw_reader.py \
  --output /ROOT/FRESH/control-packet
```

`controller.py` requires the independent Root authority and admission, exact
packet/Source/resources/reader/kernel/baseline/credential joins, private disjoint
fresh output, explicit current Docker CLI/endpoint and current resource guard.
Root fills `authority.TEMPLATE.json` and `admission.TEMPLATE.json` separately;
none of the commands below issues them. All grants are closed, accepted Root
DATA with at-most-hour validity, covering the entire requested run at entry.
Completion rechecks freshness and joins without requiring another run window.

```sh
python3 -I -B scripts/integration/arm16k_no_package_control/controller.py \
  --execute-root-bound-control \
  --packet /ROOT/FRESH/control-packet \
  --baseline /ROOT/EXACT/original-baseline \
  --kernel /ROOT/EXACT/case14-kernel \
  --credentials /ROOT/PRIVATE/original-credentials.json \
  --authority /ROOT/FRESH/control-authority.json \
  --authority-sha256 EXACT_AUTHORITY_SHA256 \
  --external-admission /ROOT/FRESH/control-admission.json \
  --source-lock-sha256 EXACT_NEW_SOURCE_LOCK_SHA256 \
  --output /ROOT/FRESH/control-output
```

These are future Root operator interfaces, not invocations performed here. Host
execution needs Linux `os.pidfd_open` for the unchanged authenticated QMP peer
primitive and Root's current rootless Docker transport. The reader is physically
included; its separate private packet copy is selected by the constructor.
After validating both public grants, the controller refuses a missing native
`pidfd_open` before private inputs, output creation or transport. CI models
explicitly create their test doubles; they provide no substitute runtime API.
The controller has no default daemon, image, kernel, secret, nonce, timing,
quota profile or Root admission. Inputs, snapshot and output must be disjoint.

## Exact execution and cleanup

1. Verify both public grants before private reads. Validate the actual explicit
   Docker CLI and transport before reading original baseline/credentials. Sample
   the Source65 whole-owner storage/RAM guard. Verify original raw/prepared and
   private credential pins, original nonce/raw lineage, and admitted built-in
   ARM16K/PL031/RTC kernel configuration. Whole-original-image digest checks stream
   64KiB chunks; they do not extract or inventory guest file bodies. No final
   readback whole-image digest is computed.
2. Record a once-only marker in the fresh **control output**, never the original
   first-boot marker. Launch only the pinned code/tool image: read-only root,
   cap0, NNP, no network/device/KVM, explicit CPU/RAM/swap/PID and output limits.
   Mount only original `guest.raw`, the two kernel files, public code/packet/
   reader, and one writable output. Credentials stay host-side, absent from
   actor mounts and argv. The original baseline directory is not mounted.
3. The actor establishes the assigned deadline and guards before tool/kernel
   verification. It validates the fresh admission epoch before any metadata read.
   It reads original host raw size/identity, calls only the pinned
   reader for fixed metadata, and creates a private qcow2 overlay backed by the
   read-only original raw. QEMU matches Source65 virt/TCG/max/RTC geometry and
   Root-selected CPU/RAM, with only original baseline nonce and RTC epoch tokens.
   No Perl case token, package service, guest staging or restoration helper exists.
   Each scan has its own at-most120s deadline inside the overall deadline; the
   minimum `boot_seconds` includes both120s budgets. After the preboot scan and
   overlay creation, `qemu-epoch.json` records fresh host UTC immediately before
   QEMU launch. Its exact pin is included with actor observations.
4. Authenticate the original QMP peer/actor PIDFD/start/argv using unchanged
   `Source65.controller.QMPPeer`. Readiness allows the120s scan plus the prior20s
   socket bound. The peer vector uses the fresh launch epoch, never the earlier
   admission epoch; stale/future/wrong-case values refuse. Perform ordinary builder PAM login and the
   unchanged `/usr/local/libexec/arm16k-login-proof`. Require exact18-field
   ARM64/16K/systemd/logind/DBus/login proof, then send the pinned serial-only
   `after_login` probe. Wait the Root-selected `idle_seconds`, send
   `before_logout`, require ordinary PAM logout, and quit that authenticated QMP
   peer. No ALPM query/transaction, GPG or package archive is issued by the control.
5. Require natural QEMU group reap and exact argv. Convert only the disposable
   overlay, perform journal-only replay on the disposable verification copy
   (return0/1 only), then read-only fsck. Call the reader for final fixed metadata.
   The original raw identity must stay unchanged. Write exact bounded observations
   before deleting verification scratch; a failure retains scratch for Root.
6. The controller joins actor bindings, receipt pins, natural QEMU/argv and both
   guest frames; reports all four phases; rechecks inputs and grants; waits for
   the natural actor exit; removes only the verified stopped owned container;
   and verifies absence. Normal cleanup uses no force or signal. Failure cleanup
   reserves25s for normal QMP/owned retirement and35s for existing owned-only
   fallback. A fallback, signal, budget failure or incomplete cleanup stays HOLD.
   Raw serial/passwords and arbitrary exception strings are never written into
   the report; only validated proof/metadata and fixed failure categories survive.

Output `COMPLETE_NO_PACKAGE_METADATA_OBSERVATION_ONLY` means the observation
protocol and cleanup completed. It is **not** preservation PASS, a baseline
certificate, ALPM/runtime qualification or Root acceptance. Those fields remain
NULL even if every observed field happens to match. Private scratch/logs remain
inside Root's bounded output. No raw/image/credential input was opened here.

## Reader and metadata contract

The separately selected reader source is mounted at `/reader/raw_metadata.py`.
Its narrow API is
`observe(raw_path,debugfs_pin,deadline,*,legacy_root,guard)` returning:

```python
{"observed_paths": list(metadata.PATHS), "nodes": {present_path: metadata_row}}
```

It must complete every fixed literal lookup before attesting coverage, call the
guard during bounded reads, refuse aliases/unreadable/unsupported metadata,
and never call inventory or read regular-file bodies. Omitted covered nodes mean
proved absence; partial lookup is not absence. The constructor checks only API
shape and exact maintained whole-source pin, not runtime reader safety. Root
separately reviews and admits the operation.
The actor passes the admitted `/usr/bin/debugfs` pin from `actor_tools`, the
fixed `/legacy` Source65 directory, its per-scan deadline and live actor guard. There is
no fallback to the earlier `scan` proposal. The reader's standalone interface is:

```sh
python3 -I -B /reader/raw_metadata.py --raw /input/image.raw \
  --legacy-root /legacy --debugfs-pin-json '{"bytes":N,"sha256":"HEX"}' \
  --deadline-monotonic END
```

The adapter uses the Python API directly; it does not spawn that CLI or interpret
its stdout as a substitute for the bound return value.

The15 selected paths are `root`, `etc`, `etc/audit`, `etc/udev`, `usr`, `usr/bin`,
`usr/lib`, `usr/share`, `var`, `var/cache`, `var/cache/ldconfig`, `var/lib`,
`var/lib/pacman`, `var/lib/pacman/local`, `var/log`. The11 fields are type, mode,
UID/GID, inode, links, size, mtime seconds/ns and atime seconds/ns. No xattr values,
ctime, child names, body/hash dump or SSH/GPG lookup is part of the observation.

`metadata.project_scan` requires explicit exact15-path coverage. `parse_frame`
requires one per-probe64KiB slice,8KiB selected frame, exact ordered paths and
nonce/stage, canonical numeric/UTC9ns fields and no replay. The clean env-i
base64-to-Bash serial transport writes no guest file and cannot echo a frame tag.
Each public parent must be canonical/searchable before absence classification;
`/root` itself is stat-only via `/`, without searching private contents.
`compare_phases` reports presence/all fields across offline-before, after-login,
before-logout and offline-after, with atime observational only and no waiver.

## Existing rules and causal limits

The old first-boot `arm16k_systemd_tcg_guest/boot.py` supplies the original PAM/
proof/logout exchange but binds an old kernel and writes the consumed baseline
marker. C01 RTC always installs/removes packages. This adapter reuses pinned
Source65 runtime, budget, frozen ownership and QMP peer primitives through
`support.py`, without changing their bytes or fabricating a Perl packet. It
shares the runtime's in-memory contract object solely for deadline enforcement.

`rules.review_policy` remains pure exact Source65 policy review. Its payload
namespace is confined to `/usr` (literal `/usr/local/` descendants excluded) plus
the exact baseline `/etc` exceptions. Valid Source65 inputs have **no `/var`
timestamp allowance**. Directory eligibility is only the explicit certified
payload/DB/cache sets, conditional absent-log `var/log`, or fixture directories,
and applies only where the original comparator compares a path. New-residue
prefixes are literal; there is no global complete-namespace equality. Strict
`/etc` and root identity/absence gates remain additional unchanged requirements.
No package-lifecycle allowance normalizes or accepts this control's observations.

The actual case14 payload-expanded eligibility set and remaining residues are
not claimed: no actual runtime certificate was opened. Root must join a bounded
policy projection to its accepted certificate. The supplied ten-directory
public packet cannot classify every path or supply15-path coverage.

After-login combines boot and login; there is no early-boot checkpoint or atomic
cross-path snapshot. A matching control change supports a boot/session-class
explanation, not creator identity. A package-only change is not proof of ALPM
causation. Original-to-final package metadata includes preparation effects;
a future matched comparison needs a Root-pinned prepared-before-VM projection.
Timing, services, probe observer effects, fixture staging and unmatched duration
remain confounders. Root must select timings/resources matching its comparison;
no current actual case14 duration or kernel pin is invented. Unknown/unobserved
paths remain unreviewed/HOLD. Native ARM/M2, performance and release remain unrun.
