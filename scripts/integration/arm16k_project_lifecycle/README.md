# Signed project-package lifecycle in a fresh emulated ARM16K guest

Current source is a **source-only diagnostic successor** to the closed r5 trial.
Root observed trust/gpg exit2 before ALPM installation; its underlying reason is
not present in sanitized retained evidence. See [GPG-DIAGNOSTICS.md](GPG-DIAGNOSTICS.md)
for the bounded persistent-receipt/date export contract. No image has been prepared
or booted from this successor. Historical r5 commands/pins below are closed records.

This opt-in workflow uses the genuine retained `cachy-asahi-ksmctl0.1.0-1`
read-only diagnostic. The historical r4 guest stopped before trust/ALPM because
cmp was unavailable; corrected r5 reached trust verification and held at gpg2.
Both inputs/markers/trials are closed. Current diagnostic source has no fresh
prepared image. Root owns fresh launch/admission. Native16K, M2, KSM policy/functionality,
performance, source/legal completeness and release acceptance remain separate.

The prerequisite Root first boot genuinely passed normal serial PAM
login/logout, aarch64/16384 pages, PID1systemd, logind/D-Bus and emulator/container
retirement. Its report is pinned at1,634 bytes,
`36de34652c9d008b4edaa6e8d12e87d10d96fc62044ba9e30ea44793908efa4d`.
This constructor preserves that report, the consumed marker and original raw
image byte-for-byte. It does not replay the old actor or marker.

## Finite materials and declared closure

`inputs.lock.json` pins the exact archives, signatures, public keys, native
retention receipts, prerequisite raw/kernel/proof and read-only reference code.
No download, build, host install or upstream/package-code execution is needed.

| Material | Bytes | SHA-256 |
| --- | ---: | --- |
| cachy-asahi-ksmctl0.1.0-1-any | 17,244 | `b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a` |
| python3.14.8-1-aarch64 | 13,588,352 | `5e00dbb30ab55fd160d64205e1f3418c8bcf5b295ff07bf9af7ad4ab85bc6984` |
| mpdecimal4.0.1-3-aarch64 | 93,808 | `388611eba7f9b0dddcc03adb4f28bcb8fd2c42fbd8c930ca6b9b0f9e4ece0f1e` |

The KSM archive is the genuine retained baseline pair from native run39139213293,
source72ea5a1e81268f08da9b9cc04cdc7e23a1a9ff8a. Its retained TEST signature and
public key now independently verify under
`7E73A80AF8FD5DA6529EF27E1AB823DC28925AA5`. Its five installed files match the
current diagnostic source; CLI SHA-256 is
`f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558`.
The0.1.0-2 management candidate is not used. The original native receipts provide
archive association; the new mathematical TEST signature check establishes no
release trust or new native acceptance.

Both retained ALARM signatures independently verify under
`68B3537F39A313B3E574D06777193F152BDBE6A6`. Python requires bzip2,expat,gdbm,
libffi,libnsl,libxcrypt,openssl,zlib,tzdata,mpdecimal,zstd. Only Python and mpdecimal
are absent from the exact111 baseline. mpdecimal's glibc/libgcc/libstdc++
requirements already exist. The declared transaction is exactly111→114→111;
it replaces/upgrades no baseline package. Actual version comparison uses only
ALPM16, lazily loaded with explicit refusal if absent; portable controls model
that ABI seam without introducing a runtime fallback. ELF DATA inspection checks
82 aarch64 runtime objects for16K LOAD geometry. One packaged relocatable object
is explicitly DATA with no LOAD/runtime/compiler acceptance. Runtime compatibility
is still untested. These are upstream Python bytes, not the separate project
Python3.14.8-1.1 source candidate.

## What the separately admitted guest would do

Offline preparation sparsely clones the original raw file, creates a new
nonce/machine ID/filesystem UUID and private TEST password, and installs only
explicit fixture files. Original kernel/config and stock systemd/PAM/login ELF
pins are checked unchanged. Each injected regular file is read back from ext4
with its content, UID/GID and mode independently checked. No ARM program runs.

A root oneshot in this disposable clone is bound to the exact fresh kernel
nonce and a guest-only consumed marker. It accepts no caller package arguments.
It imports the two pinned public keys into a new private guest TEST trust
directory, with explicit local ownertrust. A dedicated pacman config enforces
`Required TrustedOnly` signatures. Ordinary `pacman -U` installs precisely the
three pinned archives, and ordinary `pacman -R` removes exactly their names.
There is no `--nodeps`, assumed dependency, hook masking, scriptlet suppression,
host trust change or system-wide TEST enrollment.

Before another image is prepared, `tool_namespace.py` reads the exact pinned
rootfs as DATA and recomputes the selected111 namespace. The source-bound
`tools.lock.json` records the manually reviewed complete finite command list:
31 baseline external tools, plus Python/projectCLI from their signed post-install
archives. Symlink resolution, executable mode and exact package ownership are
checked, including getfattr,gpgconf,comm and base64. Shell builtins/functions are
listed separately. Runtime first checks the same fixed baseline list before any
sentinel, trust or package changes.

`same_bytes` replaces every cmp call with exact binary equality through
`base64 --wrap=0` and Bash comparison. Both inputs must be ordinary non-symlink
files, each at most16MiB. Encoder/stat failures propagate; NULs and trailing
newlines remain significant. No hash-only equality or new diffutils package is
substituted. An ERR/EXIT path exports only allowlisted phase/tool/source labels,
numeric line/exit and HOLD status. Raw commands, arguments, environment and
credentials are not exported. Expected diagnostic exits2/3 retain their original
status and do not contaminate failure context.

The service checks the exact111 and114 inventories, normal dependency checks,
all five project file hashes/modes/ownership and unprivileged UID1000 CLI
help/version/status/report/enable-refusal/disable-refusal. Status/report may
honestly return3 for an unavailable KSM interface; that is not kernel KSM
functionality or tuning. No sysfs policy action is requested. User-owned config
and data sentinels plus the private home tree are compared across the phases.

Baseline package paths, file types/modes/owners/links, file hashes, complete
original package DB bytes and xattrs (including ACLs/capabilities) are compared
before and after. Newly exclusive payload paths must disappear. Normal ldconfig
hooks run; afterward only the two known, explicitly unowned generated cache
files/directories are restored to their prior state. Fixture files/markers and
normal runtime logs are separate from package-owned baseline preservation.
Private TEST trust is removed on the successful path. Failures stay HOLD with
their phase/exit; failed disposal never earns a restoration claim.

The normal builder proof waits for this terminal result, emits a separate
30-field lifecycle frame, then runs the unchanged genuine PAM/session proof.
`boot.py` delegates the exact read-only reference controller and existing QEMU
actor, and checks both scopes. It does not create a new VM/native/Reader actor.
The fresh directory has independent project and reference first-use markers.
Old consumed markers remain intact. Root must review before launch.

The unchanged boot contract is virt/TCG2vCPU1536MiB, no NIC/display/KVM/device
forwarding, rootless cap0/NNP/read-only host container,2CPU/3GiB/256PIDs,
480s actor/420s controller,1MiB serial and256MiB overlay cap. The guest service
has240s/768MiB/96tasks limits. It deliberately does not require CPU quotas from
the kernel's absent CFS_BANDWIDTH feature. Offline preparation uses one bounded
rootless cap0 container with read-only base/material/code mounts,64MiB scratch,
2CPU/3GiB/256PIDs and360s stage/600s outer deadlines. Output is capped800MiB;
the retained source materials are about14MB. No original guest source edits.

## Actual checks and handoff

```sh
python3 -I -B scripts/integration/arm16k_project_lifecycle/test_lifecycle.py
```

The prior comparison correction passed37 controls; the current source passes46
DATA, actual private-HOME Bash and modeled controls: signature/material boundaries, unsafe archive
paths, no scriptlet execution while inspecting,16K ELF geometry and explicit
relocatable holds, missing ALPM refusal, finite dependency closure, stale/missing
frames, restoration drift, unavailable diagnostics and admission refusal. They
do not establish an actual ALPM or boot result. Binary/NUL/trailing-newline
comparisons, the exact16MiB limit, oversized/non-regular/symlink refusals, encoder
errors and sanitized failure diagnostics are exercised with the real shell helper.

Historical r5 offline preparation (closed; do not rerun these consumed paths):

```sh
python3 -I -B scripts/integration/arm16k_project_lifecycle/prepare.py \
  --allow-prepare-project-lifecycle \
  --materials /tmp/cachy-asahi-arm16k-project-lifecycle-inputs-20261114 \
  --rootfs /tmp/cachy-asahi-arm16k-inputs-20261114/rootfs.tar.gz \
  --base /tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly \
  --base-first-boot-report /tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json \
  --output /tmp/cachy-asahi-arm16k-project-lifecycle-20261114-r5
```

Result: `PREPARED_NOT_BOOTED`,28 injected regular files read back; eight stock
payload pins unchanged. Whole output allocation640,450,560 bytes. The sole new
preparation CID is independently absent. New admission markers are absent.

- `assembly/prepared.json`:68,688 bytes,
  `719e1a9a43315076ce098cb064fd259b010054dd34581bd7b736ff4cbc83d186`.
- `preparation.json`:13,369 bytes,
  `b76c9b502b81c3a910015dc17c0175bf43bd1147c94948fabe9f58a6048fc727`.
- Raw image:1,610,612,736 logical bytes,
  `6436e85b10f96a56197f8533241cfca707cb143eb0e21bfb1a21592eace98a75`.
- Existing tool image remains
  `sha256:ee1aa3da22a5d89dc1bc273fa818b1d996b7e62851f50d7b629144f6bba9f207`.

Retained refusals/corrections are explicit in `validation.json`: initial
relocatable-ELF refusal; r2's successful assembly held for an outer expected-name
rebind cleanup bug, followed by exact ownership-checked removal; r3 superseded
to include explicit xattr restoration. Those unlaunched raw copies were hashed
and retired for capacity; all logs/manifests/original materials remain. r4 is the
prior clone. Root subsequently ran r4 and observed the explicit missing-cmp
baseline HOLD. It never reached trust/package changes. The corrected r5 is a
new clone/nonce/password/UUID, prepared only after37 controls, static namespace
audit and a capacity guard (10,839,789,568 bytes free in/tmp at preflight). Nine
old input/marker/sanitized-log pins were rechecked unchanged afterward. No actor
was launched by this implementation worker.

The following was the prior r5 admission command. It is CLOSED, has already run
and held at trust/gpg2; it must not be reused with the current diagnostic source:

```sh
python3 -I -B scripts/integration/arm16k_project_lifecycle/boot.py \
  --allow-first-arm16k-project-lifecycle \
  --prepared /tmp/cachy-asahi-arm16k-project-lifecycle-20261114-r5/assembly \
  --prepared-sha256 719e1a9a43315076ce098cb064fd259b010054dd34581bd7b736ff4cbc83d186 \
  --output /tmp/cachy-asahi-arm16k-project-lifecycle-root-corrected-20261114
```

No preparation or boot of the current diagnostic successor has run.
Source/compiler/legal correspondence, current supported
composition/frozen349, native16K, both M2 Airs and release gates remain open.
