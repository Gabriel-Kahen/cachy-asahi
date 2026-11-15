# Concrete host successor boundary for Root review

**Review operand:** `host-contract-v2.json`, SHA256
`c15bf77254ee4c857c31036004e7a663a5b3d7ec25f49e59c10a4ea3e1d942d6`.
This successor preserves commit55aa3ae1 and all actual refusals. Root reviewed
this concrete boundary before the [actual signed host journey](RESULT-20261114.md),
which now passes its finite installed lifecycle. The JSON contract is unchanged.

The immutable image,82101-byte exact tool archive,17-file payload and genuine
packet pins are unchanged. The original inherited ARM/common modules, original
tool package and all frozen runtime/verifier bytes are unchanged. Scope remains
one host-x86_64 rootless Docker candidate, with no native/M2/release admission.

## Exact container/resource command

Variable operands below are a fresh random name, its unique128-bit nonce, private
copied input/runtime directories and fresh private evidence directory. Their exact
bindings are checked against parsed Docker HostConfig before container start.
No persistent Docker volume, host system or producer-checkout mount is used.

```sh
docker create --name "$NAME" --label "cachy-asahi.audio-candidate=$NONCE" \
  --pull=never --platform=linux/amd64 --user=0:0 --read-only --network=none \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=128 --memory=2g --cpus=2 \
  --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER \
  --cap-add=SETGID --cap-add=SETUID --cap-add=SYS_CHROOT \
  --tmpfs /alpm:rw,nodev,nosuid,exec,size=1g,mode=700 \
  --tmpfs /scratch:rw,nodev,nosuid,noexec,size=1g,mode=700 \
  --tmpfs /test-home:rw,nodev,nosuid,noexec,size=64m,mode=700 \
  --mount "type=bind,src=$INPUTS,dst=/inputs,readonly" \
  --mount "type=bind,src=$RUNNER,dst=/runner,readonly" \
  --mount "type=bind,src=$EVIDENCE,dst=/out" \
  --env "CACHY_ASAHI_AUDIO_CANDIDATE=$NONCE" \
  --env CACHY_ASAHI_IMAGE_ID=sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145 \
  --env TMPDIR=/scratch \
  --entrypoint=/usr/bin/python3 \
  sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145 \
  -I -B /runner/journey.py --contract-sha256 "$PRIVATE_CONTRACT_SHA256"
```

Exact six-cap mask remains0x400cb, with zero inheritable/ambient, NNP1 and active
default seccomp. No privileged/unconfined setting or namespace fallback exists.
An actual **create-only, never-started** probe confirms Docker's exact resource,
capability, mask and readonly-path declaration. That probe was removed and its
label census is empty. It is not transaction evidence.

`/alpm` must be a distinct root-owned mode0700 tmpfs of exactly1GiB, nodev/nosuid
and executable. All three tmpfs roles must initially be empty with distinct
filesystem identities and exact sizes. The actor exclusively claims a mode0600,
single-link33-byte owner marker containing its nonce, and rechecks it before
every command. `/scratch` and `/test-home` remain noexec for data and private TEST
key material. A noexec work volume refuses before mutation; no interpreter
workaround is used.

## Complete standard engine mount profile

The full engine declaration must equal these fixed lists; changed, duplicate or
additional paths refuse before actor start:

- Masked: `/proc/acpi`, `/proc/asound`, `/proc/interrupts`, `/proc/kcore`,
  `/proc/keys`, `/proc/latency_stats`, `/proc/sched_debug`, `/proc/scsi`,
  `/proc/timer_list`, `/proc/timer_stats`, `/sys/devices/virtual/powercap`,
  `/sys/firmware`.
- Readonly: `/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/sys`, `/proc/sysrq-trigger`.

Every declared masked path that exists in the guest must actually be a mount.
Seven fixed proc file masks may use only tmpfs/devtmpfs rooted at `/null`, with
rw/nosuid and a nonsymlink character1:3 node. Their path must also appear in the
actual engine declaration. Fake files, symlinks, different devices, other roots,
unknown mask paths and unmounted existing targets refuse. The five directory
masks retain the inherited exact readonly-tmpfs identity policy.

The six standard `/dev` mounts retain exact character major/minor, filesystem and
device-leaf-root checks. The new executable work volume is explicitly checked.
Only these fully validated new roles are projected out; every remaining mount
faces the unchanged inherited validator: readonly overlay root; readonly copied
inputs/runtime; dedicated writable evidence; standard proc/sys/dev/devpts/shm/
mqueue/cgroup mounts and their security flags; and Docker's three fixed metadata
file mounts. Those metadata files must remain root-owned nonsymlink regular and
not group/world writable. All extra, nested, host-source, Docker socket or hardware
mounts refuse. Actual rootless UID/GID maps and loopback-only networking remain
required.

## Exact copied-root and command journey

The unchanged helper's copied-root operation targets `/alpm/system`, with its
capacity/reserve check measured on `/alpm`. The copied `/usr`, `/etc` excluding
gnupg and local ALPM DB come only from the immutable image. Four root compatibility
symlinks are accepted only after exact source checks: `bin,sbin→usr/bin` and
`lib,lib64→usr/lib`. They are recreated inside the private copied root.

Helper-created cache/hook-mask directories are moved to noexec `/scratch`.
Unused native template configs are retained under `UNUSED-HELD-TEMPLATE-*` names.
The actual consumed x86_64, local-only Required/TrustedOnly config is retained as
`ACTUAL-host-pacman.conf`, hashed and rechecked before every pacman call.

The exact pacman prefix is recorded in the JSON contract: custom config under
`/scratch`, root `/alpm/system`, DB `/alpm/system/var/lib/pacman`, private verifier
`/test-home/verifier`, noexec cache/hook masks under `/scratch`, bounded evidence
log under `/out`, noconfirm and no color. There are no configured repositories.

Sequence: unsigned exact-archive refusal with unchanged inventory; ephemeral TEST
Ed25519 one-day signer/SHA256 and separate full-fingerprint verifier; signed
`-U --noscriptlet`; exact inventory,17-file payload/ownership, `-Qkk` and `-Dk`;
direct execution of `/alpm/system/usr/bin/cachy-asahi-audio-sources check` and
`verify` on the genuine packet; same-version signed reinstall and repeated
installed checks; actual `-R --noscriptlet`; exact base inventory/all package files
absent and caller packet/sentinel preserved. No source/audio/plugin code runs.

Private TEST agents and key homes retire, then only the nonce-labeled container
is removed. Confirmed absence is required. Unacknowledged create outcomes remain
UNKNOWN even after an empty immediate census. Every process retains existing
bounded pipes,60-second guest command/180-second actor deadlines and scoped reap.

Boundary/resource controls and the actual TEST signature,
installation/reinstallation/removal/installed packet verification pass. The parent
process explicitly uses the already declared noexec `/scratch` for temporary
input files; the first attempt without this setting is retained as failed setup.
Existing
compiler, original-binary, source/legal, wmidi, security, native ARM/16K, M2/audio,
performance, production trust and release holds are unchanged.
