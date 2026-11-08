# Versioned generic ARM16K namespace VM probe

This is an alternative **proposed build-environment route** for one unprivileged bubblewrap namespace operation. It does not change the current hosted-Docker matrix, Asahi, any host sysctl/AppArmor policy, an old Source/reader, or a package. No kernel is built. A functioning probe would establish only this finite operation in the selected generic emulated16K guest, not a complete build environment, native ARM package build, M2 behavior, performance or release acceptance.

## Safe default and dependencies

Python>=3.12, standard library only. Source/DATA validation runs without QEMU, namespaces, Docker, downloading, or package actors:

```sh
python3 -I -B scripts/ci/platform-namespace-vm-probe-v1/controller.py --source-root /absolute/trusted/source
```

`input-policy.json` permanently keeps kernel/rootfs/QEMU/actual Source/ref/run selectors NULL. `dependencies.json` pins three existing trusted project helpers: generic16K cpio/ELF handling, the generic Image-header DATA checker, and the owned process supervisor. Their code is imported only from a verified trusted source root during explicit execution, never from the collected rootfs or kernel DATA. The new actor-denied controls also exercise the trusted cpio function on modeled bytes; that is not an actual VM/source construction or acceptance result.

Root reported the actual existing three-leaf kernel DATA Source24252ac5d5b416d4407e33725ffbfabac28e0bc8/tree983d2ae6419b39824beb34da491d5ee69d3b8861, including Image9019400/SHAcd8053eb... and config68789/SHAe97d54d4..., with the required user/network and other namespace options enabled. Full pins and the historical descriptor's unmodified boot-NOTRUN status are retained in `known-kernel-DATA-reference.json`. This reference does not select an input or attest this new probe booted.

## Root-owned execution input contract

No implicit acquisition, moving URL, downloaded-code import, archive extraction, kernel build, source constructor, dispatch or resource exemption is provided. Root must supply an external full-hash selection record derived from `common.defaults()`, with status ROOT_BOUND_GENERIC16K_NAMESPACE_PROBE_INPUTS/issuerRoot/input_reviewedtrue, exact bounds, genuine actual Source/ref/run and separately qualified kernel/rootfs provenance. `native_permission` stays false: an input review is not native/resource admission. Root owns any Source publication, native/QEMU trial, Original-role GET and actual reader. The operation receives no Doc315 exemption or coexistence authority.

Kernel selection fields: Image/config/qualification each an exact {bytes,sha256}; literal expected release; genuine immutable source and run. Supply those three DATA paths separately. The existing Image must have a little-endian AArch64 16K header and a16K config. Kernel namespace config is recorded; guest actual uname/page size is checked rather than inferred from the header. Preserve historical descriptor/provenance bytes and identities.

Rootfs selection fields: archive/manifest/qualification each exact {bytes,sha256}, plus genuine immutable source/run. Qualification is independently reviewed retained DATA, not a certificate produced by this harness. The manifest is exactly:

```json
{"schema":1,"status":"CLOSED_GENERIC16K_NAMESPACE_ROOTFS_DATA","files":{"busybox":{"bytes":123,"sha256":"INDEPENDENTLY_PINNED_FULL_HEX64","mode":493}}}
```

The example is a schema sketch, not a constructed/qualified input. Use an uncompressed flat tar of exactly those ordinary single-copy members, uid/gid0, modes0644/0755, no PAX/links/specials/setuid, <=8192 files and <=256MiB archive/payload. Required executable roots are `busybox`, `usr/bin/python3`, and `usr/bin/bwrap`; include actual Python standard library/extensions and ELF interpreter/DT_NEEDED closure. Flatten guest aliases to the exact independently verified regular target bytes. Names `init`, `probe/**`, `proc/**`, `dev/**`, `tmp/**`, `home/**`, `var/lib/pacman/**` are harness-reserved. ELF64 AArch64 load alignment and declared loader/library names are checked. That static presence check is not proof of runtime closure; actual guest startup remains required. No unshare executable or second namespace command is used.

The QEMU selection is the actual canonical installed binary's full {bytes,sha256}, with ordinary0755 mode; no download/install fallback. Work and output must be separate nonexistent direct children of preexisting owned0700 canonical parents, outside source and all inputs.

```sh
# Root only, after independent resource and actual input qualification:
python3 -I -B scripts/ci/platform-namespace-vm-probe-v1/controller.py \
  --source-root /trusted/source --execute \
  --selection /reviewed/selection.json --selection-sha256 ROOT_REVIEWED_FULL_HASH \
  --kernel /inputs/Image --kernel-config /inputs/config \
  --kernel-qualification /inputs/kernel-qualification.json \
  --rootfs /inputs/guest-rootfs.tar --rootfs-manifest /inputs/guest-rootfs.json \
  --rootfs-qualification /inputs/rootfs-qualification.json --qemu /usr/bin/qemu-system-aarch64 \
  --work /owned0700/work --output /owned0700/output
```

## Finite operation and evidence

The fresh diskless initramfs mounts only guest proc/devtmpfs. Busybox init launches the marked guest entry, then explicitly powers off. Root bootstrap is verified against nonce-bearing kernel command line, AArch64, exact release and actual16384-byte pages before capability/identity changes. The probe runs as UID/GID23001 with no supplementary groups, all outer capability masks zero and NoNewPrivs1. It invokes one same-process wrapper, records actual PID/PGID/SID and exact non-setuid root-owned bwrap hash, then execs the fixed existing-matrix-style bwrap argv. The inner Python observation records actual UID/groups/maps/capabilities and namespace links. User/mount/network links must actually change, and actual inner UID/GID maps must resolve to the unprivileged outer23001 identity; inner capabilities are recorded as scoped namespace facts, not equated with outer privilege.

Each execution records exact argv, actual exit/output hashes and source-supervised group retirement, with one nonce-bound exec/inner/report/end frame. A nonzero bwrap result is distinct from exec, timeout or retirement failure. Numeric clone/unshare errno and policy cause stay UNKNOWN; text is not converted to a cause. Duplicate/conflicting/truncated/overflow/unbound frames refuse. Raw stderr is pinned, not expanded into a guessed policy result. Generic/emulated16K is explicit throughout.

Finite proposal: one TCG CPU,1024MiB guest, no NIC/shared host filesystem/drives,240s owner/180s VM/20s guest command,64KiB command output/1MiB UART,256MiB kernel/rootfs and300MiB initramfs. Existing supervisor pins the unreaped leader through group cleanup. Unknown QEMU retirement retains all private files. Known retirement removes only exact owned Image/initramfs paths; unknown files prevent cleanup and positive qualification. Prestart cleanup is labeled VM_NOT_STARTED. Actor failure/interruption still attempts cleanup and saves a report; natural QEMU exit, guest report, explicit poweroff path and actual group retirement must all join. These bounds are a proposal for separate Root resource review, not an automatic native scheduling admission.

## Current status

Maintained source and actor-denied DATA controls only. Guest rootfs and actual trial selectors remain NULL; no QEMU, native, bwrap, unshare, kernel compilation or host policy operation has been executed for this lane. Root must bind the separately owned closed payload and classify the exact trial before execution. Existing A9, Source80 and namespace host-matrix records remain unchanged.
