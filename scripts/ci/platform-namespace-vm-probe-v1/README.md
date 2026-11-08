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


## Separately versioned Root-local route

`local-input-policy.json` is an additional unbound schema2 template. The original hosted schema1 policy and `common.bound()` function remain byte-for-byte held and still require a genuine GitHub run. Local selection requires an explicit Root-local ID and32-hex nonce, `actual_run:null`, exact maintained Git source/ref, and independently qualified kernel/rootfs/provider pins and provenance. A locally assembled rootfs may truthfully retain source/run NULL; its mandatory provenance receipt must be separately Root-reviewed. No existing A9/Security run can be reused as a local identity.

The dedicated `local_operator.py` is Root-only and requires isolated `-I -B`, an external Root authority file plus independently supplied SHA, and all controller input/output paths. Without `--execute` it only checks source/templates. The authority schema is specific to this one operation: issuerRoot/status ROOT_ISSUED_EXCLUSIVE_LOCAL_EMULATED16K_NAMESPACE_PROBE/approvedtrue, exact selection pin/local ID/nonce/caps, actual Linux x86_64 host and hashed boot identity, fixed fresh work/output paths, Root-created owned0600 lease dev/inode/UID under0700 parent, and a<=1h issuance/expiry window. Required independent Root reviews cover Git code/DATA CI, authenticated input/provider closure, exclusive local host resources, no hosted-A9/native waiver and preserved physical/kernel/signer serialization. No authority or reservation is generated by source defaults.

`code` binds actual Git source/ref/tree, pinned raw commit and complete Git mode/OID map, and every fixed runtime/dependency/CI leaf with full byte/hash/mode/blob joins. The actual lane must have exactly its tracked file namespace, with no untracked import candidates. Root must use a clean checkout/export of that exact maintained source. No collected input is a code root. A dedicated exclusive nonblocking local lease is held through existing QEMU supervision/cleanup; it is closed, never unlinked. Authority freshness/identity/actual code and held lease are rejoined immediately before QEMU. Fixed fresh output is the one-trial boundary; consumed/partial outputs are never replayed.

The reviewed private provider manifest binds a closed owned0700 root, exact ordinary file hashes/modes, actual x86_64 ELF QEMU (implicit scripts/daemon wrappers refuse), and pinned canonical host-library dependencies. The only private environment additions are exact root/usr/lib LD_LIBRARY_PATH and root/usr/lib/qemu QEMU_MODULE_DIR; the local argv adds explicit `-L root/usr/share/qemu`. QEMU remains the direct owned child; there is no Docker/daemon helper or shell wrapper. Default hosted argv/environment remain unchanged. Executable promotion, Root-reviewed manifest and actual resource authority are mandatory separate Root actions; nonexecutable staged DATA alone cannot run.

```sh
# Root only, with the independently issued local selection/authority and existing explicit inputs:
python3 -I -B scripts/ci/platform-namespace-vm-probe-v1/local_operator.py \
  --source-root /exact/maintained/code --execute \
  --selection /Root/local-selection.json --selection-sha256 EXACT_SELECTION_SHA \
  --local-authority /Root/local-authority.json --local-authority-sha256 EXACT_AUTHORITY_SHA \
  --kernel /inputs/Image --kernel-config /inputs/config --kernel-qualification /inputs/kernel-proof.json \
  --rootfs /inputs/guest-rootfs.tar --rootfs-manifest /inputs/guest-rootfs.json \
  --rootfs-qualification /inputs/rootfs-proof.json --qemu /private/provider/usr/bin/qemu-system-aarch64 \
  --work /owned0700/local-work --output /owned0700/local-output
```

The local result records the independent local ID/nonce/host/lease/authority pin with `actual_run:null`; it grants no native ARM, M2, hardware, performance or release credit. All existing QEMU/guest/deadline/cleanup/output caps remain unchanged. New actor-denied local controls exercise schema separation, no GitHub-ID reuse, explicit nonce/caps/provenance, genuine Git object/body proof counterexamples, unissued-authority refusal, implicit-wrapper refusal and held hosted argv. Package/source/provider inputs may be authenticated and staged as DATA without executing them; actual VM execution remains Root-only after the independent local resource decision.

The diskless PID1 script uses the already selected Python and `boot.py` for fixed libc `mount(2)` calls and directory creation; it requires no BusyBox mount/mkdir applets. BusyBox sh and poweroff remain the known entry/retirement route. The bootstrap requires a fresh root AArch64/16K guest, matching release, PID1 parent and empty harness `/proc`; after mounting proc it joins the exact nonce command line before creating devtmpfs. A bootstrap error powers off through the existing failure path. This repair addresses an observed missing mount applet; it does not claim a successful bwrap probe.

Guest reports include a version1 child-stderr diagnostic: whole length/SHA256 plus a canonical base64 prefix of at most16KiB and explicit truncation. The existing64KiB command/report limits remain. The preview joins the actual command stderr pin; complete previews must also match its whole hash. Truncated previews do not independently prove omitted suffix bytes. Text never establishes syscall errno or namespace-policy cause, and no identity/inside/success predicate changes. This makes a new failed guest run diagnosable; the previous577-byte stderr was hash-only and cannot be recovered from its retained report.

The inner user/group map is relative to its immediate parent when read from inside. Bubblewrap0.13.0 can create two user namespaces for devpts while preserving the requested UID/GID; that map alone cannot prove the original outer identity. The original bwrap argv/UID behavior remains fixed. A VM-lane-owned command runner inherits only a fresh connected AF_UNIX SOCK_SEQPACKET sender on FD3 (and closes all other nonstdio FDs). The shared glibc runner remains unchanged. No unknown FD3 is overwritten and no extra namespace operation occurs.

The inside process sends one bounded raw nonce/release/context packet before validation. The unchanged outer UID/GID23001 observer receives exactly one kernel SCM_CREDENTIALS record using SO_PASSCRED, binding the kernel-projected UID/GID and sender PID to that exact context. Success requires outer23001, matching PID namespaces and nonce/context, valid immediate-parent map membership, all previous identity/capability/NNP/namespace-change predicates, natural zero exit and owned retirement. SO_PEERCRED creator identity is never used. Missing/extra/truncated/forged or unjoined records cannot pass; unexpected SCM_RIGHTS descriptors are closed and refused. Raw inner context remains diagnostic data if parent validation fails. No privilege fallback or errno inference is introduced.

Source semantics: [pinned bubblewrap0.13.0](https://github.com/containers/bubblewrap/blob/719a4fd474d44b26906bcf2b1b0fb6eddd8d56d0/bubblewrap.c) and [selected Asahi kernel SCM projection](https://github.com/AsahiLinux/linux/blob/94fb23346d522edf53722357c426a3e58030beea/net/core/scm.c). The new socket/struct guest imports and native extensions already exist in the held2534-file rootfs; runtime execution of this repair still requires a fresh Root trial.
