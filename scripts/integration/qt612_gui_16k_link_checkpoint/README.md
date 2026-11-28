# QtGui link checkpoint on emulated AArch64

The pinned Q3 Ninja graph contains 639 commands for `lib/libQt6Gui.so`,
including all 321 commands for `lib/libQt6Core.so`. The remaining
multiset has 318 commands and 294 compiler edges. It includes QtDBus and
the QtGui shared-library link against system md4c. The November 22 guest
dry run confirmed all 318 remaining steps against the retained Core overlay.
[QtGui validation](../../../docs/validation/qtbase612-emulated-arm16k-qtgui-link-20261122.md)
· [QtCore checkpoint](../qt612_base_16k_link_preflight/README.md)

```sh
lane=scripts/integration/qt612_gui_16k_link_checkpoint
python3 -I -B -Werror "$lane/inspect_checkpoint.py" graph \
  --manifests "$pinned_q3_ninja_directory"
```

## Select the completed Core result

`continuation.py` takes a canonical JSON selection and an external
SHA-256. Use kind `ROOT_QTGUI_LINK_SUCCESSOR_SELECTION_V1`, issuer
`Root`, and approval `true`. Its `core` object selects the existing
Core `handoff`, `independent`, and `post_scope` files with absolute
`path` and `sha256` fields, and the original `output` directory as
an absolute string. Use the independent readback's SHA-256 as
`budget_basis_sha256`. The preparer replays the original Core report,
commands, result disk, scope closure, and measured resource records before
accepting any limits. The selected Core report must include the post-scope
exit and verified Core ELF.

Supply `limits` with integer `guest_build_seconds`, `build_log_bytes`,
`artifact_bytes`, `qemu_seconds`, `overlay_file_bytes`,
`result_disk_bytes`, `report_allocation_bytes`, `host_disk_reserve_bytes`,
`guest_memory_bytes`, and `actor_memory_bytes`. Choose them after
reviewing measured Core time, memory and allocated storage. The existing
owned runtime supports a QCOW2 writer file limit up to 4 GiB. A result disk
needs room for all retained artifacts, the build log, and filesystem
overhead. The command checks these structural bounds and records the
selected limits without estimating a completion time.

```sh
python3 -I -B -Werror "$lane/continuation.py" --selection "$root_selection" \
  --selection-sha256 "$selection_sha" --output "$fresh_private_staging"
```

The optional output directory holds separate, read-only reflinks for the
accepted Core QCOW2 and original 16 GiB raw scratch, the accepted Core
ELF from its original result disk, and the unsigned guest and backing
plans. Both reflinks must match their original pins. The proposed
writable child uses `/inputs/core.qcow2` as its backing file. The Core
clone keeps its original absolute `/inputs/scratch.raw` backing path.
The independent header check refuses unclean flags, encryption, snapshots,
unknown extensions, or any additional external data operand. A later
owned actor must validate the fresh child and its entire chain with
QEMU's image inspector before boot.

## Guest link and evidence

In the future owned AArch64 guest with 16 KiB pages, run
`guest_link.py` as UID/GID 1000 at the original Q3 chroot path. The
worker requires the exact Q3 inputs, 356-package inventory, and accepted
Core ELF and aliases. It verifies that Ninja schedules no Core work and
that the Gui dry run contains only incremental actions and the exact
Gui link edge. It then runs the serial `cmake --build` target, retains
original bounded logs and metrics, and verifies the Core bytes and aliases
again before retaining QtGui, QtDBus, and the pinned system md4c ELF.

```sh
python3 -I -B -Werror /qtmedia/guest_link.py \
  --plan /qtmedia/GUI-GUEST-PLAN.json --plan-sha256 "$guest_plan_sha" \
  --evidence /qtgui-evidence
```

The outer owner verifies the attempt, original result disk, and retirement
before passing the finite extracted evidence to the linkage reader. The
reader checks the AArch64 shared ELF and 16 KiB load geometry, direct
QtCore, QtDBus, and md4c SONAME dependencies, the exact accepted QtCore
bytes, and the original dynamic relocation for undefined `md_parse`.
It verifies the callable export in the pinned md4c provider.

```sh
python3 -I -B -Werror "$lane/inspect_checkpoint.py" guest-result \
  --evidence "$retained_guest_evidence" --guest-plan "$guest_plan" \
  --guest-plan-sha256 "$guest_plan_sha" --result-sha256 "$guest_result_sha" \
  --accepted-core "$accepted_core_elf"
```

## Materialize a sealed capsule

Keep the filled [descriptor](descriptor.TEMPLATE.json), continuation
selection, and runner profile in a private directory. The descriptor
selects the continuation and runner documents by absolute `path` and
`sha256`. Its `prepare_tools` entries bind `debugfs`, `e2fsck`, and
`mke2fs` on the preparation host by absolute path, byte count, and
SHA-256. Use each tool's canonical executable path in `/usr/bin` or
`/usr/sbin`, as installed by the host distribution. The preparer requires
the exact tool basename and rejects symlink aliases.

Use kind `ROOT_QTGUI_LINK_RUNNER_PROFILE_V1` for the runner profile. It
contains `actor_image`, `tools`, `vcpus`, and `docker`. Copy the image
and six original tool pins from the accepted Core plan's
`actor.profile`. Copy the Docker CLI pin and socket endpoint from the
accepted Core handoff. The profile keeps that runner's four vCPUs.
The preparer compares the whole selected map with the retired Core packet.
The approved continuation supplies time and memory limits after the
accepted Core measurements are available.

```sh
python3 -I -B -Werror "$lane/prepare.py" --descriptor "$descriptor" \
  --descriptor-sha256 "$descriptor_sha" --output "$fresh_capsule"
```

This command independently replays the accepted Core outcome and its
owned closure before opening the original backing images. It materializes
new read-only reflinks and a fresh boot carrier, checks the boot payload
from the private partition, formats a separate result template, and
seals the source, plan, input references, runner and unsigned binding.
The capsule's only future writable backing layer belongs to the new
actor. The actor validates all three image nodes before QEMU and checks
the backing pins again after retirement.

```sh
sealed="$fresh_capsule/source/$lane"
handoff="$fresh_capsule/HANDOFF.UNISSUED.json"
python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" preflight
```

The passive preflight checks the sealed source, carrier pins, external
input documents, and live host capacity without opening Docker or QEMU.
Once Root separately issues the exact binding to `$issued_entry`, the
site can claim one attempt in its own user scope. The original Q3, R4,
and Core scopes and container IDs must each be absent on two checks.

```sh
systemd-run --user --scope --unit=cachy-asahi-qtbase16k-qtgui-link.scope \
  /usr/bin/python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" run --authority "$issued_entry" \
  --authority-sha256 "$authority_sha"
```

After the scope retires, capture the site observation once in a fresh file
and independently pin it. The raw reader replays the owned exit and
original streams, checks the clean ext4 disk and metadata, and runs the
linkage reader over the exact retained bytes. A natural nonzero attempt
with no complete actor result can be read as HOLD by leaving out
`--actor-result-sha256`.

```sh
python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" observe --attempt "$attempt" > "$post_scope"
python3 -I -B -Werror "$sealed/read_capsule.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" --attempt "$attempt" --post-scope "$post_scope" \
  --post-scope-sha256 "$post_scope_sha" --actor-result-sha256 "$actor_result_sha"
```

## Offline controls

```sh
bash -n "$lane/guest-init.sh"
for test in test_continuation.py test_guest_link.py test_elf_readback.py \
            test_guest_init.py test_actor.py test_site.py test_capsule.py; do
  python3 -I -B -Werror "$lane/$test"
done
```
