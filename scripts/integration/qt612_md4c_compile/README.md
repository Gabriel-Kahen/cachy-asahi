# Bounded Qt Markdown importer continuation

This lane compiles the Qt 6.12 Markdown importer object from a successful
16 KiB AArch64 configure rehearsal. It runs the six generated header-sync
commands and the exact generated PCH and importer compile commands. It keeps
Qt's configured chroot path, installed md4c, and compiler flags. The full native
Qt family retains its 14 GiB gate. The configure rehearsal retains its separate
24 GiB gate.

## Prepare an unissued packet

Supply an independently pinned `QT_MD4C_CONTINUATION_INPUT_PROFILE_V1` JSON
object. File references have `path`, `bytes`, and `sha256` fields. The profile
contains these roles.

| Field | Contents |
| --- | --- |
| `configure` | `attempt` is the original absolute attempt directory. `closure`, `claim`, `corrected_independent_readback`, `guest_serial`, `original_qemu`, `guest_result_disk`, `host_result`, and `absent_observation` are pinned files. The closure must establish the exact configure-only success and two absence observations. |
| `original_inputs` | Pin `Image`, `boot.raw`, and `scratch.raw` from the same configure output directory. |
| `scratch_uuid` | The canonical ext4 UUID of the selected 16 GiB scratch image. |
| `tools` | `profile` is the pinned five-tool configure profile. `qemu_img` provides the separately reviewed `bytes` and `sha256` for the same actor image. |
| `operand_sha256` | Exact guest-path digest map for the reviewed generated Ninja files, CMake state, importer source, and installed md4c files. The permitted paths are `prepare.OPERAND_PATHS`. |
| `command_sha256` | Digests of the exact `headers`, `pch`, and `importer` command streams emitted by Ninja. |

```sh
lane=scripts/integration/qt612_md4c_compile
python3 -I -B -Werror "$lane/prepare.py" "$OUTPUT" \
  --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA"
python3 -I -B -Werror "$lane/prepare.py" "$OUTPUT" \
  --profile "$PROFILE" --profile-sha256 "$PROFILE_SHA" --preflight-sha256 "$PLAN_SHA"
```

Choose a fresh private output on the same Btrfs volume as the originals. The
preparer uses mandatory reflinks, checks the selected bytes before and after
preparation, injects the byte-pinned guest into a fresh boot carrier, and
creates a fresh result disk with its own UUID. The resulting plan is unissued.
Preflight reopens the plan, tool/profile custody, original receipts, and prepared
operands. These commands perform preparation and readback without running a VM.

## Owned execution and readback

The site adapter supplies the once claim, host scope, rootless container
identity, and live capacity checks. It stages the exact immutable source leaves
from `common.REQUIRED` under `/src`, seals their `bytes`, `sha256`, and `mode`,
and passes an externally pinned `QT_MD4C_PORTABLE_HANDOFF_UNISSUED_V1`.
The envelope records `authority` as null, the selected `scope`, `actor_image`,
`plan` pin, `attach_seconds`, `required_disk_bytes`, `result_uuid`, `source` map
and `source_tree_sha256`. It also records the site `operand_root` and the
`prior_closures` map of explicitly vetted file references. The map includes the
successful configure predecessor. The site authenticates these receipts and
supplies the separately issued Root selection. `common.binding` defines the
unissued selection fields and `common.verify_selection` checks the issued form.

The retained rootless container uses a read-only root, no network, no
capabilities, no added devices, and no-new-privileges. Its limits are four
CPUs, 6 GiB RAM, zero additional swap, 256 PIDs, and a 32 MiB restricted
temporary filesystem. The actor requires the existing
`CACHY_ASAHI_QTBASE16K_ACTOR=1` and `CACHY_ASAHI_OVERLAY583_ACTOR=1` flags.
It mounts `/src`, `/handoff.json`, `/plan.json`, `/selection.json`, and `/inputs`
read-only. Its only writable data bind is `/out`, initially containing one
fresh clone of the pinned 64 MiB result template. The site passes the handoff
and authority digests as `--handoff-sha256` and `--authority-sha256` to the
isolated Python actor. The actor verifies the plan, source seal, six tool
bytes, exact QEMU invocation and live admission. It uses the existing owned
runtime and retains its natural retirement and disk-watch records.

The continuation requires 4.09375 GiB free, 6 GiB MemAvailable, and four allowed
CPUs. That disk budget includes a 2 GiB QCOW2 file limit, the 64 MiB result, 32
MiB for reports and overhead, and a 2 GiB live reserve. The raw scratch backing
is read-only. The guest checks the read-only root mount and uses exact UUID,
label, geometry, and write-state checks to select two distinct unpartitioned
whole virtio data disks. The fresh boot disk is MBR-partitioned. The VM deadline
is 2,100 seconds and the guest compile deadline is 1,800 seconds.

The passive `readback.result` takes the exact attempt, independent handoff,
authority and post-scope closure pins, and the site's trusted read-only `entry`
adapter. The adapter supplies `load_handoff`, `verify_selection`, `attempt_meta`,
and `matching_inspects`. The reader verifies the once claim and recorded closure
copies, natural Docker and QEMU retirement, twice-absent CID and scope, original
command streams, raw ext4 evidence, and immutable input bytes. A complete PASS
requires an AArch64 relocatable object defining the importer and carrying an
executable branch relocation to the external `md_parse` symbol. Site launchers,
private input selections, and original receipts live with the site owner.

## Historical actual validation

Root closed the r4 site attempt as an importer-object PASS. It booted AArch64
with 16 KiB pages and retained five original evidence files. The 79,240-byte
ELF64 AArch64 `ET_REL` object defines
`_ZN21QTextMarkdownImporter6importERK7QString` and contains one executable
relocation to undefined `md_parse`. Its SHA-256 is
`98f9e29ca5a8fd7c60dac1e40622c2f34d95dcd90b3f53084b62577caaf16561`.
QEMU retired naturally after about 209 seconds. Watched output allocation
peaked at 354,492,416 bytes across 426 samples. Scope and container retirement
were observed twice. The 3,598-byte close has SHA-256
`c930b0cd60456d7f7e756829f71a72c8b7bad7faa3ab5664bb4f60c4c541f9b3`.
The portable lane carries the exact r4 guest bytes and is checked offline.
A full Qt build and physical M2 validation remain unrun.

## Offline controls

```sh
for test in test_prepare.py test_actor.py test_readback.py test_storage.py; do
  python3 -I -B -Werror "$lane/$test" -v
done
bash -n "$lane/guest.sh"
```
