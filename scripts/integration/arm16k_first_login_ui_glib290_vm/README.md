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
not accepted. Its counters measured no OOM and its QEMU retired naturally; this
does not explain an earlier trial's unmeasured SIGKILL.

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
9 exact preparation binds, 3GiB preparation cap, 4GiB/no-extra-swap boot cap,
2GiB guest,1GiB overlay,2CPU/256PIDs,6GiB minimum host availability/2GiB reserve,
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
