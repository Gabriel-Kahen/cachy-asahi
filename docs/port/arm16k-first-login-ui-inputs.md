# ARM16K first-login UI input plan — 2026-11-15

The retained ARM111 reference admits a **finite metadata proposal of 145 additions
and 256 final packages**, preserving all 111 baseline versions. This is
`HOLD_METADATA_PLAN_ONLY`, not a prepared install or an ARM GUI result. The
successful x86 GTK/seat0 journey remains separate
([actual x86 result](../validation/first-login-ui-real-seat-20261115.md)).

## Reproduce without acquisition or installation

From the checkout, with Python 3.14 and the existing exact libalpm 16.0.1 engine:

```sh
python -I -B scripts/port/arm16k-first-login-ui-inputs/plan.py \
  --output /tmp/new-owned-arm111-ui-plan
python -I -B -m unittest discover \
  -s scripts/port/arm16k-first-login-ui-inputs -p 'test_*.py' -v
```

The output directory must be new. Exit 2 denotes the expected held plan; exit 1
is an input/resource/tool refusal. Absolute retained input locations and byte pins
are in [inputs.json](../../scripts/port/arm16k-first-login-ui-inputs/inputs.json).
The adapter verifies four existing engine source pins, reuses the existing
conservative graph and isolates genuine `transaction.prepare` in a private child.
It never commits an ALPM transaction, imports package code, downloads, installs,
starts a daemon or launches a guest. Metadata-only NOHOOKS/NOSCRIPTLET flags do
not authorize suppressing hooks during a future real installation.

The parser phase has a 256 MiB address-space limit. Before the child starts, the
parent releases catalogs and takes a 160 MiB limit; the child has 96 MiB, core
dumps disabled and bounded CPU/wall time. Actual `/proc` parent VmHWM was
161,480,704 bytes and child VmHWM 30,957,568 bytes; parent/child VmPeak were
177,201,152/89,714,688 bytes in their separate phases. Both Python 3.14 and 3.12
passed ten controls. The standalone 3.12 interpreter can exceed the constrained
child's ICU mapping budget: that exact loader refusal remains a named HOLD, with
no alternative resolver or weakened ABI gate.

## Exact baseline and actual result

[baseline111.json](../../scripts/port/arm16k-first-login-ui-inputs/baseline111.json)
contains only the real selected installed records, not invented individual
archive identities. Its SHA256 is
`7a57dce67a65f58e5d1ece471879424ef819ee2bd6226a42452aeccb4a899f6e`.
It is joined to the exact selected inventory and prepared r5 descriptor
`f7b3073f58acce8ab5e21ff61f2182779d24046e1582cda6adb0a3db66b7036e`.
The whole ALARM 2026.08 rootfs is 829,367,415 bytes, SHA256
`42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319`;
individual installed records inherit that custody rather than new package
signature checks. See the [ARM reference](../validation/arm16k-systemd-reference-20261114.md).

The actual aarch64 core/extra catalogs are the retained 2026-10-12 records, not
the x86 November snapshot. Explicit roots select GTK4, python-gobject, Polkit,
Fish/Zsh, Xvfb/xauth and the three project packages; font, Mesa and libglvnd
providers are explicit. Generic Mesa here describes a TCG reference dependency,
not an Asahi or physical M2 selection. Baseline glib2 2.88.3-1, glibc, systemd,
DBus, ICU and every other baseline version remain frozen. Unversioned dependency
satisfaction against newer catalog consumers does not prove symbol/ABI compatibility.

Actual libalpm 16.0.1 preparation of the explicit finite proposal returned zero
errors, removals, conflicts or questions and 1,196 final satisfier relations.
There are 142 official plus three project additions (129 aarch64, 16 any).
The conservative graph still reports FAIL: six unrelated malformed catalog rows
and inherited ca-certificates/dbus-units direct-name/provider overlaps remain
named in the output. Its controls were not changed. The separate finite libalpm
result describes the exact candidate set, not a clean full-catalog acceptance.

Full local report:
`/tmp/cachy-asahi-arm16k-ui-plan-20261115-handoff/plan.json`, 1,031,521 bytes,
SHA256 `893ee5ed2cba013af2751ee1582b84120348c5cb8e10608dc5ef1447a83201ac`.
[actual-facts.json](../../scripts/port/arm16k-first-login-ui-inputs/actual-facts.json)
retains counts, exact root identities, missing archive/signature pins, memory
observations and named graph holds.

## Six missing exact inputs

| aarch64 archive | Bytes | SHA256 |
| --- | ---: | --- |
| gobject-introspection-runtime-1.86.0-2 | 30,644 | `fe0d6a936340bf8b6752d96f198f130ad0fdbc39521dd71257346f297a0287ae` |
| libgirepository-1.86.0-2 | 178,880 | `c9c9715f03a1b4bbbd9e03c203275f4571a4c8b6bd1e5307eafc02ebf1789fed` |
| libxmu-1.3.1-1 | 72,980 | `598e2e2422a1136171264744c54dd0d1e884a2c6c86d6850611c2128dc976362` |
| python-gobject-3.58.1-1 | 300,132 | `49b8991906522d676aafc7588c6a1760dfe5b2316e3c4168ac8a62ea01bf7d1f` |
| xorg-server-xvfb-21.1.25-1 | 705,376 | `9799e250607b6ebe1b143138fe7cf64366fc94127bb5fbaea6c456c68c2bf715` |
| xorg-xauth-1.1.5-1 | 24,608 | `0384b75f97e0b659e85366698ced6028b13aa2964f6d7f1117548b942a062ac7` |

All filenames end `-aarch64.pkg.tar.xz`; total archive bytes are 1,312,620,
with six separately pinned 566-byte signatures. No acquisition was performed
for this metadata result. The other 139 identities have retained observations:
size, bounded PKGINFO identity/dependency checks and signature-byte/catalog joins.
Only archives at most 1 MiB were freshly fully hashed. Large archive hashing,
cryptographic verification, revocation/freshness and source/license completeness
remain held; an observation is not authenticated material acceptance.

The three small project archives were fully hashed and their real PKGINFO
name/version/`any` architecture, dependency/provides/conflicts/replaces/license
fields matched pinned SRCINFO. UI and FirstLogin remain host-assembled `any`;
Setup8 retains its separately bound prior native-component observation. No new
ARM build qualification follows. Public certificate and detached signature bytes
were pinned without importing trust. Fish/Zsh config archives were checked only
as explicit private template DATA, not installed defaults.

## Next boundary

The six exact pairs can be acquired only under a separate bounded intake, then
joined to the catalog pins and independently verified with the retained official
keyring and explicit signer policy. That does not authenticate the other 139
observations. A complete archive audit must still cover ELF16K geometry, dynamic
symbol/ABI closure, file ownership, hooks, namespace tools and source/license
materials before any installation proposal.

The pinned original reference kernel declares VT, VT console, evdev and virtio
GPU, but no CONFIG_VIRTIO_INPUT. The x86 ATkbd/seat0 controller cannot be reused as
ARM seat proof. Root has a separately exercised RTC successor; this planner binds
only the original config and does not reject or qualify that successor. A
separately pinned ARM input/seat and current-kernel contract is needed before a
Root-admitted VM. ARM GTK runtime, real ARM seat0, physical M2 networking/display,
hardware and release acceptance remain NOT RUN by this work.
