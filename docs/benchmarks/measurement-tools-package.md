# Measurement tools package integration proposal

This candidate supplies `cachy-asahi-measurement-tools` 0.1.0-1 as an unselected
MIT/any package with Python >=3.12 runtime dependency and bubblewrap check dependency.
The canonical starting point is commit `852d1b7324e4ad840fa94ea7c9fc994b1aa07280`.
Root owns adoption, selection, shared CI dispatch, native constructors and release.
No existing benchmark, tests, manifest or Git reference is changed by this packet.

Adopt `packages/tools/cachy-asahi-measurement-tools/` as a new exact recipe namespace,
the two uniquely named release scripts, explicit static checker, this guide,
and `manifests/measurement-tools-source-20261028.json` as a finite transport profile.
The separate proposed package row is for Root reconciliation only. Do not route
the candidate through existing three-category auto-discovery and then claim it
was checked: `package_checks.discover()` scans desktop/shells/settings only.
The explicit checker uses the current public `recipe()` API on the named recipe.

```
python -IB scripts/checks/check_measurement_tools_v1.py --root /absolute/adopted/root
python -IB scripts/release/test_measurement_tools_source_delivery_v1.py --root /absolute/adopted/root
cd packages/tools/cachy-asahi-measurement-tools
makepkg --config /etc/makepkg.conf --cleanbuild --noconfirm
```

The first command is recipe/static/source-only. `check()` runs eight original
packaging controls, stages actual prepare()/package() with makepkg-style symlink
inputs, moves prefixes, executes 24 real owned host trials in two complete frozen
blocks, replays captures/reports, and rejects drift/tampering/missing/duplicate/mixed
trials. Its bwrap namespace has private `/proc`, `/dev`, network and empty `/sys`;
it collects no live session or sensor observations. No unsandboxed fallback exists.
A clean native builder must support nested ordinary-user bwrap isolation; failure
is a visible check blocker, not permission to skip check(). No shared CI is added.

The original legacy benchmark cleanup calls `poll()/wait()` before a later numeric
`killpg()`. Installed `run` therefore requires the exact existing explicit
`--platform-metrics` mode and its frozen plan declaration. The pinned owner holds
exclusive non-reaping custody through cleanup. All five original sources remain
byte-identical; no replacement core is proposed. The launcher supports generic
complete-block comparison, excluding artifact-specific paired_zlib preparation,
which embeds unrelated checkout/ARM-experiment assumptions.

The installed README records limits and commands. `payload-map.json` records
fourteen files under `/usr`: launcher, five private source modules, two license
files and six documentation/example/map files. There are no protected Asahi paths,
hooks, configuration, service, bootloader or hardware-policy files. Namespaces
are private to measurement-tools and disjoint from other project tools.

Before selection, qualify clean native ARM build pairs and compare actual
archives/BUILDINFO/payloads. Independently scope a signed disposable ALPM
install/repeat/remove/reinstall lifecycle, inspect the installed-file inverse
and data preservation, and run ordinary-user installed CLI checks. Native4K,
emulated16K, native16K, installed Asahi and both physical M2 Air sizes remain
separate evidence. Host controls are plumbing tests. No host fixture demonstrates
M2 power, thermals, speed, recovery, release or optimization acceptance. No
publication or shared-run dispatch is authorized by this packet.
