# NetworkManager 1.58.1-2.1 source candidate

This is original packaging for the exact upstream commit
`7406dfbcc35beed79bf2734e3e7376ead320bd99`, with a distinct `2.1` release.
It does **not** reproduce or authenticate the historical ALARM `1.58.1-2`
recipe or binary. Nothing selects this candidate for an installed system.

`source-provenance.json`, `.SRCINFO` and the PKGBUILD bind the 13,056,926-byte
snapshot, its three exact upstream notices, original MIT packaging, feature
profile, and a test-only patch. The patch renames a local `_s1` variable that
collides with GLib 2.90's `g_assert_cmpstr` temporary; all assertions and
production code remain unchanged. Independent upstream signature/freshness,
complete license/grant acceptance, ARM/16K execution, original transaction
proposal, M2, full-system integration and release acceptance remain held.

## Payload and behavior

The complete staged tree is partitioned into four exact-version candidates:

| Package | Ownership |
| --- | --- |
| `networkmanager` | Daemon, nmcli/nmtui/nm-online, plugins, normal units, dispatcher scripts, D-Bus/polkit policy, manuals and default configuration |
| `libnm` | libnm shared library, headers/pkg-config, GIR/typelib, Vala bindings and client helper |
| `nm-cloud-setup` | Optional cloud helper, units/timer and dispatcher scripts; exact daemon/library dependency |
| `networkmanager-docs` | Built API HTML and inert OVS unit-drop-in example |

Each makepkg packaging invocation stages the current Meson output once in
`.networkmanager-split`, beside the four package directories. Repackaging
gets a fresh workspace and stages the completed build again. Before each
copy, the helper recomputes the ownership records from that private DESTDIR
and verifies every split file, symlink, directory and mode. It checks the
copied payload again before the recipe adds its notices and provenance.
Extra entries, special files, missing required features, escaping links,
setuid/setgid payloads, live resolver configuration, packaged connection/state
files, ALPM hooks and boot/pacman paths are refused.
Each package retains the exact notices and source provenance. Removal removes
owned payload; pacman's normal backup handling applies to
`etc/NetworkManager/NetworkManager.conf`. No install script starts/enables a
service or changes connections, DNS, trust or user state. The normal packaged
units/dispatcher scripts can change networking only if an administrator later
activates them. The optional cloud package is never enabled by this recipe.

The explicit profile preserves keyfile, wpa_supplicant by default and an iwd
alternative, internal DHCP, symlink resolver management, systemd session/suspend
and journal integration, Wi-Fi/PPP/ModemManager/team/OVS, BPF/NBFT/CLAT,
connectivity checking, nmcli/nmtui, GIR/Vala and documentation. Polkit keeps
upstream authorization defaults with no password-free group. OVS support stays
compiled; its service dependency drop-in is retained as an inert docs example
rather than automatically altering service ordering. The connectivity snippet
retains the Arch check URI; staging/building does not request it.

## Local checks

These checks read source/data and create only private temporary fixtures:

```sh
python -m unittest discover -s packages/port/networkmanager-source-candidate -p test_candidate.py -v
python packages/port/networkmanager-source-candidate/check_source.py --archive /absolute/path/NetworkManager-7406dfbcc35beed79bf2734e3e7376ead320bd99.tar.gz
```

For a normal target build, use an owned directory with the declared prerequisites
already installed and ordinary-user `makepkg --verifysource`, followed by
`makepkg --cleanbuild --nosign`. The target declaration is `aarch64`; it is not
ARM build or Asahi acceptance evidence. Do not use `--nodeps`, install a result,
or source the recipe as a discovery step.

## Disposable x86_64 software probe

`Dockerfile.host` is specific to this candidate. Its official base digest and
2026-11-09 core/extra DB SHA256s are fixed. Prerequisites are installed **only
inside the disposable image** with required package signatures under that
image's Arch keyring. The fixed DB hashes are custody pins, not a new claim of
repository freshness. The finite prerequisite transaction disables libalpm's
low-speed timeout under an explicit outer 600-second deadline. A transfer failure
is a hold, not permission for indefinite retries or different versions.

Create a private context containing this directory's files plus the exact source
archive as `input/`; verify the archive with `check_source.py` first. Copy
`Dockerfile.host` to the context's top level. No host state is mounted:

```sh
docker build --network=host --pull=false -f "$context/Dockerfile.host" -t cachy-asahi-nm-source-probe:local "$context"
docker create --name nm-source-probe --init --network=none --cap-drop=ALL \
  --security-opt=no-new-privileges --cpus=2 --memory=4g --pids-limit=256 \
  cachy-asahi-nm-source-probe:local
docker start --attach nm-source-probe
docker cp nm-source-probe:/work/results "$private_output/results"
```

Network access is confined to prerequisite acquisition. Host networking was
necessary for this host's rootless Docker acquisition path. The runtime has no
network, host mounts, privileged mode, devices or host bus. The input is
root-owned/read-only; a non-root user copies it into private HOME/XDG/TMP/work
state and runs two fixed dependency-checked makepkg commands under a shared
1500-second deadline. `--ignorearch` is an explicit x86 software probe override;
there is no `--nodeps`. A private `dbus-run-session` wraps the full upstream test
suite. Natural test skips/refusals are retained. All logs and any archive facts
are in `/work/results`, including on failure. Keep the stopped container until
those diagnostics are copied; remove only that owned container afterwards.

## Recorded execution

See `validation.json` for exact observed commands, results and private diagnostic
locations. These are host software/build/stage results, never native or hardware
qualification. The initial host build correctly refused eight missing declared
prerequisites. A first container prerequisite acquisition failed on a clang
low-speed timeout; its one bounded exact-input retry succeeded. The first full
software run built the full profile, then passed 85/87 tests: the GLib temporary
collision above and an XML dependency omitted by this recipe's initial
`meson test --no-rebuild` invocation. Explicitly generating that XML matched the
upstream expected template byte-for-byte; expected metadata was not changed.
The corrected check permits Meson to build test dependencies normally.

The corrected clean run passed **87/87** upstream tests and staged all four
payloads (634 leaves). After a standalone relative-output verifier fix, the
current recipe verified sources again and reran build/check/package using the
unchanged completed source/build (`--noextract --force`): **87/87** again, all
four unsigned x86_64 archives assembled. Their BUILDINFO hashes match the
PKGBUILD used in that run. Seven local DATA tests passed, including the path regression;
21 staged ELF objects were inspected as data for dependency coverage. No package
was installed. Archive hashes/sizes and the separate clean/follow-up commands
are recorded in `validation.json`; this is not a bit-reproducibility claim.

The build-scoped split change is covered by local fixtures only. Those
fixtures exercise the packaging functions with a modeled Meson install,
stale-stage and stale-cache refusal, mode and namespace validation, and retry
after failed staging. The archived host build record predates this change.
