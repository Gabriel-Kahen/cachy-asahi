# Private real Mako delivery trial

This bounded diagnostic runs the unchanged Fish Done 0.1.0-2 module through real
Fish, coreutils timeout, libnotify notify-send and the selected Mako daemon. It
uses a fresh private D-Bus daemon, headless Sway with the CPU pixman renderer,
ordinary private HOME/runtime directories and user/PID/mount/network/IPC
namespaces. No DRM or input devices, live desktop sockets, shell files or
notification services are shared. No downloads, builds or package installations
are performed. It preserves the product's default **more than 5000ms** threshold,
handlers, private default bodies, urgency, transient hint and 3000ms expiry.

The default `alpm-installed` mode requires the actual eight ALPM-owned files of
the exact retained package, including root ownership and original mode/hash.
The constructor queries the installed version and complete file list before
creating session actors. It rechecks metadata and contents against the readonly
package database inside isolation. Host-root ownership is translated through
the actual namespace UID/GID maps, which are retained; an unmapped root cannot
be confused with the ordinary caller's ownership. Source-staged files never
satisfy this mode.

Explicit `archive-staged` mode tests the exact package payload unpacked privately
under `/work/done`; it reports that context throughout. It earns no installation
or ALPM lifecycle credit. Both modes require the original 15380-byte package,
SHA256 `9ce3c7ba89467f04660014c1b12056dce28bd0c4e69b4cab8a9c2c98e1cce54f`.
No product file is edited or automatically registered in Fish startup paths.

## Closed constructor inputs

Pass a single ordinary JSON file, its SHA256 and a fresh nonexistent work child
of an owned non-public parent. Schema1 has exactly these fields:

```json
{
  "schema_version": 1,
  "tools": {},
  "libraries": [],
  "mako_config": {"path": "/absolute/mako.conf", "sha256": "actual hash"},
  "done_archive": {"path": "/absolute/package.pkg.tar.xz", "sha256": "actual hash"},
  "source_metadata": {}
}
```

`tools` must contain exactly `sway,swaymsg,mako,makoctl,fish,busctl,dbus_daemon,
notify_send,timeout,bwrap,sleep,shell,python,pacman`. Every row has only absolute
`path` and SHA256. Sway/Mako tools can be privately retained binaries; all other
tools have the fixed native `/usr/bin` paths in `run.py`. Python is the actual
system interpreter and shell is bash behind `/usr/bin/sh`. `libraries` contains
at most16 ordinary native uniquely named `.so` path/hash rows. The unchanged
shipped Mako style hash is required. `source_metadata.mako` must declare version
1.11.0/revision `91c6b799855762ad1eb8b4498967c270a339be0c`.

The retained native input/archive validators are reused byte-for-byte as
`native_inputs.py`, with their original hash bound in the launcher. Inputs must
be ordinary, immutable during reading, bounded, nonoverlapping and native ELF64
little-endian for the **actual** x86_64 or aarch64 machine. Symlinks, aliases,
unknown source sets and mixed architectures refuse before actors/work. The only
hardlink exception is Fish's complete existing three-file multicall group.
The seven runtime helpers and exact product payload have a closed hash map.

No render node is required or mounted. Private Sway disables its background
helper and uses headless/pixman. The private bus configuration has no service
activation directories, so an absent Mako cannot activate a host daemon. Bus
calls use the explicit private address; the monitor inherits only that address.

Runtime `/usr` and `/etc` are readonly inputs. This constructor does **not**
attest every host shared library/font byte, nor authenticate a caller's claimed
source-to-binary correspondence. Native CI must retain its immutable image,
full inventory and selected binary/library hashes. The committed source/revision
metadata and a daemon's wire version are distinct evidence.

```sh
python3 -I -B scripts/diagnostics/fish-done-real-notifications/run.py \
  --inputs /absolute/inputs.json --inputs-sha256 ACTUAL_SHA256 \
  --work-dir /absolute/private-parent/fresh-work \
  --package-context alpm-installed --validate-only
```

Remove `--validate-only` to execute. That option creates no work or session
actors; installed mode still performs bounded read-only package queries.
An ordinary user and working unprivileged bwrap namespaces are prerequisites.
The entire isolated sequence has a180-second outer deadline. Every command,
Fish prompt, notification transport, monitor and actor has a finite local bound.

## Meaningful cases and receipts

Twelve ordered cases cover foreground success and exit7, a real sleep8 watched
job with duplicate registration, short commands/invalid-own-PID/pipeline watch
refusal, user exclusions, invalid user thresholds, disable, repeated sourcing
with custom bindings/unrelated hooks, a preexisting plugin namespace, missing
bus environment, noninteractive silence, and an unavailable manager. Qualifying
commands run for5.25s; the original handlers produce every notification. No
test calls `__done_notify` or fabricates a Notify server.

Four positive cases require one typed real Notify, the exact app/body/privacy,
normal/critical urgency and transient/image-path hints, Mako's own matching
method reply/ID, a matching actual Mako list entry, and its real reason1 expiry
signal. Bus name/UID/PID and `/proc/PID/exe` bind delivery to the selected owned
Mako executable. A real observed benign capability call synchronizes each
monitor before triggering Fish. Caller0/7 and independent watched-child caller
continuation/retirement are checked. Complete raw bounded PTY and bus bytes are
retained with digests; a Boolean is insufficient.

Negative cases require no Notify, actual expected Fish return statuses and
normal shell exits. The unavailable-manager case preserves caller0 inside the
product's2s+1s transport bound and verifies no daemon activation. The legacy18
cases remain separate: this diagnostic does not replace their timeout,
command-text, disown, signal or other assertions.

Fish, monitor, commands, Mako, bus and compositor are reaped and their owned
process groups checked absent. Private socket files are removed after actor
retirement, including on failure; the outer PID namespace bounds all remaining
descendants. Private evidence is retained. Failures are never converted into
passing records, and earlier work directories are refused rather than reused.

```sh
python3 -I -B scripts/diagnostics/fish-done-real-notifications/test_run.py
python3 -I -B scripts/diagnostics/fish-done-real-notifications/replay.py /absolute/completed-work
```

The inert controls include namespace ownership, constructor refusal and
mutations of an actual retained Mako wire exchange. Replay independently joins
raw bytes, sender/reply cookies, payload, list, close signals, caller/watch
markers and owned actor exits. These are data checks, distinct from execution.

## Current boundary

Native x86 CPU-only archive-staged execution passes all12 cases, with four real
Mako notifications and normal actor retirement. Original18 host recorder cases
also pass, unchanged. Native ARM installed execution and16K real-manager
delivery are **NOT_RUN**. This trial takes no screenshots and claims no readable
presentation, Hyprland integration, physical M2 compatibility, performance or
release admission.

`native-context.json` in the development handoff records the exact retained ARM
Mako1.11.0-1 package/hash and Done archive, plus the missing native aarch64 Sway
1.11/wlroots0.19 inputs. Their source archives are already retained/pinned, but
this handoff supplies no aarch64 Sway build. Root owns native build/image input
selection, actual CI and admission. The existing18-case/16K recorder evidence
and managed Hyprland presentation lane remain separate.
