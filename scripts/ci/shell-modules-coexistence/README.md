# Six-module host coexistence driver

Run with existing Fish>=4.9.3, Zsh>=5.9, Python and coreutils on Linux:

```sh
python3 -B scripts/ci/shell-modules-coexistence/run.py --source /absolute/project --output /absolute/fresh-private-output
```

Optional --overlay /absolute/proposed-root selects complete proposed package
directories at their ordinary repository-relative paths. Every selected flat
package input is copied into the new private output, hashed and joined to its
literal local PKGBUILD source checksums before runtime imports. No source,
startup file, login shell or real HOME is edited. No packages are installed.
The resulting receipt pins all inputs and interpreter identities. A frozen
snapshot avoids a canonical source update changing a case halfway through.

Six finite cases run real PTYs/processes: Fish bang-bang/autopair/Done in
bang->autopair->Done and Done->autopair->bang order, Zsh autosuggestions/
highlighting/substring in autosuggestions->highlighting->substring and
highlighting->substring->autosuggestions order, plus noninteractive/caller
controls for both shells. Other source orders are not claimed supported.
Highlighting is always loaded before substring. Explicit user bindings to module
widgets are made only after loading; binding an undefined substring widget first
correctly triggers its preexisting-namespace guard. Zsh history suggestions use
explicit synchronous history strategy (async disabled for deterministic typed
observations), with fixture widgets ignored by autosuggestions. No performance
or default-async behavior claim follows from this focused matrix.

Fish proves empty !! stays literal, typed !! inserts a quoted previous command,
three nested pair types and quote deletion, one private Done notification argv,
custom key/hook/function/binding preservation and repeated source-caller
continuation. Only the harmless literal printf history seed and sleep execute;
expanded history buffers and touch-looking data are never submitted. Zsh proves
actual typed-prefix POSTDISPLAY, acceptance, real colored syntax-highlighting
spans, empty/unmatched state, older/newer substring traversal, literal glob/dollar/
command-substitution history, custom key/widget/function preservation and repeat
caller continuation. Private startup/history sentinels and normal exits are
checked. Noninteractive cases must be silent, load no module, emit no private
notification and continue the caller.

The driver reuses the existing Done and substring test Terminal/private-HOME
helpers from the frozen product inputs. Its one exact adapter changes the Done
fixture's initial binding equality to a subset check: all old preset/user binding
lines must remain identical while bang-bang/autopair are allowed to add their
opt-in bindings. No existing binding may disappear or change. The ordinary Done
module test never receives this adapter. All other reused readiness, PID/process,
config/history and byte limits remain unchanged. Highlighting files are copied
into their package() directory layout; no shell recipe is executed to stage it.

Each fixed case has a 30s watchdog plus bounded teardown. Reused PTYs have 5s
transition waits, <=64KiB output and <=4096-byte input/snapshots, CPU/memory/file
limits and normal/forced process cleanup. No real D-Bus/notification service or
host desktop is contacted: PATH selects the product's executable private
notify-send recorder and its bus address is intentionally nonexistent. The
complete output tree is fixture-generated and should be retained only as local
validation evidence. Failed cases stay FAIL; no unavailable module is skipped.

Source controls run with `python3 -B -m unittest discover -s scripts/ci/shell-modules-coexistence -p test_source.py`.
They cover binding addition versus overwrite and source alias/checksum refusal;
real behavior comes from the PTY receipt. Current source-only/handoff host
results do not establish native ARM, 16K, package-manager integration, real desktop
notifications, M2 or release acceptance. The script is reusable on later native
hosts; machine/page/interpreter facts remain separately recorded.
