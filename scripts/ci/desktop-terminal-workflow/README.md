# Owned terminal/editor/build/clipboard generic ARM workflow

Source-ready, runnable lane; native execution and visual acceptance are NOT_RUN.
All new files are confined to this artifact directory. Root supplied canonical
base e55bdf42; file hashes, rather than an independently queried Git identity,
pin its accepted dependencies. No shared source, manifest or workflow was edited.
This is a bounded R4 representative workflow, independent of the bar/repaint and
managed-session work. Thunar is deliberately UNSELECTED_NOT_RUN.

## Implemented exercise

Both minimal and shipped-overlay compositor configurations run the same private
workflow. The existing fixture opens its private D-Bus session and owned Wayland
socket, then launches the installed Alacritty explicitly with an owned TOML,
app_id/title, working directory and direct Python child. A native mapped/visible
window must belong to that exact PID, remain onscreen and be at least 640x400.
Only after that check does the parent release the worker's start marker.

The Alacritty child must have a real /dev/pts/ terminal, native aarch64 guest
markers and the expected parent PID. Its fresh 0700 workspace contains synthetic
inputs only. It performs these actual commands in the future native run:

1. Vim 9.2.1178 Ex mode edits and saves main.c. -uNONE/-UNONE/-iNONE, --noplugin,
   -n and explicit script arguments avoid user configuration, Viminfo and swap.
   The file must change from the exact UNEDITED/0 seed to the exact requested
   source. This tests real Vim file editing; it does not claim an interactive
   Vim UI, physical typing or shortcut-input coverage.
2. The installed cc compiles that edited C using -std=c11 -O0 -Wall -Wextra
   -Werror. The result must be little-endian ELF64 AArch64 and actually execute
   with status 0 and exactly `Cachy Asahi native C: 42\n` on stdout.
3. A separate owned wl-copy --foreground --paste-once offers the explicit
   text/plain;charset=utf-8 MIME. A bounded type-readiness check precedes a
   separate wl-paste --no-newline request. Exact UTF-8 bytes must roundtrip:
   `Cachy Asahi — café / Ελληνικά / λ = 42\n`. The producer must exit 0 after
   that single paste; failures retire and drain it before propagating.

The child prints a readable transcript and waits for an owned release marker.
The parent independently checks source/executable hashes, report bytes, worker
UID/parent identity and the PID-owned window, settles five seconds, requests the
existing QMP capture and keeps eight subsequent seconds of healthy clients.
It then releases the child, requires clean Alacritty/child exit 0 and window
retirement, dispatches compositor exit and requires status 0. Failure paths
retire every owned process and preserve the original failure. No host clipboard,
physical pointer, keyboard, application, package, service or device is changed.

User-owned config sentinels are observed before/after both phases; programs use
explicit fixture configuration and never overwrite or remove those sentinels.
Workspaces live only on the disposable guest disk. Their exact source-before,
source-after, C stdout and clipboard bytes/hashes, ELF header/hash, child exits,
command arguments, PTY/parent join and transcript are embedded in the bounded
terminal_workflow_result event and runtime.json. No compiled binary or guest disk
needs public upload. The generic fixture's outer cleanup remains unchanged.

## Pinned inputs and source preparation

package-inputs.json pins existing Alacritty 0.17.0-1, Vim 9.2.1178-1,
GCC 16.1.1+r12+g301eb08fa2c5-1 and wl-clipboard 1:2.3.0-1 plus their 103-package
transitive closure and 334 dependency edges. Every selected row retains exact
archive/signature sizes and SHA256, versions, licenses and providers. No package
addition or replacement is proposed. Native libalpm checked versions/providers
and conflicts using private metadata only; this is not an ARM execution claim.
The existing exact 574 builder, its 16 tooling additions and the built project
settings package still give 591 runtime packages.

Relevant pinned archive man-page bytes were read locally for the Alacritty CLI
and wl-clipboard foreground/paste-once/MIME flags; excerpts remain in this
artifact's upstream/. Distribution signature/native transaction trust continues
through the accepted 574 build. No new GPG, package or compiler actor was run.
source-pins.json records 30 accepted shared prerequisites. prepare.py refuses
source drift, creates a fresh runner and adapts only the fixture/controller:
extra private guest files/marker, helper wait 480→720, fixture timeout 650→900,
host guest deadline 700→1000 and the new result/source/inventory gates. The
original 1750-second controller alarm and 2050-second outer limit remain.
Asahi's boot/platform stack is unchanged; the fixture uses the same generic 4K
kernel and software graphics path.

## Checks and runnable invocation

From the repository root, after adopting the declared files to
scripts/ci/desktop-terminal-workflow/:

```bash
python3 -B -m unittest discover -s scripts/ci/desktop-terminal-workflow -p test_workflow.py
python3 -B -m unittest discover -s scripts/ci/desktop-terminal-workflow/ci -p test_caller.py
python3 -B scripts/ci/desktop-terminal-workflow/prepare.py --source "$PWD" --output /absolute/fresh-terminal-runner
python3 -B /absolute/fresh-terminal-runner/test_desktop574_runtime.py
bash -n /absolute/fresh-terminal-runner/desktop574_fixture.sh
```

Optional local metadata audit (requires host libalpm, performs no package process
or installation): `python3 -B scripts/ci/desktop-terminal-workflow/check_inputs.py
--source "$PWD"`. The CI job does not require host libalpm.

Root owns the actual native Linux ARM64/ARM Docker run, with a retained successful
exact 574 builder output/image and a fresh output directory:

```bash
timeout --signal=TERM --kill-after=30s 2050s python3 -B /absolute/fresh-terminal-runner/desktop574_runtime.py --source "$PWD" --base-dir /absolute/successful574-output --output /absolute/fresh-terminal-output
```

A generated source-only runner is also staged under runner/ here. Its successful
status is PASS_TERMINAL_EDITOR_CLIPBOARD_GENERIC_ARM_SMOKE. It cannot accept the
old 591 or bar-only event shape. The CI caller preserves original owned-builder
cleanup after every consumer and uploads only bounded public reports/logs and
both actual QMP PPMs. See ci/HANDOFF.md and ci/adoption.json for exact copy paths,
source/derived hashes and a single manual workflow.

## Evidence limits

Current validation is inert only: real editor/compiler/clipboard/compositor
processes are mocked in the new controls. No native build/run, real clipboard
transfer or new frame was produced by this worker. Root must independently see
the terminal title, edited source, native 42 output and clipboard PASS/Unicode
line in both exact QMP images. Visible/mapped metadata and a good transcript
cannot replace readable pixels; the separate bar/reload opacity/capture gap
remains open and supplies no terminal visual acceptance.

The shipped SUPER+RETURN binding names Alacritty and is pinned as source; this
route launches the same program explicitly and does not exercise that physical
key binding. Managed login/session integration, Thunar GUI, full services,
16K/M2 hardware, graphics acceleration, battery/audio and performance are
UNSELECTED/NOT_RUN here. No measured M2 or performance result is fabricated.
