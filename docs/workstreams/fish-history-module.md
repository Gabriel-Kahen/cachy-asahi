# Opt-in Fish history expansion module

This implements one R4/M6 shell function as a separately reviewed package proposal:
`cachy-asahi-fish-bang-bang` 0.1.0-1. The two upstream helpers and an original
guarded wrapper provide editing-buffer `!!` and `!$` expansion. The existing
original Fish configuration and shared package inventory are unchanged.
This is partial feature implementation, not M6 or full-port acceptance.

Only this guide and `artifacts/reviews/fish-history-module-proposal-20261013/`
are owned by this lane. There is no primary package/map/workflow/Git edit,
global installation, shell change, service, native Docker build or M2 trial.
The prior Vim source-closure receipt `ceeec2ab…` remains frozen and is not rerun.

## Exact upstream source and license

The [complete upstream source](https://github.com/oh-my-fish/plugin-bang-bang/tree/ec991b80ba7d4dda7a962167b036efc5c2d79419)
is pinned to `ec991b80ba7d4dda7a962167b036efc5c2d79419`.
The official codeload archive is 2,293 bytes, SHA256
`e34bc0071a2303f0d066c9c010a0908c2c4e3297b561600c09baa2b0176ecaf1`.
All six regular source files are retained, with a complete member/pin record,
20,480 decoded bytes and the exact commit in the archive PAX comment.
The bounded capture permits only safe unique relative regular/directory members
before writing them. It executes no upstream installer, hook or recipe.

| Selected unchanged source | Bytes | SHA256 |
| --- | ---: | --- |
| `__history_previous_command.fish` | 170 | `d34b75125a34199775eaa74dd47ae37488c4e67f95f40f71b101b6a8f6f32e50` |
| `__history_previous_command_arguments.fish` | 198 | `4e72dcce435d0fe1cf332fb339ed9608f10b29295b28f85ed6e7411ef8c05b64` |
| Full upstream MIT LICENSE | 1,108 | `14c6826a7e33a6c74194ece88b26b5f5aee8473474001946a73d0f298b69fce0` |

Both 2015 copyright lines for Aerys Bat and Derek Stavis and the complete
permission/warranty notice remain in `LICENSE.upstream`. `NOTICE` identifies
the exact selected functions. The unchanged project MIT grant is retained as
`LICENSE.project` for the original wrapper, recipe, tests and documentation.
This grant covers the selected plugin; it does not license the deferred whole
CachyOS Fish configuration.

The archived upstream `conf.d/plugin-bang-bang.fish` immediately erases and
rebinds `!`/`$`, registers a binding-change handler and defines an uninstall
event. The separate uninstall hook erases those bindings in all modes. Neither
file is installed or sourced. They remain in the full source record.

## Behavior and preservation

`package/opt-in.fish` returns immediately outside an interactive shell. It
yields to existing upstream/helper functions, including autoloadable user
functions, rather than replacing them. With initialized stock default bindings,
it adds `!`/`$` only in default editing mode; with vi or hybrid bindings it adds
them only in insert mode. It preserves vi normal mode and registers no
binding-variable handler. A different binding set requires a fresh shell with
the module sourced after that set is selected.

A user generic binding, either affected single key, a longer user sequence
starting with either key, or an affected preset key prevents activation. The
generic preset must be exactly the supported self-insert form. Nonconflicting
bindings remain intact. The prefix check is conservative and can also yield
on key-like text in a serialized binding command. Unknown or uninitialized
binding maps yield without modifying them. Repeated sourcing is harmless and
does not undo later user binding changes.

The unchanged command helper replaces the current `!` token with the last
history command. The argument helper delegates token selection to Fish's
`history-token-search-backward`; it is not a reimplementation of Bash's full
history grammar. Original adapters keep `!!` and `!$` literal when history is
empty and add a repaint after editing. Expansion does not execute the command;
the user presses Enter separately. History files, persistence/filter settings,
universal variables, prompt, aliases and original `caa_ll`/`caa_mcd` helpers are
not changed by the wrapper.

The installed usage guide provides two separate guarded source blocks: one
for the optional original Fish helpers and one for this module, placed after
the user's binding choices. No package startup hook, vendor Fish autoload path,
framework installer or first-login network fetch is added. Package removal
deletes its owned files; the user-owned guard remains harmless in fresh shells.
Already-running shells retain loaded functions/bindings until restart.
Reinstallation restores the same opt-in path. Actual package-manager lifecycle
and configuration migration remain untested.

## Dependencies and package contents

The recipe declares `arch=('any')`, `license=('MIT')` and `depends=('fish>=4.0')`.
Fish 4.9.3-1 aarch64 is already named by both the original input snapshot
`3c16c37d…` and maintained successor `beca39e0…`; the selected rows match.
That is declared package availability, not signature, selected-target
installation or runtime acceptance. The wrapper is tested on host Fish 4.9.3;
other supported version behavior remains to be validated. No compiled object
is introduced; Fish/base binary and 16K compatibility remain base acceptance.

The selected functions and wrapper call Fish builtins only. Coreutils is used
by the recipe's standard installation command, and Python runs the development
tests; neither is a runtime dependency of this module. The existing original
helper package is an optional dependency and still declares its own coreutils
requirement. Both source checks and package assembly perform no network fetch.
Every local recipe source has a full literal SHA256, with no `SKIP` or moving VCS
checkout. `check()` parses the three Fish files without executing them.

The seven regular 0644 package payload paths are:

- `/usr/share/cachy-asahi/fish-bang-bang/__history_previous_command.fish`
- `/usr/share/cachy-asahi/fish-bang-bang/__history_previous_command_arguments.fish`
- `/usr/share/cachy-asahi/fish-bang-bang/opt-in.fish`
- `/usr/share/cachy-asahi/fish-bang-bang/README.md`
- `/usr/share/licenses/cachy-asahi-fish-bang-bang/NOTICE`
- `/usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.upstream`
- `/usr/share/licenses/cachy-asahi-fish-bang-bang/LICENSE.project`

No `/etc`, `/home`, Fish vendor startup path, package transaction hook, service,
login-shell or platform file is owned.

## Bounded validation

The author runs 24 finite controls through the actual Fish 4.9.3 interpreter
on x86_64. These include activation/refusal, default/vi modes, existing modules,
unrelated bindings, repeat sourcing, original helper preservation, local-variable
preservation and previous-command/empty-history adapters. The commandline and
token-search interface in the adapter fixtures is modeled; those fixtures do
not establish actual terminal token search. Each child has an 8-second wall
limit, 5 CPU seconds, 512 MiB address space and 64 KiB output/file bounds.
Every fixture has fresh owned XDG config/data/cache, no-config/private Fish and
inherited unchanged HOME. No real user configuration/history is read.

The first suite passed 23/24 and caught a dollar-prefix preservation bug.
An independent reviewer reproduced it. Fish serializes `$` keys with a
backslash, while ordinary string escaping selected quotes; the corrected
prefix checker uses unquoted script escaping before regex escaping.
The final 24/24 suite passes. The original wrapper, recipe/provenance, fixtures
and failed result remain in `models-attempt01/`; the corrected result is in
`models/`. This is a real preservation repair, not a waived failure.

Independent actual terminal behavior and two host package assemblies are
recorded in their separately frozen `peer/` and `host-assembly/` lanes below.
Their scope remains x86_64 host validation, not native ARM, installation,
performance, full user-module compatibility or either M2 Air size.

Two independent fresh source copies passed actual `makepkg --nodeps --noconfirm`
in 1.27 and 1.22 seconds. The seven literal source checksums and three Fish
syntax checks ran successfully. An owned explicit makepkg config bypasses
user/system override files; `--nodeps` skips dependency handling, and a narrowly
scoped pacman query shim uses an owned empty database/config/cache for BUILDINFO.
That controlled-empty inventory is not the host's installed package inventory
and provides no dependency-resolution acceptance. No package was installed or
signed. Each assembly is bounded to 20 wall seconds, 10 CPU seconds, 512 MiB and
256 KiB log output.

Both archives contain exactly the seven expected regular 0644 payload files,
with matching full hashes and PKGINFO and no hooks or startup registration.
Archive hashes differ; only their BUILDINFO builddir/startdir fields differ.
Payload identity, rather than byte-identical archive reproducibility, is proved.
Generated `.SRCINFO` is 1,120 bytes with SHA256
`2d51a0849e341581ae89d548a81a7074b8d5acc79c143155b3991b96232c6c01`.
The exact recipe SHA256 is
`05a1b2cb4710cc14f62678df37d1236fee909874b5b709d82d54fe4b8dc0f93d`,
and the corrected wrapper is
`d4dbd9dc123ebb31f821afd78c4b55554b4f17929d214baff35e405436e4cce7`.

Independent review passes 16 actual Fish CLI controls and 11 actual PTY
controls on x86_64 Fish 4.9.3. Real command-buffer snapshots confirm `!!`,
native `!$` last-argument search with a quoted two-word argument and an `echo`
prefix, empty histories, quoted literal input, vi/hybrid insert mode and
cancellation. Existing generic/single/prefix bindings, an autoloaded sentinel,
original helpers and repeated opt-in remain preserved. Owned existing history
and configuration retain their full hashes, modes, mtimes and link counts.

One explicit control observes that this Fish version reads an existing named
history file under `--private`, while leaving it unchanged. Privacy-mode flags
are not used as a no-read proof: expansion and empty-history cases use fresh
owned XDG locations and per-case history names, and the preservation case reads
only its own controlled record. No real user history/configuration is accessed.
The peer's corrected dollar-prefix finding is closed at the exact final wrapper
hash. These finite fixtures do not certify every third-party module or terminal.

## Proposed Root integration

Copy only the reviewed package files under `package/` to
`packages/shells/cachy-asahi-fish-bang-bang/`. `source-provenance.json` and
`integration-proposal.json` identify their source and proposed disposition.
The author/peer test scripts and exact source archive remain review artifacts.
Do not copy the artifact cache or transient fixture directories into a package.
`integration-files.json` supplies the exact twelve source-file/target-path/mode/
digest entries, and `proposed-packages.toml` supplies the reviewable manifest
record. All twelve final package files are independently bound by the peer.

The proposed new `manifests/packages.toml` record is a development candidate:
name `cachy-asahi-fish-bang-bang`, phase `complete-port-tools`, source
`https://github.com/oh-my-fish/plugin-bang-bang`, full upstream pin above,
recipe `packages/shells/cachy-asahi-fish-bang-bang/PKGBUILD`, license MIT,
development selection proposed, release selection false, and native build,
installation and hardware `NOT RUN`. Link this guide as its audit. The deferred
whole-config entry and original Fish package remain unchanged.

Root alone reviews/adopts that record, exact recipe/SRCINFO/source pins and
the related addon build/compare consumer in the existing development path.
Any changed recipe/source/integration/stage/job/packet bindings must be derived
and reviewed through that process before dispatch. No new workflow family or
general guard framework is introduced. Complete native builds, dependency/trust
closure, package/configuration lifecycle and both-size terminal workflows
remain required. This single feature does not complete R4/M6 or R1–R5/M5–M9.

The final hold verifies the four frozen lane indexes and binds all retained
regular outputs, the fourteen internal makepkg cache symlinks and this guide.
The independent peer receipt is
`467c186a2101eb8ad00b1bfb6535e3641771062216ba39ff223d08cdaea3940e`;
host assembly receipt is
`61ff017ed190951346d33a7771648f7157d655d6f40812969d22fcb0dcaa4d8d`.
`final-receipt.json` excludes itself from its content index; its external digest
is reported with delivery. This seal establishes source/host-review custody,
not primary adoption or target acceptance.
