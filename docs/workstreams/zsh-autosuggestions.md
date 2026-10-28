# S02 / M6 / T02: opt-in Zsh autosuggestions

This work adds one pinned, individually licensed shell function in a new package.
It preserves the four original template/setup packages and their user-facing
configuration contracts. It does not close the complete Cachy experience,
protected-platform dependency/ELF/firmware blockers or native/target acceptance.
The [software-gap review](../reviews/updated-roadmap-software-gap-20261012.md)
and [tools disposition](../port/tools-functionality.md) select the function.

## Exact source and grant

Package `cachy-asahi-zsh-autosuggestions` 0.7.1-1 selects the unchanged aggregate
from [upstream revision 85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5](https://github.com/zsh-users/zsh-autosuggestions/tree/85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5).
Official commit archive: 29,979 bytes, SHA256
`20665e469e720e674964a66854d5534b9af78cdfd438512746ecd1ade8e819ce`.
Module: 27,017 bytes, SHA256
`eec7ba8f7a71414ace0ea0fab0908d005b24cf65d83b169c0ff97815d3cfc51a`.
Full [MIT license at that revision](https://github.com/zsh-users/zsh-autosuggestions/blob/85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5/LICENSE):
1,096 bytes, SHA256
`4598a6be0b8d7f2b708da5259d2a30d4e15e59b3c66781bab9e27744a9f859d8`.
Both original copyright lines and the complete permission/warranty notice remain
in the module header and installed `LICENSE.upstream`. Original integration
material has the unchanged project MIT grant in `LICENSE.project`.

The bounded primary-source packet checks 61 regular archive files and 11
directories, with no links/special files. Inert concatenation of the Makefile's
specified source/header order exactly reproduces the selected aggregate.
Twenty-seven source/notice controls pass. Additional upstream Ruby/Gem test
files and dependencies are not shipped. This selected-file grant proof does
not clear the separate ungranted Cachy Zsh configuration or all other plugins.
`source-provenance.json` records the selected bytes; every local recipe source
has a finite SHA256 in PKGBUILD and generated `.SRCINFO`. Packaging requires
no network fetch, Git checkout, compilation or generation of upstream code.

The existing shell dependency observation names ARM-extra package
`zsh-autosuggestions` 0.7.1-1, archive
`zsh-autosuggestions-0.7.1-1-any.pkg.tar.xz`, SHA256
`f7518709486c1eac2b862d0af2de97011c6e95815e742759bd6adbcb541aeb82`.
A filename lookup in project artifacts finds no matching filename. The metadata
inspected here does not bind a retained payload to the selected full revision.
This work therefore packages the independently retained selected source; it
makes no assertion that the observed base package is unavailable or unsuitable.

## Dependencies, ownership and lifecycle

Runtime: `zsh>=4.3.11`, as documented upstream. Recorded current ARM builder:
Zsh 5.9.2-1, which remains an input observation rather than target installation.
Optional `coreutils` supplies `stty` for the unselected optional completion
strategy. Default history suggestions need no additional external helper.
Standard Arch makepkg/base-devel tools assemble the package; Zsh is needed by
its syntax-only check(). No additional makedepends or compiled objects.

Six ordinary 0644 payload files are installed:

- `/usr/share/cachy-asahi/zsh-autosuggestions/zsh-autosuggestions.zsh`
- `/usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh`
- `/usr/share/cachy-asahi/zsh-autosuggestions/README.md`
- `/usr/share/licenses/cachy-asahi-zsh-autosuggestions/LICENSE.upstream`
- `/usr/share/licenses/cachy-asahi-zsh-autosuggestions/LICENSE.project`
- `/usr/share/licenses/cachy-asahi-zsh-autosuggestions/NOTICE`

The original four-line wrapper guards noninteractive sourcing and an existing
`_zsh_autosuggest_start` function, then sources the adjacent pinned aggregate.
It sets no options, history path, alias, prompt, widget or keybinding itself.
Upstream activates its expected ZLE wrappers/precmd hook after explicit opt-in.
Widget behavior and keybinding choices must survive; their definitions need
not remain identical while upstream wraps them. No global rc, skeleton,
service, package transaction hook, login shell, boot or installer state changes.

The installed usage guide supplies one-session and guarded persistent opt-in.
Package removal removes only its six owned files; a guarded source line remains
user-owned and becomes a no-op. Functions/widgets already loaded in an old
shell process persist until that shell restarts. Reinstallation restores the
same guarded path. Actual package manager install/upgrade/remove/reinstall and
migration of existing users remain separate acceptance work. Async suggestions
are upstream's newer-Zsh default; isolated history tests explicitly unset the
async flag after sourcing. Completion-strategy/async behavior and integration
with every other plugin are not certified by those synchronous fixtures.

## Current validation and integration proposal

Static Bash/Zsh syntax and makepkg --printsrcinfo checks pass. Two independent
isolated source copies ran `makepkg --nodeps --noconfirm`; syntax check() ran,
no installation was requested, and dependency resolution was explicitly skipped.
All six payload paths, modes and byte hashes match between builds. Archive
hashes differ; payload identity is the established result. Both packages,
metadata, bounded logs and type/path/hash checks are retained in the owned
`artifacts/reviews/zsh-autosuggestions-20261012/host-assembly/` namespace.
These x86_64 host assemblies are not two clean native ARM build attempts.

The new package's `integration-proposal.json` proposes a development candidate
with MIT license, arch any, required Zsh and optional coreutils, release
selection false, and native/installation/hardware NOT RUN. Root alone updates
the shared manifest/locks/source map and registers the exact source closure in
the existing native build/compare path. No new workflow family or dispatch is
created here. Full target Zsh dependency/trust closure, actual package lifecycle,
16K/base runtime, both M2 Air sizes and publication remain pending.

The updater four-file source hold and its historical handoff remain unchanged.
The protected-platform closure proposal remains a proposal; no graph/provider,
ELF or firmware decision was applied by this workstream.

## Isolated actual Zsh behavior

The author's final five finite fixture groups pass on actual host Zsh 5.9.2,
x86_64. A private PTY/ZLE shows a controlled history suffix; the documented
right-arrow/forward-char operation accepts it into the buffer without executing
it. Backspace editing, an existing Ctrl-X/Ctrl-U widget/keybinding and configured
highlight style survive first/repeated source. A preloaded function sentinel
blocks duplicate module loading. Noninteractive sourcing loads nothing. Actual
SIGINT after a displayed suggestion leaves the same private shell/custom widget
usable, with bounded process/PTY cleanup. A simulated absent package path
skips sourcing and preserves the fixture's guarded user line; its condition
status 1 is retained. This is not an actual package uninstall/reinstall test.

Every fixture uses an isolated HOME/ZDOTDIR, controlled history and Zsh -f;
poison startup files are not read, history contents and 0600 permissions remain
unchanged, and no real user configuration/history or network command is used.
The author disables async after source for these synchronous history fixtures.
The final script/inputs are held with exact pins. Earlier fixture attempts are
retained: attempt01 failed because queued control input suppressed fetching and
a bare exit inherited SIGINT status; attempt02 passed the explicit accept
widget; attempt03 passes the documented right arrow and records a displayed
suggestion before interruption. Earlier helper revisions were not separately
frozen; only the final attempt is bound to the held final script. These harness
limitations do not become native or target acceptance.

## Independent review and final hold

Independent review accepts the source/host-fixture scope with no blockers.
It replays the five author groups on fresh copies and adds three actual ZLE
cases: the current aggregate loaded directly before the wrapper (functions,
precmd list, configuration and a custom keybinding remain unchanged), a
controlled host history case with the upstream async flag enabled, and SIGINT
while that suggestion is displayed. This establishes only those finite
host-history cases; general async, completion and third-party integration
remain unaccepted. It independently rehashes/parses both retained package
archives, confirms six regular 0644 root-owned payload entries and their exact
byte identity, and preserves the differing archive hashes.

The peer receipt binds all twelve live/held new package files, exact sources
and its 96 evidence artifacts. Its SHA256 is
`62593a7ba6d4620b30a6f6f31575bffada236c1a779dc55916d1f37d569551fe`.
The final handoff indexes the source hold, primary source, static metadata,
host packages, author/peer fixture evidence and this guide. Standard makepkg
created twelve build-cache source symlinks pointing inside the owned assembly
namespace; they are indexed separately and are not installed payload files.
No package manager installation or native dispatch follows from this receipt.
