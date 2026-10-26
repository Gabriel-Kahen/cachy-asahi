# Pinned opt-in Zsh autosuggestions

Status: source/grant audited; two isolated x86_64 host assemblies pass. Native
ARM packaging, selected-target package lifecycle and M2 acceptance remain open.
This implements the first bounded M6/T02/S02 history-autosuggestion function.
The existing Cachy Zsh configuration remains deferred for its own unresolved
grant; none of it is included here.

The exact unchanged upstream aggregate is from zsh-users/zsh-autosuggestions
revision `85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5`, VERSION v0.7.1. Its embedded
full MIT notice and `LICENSE.upstream` retain both original copyright lines.
`LICENSE.project` licenses our original wrapper/recipe/docs. `NOTICE` separates
their provenance. `source-provenance.json` binds the retained official commit
archive, generated aggregate and selected license. The aggregate matches the
inert concatenation specified by upstream's Makefile; the recipe packages the
already-generated exact bytes and compiles nothing. Ruby/Gem test dependencies
and other upstream tree files are not shipped.

Runtime dependency: `zsh>=4.3.11`. The current recorded ARM builder has Zsh
5.9.2-1; that observation does not prove target installation. Optional
`coreutils` supplies `stty` used by upstream's optional completion strategy.
The selected/default history strategy does not use that external helper.
Build environment: standard Arch makepkg/base-devel (`bash`, `install`, archive
creation), with Zsh needed by check(). No extra makedepends, compiler, Git,
network fetch, dependency installation or source generation is introduced.

The six local source files are independently SHA256-pinned in `PKGBUILD` and
`.SRCINFO`. check() runs Zsh syntax checks on the wrapper and module. See
`usage.md` for explicit session/persistent opt-in, history strategy, plugin
ordering, acceptance into the editable buffer, async opt-out, disable/removal
and the existing-module guard. The package installs six ordinary 0644 files
only under `/usr/share`; no install script, transaction hook, service, startup
rc, user history, skeleton, boot file, alias or login-shell mutation is present.
Upstream's interactive ZLE wrappers/precmd shell hook activate only after the
user sources the wrapper. Package removal leaves loaded state in old running
shells; restarting a shell with a guarded source line supplies removal behavior.
Actual package manager upgrade/remove/reinstall has not been tested here.

Static syntax and makepkg --printsrcinfo checks pass. Two independent copies
ran makepkg --nodeps --noconfirm without installation; check() ran. --nodeps
explicitly bypassed dependency resolution. Both package payloads have the same
six paths, byte hashes and 0644 modes; whole archive hashes differ. These are
host assemblies rather than clean native ARM build pairs. Artifacts and final
runtime/independent-review receipts live in
`artifacts/reviews/zsh-autosuggestions-20261012/`.

The coordinator alone registers this new development recipe and its input
closure using the existing build/compare path. No existing package, shared
manifest, lock, workflow or source map is edited by this workstream. Neither
this one module nor its host tests close M6, platform graph/ELF/firmware
blockers or hardware/performance gates.
