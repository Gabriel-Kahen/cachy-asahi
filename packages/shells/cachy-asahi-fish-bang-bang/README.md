# cachy-asahi-fish-bang-bang

Development package proposal for R4/M6, version 0.1.0-2. Two unchanged MIT
upstream helpers at ec991b80ba7d4dda7a962167b036efc5c2d79419 are paired with an
original opt-in wrapper. Full copyright/permission/warranty notices are shipped.
The complete six-file upstream source record is held in the accompanying review.
The upstream auto-binding/uninstall hooks are not installed or sourced.

Runtime dependency: Fish>=4.0. Actual source/adapter and package checks use
Fish 4.9.3 on x86_64. Seven ordinary 0644 files under /usr/share provide the
functions, wrapper, usage and licenses. Source checksums are literal and local;
no network, compiled objects, package hooks or global Fish startup are added.

Read usage.md for explicit activation after user bindings and optional original
project helpers. Existing helpers/modules and affected user bindings win;
empty history keeps !!/!$ literal. Expansion edits the buffer and requires a
separate Enter to execute. The user configuration/history is not rewritten.
Removal leaves the user's guarded source line intact and becomes inactive in
fresh shells; already loaded state lasts until restart. Actual package-manager
lifecycle, native ARM builds and both M2 Air targets remain NOT RUN.

The author validates 24 finite models with an actual isolated interpreter,
while the readline/token-search interface is modeled. Independent review passed 16 actual Fish CLI controls and 11 real terminal
controls, including quoted argument expansion and existing-state preservation.
Two fresh host makepkg assemblies are held separately. Package
payload identity passed; archive-byte reproducibility is not established.
Host makepkg uses --nodeps and controlled-empty pacman metadata, so it neither
resolves dependencies nor proves the host or target dependency inventory.

This directory is not adopted into shared maps or the primary package tree.
Root must review source/recipe/SRCINFO pins, manifest and existing development
addon bindings before native dispatch. See docs/workstreams/fish-history-module.md
and the accompanying review receipt. No full M6, release, hardware or performance
acceptance is claimed.


Pkgrel2 corrects source-caller continuation identified by real three-module Fish
PTY composition: top-level return in the previous wrapper cut off a calling
function on repeat or noninteractive source. Only the independent wrapper's
scope changes; full original upstream source and MIT notices, helper bytes,
affected-binding precedence, expansion semantics and payload paths remain.
All legacy standalone cases and the composed host checks are rerun separately.
No old pkgrel1 or held587 evidence is relabeled as new native acceptance.
