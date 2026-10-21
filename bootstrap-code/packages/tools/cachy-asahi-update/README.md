# Cachy-update development package

This candidate preserves the full upstream updater and compiled tray. It has no
automatic activation, global autostart file, package install hook or enabled user
timer. It is **not accepted for Apple system updates or release installation**.
This is source/recipe integration only: native package builds, installation and
Apple execution are **NOT RUN**.

The software is CachyOS's Arch-Update fork at
`e2b1b7144be71cf392809f48d1440f8da1d9c81a`. Original geometric project icons replace
upstream artwork whose provenance remains unresolved; source/translation notices
are retained. Source and every locked Cargo archive are pinned separately.

Do not infer updater safety from compilation. Invoking the UI/updater can start
pacman transactions, optional AUR/Flatpak operations, cache/orphan removal,
configuration merging, service restarts and reboot requests. The tray searches
user-controlled desktop files and state before system defaults. Apple kernel
reboot decisions now use the original read-only Python policy helper at
`/usr/lib/cachy-asahi-update/asahi-policy`; the PC vmlinuz heuristic is removed.
The helper derives module releases from supplied package-owned module paths,
compares every mapped protected package before/after, and requires an exact
caller-pinned transition. It never assumes a package version equals uname.

No accepted policy or default approval is installed. Full upgrades require
preflight before update, orphan and cache stages, including with no repository
updates listed. AUR and Flatpak paths require explicit operation declarations.
Missing policy is reported as unconfigured; protected platform changes require
coordinated handling. Kernel/module-hook and container conditions cannot bypass
the post-update policy check. Generic service restarts accept only reviewed unit
argv and exclude the fixed audio protection units and policy-designated units.
The updater/reboot/restart implementations remain behind these conditions.

The trusted release caller must provide `CACHY_ASAHI_POLICY_FILE` and its
`CACHY_ASAHI_POLICY_SHA256`, plus separately pinned
`CACHY_ASAHI_PRE_OBSERVATION_FILE`/`CACHY_ASAHI_PRE_OBSERVATION_SHA256` and
`CACHY_ASAHI_POST_OBSERVATION_FILE`/`CACHY_ASAHI_POST_OBSERVATION_SHA256`.
Policy schema, operation names and synthetic examples are defined by
`asahi-policy.py` and `test-asahi-policy.py`. Test fixtures are not usable target
approval. The caller still needs authenticated actual observations, frozen signed
repository inputs, exact transaction binding, coordinated platform handling and
target recovery/hardware evidence. JSON hashes alone prove none of those facts;
the source checks do not bind a later rolling-repository pacman/AUR transaction.

`--check --enable` explicitly enables the user timer and propagates failure;
ordinary `--check` does not enable it. No activation is part of package creation.

Build acceptance requires the completed source/artwork/Cargo license audit, a
reviewed offline vendor closure and build scripts, and a separately frozen native
builder extension. The coordinator's private compile trial uses an authenticated
354-package worker and verifies its finite compiler/check dependency set. It uses
`makepkg --nodeps` because that worker omits four declared runtime roots: htmlq,
pacman-contrib, archlinux-contrib and xdg-utils. Package dependencies remain intact;
their complete actual target transaction is **NOT RUN**. A private compiled
artifact does not establish runtime dependency availability or installation
acceptance. The coordinator runs two isolated, network-disabled native builds
and retains artifacts/provenance. Source checks comprise 19 unchanged
upstream characterizations, 38 behavior-patch cases and 47 synthetic policy/mock
integration cases; they execute no real updater or host services. 16K-page
loading, real private-D-Bus tray/menu tests, package lifecycle and M2
update/recovery remain separate gates.

Installation owns upstream paths below `/usr` including `arch-update`, its
libraries, tray, desktop files, user units, completions, translations and manuals,
plus the read-only policy helper and its full project MIT grant.
It conflicts with packages already owning those paths (`arch-update` and
`cachy-update`). Removal uses pacman's ownership and preserves user config/state;
running processes and manually enabled user units require an explicit reviewed
lifecycle procedure. No build or research script changes the host package or
service state.
