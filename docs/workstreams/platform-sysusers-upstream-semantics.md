# Pinned sysusers and ALPM source semantics

This is a source-audited proposal. Official upstream systemd v262 resolves to
`8cc40e0c5e9234bf45084751ac53b1fbfe70b492`; pacman's selected version prefix
54d9411 resolves to `54d94116164b0b2202c6061c4a59c6f3e70820d8`.
These revisions pin the inspected upstream bytes. They do not identify an ARM
package-build commit or establish the retained binaries' patches/constants.

Retained PKGINFO and BUILDINFO select systemd 262-1/aarch64 and pacman
7.1.0.r9.g54d9411-2/aarch64. Their PKGBUILD hashes differ from the official
recipes acquired here:

| Package | Selected BUILDINFO PKGBUILD SHA256 | Inspected recipe SHA256 |
| --- | --- | --- |
| systemd | `9ea4d4fa1341fa640f98cbf4bd9b42b7d7c77c2344db2a243b703a6b73b24433` | `a3ac91580efa00668e2453b4fc890c32c4dbe899a196271e10b201cce1e9e4cc` |
| pacman | `3064461fa0821e329e5c9fce4962016e358e1b0d5d259c5d18f7a77174c80219` | `0043b86a639da6a67239cee8479b46e5ec43835c722ff3bdda8c1f34616ca651` |

The systemd recipe is read-bound to packaging commit
`301752c301d8d27080323e8ceea17c1e90a7a726`. Pacman's current recipe has an
immutable blob identity; its latest path-log commit
`fd636a0077db0efe900d67d4de910c0d270fc8c4` remains a qualified candidate, not
an explicit-ref file observation or selected build revision. Matching version
strings and changing an arch field do not resolve the hash differences.

The packet is under
`artifacts/reviews/platform-sysusers-upstream-semantics-proposal-20261013/`.
`selected-package-metadata.json` preserves the retained version/build evidence;
`systemd/` supplies 17 conditional claims and annotations for all 64 rules;
`pacman/` maps all 23 INSTALL and 31 hook texts;
`packaging/` records recipe correspondence and declared patches/options;
`build-defaults/` closes the upstream SCRIPTLET_SHELL option definition.
Source hashes, full revisions, immutable URLs, byte counts, acquisition methods
and license context are recorded; available per-file notices are preserved.
Source/manual files were read as text.

## Sysusers semantics established in upstream v262

[sysusers.c](https://github.com/systemd/systemd/blob/8cc40e0c5e9234bf45084751ac53b1fbfe70b492/src/sysusers/sysusers.c)
and the matching manuals define `u` as a user with a normally same-name primary
group, `g` as a group and `m` as supplementary membership. `m` can synthesize
missing user/group declarations. `u!` expires a newly created shadow account
at day 1; it does not retrofit expiry/home/shell/GECOS onto an existing name.
Omitted, empty and dash fields normalize to unset. New unset home defaults to
`/`, GECOS to empty, and shell to generated NOLOGIN except UID 0 and credential
overrides. No home directory is created by this program.

These source rules annotate the retained 38 `g`, three `u`, 18 `u!` and five
`m` lines, including 32 dash IDs. They do not predict actual accounts. Existing
names retain loaded database IDs. Explicit numeric IDs for new names are
suggestions; conflicting suggestions can fall back to allocation. Groups are
processed before users, in insertion order, with a shared descending allocation
cursor. Existing/queued occupancy and strict/reference modes affect collisions.
Mail UID 8 need not equal its same-name group GID 12; ftp UID 14 need not equal
group GID 11. The two normalized `g root 0` items are equivalent if both are
effective inputs; the first item is retained. UID and GID namespaces remain
distinct. No initial account preimages or final IDs were invented.

For the packet's no-`r` branch, allocation depends on runtime login.defs and
generated SYSTEM_UID_MAX. Meson zero-valued options read build-host login.defs,
with fallback minima 1 and maxima 999. This is not evidence that the selected
binary used 1–999. The runtime `read_login_defs` helper and generated config are
outside the acquired closure. Generated NOLOGIN and DEFAULT_USER_SHELL also
depend on options; root's shell helper prefers an available generated default
before `/bin/sh`. Neither manual prose nor the upstream Meson `/bin/bash`
default establishes the retained binary's effective shell.

The manual's directory precedence, lexical selected-file ordering and
same-basename overrides include `/dev/null` masks. First duplicate items are
retained; conflicting later lines warn and are ignored. Item equivalence does
not compare the locked flag. Full macro/build correspondence and both call
phases' effective config namespaces remain required. Positional files,
`--replace`, stdin and `sysusers.extra` credentials can change the input set.
Without a sysusers alternate-root argument, NSS adds account lookups;
alternate-root branches bypass those lookups. ALPM chroot does not itself set
that argument. The two bare sysusers calls therefore also need the selected
root's effective NSS lookup context. Missing database files and erroneous
files are distinct.

The writer prepares group/gshadow/passwd/shadow temporaries and backups, then
renames in that order. A later rename failure may leave earlier files changed;
there is no four-file rollback here. Existing file permission preservation and
absent-file modes are source branches, not observed output metadata. Time,
credentials, generated constants and unfetched helper behavior still matter.
Config and item errors can be logged/continued while the final write result
returns success. **Exit 0 does not prove all requested account effects.**

## ALPM dispatch at the pinned pacman revision

[trans.c](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/lib/libalpm/trans.c)
sources INSTALL through `SCRIPTLET_SHELL -c`, then calls the callback. INSTALL's
shebang is ignored by that route. Upstream `meson.build:68` derives the macro
from `scriptlet-shell`; `meson_options.txt:17` defaults it to `/bin/sh`. The
inspected, mismatching ALARM recipe explicitly supplies `/usr/bin/bash`.
**The retained binary's compiled interpreter is unresolved.** Actual target
path resolution and packaging patches must be reconciled before using either
value as execution evidence.

There are six callback names: pre/post install, upgrade and remove. Upgrades,
reinstalls and downgrades use the new INSTALL, with new version then old version
as arguments. Removal uses the old INSTALL and removed version. Upgrade's old
package removal skips removal callbacks. `post_uninstall` is not a dispatcher
callback. Pre-add callbacks precede extraction; post-add callbacks follow that
package's extraction/database update, before later package steps. Their return
values are ignored by callers; successful commit does not prove scriptlets
succeeded or effects rolled back.

Hooks reload their namespace for each pre/post phase. Later configured hook
directories take priority over earlier ones for valid same-basename overrides;
selected names sort lexically with suffix ignored. Multiple trigger sections
are OR. Path matches use package file lists and fnmatch without FNM_PATHNAME;
last matching target pattern wins. Reinstall/downgrade and coincident removed/
added paths can classify as Upgrade. These are source rules, not a replay of
the selected 261-package transaction.

Depends uses the local package cache at the running phase. NeedsTargets supplies
sorted unique matching targets (paths or package names) on stdin, not argv.
Hook Exec is word-split and
passed to `execv`, with no implicit shell or PATH search in this layer. Direct
script execution can therefore involve its shebang, unlike sourced INSTALL.
Both routes use the source's child-root/CWD handling: chroot when appropriate,
CWD `/`, umask 0022, SHLVL initialized only if absent and BASH_ENV unset. Other
environment remains inherited. Package patches affecting child pipes/stdin and
the actual root, privileges, environment and loader remain unproved.

NOSCRIPTLET and NOHOOKS independently suppress their routes. DBONLY is not a
blanket callback/hook suppression flag. Pre-hook errors can stop commit;
post-hook return is ignored. AbortOnFail is phase-dependent and absent from the
31 retained hooks. There is no general effect rollback. Logged errors,
callback status and transaction status need separate finite effect predicates.

This establishes two **conditional** sysusers phases: systemd's post_install/
post_upgrade body calls post_common during its package step, then the effective
matching post-transaction hook can call systemd-hook sysusers. Those phases can
see different configs/account states. Flags, matching, ordering and successful
invocation are not established by the source mapping alone.

## Remaining finite closure

First obtain the exact recipes matching both BUILDINFO hashes, or authoritative
builder transformation records, and their complete patches/helper/config
closure. The candidate systemd device-access-groups patch is unfetched; pacman
declares six applied/reverted patches, including stdin/chroot-child changes.
Their effects cannot be substituted with unpatched upstream semantics.

Then close the named missing sysusers helper/generated-constant context, select
the target account and local-package DB prestate, and retain complete effective
config/hook namespaces at both phases. Root must choose provider/cycle/bootstrap
policy, operation/version sequence, flags, interpreter/loader/environment and
an isolated root. Only a separately selected finite account/file effect,
repeat/interruption/removal/recovery oracle can establish runtime effects.

Acquisition is closed at at most 30 retained fetched/decoded text leaves and
less than 8 MiB processed response/decoded bytes. Failed requests are retained
as diagnostics, including a missing license path and raw API timeouts; they are
not accepted source. Upstream LGPL/GPL texts and notices are preserved, but
whole-package license/source/crypto acceptance remains false. No host account
files, raw archives, GPG/signatures, Docker, builds, target interpreters,
sysusers, target libraries, hooks, installation or system mutation ran.
Historical seals, shared manifests, Git and goals are unchanged. R1–R5 and
M5–M9 remain mandatory and incomplete.
