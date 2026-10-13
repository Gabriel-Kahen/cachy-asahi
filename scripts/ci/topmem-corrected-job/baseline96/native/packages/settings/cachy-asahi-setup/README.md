# Original setup/removal CLI

Development candidate. This package ships the original, self-contained runtime
helper as `/usr/bin/cachy-asahi-setup`. It requires Python 3.11+ and its standard library
only; Hyprland/Fish/Zsh template packages are optional, separately installed and
separately owned. No third-party files or compiled payload are bundled. Original
material is MIT-licensed; the complete project license is installed.

Installing/upgrading/removing the package owns one CLI and its documentation and
notices below `/usr/share`. There are no hooks, `/etc` or default-session changes,
service operations, package installation or automatic user activation/removal.
The helper creates no user configuration unless explicitly invoked with `--apply`.

## Explicit per-user operation

Run as the intended non-root user after the template packages and target base
have passed their separate installation/dependency gates. Preview first:

```sh
cachy-asahi-setup --help
cachy-asahi-setup activate --components fish zsh hyprland
```

Inspect the JSON actions. The preview is read-only. Apply explicitly if its
reported actions are appropriate for that user:

```sh
cachy-asahi-setup activate --components fish zsh hyprland --apply
```

Fish/Zsh gain identifiable guarded source blocks without replacing existing user
configuration. Hyprland gains a separate user-owned config file; the helper does
not launch/register a compositor or select a session. Run the printed parser-check
guidance separately and retain the validated base launcher/UWSM contract. A generic
setup result cannot establish graphics, portals, locking, audio or speaker safety.

Defaults use templates under `/usr/share/cachy-asahi`, Fish config under the user's
configuration directory, Zsh's current ZDOTDIR (otherwise home), a separate
`cachy-asahi/hyprland.lua` in the configuration directory, and state/journal under
`.local/state/cachy-asahi/setup` (or the selected XDG state home). Read the helper's
`--help` and canonical `docs/setup-tooling.md` for home/config/ZDOTDIR/state options
and limitations. Explicit roots must stay inside the selected home; unsafe paths
and user-edited managed content are preserved/refused rather than overwritten.
Resulting configuration and state/journal text must fit the helper's 2MiB limit;
large additions are rejected before changing any configuration. Pending shell
additions/replacements must retain the journal's selected template root.

Before removing templates or this CLI, switch back to the previous Hyprland
config/session and review helper removal while the CLI is still available:

```sh
cachy-asahi-setup remove
cachy-asahi-setup remove --apply
```

Removal targets only recorded additions. Edited files/blocks stay for user review;
existing process state survives until fresh shells/session. This operation does
not uninstall packages or stop applications. Removing the CLI package itself
never runs the helper and leaves user configuration and state untouched.
Reinstalling the package restores the CLI, with prior user state still separately
owned. Existing state can guide later preview/recovery; it is not silently reset.

An interrupted transaction is reported, not hidden. Use the same home/config/
ZDOTDIR/template-root/state options to inspect and explicitly resume:

```sh
cachy-asahi-setup recover
cachy-asahi-setup recover --apply
```

Existing edits that conflict with replay stop recovery and retain the journal.
Exit codes distinguish success (0), error/refusal (1) and preserved conflicts or
pending previewed recovery (2). Inspect all reported actions; a zero exit code is
not hardware or package lifecycle acceptance.

## Source synchronization and build review

`source-provenance.json` pins the exact canonical file under `scripts/setup/` and
root LICENSE bytes. The packaged CLI is copied byte-for-byte without a shebang or
behavior change. Before every source snapshot/build/release from this checkout:

```sh
python -B check-sync.py
python -B test-sync.py -v
```

The checker never executes/copies the helper. Canonical/package code or license
drift, stale provenance, missing sources or unsafe canonical paths fail. Explicit
`--canonical`, `--copy` and `--license` permit independently retained snapshots;
they must still match the recorded hashes. Do not update only a checksum to hide
canonical drift: review the new helper, copy it explicitly, refresh provenance and
recipe checksums/metadata, and rerun the affected checks.

Local source acquisition is offline and all inputs use fixed SHA256 values.
In-checkout makepkg prepare() also compares the actual canonical source and
root license; missing or changed canonical inputs fail. Isolated snapshots instead
verify their fixed provenance/source pins and require that pre-snapshot check.
Ordinary Arch `base-devel`/makepkg tools and Python assemble the recipe. Package
checks parse Python without writing bytecode; internal snapshot hashes verify
provenance. These standalone snapshot checks do not replace the mandatory
checkout-to-canonical comparison before snapshotting the recipe.

Final host build, content, synchronization and isolated packaged-CLI results are
recorded in `host-validation.json` and `evidence/`. They are x86_64 development
checks, not clean native aarch64 builds or actual package installation. Published
ARM Python availability does not establish the selected Asahi dependency/trust
snapshot. Native ARM build/rebuild, package-manager install/upgrade/remove/reinstall,
real-user/target lifecycle, M2 13-inch/15-inch and stable release gates remain pending.
