# Original setup and repository CLIs

Development candidate 0.1.0-6; source/host-fixture validation only. Native package
build, installation and hardware results for this revision are NOT RUN. This package ships original helpers as
`/usr/bin/cachy-asahi-setup` and `/usr/bin/cachy-asahi-repository`, plus the repository
guide under `/usr/share/doc/cachy-asahi-setup/repository-enrollment.md`. Runtime
dependencies are Python 3.11+, gnupg, and pacman. The existing per-user helper still
uses only Python's standard library; the separate repository helper invokes GPG
and pacman-key. Hyprland/Fish/Zsh templates and the six shell modules remain optional, separately installed
and separately owned. No third-party files or compiled payload are bundled.
Original material is MIT-licensed; the complete project license is installed.

Installing/upgrading/removing the package owns two CLIs and their documentation and
notices below `/usr/share`. There are no hooks, `/etc` or default-session changes,
service operations, package installation or automatic user activation/removal.
The per-user helper creates no user configuration unless explicitly invoked with
`--apply`. Package lifecycle operations never invoke either helper and never
change repository selection or public-key trust. Removing/reinstalling the package
leaves existing managed user/system configuration and imported trust untouched.

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

Recovery preview lists each recorded component/path as `would-add`, `would-update`,
`would-remove` or `already-applied`. It checks the same pending file hashes,
ordered blocks and required template contents that apply will check, without
creating locks, state or configuration. A user edit or changed required template
stops the preview with exit1 and retains the journal. Review the error and
reconcile the affected path before retrying. Preview cannot reserve files;
`--apply` repeats all checks before writing.

Existing edits that conflict with replay stop recovery and retain the journal.
Exit codes distinguish success (0), error/refusal (1) and preserved conflicts or
pending previewed recovery (2). Inspect all reported actions; a zero exit code is
not hardware or package lifecycle acceptance.

## Explicit optional shell modules (candidate 0.1.0-5)

Select each module by name. Selecting fish, zsh or hyprland keeps the earlier
behavior and enables no module. An activate request without components still
fails; removal without components considers all recorded ownership. Installed
packages are prerequisites; setup never installs them, changes a login shell,
registers a service/session/repository, launches a desktop or enables a default.
It supplies guarded source blocks, with no new keybinding declarations. Each
module's explicitly sourced opt-in wrapper keeps its own namespace/binding policy.

| Component | Optional package | Exact source below /usr/share/cachy-asahi |
| --- | --- | --- |
| fish-bang-bang | cachy-asahi-fish-bang-bang | fish-bang-bang/opt-in.fish |
| fish-autopair | cachy-asahi-fish-autopair | fish-autopair/opt-in.fish |
| fish-done | cachy-asahi-fish-done | fish-done/opt-in.fish |
| zsh-autosuggestions | cachy-asahi-zsh-autosuggestions | zsh-autosuggestions/opt-in.zsh |
| zsh-syntax-highlighting | cachy-asahi-zsh-syntax-highlighting | zsh-syntax-highlighting/opt-in.zsh |
| zsh-history-substring-search | cachy-asahi-zsh-history-substring-search | zsh-history-substring-search/opt-in.zsh |

For example, preview and explicitly apply just the Zsh modules:

```sh
cachy-asahi-setup activate --components zsh-autosuggestions zsh-syntax-highlighting zsh-history-substring-search
cachy-asahi-setup activate --components zsh-autosuggestions zsh-syntax-highlighting zsh-history-substring-search --apply
cachy-asahi-setup remove --components zsh-syntax-highlighting
```

Each module receives its own v1 marker and ownership record in the existing Fish
config.fish or Zsh .zshrc. Existing configuration bytes, metadata and unrelated
records remain user-owned. Owned source blocks use deterministic order: existing
base shell template first, then Fish bang-bang/autopair/Done or Zsh autosuggestions/
highlighting/substring. Highlighting precedes substring search even when selected
later in a separate invocation. This orders only exact tool-owned blocks, not
arbitrary user initialization. An edited ordering anchor or manually reordered
owned blocks causes safe refusal; setup does not rewrite user edits to reconcile
order. Module sources are literal namespaced paths. Missing selected sources fail
with the component name before creating configuration, locks or state directories.
All selected source paths use the same no-symlink/ownership/size gates as templates.

All changes to one startup file are planned as a joined sequence and published in
one atomic file write. New grouped journal entries keep exact intermediate and
outer before/after hashes; every delta and source-root/ownership claim is checked
before any configuration write. Already-applied file endpoints and a committed
state resume without repeating blocks. Source guards skip missing packages at
shell startup; explicit removal remains possible after packages disappear. A file
originally created by setup can be deleted only when its last unchanged owned
block is removed and no user bytes remain. Preexisting empty files stay.

The state schema remains exact integer 1. Existing 0.1.0-3/4 records and ordinary
single-entry pending journals remain readable without rewriting or discarding
ownership. Old helpers safely refuse new module records/grouped journals; keep
the candidate CLI to finish recovery/removal before a downgrade. New state is not
silently reset, adopted, ignored or migrated. An interrupted user's conflicting
edit retains both their bytes and the pending journal. Unknown components, paths,
markers, endpoints, insertion anchors and unsafe source roots are not waived.
Existing path/root/privacy/limit/preview-read-only rules still apply.

This feature is a source/host-tested development candidate. Earlier setup3/4
native results and the held old587/expanded600 package selections are unchanged;
they do not validate setup5. Actual package-manager upgrades/lifecycle, native
ARM/16K, real-user profiles, M2 and release acceptance remain NOT RUN for setup5.

## Explicit repository operation

Read the installed repository guide before use. This command is a separate
system-administration operation; it is not a per-user setup component:

```sh
cachy-asahi-repository --help
cachy-asahi-repository enroll --snapshot-url "$SNAPSHOT_URL" \
  --public-key /etc/pacman.d/operator-public.gpg --fingerprint "$EXPECTED_PRIMARY_FINGERPRINT"
```

Preview is the default. An authenticated full primary fingerprint, separately
obtained root-owned public export, existing initialized base keyring, and explicit
HTTPS generation URL are required. Only an operator invocation with global
`--apply` before `enroll` or `disable` changes configuration/trust. Both package
and database signatures are mandatory. Disabling retains public keys and local
signatures. Neither helper installs packages or fetches a repository. The URL
selects a location without proving remote immutability, currency, or release
authorization; no production endpoint/key is selected here. Partial keyring edits
are not automatically rolled back. See the unchanged installed guide for refusal
conditions, recovery, global pacman-trust limitations, and target-test boundaries.

## Source synchronization and build review

`source-provenance.json` pins the current setup helper and the unchanged exact
canonical repository CLI and guide. Both CLIs and the guide are copied
byte-for-byte, without a shebang or behavior change. Root LICENSE bytes are pinned. Before every source snapshot/build/release from this checkout:

```sh
python -B check-sync.py
python -B check-sync.py --source repository
python -B check-sync.py --source repository-doc
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

The 0.1.0-3 source-only successor refuses duplicate JSON object keys and
floating-point, exponent-form or non-finite numbers in recovery metadata before
replay or committing state. Metadata schema must be exact integer 1. Refused state
or journal bytes are preserved for inspection; this does not authorize recovery
of malformed metadata. It adds no automatic user activation or removal.

The 0.1.0-4 delivery candidate leaves that per-user helper byte-identical and
adds only the reviewed repository helper, guide, and explicit GPG/pacman runtime
dependencies. Existing source-level repository fixture tests are separate from
package-delivery validation and are not rerun by makepkg.

`host-validation.json` and `evidence/` retain historical 0.1.0-2 host build, content
and isolated packaged-CLI results unchanged. They do not validate this corrected
0.1.0-5 package. Separately recorded 0.1.0-3 native evidence remains evidence for
that frozen recipe; it is not validation of this 0.1.0-5 feature change. Candidate
native ARM build pairs, install/lifecycle, and hardware validation are NOT RUN. Historical x86_64 development checks are not
clean native aarch64 builds or actual package installation. Published
ARM Python availability does not establish the selected Asahi dependency/trust
snapshot. Native ARM build/rebuild, package-manager install/upgrade/remove/reinstall,
real-user/target lifecycle, M2 13-inch/15-inch and stable release gates remain pending.
