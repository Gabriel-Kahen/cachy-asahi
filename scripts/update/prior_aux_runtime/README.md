# Prior data leaves with retained auxiliary/link state

`prior_aux_runtime` is a new explicit Python adapter for the existing guarded
disposable-root update engine. It does not change `internal_runtime`, the frozen
setup3→4 auxiliary/link adapters, their defaults, or any CLI. Caller usage:

```python
import prior_aux_runtime
result = prior_aux_runtime.apply(args, comparator_path=exact_existing_comparator)
```

The existing settings/policy/release authentication, exact587 before/after locks,
package-manager lock, capacity and commit/checkpoint machinery still apply.
`args.prior_archive` and its adjacent `.sig` are mandatory. The sole selected
authenticated release row must exactly match the one changed installed package.
No additional release, arbitrary path sweep, target install or recovery interface
is introduced. The current release signer/keyring must authenticate the exact old
archive, whose identity/version/architecture and complete ownership must match
the installed package. Existing backup, archive/snapshot recheck and aggregate
old+new archive budgets remain. The prior archive is not rollback authorization.

This first candidate permits non-executable ordinary files and contained relative
symlink leaves below `usr/share/PACKAGE/`, `usr/share/doc/PACKAGE/` and
`usr/share/licenses/PACKAGE/`. Existing ordinary directory headers may appear
only with unchanged metadata. No directory creation, removal or replacement is
allowed. All prior leaves must match both the observed map and a live descriptor
read, including updated leaves. New leaves cannot overwrite unselected existing
nodes. Foreign ownership, hardlinks, parent aliases, escaping links, hooks,
service/socket/desktop-entry paths and executable/special modes refuse.

The original parser ignores `.INSTALL`. A separate instance of that same bounded
decoder therefore removes `.INSTALL` from its control allowlist and rejects
initial Linux ELF/shebang bytes while delegating the actual SHA256 computation.
No existing parser/module or stdlib hashing object is changed. This control/data
audit re-reads each archive; its own old+new counters have the same ceilings and
absolute deadline as the canonical inspection. Canonical shared budgets remain
unchanged; the extra audit never expands accepted archive limits. Other inert
packaging controls retain their existing treatment. Non-executable package data
is not a general proof that arbitrary future consumers cannot interpret data.

The existing pinned comparator and complete live auxiliary checkpoint remain
mandatory. Old and new leaves cannot touch the helper/config/cache/library
closure, selected literal links or their resolved endpoints. Projection uses
the existing private eligible view and restores the helper and every selected
raw link literal before comparison. Raw baseline/live maps are never replaced
permanently or stripped. Prior source/copy identities and hashes are rechecked
before and after observations/projection and at final precommit. The commit-ready
flag follows all checks. Postcommit auxiliary cache changes remain restricted
to the existing comparator's accepted exact transition; helper execution status
stays `NOT OBSERVED`.

`apply` adds authenticated prior/projection evidence, auxiliary checks and link
diagnostics to the engine's result. It retains known/unknown commit and checkpoint
truth on failure. There is no automatic rollback or assertion that a failed
transaction restored the root. Missing parents of foreign-owned persistent paths
still fail closed; synthetic fixture success does not establish full587 root
suitability, true-root use or M2 compatibility.

Focused checks run with genuine fresh TEST signatures and the host's unchanged
exact-pinned libalpm in read-only handles. They use a synthetic587 local database
and explicitly inert helper/library pins from the existing auxiliary fixture.
No helper, hook, ALPM commit or host trust store is executed/changed. Modeled
precommit/postcommit filesystem edits and delegated failure results are labeled
as such, not successful transactions. The suite requires mapped UID/GID0 and
does not skip unavailable prerequisites. For example, with a private short
`TMPDIR` beneath an owned scratch directory:

```sh
unshare --user --map-root-user --net -- \
  python3 -I -B -Werror::ResourceWarning scripts/update/test_prior_aux_runtime.py -v
```

Actual complete auxiliary binaries, a real signed ALPM update/commit, native ARM,
the complete selected Asahi composition, both M2 Air models, recovery and release
qualification remain NOT RUN. This source component grants no target acceptance.
