# Checkout-to-shell host rehearsal

November 14, 2026. **PASS: four local host assemblies followed by the actual
extracted-package developer-shell journey.** This adds a direct reproduction
entry point; contributors no longer need to assemble four archives or write an
input selection by hand.

From the checkout, as an ordinary user, with a new absolute output directory:

```sh
python3 -B scripts/integration/first_login_rehearsal.py \
  --output /absolute/new-first-login-evidence --build-and-rehearse
```

For CI, after the prerequisites are present, the exact command is:

```sh
python3 -B scripts/integration/first_login_rehearsal.py \
  --output "$RUNNER_TEMP/first-login-rehearsal" --build-and-rehearse
```

The output directory must not already exist. Required local programs are
`/usr/bin/{makepkg,fakeroot,bsdtar,fish,zsh,python3,git,zstd}` plus the normal host
makepkg/core utility environment and `/etc/makepkg.conf`. This tool does not
install prerequisites. Missing programs fail visibly; there are no substitutes
or skips. It refuses root and requires the explicit execution flag. No shared CI
workflow or project package selection was changed.

The finite recipe set is first-login `0.1.0-2`, Setup8 `0.3.0-1`, and the selected
Fish/Zsh configuration packages `0.1.0-1`. Recipe identities and versions must
match. The adapter copies each recipe to a newly owned private workspace,
generates its metadata, rejects non-local or duplicate source names and missing
SHA-256 pins, and verifies every declared source before copying it. The existing
first-login and Setup8 synchronization checkers also verify canonical source,
document and test copies. Generated `.SRCINFO` accompanies the private copies so
Setup8's retained checker can verify the actual recipe/source arrays.

All local source verification completes before the first assembly. Each private
recipe then runs `makepkg --verifysource`, followed by
`makepkg --nodeps --nocheck --noconfirm --nosign`. **Dependency resolution and
recipe `check()` functions are NOT RUN.** These are unsigned host assemblies;
they do not replace the separately recorded recipe checks or qualify native ARM,
a supported target transaction or release readiness.

A task-local makepkg configuration reads system defaults, then forces source,
package, source-package, log and build destinations into the private workspace.
It disables signing, distributed compilation and compiler caching, uses one zstd
compression thread, and fixes `SOURCE_DATE_EPOCH=1794614400` (2026-11-14 UTC).
HOME/XDG/GnuPG paths are also private. No global configuration is changed.
Observed `.PKGINFO` build dates equal that epoch for all four actual archives.
A fixed timestamp alone is not evidence of byte-reproducible builds.

The adapter derives archive paths/checksums and sends them through the existing
journey intake. Actual package identities and selected payloads are verified
there, then the same 41-command, ten-shell-startup journey runs: inspect,
preview/apply, Fish helpers and Zsh completion, preserved user edits, repeat,
deactivation, actual delivered Setup8 process-death injection, pending-operation
refusal, recovery and final deactivation. See the
[actual shell journey](first-login-actual-shells-host-20261114.md) for its exact
scope and injected interruption boundary. No fake templates or availability
checks are substituted in this combined path.

Host-build commands have 60-second individual deadlines; shell-journey commands
retain their 20-second deadlines and existing process-group cleanup. Build and
user state are removed at the end. The output retains `result.json`, recipe and
source digests, `derived-inputs.json`, all command diagnostics and the complete
`journey/` result. Paths in the derived selection refer to removed temporary
archives; repeat the adapter to rebuild them. Failures after output creation
retain a FAIL report and available command diagnostics while removing scratch.
Two initial metadata-setup failures confirmed this cleanup/report behavior.

## Actual verification

```sh
python3 -B -Werror::ResourceWarning \
  scripts/integration/first_login_rehearsal_test.py \
  --output /absolute/new-test-evidence --build-and-rehearse-test -v
```

The actual combined-path test passes in 13.2 seconds with zero skips on the
x86_64/4096-page host: 16 host-build commands and all 41 journey commands pass.
Its assertions verify source verification precedes each build, build flags and
fixed epoch, exact critical payload hashes against checkout sources, ten real
Fish/Zsh startups and removal of private build/user state. This explicit `_test.py`
file is excluded from ordinary `test_*.py` source discovery.

The retained local result is under the worktree's ignored
`work/first-login-build-and-rehearse-20261114-r3/`. Native ARM, M2, GUI,
package-manager installation, signing and release acceptance remain **NOT RUN**.
