# First-login CLI and opt-in package: host validation

November 14, 2026. Development x86_64 host only; ordinary-user temporary-home
checks and unsigned `any` package assembly. No installed package transaction,
Asahi/M2 session, native ARM or release acceptance is claimed.

The new `scripts/install/first_login.py` uses the separately installed setup
helper's schema-1 status and configuration operations. `inspect` discovers the
three original components; explicit activation first previews the complete
selection and refuses a known conflict before any apply call. Pending setup
transactions route to explicit recovery. A migration-owned journal remains with
the migration helper. Effective HOME/XDG/ZDOTDIR/state roots are retained in
follow-up commands, including when recovery runs in a different shell.

## Actual checks

- `python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/install -p test_first_login.py -v`: 11 passed, zero skips.
- `python3 -I -B packages/tools/cachy-asahi-first-login/check-sync.py --root .`: retained pins and canonical copies match.
- `makepkg --verifysource --noconfirm`: all ten local source checksums pass.
- `makepkg --nodeps --noconfirm`: unsigned package assembled; 11 real-Setup8 fixture cases and three actual package-layout/relocated-launcher cases pass, zero skips.
- Archive readback independently verifies the exact six installed files plus `.PKGINFO`, `.BUILDINFO` and `.MTREE`; launcher and implementation bytes match their retained sources. There is no `.INSTALL`, hook, service or autostart file.
- The actual archive was extracted to a temporary prefix without root ownership restoration. Its relocated launcher runs from `/`, prints help, and applies Fish configuration through the real Setup8 fixture in a new temporary home. This host has `/usr/bin/fish`; activation and repeated activation also execute in the package delivery test.
- The launcher runs with isolated Python: poisoned `PYTHONPATH`, `PYTHONHOME`, and working-directory modules cannot replace its implementation or standard-library imports during `--help`.
- `git diff --check`: passed.

`--nodeps` bypasses package dependency checks. The runtime setup dependency is
supplied as a private retained fixture for these checks, not installed into the
host. This is package assembly and relocated execution, not a successful
package-manager installation or supported target transaction. The check-only
Setup8 fixture is never installed by the package.

The retained local archive is under the worktree's ignored
`work/first-login-build-20261114/` directory:

```text
cachy-asahi-first-login-0.1.0-1-any.pkg.tar.zst
19461 bytes
SHA-256 ef69bba6790ea6d06ef8f6743675954fa041a6fd6d9a8f7ad547f3f6a8839db0
```

One host build is not a reproducible-build pair. The recipe pins the original
implementation commit and delivered Setup8 fixture commit through
`source-provenance.json`; `.SRCINFO` is generated from the actual recipe.
The package is opt-in and remains outside shared package selections.

## Remaining gates

Actual signed native ARM package build/install/remove, compatible dependency
selection, target launcher/graphical session validation, macOS-to-first-login
installation, physical recovery and both M2 Air models remain NOT RUN for this
new capability. Package installation does not activate user configuration.
