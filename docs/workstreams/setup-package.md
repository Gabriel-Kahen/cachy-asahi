# Setup package workstream

Completed October 11, 2026. **Original source packaged and independently reviewed
on x86_64; native aarch64 builds, actual package installation and target lifecycle
remain NOT RUN.** This worker owns this report and
`packages/settings/cachy-asahi-setup/` only. Canonical helper, setup guide/tests,
shared manifests, other implementation paths and Git state were not changed.
Research/build checks did not mutate the real HOME or host packages/services/session.

## Corrected-source refreeze

Independent root review reproduced two defects in the prior `c7d4b9...` helper:
pending new shell blocks could coherently retarget another template root, and
appended results could exceed the helper's own 2MiB read/manage limit. The setup
owner fixed the canonical script and refroze it after 40 tests. This worker did
not edit that canonical source. Package copy/provenance/checksums/README/.SRCINFO
were refreshed; pkgrel was raised to 2 to distinguish corrected artifacts.

`check-packaged.py` adds six temporary-fixture regressions, covering oversized
Fish and mixed Fish/Zsh requests plus coherently forged pending journals, in
preview/apply modes. All six fail as expected against the superseded archive,
and all six PASS against corrected source and each final archive's extracted CLI.
No shell block, real HOME or session command is executed by these checks.
The previous host receipt is retained only as explicitly superseded evidence.

Final reviewed PKGBUILD SHA256:
`1d4326ccfa5b0a68b4eb82351c29a99ca2c0ad8af7503e84aa01bcd3dd1cbe68`.
Canonical/package source SHA256:
`a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`.
These inputs and receipts are ready for the coordinator's native CI recipe-lock
refreeze. This worker does not edit that lock, shared manifests or Git state.

## Delivered inputs and package ownership

[Recipe and usage](../../packages/settings/cachy-asahi-setup/README.md) implement
`cachy-asahi-setup` version `0.1.0-2`, `arch=('any')`, original project URL
`https://github.com/Gabriel-Kahen/cachy-asahi`, MIT license.

Canonical source: `scripts/setup/setup.py`, frozen by its owner after 40
fixture tests and read with `docs/setup-tooling.md`/`docs/workstreams/setup.md`.
The package's `cachy-asahi-setup` input is byte-for-byte identical, with SHA256
`a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`.
No shebang, imports or behavior were changed in copying it. Runtime imports are
Python 3.11+ standard library only, including Linux `fcntl`/directory operations.
The package requires `python>=3.11` and optionally the three original template
packages; it bundles no template, third-party module, font or compiled binary.

Seven offline local source inputs have fixed recipe SHA256 values: CLI, README,
NOTICE, actual root MIT LICENSE, source-provenance.json, check-sync.py and its
fixture tests. Source provenance records canonical path, source/license hashes
and original-project URL. The last three validation inputs are not runtime payload.
The generated `.SRCINFO` matches final recipe metadata.

Exactly four regular files are owned:

- `/usr/bin/cachy-asahi-setup`, mode 0755.
- `/usr/share/doc/cachy-asahi-setup/README.md`, mode 0644.
- `/usr/share/licenses/cachy-asahi-setup/NOTICE`, mode 0644.
- `/usr/share/licenses/cachy-asahi-setup/LICENSE`, mode 0644.

No install/remove/upgrade hook, `/etc`, default session, service unit, automatic
activation or user-home ownership is added. The CLI itself is an explicit per-user
runtime tool. Preview is read-only; `--apply` performs the requested user-config
operation. Package-manager removal deletes only the four payload files and never
runs deactivation. User-owned config/state persists; use explicit CLI removal
before removing the CLI if deactivation is wanted. Reinstallation restores the
CLI without resetting that user state. Actual package-manager behavior is not
claimed tested from the temporary-prefix checks.

## Synchronization contract

[check-sync.py](../../packages/settings/cachy-asahi-setup/check-sync.py) is read-only;
it never copies or executes the helper. Before every source snapshot/build/release,
run from the source repository:

```sh
python -B packages/settings/cachy-asahi-setup/check-sync.py
```

It compares canonical and packaged helper/license against fixed provenance hashes.
Missing sources, stale canonical/package bytes, changed grant, malformed provenance
and unsafe canonical paths fail. Explicit canonical/copy/license paths permit
retained source snapshots, still bound to the same expected hashes. Tests simulate
drift without modifying the real canonical file.

A normal in-checkout makepkg `prepare()` also runs the canonical comparison, with
repository layout identified by its root AGENTS.md. Missing/changed canonical input
in that layout fails. A standalone recipe snapshot has no canonical checkout;
its check() instead verifies fixed source/provenance/license pins, and requires
the canonical comparison before creating that snapshot. Snapshot pin validation
alone does not attest that a subsequently changed repository helper is synchronized.
Coordinator CI/source-freeze workflows should run this checker before invoking
clean-build source acquisition; no shared CI/build files are edited by this worker.

## Actual results

| Check | Result / limit |
| --- | --- |
| Canonical/source/license identity | PASS against owner-frozen source and actual root MIT grant, before and after packaging |
| Nine synchronization fixture tests | PASS: canonical/package drift, missing inputs, stale hashes/licenses, malformed/unsafe paths, symlink escape; no helper execution or caller-HOME writes |
| Bash syntax, Python syntax/help, source SHA256 | PASS; package check() executed snapshot pins and nine tests; no bytecode cache writes |
| Recipe static inspector and `.SRCINFO` comparison | PASS; body and canonical-copy behavior also independently reviewed |
| In-checkout canonical-drift reproduction | PASS: synthetic checkout kept packaged inputs intact but changed canonical code; `makepkg --nobuild` failed in prepare() for canonical hash mismatch |
| x86_64 package assembly | Two `makepkg --config /etc/makepkg.conf --noconfirm` builds PASS, isolated work/home directories, no dependency-sync/install flags |
| Archive inspection | PASS both: exactly four expected payload files, CLI mode 0755/docs mode 0644, MIT metadata, Python-only required dependency, no .INSTALL/ELF/protected paths |
| Repeat-build payload comparison | PASS matching four payload hashes; archive bytes differ due non-normalized generated metadata; same host is not independent clean-build evidence |
| Corrected packaged regressions | PASS all six against source and each final archive CLI; old c7d archive reproduces all six failures in temporary fixtures |
| Actual packaged CLI smoke | PASS: archive CLI extracted into temporary prefix, isolated home/templates; help/preview wrote nothing; all-component apply/repeat preserved base/existing bytes; surgical removal and edited-desktop conflict exit 2; CLI deletion/recreation left user data unchanged; later fixture activation/removal remained usable |
| Independent read-only review | PASS final pkgrel2 canonical/license identity, seven pins/.SRCINFO, artifact hashes/modes, six corrected regression cases, old-source reproduction and normal lifecycle smoke; no reviewer edits |
| Clean native ARM build/rebuild | NOT RUN |
| Actual pacman install/upgrade/remove/reinstall | NOT RUN |
| Real existing-user/Asahi lifecycle, filesystem power-loss recovery | NOT RUN |
| M2 Air 13-inch/15-inch, release/hardware/performance gates | NOT RUN |

[Host validation](../../packages/settings/cachy-asahi-setup/host-validation.json)
and [retained evidence](../../packages/settings/cachy-asahi-setup/evidence/)
record actual commands, logs, package metadata, temporary archive paths,
payload/artifact checksums, drift refusal, static inspection and packaged-CLI
fixture results. These are development artifacts, not release packages. The
owner's 40 canonical tests are separate evidence in the setup handoff; this
worker did not label them as another 40 independent package tests.

[Runtime dependency observation](../../packages/settings/cachy-asahi-setup/runtime-dependency-observation.json)
records the official ARM Python package page and response hash. Published
availability is not a trusted selected Asahi snapshot, dependency transaction,
16K-page interpreter verification or target execution. Python's own compiled
payload remains a base dependency; this package introduces no ELF object.

## Coordinator-only manifest proposal

This worker does not edit the shared manifest. Proposed entry:

```toml
[[packages]]
name = "cachy-asahi-setup"
phase = "setup-tooling"
status = "candidate"
source = "local-original"
recipe = "packages/settings/cachy-asahi-setup/PKGBUILD"
license = "MIT"
audit = "docs/workstreams/setup-package.md"
selected_for_development = true
selected_for_release = false
native_build = "NOT RUN"
installation = "NOT RUN"
hardware_validation = "NOT RUN"
next_step = "Require canonical-source synchronization before snapshots; freeze the Asahi Python/template transaction, run two clean native ARM builds, and execute setup/package/user lifecycle and onboarding on both M2 Air sizes."
```

Retain the exact canonical SHA and host receipt with integration evidence. No
package selection, M0/M1 acceptance, installed/hardware-tested status or release
promotion is inferred from this implementation. Native builder, chosen/trusted
base transaction, actual package/config lifecycle, independent complete onboarding,
filesystem interruption/recovery and both exact-machine gates remain open.
