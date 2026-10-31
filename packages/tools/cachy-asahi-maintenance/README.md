# cachy-asahi-maintenance 0.1.0-2

An offline, read-only health and rebuild-planning review for an explicitly
selected signed ARM release. This is an original MIT project package candidate.
No package selection, release or hardware acceptance follows from this recipe.

## Command and inputs

```sh
cachy-asahi-maintenance --version
cachy-asahi-maintenance --help
cachy-asahi-maintenance \
  --release /data/releases/candidate \
  --release-sha256 SELECTED_RELEASE_JSON_SHA256 \
  --key INDEPENDENTLY_SELECTED_FULL_FINGERPRINT \
  --gpg-home /data/offline-public-verifier \
  --as-of 2026-10-27T05:00:00Z --context-only
cachy-asahi-maintenance \
  --release /data/releases/candidate \
  --release-sha256 SELECTED_RELEASE_JSON_SHA256 \
  --key INDEPENDENTLY_SELECTED_FULL_FINGERPRINT \
  --gpg-home /data/offline-public-verifier \
  --as-of 2026-10-27T05:00:00Z \
  --observations /data/observations/index.json \
  --observations-sha256 SELECTED_INDEX_SHA256 --format text
```

The launcher exposes the existing health arguments unchanged, plus `--version`.
The packaged `health-inputs.md` describes the complete schema, replay semantics,
limits and clocks. Replace its source-tree invocation with this command. Its
historical packet/test paths are source evidence references, not installed files.
All inputs must be explicitly supplied ordinary local files. The public verifier
home must be outside the release storage and private runtime root. JSON is the
default format. Missing observations produce unavailable actions. Valid held
reports exit 0; invalid/conflicting inputs exit 2 with empty stdout. Exit 0 never
means security, maintenance or release acceptance.

The command checks the release's selected SHA-256, signatures against the selected
full fingerprint, base/release inventory, provenance and observation generation.
It uses the existing frozen planner and actual Arch version comparator; it never
substitutes its own relation or version ordering. `--as-of` evaluates observations
and expiry; release signatures are checked at the actual GPG clock. Expired TEST
keys must refuse authentication; do not bypass it to refresh historical evidence.
Reports on withdrawn TEST DATA do not reverse a withdrawal or authorize its use.

## Payload and dependencies

Runtime dependencies: Python >=3.11 (standard library only), GnuPG, libarchive
(`bsdtar`) and pacman (`vercmp`). No dependency installation happens in the recipe.
The package is architecture-independent Python/data (`arch=any`); this declaration
is not an ARM build, 16K runtime or M2 compatibility result.

Exactly nine modules, 167951 bytes at this proposal, retain their original bytes:

- `scripts/maintenance/{health,update_plan,rebuild_plan,signing_expiry,security_advisories}.py`
- `scripts/release/{check_source_pins,compare_releases,release,source_delivery}.py`

They live under `/usr/lib/cachy-asahi/maintenance/`, preserving only the relative
paths the existing import closure needs. They do not discover or import a source
checkout. No tests, fixtures, Git data, manifests, workflow, history or other tools
are installed. The `/usr/bin/cachy-asahi-maintenance` launcher derives this private
tree from its own installed path and starts Python with isolation and no bytecode.
No cwd, PYTHONPATH, PYTHONSTARTUP or environment-selected runtime path is used.

`source-provenance.json` pins the nine original source paths/bytes; the recorded
checkout HEAD is context only. `payload-pins.json` also pins the launcher and modes.
The PKGBUILD and `.SRCINFO` pin every local source with SHA-256, including notices,
tests and these records. There are no moving upstream downloads or VCS sources.

The release helper also contains producer functions because it is preserved
byte-for-byte. The installed launcher invokes only the read-only health main;
it offers no signing, publish, install, withdraw or other producer dispatch.

## Installation and removal behavior

The recipe installs exactly 16 regular files: the launcher (0755), nine private
modules (0644), four documentation/provenance files (0644), and LICENSE/NOTICE
(0644). The file map is enforced by `check_source.py --stage STAGE`.

There are no install/remove hooks, services, timers, privileged helpers, cache
directories, configuration files or trust changes. Installation only adds those
package-owned files. Removing it deletes those files; caller-owned release data,
public keyrings, observations and redirected reports remain caller owned.
Running a review reads the supplied keyring, creates a temporary isolated public
verifier under the system temporary directory, writes the report to stdout and
removes its verifier. It never changes the supplied home, inputs or installed tree.
No automatic networking, signing, building, updates or package transaction runs.

## Build and checks

From this recipe directory in a disposable build working tree:

```sh
python -I -B check_source.py
python -I -B -Werror::ResourceWarning test_package.py
makepkg --cleanbuild --force
```

`makepkg` checks existing dependencies; it has no sync/install flag. Its `check()`
runs the source controls and stages the real `package()` function under an
unprivileged temporary directory. The tests run the actual staged executable from
an unrelated working directory, including relocation, source checks, malformed
inputs, Python environment isolation and frozen planner tamper refusal.

Host assembly/staging and native ARM build/ALPM lifecycle evidence are different.
See the handoff/native plan accompanying this proposal for actual results and
required next gates. Native ARM, real ALPM lifecycle, 16K runtime, physical M2,
performance, production release and maintenance acceptance remain NOT RUN.

The package checks copy only the declared20-file recipe. Live makepkg logs, FIFOs,
source extraction and package outputs are outside that fixture. Declared inputs
remain checksum-checked ordinary files; symlinks and special files are refused.
