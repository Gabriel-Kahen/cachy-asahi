# Build/validation workstream

October 11, 2026. Owned tooling and documentation implementation is complete for the current portable build/inspection scope. **No native ARM clean build, image provisioning execution, package installation, exact-M2 hardware validation or accepted release is claimed.** M1 and later execution gates remain pending.

## Delivered

- `scripts/checks/package_checks.py`: recursive recipe discovery, non-executing metadata inspection, fixed archive/Git pins, local checksum verification, symlink/special input rejection, non-extracting package archive inspection, package metadata/BUILDINFO consistency, protected Asahi files/package relations, hook blockers, ownership/mode/path/file-collision checks, structural AArch64/16K ELF checks with separate relocatable-object handling.
- `scripts/checks/dependencies.py`: explicit reviewed ARM inventory, Arch `vercmp` comparisons, virtual/versioned providers, required dependency closure, declared conflicts/replacements, overlay build ordering and cycles. This checks declarations, not undeclared runtime behavior or a real transaction.
- `scripts/build/provision.py`: default context-only preparation from a pinned ARM base plus SHA-256 reviewed signed dependency cache; explicit `--execute` provisions offline **inside an image only** with mandatory local package signatures and captures the image ID, log, input hashes and package lock. No trust bootstrap, host pacman, binfmt setup or downloads.
- `scripts/build/build.py` and `container-entry.sh`: fresh constrained container per attempt, native/emulated labels bound to observed daemon architecture, pre/post dependency lock checks, immutable image and reviewed recipe input hashes, source verification, isolated generated `.SRCINFO`, effective metadata binding in both directions, final artifact binding including exact version/dependencies/relations/recipe hash, failed/successful provenance and logs. Only new artifact storage is host-writable; root remains read-only and recipes run non-root.
- `scripts/build/compare.py`: verifies evidence/input/artifact integrity, requires matching inputs/epoch/image/mode/entry script/dependency-lock, rejects reused clean-container identity/copytree evidence, rebinds artifacts to reviewed metadata, compares complete installed contents and metadata, reports byte identity independently and can require it.
- `tests/test_build_validation.py`: 33 meaningful boundary tests, including a mocked complete build command. These reject the reviewer's wrong-version, hidden aarch64 dependency, `provides=linux-asahi`, unexpected hook, copied-evidence and speaker-protection override reproductions.
- `.github/workflows/static.yml`: pinned checkout v7.0.0 (`9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0`), read-only token/disabled persisted credentials; portable tests, hardware baseline tests, benchmark tests, release tests, non-executing recipe inspection and shell syntax. Recipe discovery fails when empty. GitHub-hosted workflow execution itself is NOT RUN. Release tests visibly skip on Ubuntu if its external Arch tools are absent; a skip is not a signing/release PASS.
- `docs/build-system.md` and `docs/package-validation.md`: clean builder contract, exact commands, review/evidence gates, reproducibility/16K limits and release-schema interface.

## Actual checks and observed resources

Executed on the existing **x86_64 Linux host**, using already installed tools, without installing dependencies or disturbing Docker jobs:

| Command/check | Actual result |
| --- | --- |
| `python3 -m unittest discover -s tests -q` | 33 passed; Docker and provisioning execution in these tests are mocked/context-only |
| `python3 -m unittest discover -s scripts/hardware -p 'test_*.py' -q` | 3 passed (coordinator-owned collector tests) |
| `python3 -m unittest discover -s scripts/benchmarks -p 'test_*.py' -q` | 19 passed (benchmark-worker tests, including synthetic workloads) |
| `python3 -m unittest discover -s scripts/release -p 'test_*.py' -q` | 19 passed on host with existing Arch/GPG tools; synthetic package/key fixtures, no real release |
| `python3 -m py_compile scripts/build/*.py scripts/checks/*.py` | Passed |
| `bash -n scripts/build/container-entry.sh` | Passed |
| `python3 scripts/checks/package_checks.py recipes --require-recipes` | Three current original recipes static-pass: Hyprland, Fish, Zsh; no recipes sourced |
| Read-only `package_checks.package(...)` on retained host archives | Two Hyprland and two Fish host-assembled archives individually artifact-static-pass; separate attempts are not a combined install set |
| `docker info --format '{{.Architecture}} {{.OSType}}'` | `x86_64 linux` |
| `docker image ls` | Existing application/development images only; no verified pinned clean ALARM ARM builder selected |
| Upstream `git ls-remote` for actions/checkout v7.0.0 | Returned pinned SHA above; no repository state changed |

Host-generated Zsh archive paths were unavailable from its retained run record during this workstream's independent archive pass; its own worker evidence remains separate. No absent artifact is treated as a successful independent check. Host assembly metadata and source licenses were reviewed separately by package workers; the static artifact results here do not upgrade them to clean/native ARM results.

First local test run found fixture extension and dependency parser bugs; corrected them and reran. Coordinator/reviewer findings prompted added complete metadata/artifact binding, copied-run rejection, audio guards and malformed/no-load ELF checks. Current counts above describe the final checked tree, not superseded runs.

## Exact execution prerequisites and remaining work

1. A verified native aarch64 Docker daemon/builder machine reachable by the coordinator. Current daemon is x86_64; an emulator, cross toolchain or x86 arch=any build cannot close native M1.
2. An accepted Asahi ALARM base/repository snapshot and complete dependency transaction. For desktop this must meet the recipe's constrained Hyprland range and preserve the Asahi graphics/audio/kernel integration; an image's ARM label alone cannot establish that.
3. A locally present digest-pinned trusted ARM builder image with `makepkg`, `base-devel`, `diffutils`, all recipe/check/runtime dependencies, trusted ALARM signing keys and a non-root account matching the invoker's UID/GID. For provisioning, supply complete signed original `.pkg.tar.zst`/`.pkg.tar.xz`/`.pkg.tar.gz` dependency closure and a reviewed package/signature SHA-256 map. Retain original image/rootfs provenance, source archives, signing fingerprints and repository/dependency inputs.
4. Independent review of each final recipe snapshot and an explicit sorted `pacman -Q` lock; store the scanner's complete `input_sha256` object as the runner's reviewed input JSON. Split packages/dynamic fallback metadata/automatic hooks remain unsupported and fail closed.
5. Execute two fresh native container runs per coordinator-selected package using the same documented `SOURCE_DATE_EPOCH`, compare contents and bytes, retain every failed run, perform independent package review and satisfy target transaction gates. No actual clean second build has run here.
6. Exercise actual image provisioning, source download behavior where enabled, package installation/removal and exact-model 16K hardware behavior. Portable/mocked tests cannot establish their results.
7. Translate retained local runner records into the separate release worker's per-artifact provenance/build/dependency-lock schema **after** the coordinator freezes the project commit, snapshot ID and retained dependency cache. The runner deliberately does not invent these release inputs or hardware evidence. Stable promotion currently requires byte identity, stricter than content-only comparison.

## Manifest proposals (coordinator-owned)

The reconciled `recipe`, license, selection flags and explicit NOT RUN fields already cover development discovery. No mandatory shared schema change is needed for the present runner. Consider adding `build_records = [".../provenance.json", ".../provenance.json"]`, `package_review = "..."`, and `reproducibility_record = "..."` only once those retained, hash-bound records actually exist. Keep native/emulated/cross, content/byte comparison, installation and exact-machine states separate. These are proposals; this worker did not edit the manifest.

All selected-for-release flags remain false in the current shared inventory. Upstream deferred candidates remain visible and cannot be silently counted as supplied by the three original recipes. No host package/database/system configuration was changed by these tools; only owned source/docs/tests and temporary test/evidence storage were written. Git integration stays with the coordinator.

## Narrow provisioning/metadata follow-up

Coordinator authorized support for the native CI worker's original signed xz dependencies, without recompression. `provision.py` now accepts zst/xz/gz archives and exact matching detached signatures, records/copies/checks original bytes unchanged, rejects unsupported/unsafe names and orphan or mismatched signature extensions, and emits explicit cache archive arguments rather than globs. Mixed-format context-only fixtures and xz checksum tampering pass/fail at the intended boundaries, without a Docker call.

`container-entry.sh` compares `.SRCINFO` after dropping only full blank/comment lines. Its read-only comparison function is tested in isolation (the container entry and recipes never execute on the host). It retains exact field/value/indentation/order checks, fails missing inputs, and the existing effective-field/artifact binding remains unchanged. This resolves the harmless introductory desktop comment without weakening unexpected-dependency/hook/version guards.

`python3 -m unittest discover -s tests -q`: **33 passed** after these changes. Bash syntax and Python compilation checks passed. Actual native ARM provisioning/build execution remains NOT RUN; signed archive fixture copying is not cryptographic signature verification or ARM build evidence. The dated rootfs/base import belongs to the separate native CI worker, and is not implemented or claimed by this narrow fix. The frozen runtime setup script was not modified.
