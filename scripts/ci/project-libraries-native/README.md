# #622 native build acquisition hold

The reviewed candidate is `a7c2a30fb37934cad320d982b7d2ab2413dab2a7`.
Hosted run [45688818426](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45688818426)
passed the native runner probe. The retained Minimal206 r12 ref still resolves
to `1604862d09fb04e471da03df2e2a98a5c05a77bf`, the producer used in
[44263404780](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44263404780).
That run retired its derived and imported images and has zero Actions
artifacts. The repository's current Actions cache listing contains no
Minimal206 inputs.

On November 25, 2026, the primary routes returned HTTP 404 to HEAD for 14
of the 206 locked package bodies. This included all four packages eligible
for the original producer's archive fallback. The rootfs, its signature,
the three keyring inputs, and 192 package bodies returned HTTP 200 to HEAD.
These response codes establish transport availability at probe time.

A decisive public acquisition failure was
`linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz`, 69,887,600 bytes with SHA-256
`ba67012ac8ae1312e32c9e5bbee49428e3c8e9405d3d85312732847a9820964c`.
Full GETs returned HTTP 404 from the California and Florida ALARM mirrors,
the original per-package archive fallback, and the archive's November 15
and 23 snapshots. The original Minimal206 cache was recovered separately. All 417 objects
matched their exact lengths and SHA-256 pins, including the kernel archive.
All 207 detached signature checks passed against the locked ALARM signer.
The runner still needs an authenticated route to the retained objects.

The candidate's `scripts/build/project-libraries/prepare.py` accepted all
four pinned upstream files and produced byte-identical recipe trees in two
fresh scratch directories. Its `baseline.py` verified all three official
codec archive/signature pairs and derived the declared 210-package lock.
The candidate's seven controls and the four acquisition controls pass.

Recheck the missing input from a checkout with the r12 Git object available.

```sh
python3 -I -B scripts/ci/project-libraries-native/preflight.py
python3 -I -B -Werror::ResourceWarning -m unittest discover -s scripts/ci/project-libraries-native -v
```

The recheck uses bounded HTTPS GETs, validates the pinned lock and detached
signature, and deletes its own scratch directory. It exits 1 on HOLD.
`KERNEL_PIN_RECOVERED` requires the exact archive and a matching ALARM
signature. Full 417-input acquisition and authentication must still pass
before a future native build. A successor baseline requires review of its
own signed inputs and exact package inventory.

Hosted dispatch needs a runner-readable source for the recovered inputs or a
reviewed successor baseline. Both native pairs and signed lifecycle checks
remain pending.
Future public CI evidence must be limited to approved metadata and must
exclude package bodies, materialized recipes, and held source.

## Recheck the retained inputs locally

This lane reuses the reviewed r12 signed-rootfs bootstrap and the existing
offline build driver. The local preflight needs the r12 Git object, Python
3.11+ and GnuPG. It runs without Docker. Supply the three private input
directories to keep this command offline. The Minimal206 directory may
contain historical files outside this lane's exact 417-object selection.

```sh
python3 -I -B scripts/ci/project-libraries-native/build622.py --inputs-only \
  --minimal-cache "$minimal206_cache" --codec-cache "$codec_cache" \
  --upstream-dir "$upstream_inputs" --export-retained "$new_private_export"
```

The command checks all 417 r12 lengths and hashes, all 207 ALARM signatures,
the signed rootfs layout, the six codec files and three codec signatures,
and the independently pinned 206- and 210-package locks. It materializes
the recipes twice and compares the exact 27-file set and both recipe hash
maps. The optional export contains only the 14 package bodies whose pinned
primary URLs returned 404 in the November 25 recheck. It is a flat private
directory keyed by the original basenames. It totals 107,101,116 bytes.
The largest member is 69,887,600 bytes. An uncompressed archive of the whole export exceeds
GitHub's 100 MiB Git limit, as does the 829,367,415-byte rootfs
fetched from its public origin.

## Publish the private carrier

The local carrier is a parentless SHA-1 Git commit with 14 regular
`100644` blobs under `alarm-cache/`, each at its original basename.
Its only intended destination is the private
`Gabriel-Kahen/cachy-asahi-ci-inputs` repository.

| Ref | Commit | Tree |
| --- | --- | --- |
| `refs/heads/native622-r1` | `c6ed50287db7e7d743111d76e9f0c35179c90b7f` | `203b14cc4d8afc806c97b10f53518b6b3b5c8659` |

Use a publish credential to create that branch. The runner uses the existing
read-only deploy key. It pins GitHub's Ed25519 host key, the deploy-key
fingerprint, ref, commit, tree, file modes, sizes, and per-file SHA-256s.
Only the dedicated SSH step receives `CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY`.
The step removes its identity file before materialization and retires the
temporary Git store before returning. The build step rechecks the 14 files as
part of full r12 authentication and uses the original pinned public routes
and r12 signature seed for the rest. A failed fetch or pin mismatch holds
the lane.

## Dispatch the hosted lane

The standalone `.github/workflows/native-arm-project-libraries-622.yml` must
be present on the default branch before it can receive manual dispatch.
Review the selected branch or tag and its full SHA. The workflow and
checked-out source must resolve to that SHA, and the historical public r12
ref must resolve to the producer above. Use the `native-622-inputs`
environment and restrict deployment to the reviewed ref. The carrier
branch must already contain the exact retained commit.

```sh
gh workflow run native-arm-project-libraries-622.yml \
  -R Gabriel-Kahen/cachy-asahi --ref "$reviewed_ref" \
  -f reviewed_head="$reviewed_head" -f lane=inputs
gh workflow run native-arm-project-libraries-622.yml \
  -R Gabriel-Kahen/cachy-asahi --ref "$reviewed_ref" \
  -f reviewed_head="$reviewed_head" -f lane=native
```

Run the second command after the first reports `INPUTS_AUTHENTICATED`.

The existing registered `native-arm-build.yml` can also dispatch this
same-commit reusable workflow from a reviewed ref. Add two explicit
Project Libraries modes to that caller, keep its existing job excluded
for those two modes, and use a separate conditional job to call
`./.github/workflows/native-arm-project-libraries-622.yml`. Pass the reviewed
SHA, selected lane and only the named read-only deploy-key secret. The
registered caller uses a different concurrency group from the callee.
This route needs a reviewed caller update on the dispatch ref. The
registered workflow's existing modes do not provide that routing. After
adding the caller job, dispatch its input check and then the native lane as
follows.

```sh
gh workflow run native-arm-build.yml \
  -R Gabriel-Kahen/cachy-asahi --ref "$reviewed_ref" \
  -f mode=project-libraries-inputs -f project_libraries_head="$reviewed_head"
gh workflow run native-arm-build.yml \
  -R Gabriel-Kahen/cachy-asahi --ref "$reviewed_ref" \
  -f mode=project-libraries-native -f project_libraries_head="$reviewed_head"
```

The native lane requires an unprivileged GitHub-hosted Linux ARM64 runner
with local ARM Docker, the reviewed r12 legacy builder/import path, at
least 7 GiB available memory and 10 GiB free in runner scratch. It compares
two clean offline builds of each package for byte identity, verifies the
actual package payloads and their SONAMEs, and binds the TIFF builder's
Required-signature installation to the exact passing JBIG archive.

The fresh signed lifecycle starts on the same unextended Minimal206 image
with no existing JBIG/TIFF provider. It checks unsigned refusal and an
unchanged inventory after that refusal, installs the exact signed pair and
three official codecs, checks installed ownership and loader resolution, and
runs the installed TIFF/JBIG consumer and `tiffinfo`. It then removes,
reinstalls and removes the five packages, checks both roundtrips and restores
the 206-package inventory with package-owned files absent. Only bounded
metadata and hashes reach the hosted log. Private inputs, raw build logs,
archives and TEST key material are confined to the disposable job. A
failed build reports its attempt, bounded failure category, container exit
code when available, observed makepkg phases and recognized diagnostic
markers. The cleanup report covers the job's named and labelled containers and images.
Daemon build-cache retirement is unverified.

Native AArch64 build pairs and the fresh signed lifecycle await dispatch.
Replacement and restoration on a reviewed maintenance image with original
providers and representative consumers, native 16 KiB validation,
physical M2 validation and public distribution review remain open.
