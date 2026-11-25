# JBIG and TIFF reproducibility for #622

This directory brings the reviewed recipe inputs and canonical source
projection from `32dea27b8c3ea0b8fc618eb5db9761b5291d428f` into the current
offline builder. The generated recipe directories can be passed directly to
`build_v2.py`. [Issue #622](https://github.com/Gabriel-Kahen/cachy-asahi/issues/622)
· [Archived source](https://github.com/Gabriel-Kahen/cachy-asahi/commit/32dea27b8c3ea0b8fc618eb5db9761b5291d428f)

## Prepare the recipes

The [materialization plan](materialization-plan.json) pins the four upstream
objects by URL, size and SHA-256. Keep these originals in private scratch
storage. The preparer checks each input and generates canonical USTAR and gzip
archives using fixed metadata and stored DEFLATE blocks. It checks the output
inventory and modes against the reviewed pins, runs the static recipe checker
and writes reviewed-input hash maps for the offline build runner.

```sh
scratch=$(mktemp -d)
mkdir "$scratch/upstream"
plan=scripts/build/project-libraries/materialization-plan.json
for name in jbigkit libtiff shared_patch reuse; do
  url=$(jq -er --arg name "$name" '.upstream[$name].url' "$plan") || exit
  bytes=$(jq -er --arg name "$name" '.upstream[$name].bytes' "$plan") || exit
  curl --fail --location --silent --show-error --max-time 30 --max-filesize "$bytes" \
    --output "$scratch/upstream/$name" "$url" || exit
done
python3 -B scripts/build/project-libraries/prepare.py \
  --jbigkit "$scratch/upstream/jbigkit" --libtiff "$scratch/upstream/libtiff" \
  --shared-patch "$scratch/upstream/shared_patch" --reuse "$scratch/upstream/reuse" \
  --output "$scratch/recipes" > "$scratch/materialization.json"
```

The 20 JBIG and seven TIFF files form two self-contained recipe directories.
Each contains the filtered source archive and applicable notices alongside the
PKGBUILD. Retain the native archives and build records to compare against a
rebuild using the corresponding-source directories from the packages.

## Derive the proposed native builder locks

Use the Minimal206 base exercised by the November 18 llhttp pair. Its
provisioning input lock has SHA-256
`629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16`.
Minimal206 already includes GCC, make, patch, Python, CMake, xz, zlib and zstd.
Its inventory contains neither old ALARM JBIG/TIFF provider, avoiding a
replacement that leaves TIFF linked to the old JBIG SONAME.
[Minimal206 native result](../../../docs/validation/llhttp-minimal206-native-arm4k-20261118.md)

Build JBIG against the exact 206-package base. Derive the TIFF builder from
that same image by adding the passing project JBIG archive and the official
`libdeflate 1.26-1`, `libjpeg-turbo 3.2.1-1` and `libwebp 1.6.0-2`.
All three official additions declare glibc as their only runtime requirement.
The [extension contract](minimal206-extension.json) pins the six transport
files, full ALARM signer fingerprint and resulting 210-package inventory.

```sh
git show 1604862d09fb04e471da03df2e2a98a5c05a77bf:held-source/scripts/ci/llhttp-minimal-builder-source/base/expected206.lock \
  > "$scratch/expected206.lock"
python3 -B scripts/build/project-libraries/baseline.py \
  --base-lock "$scratch/expected206.lock" --codec-cache "$verified_codec_cache" \
  --keyring "$reviewed_dearmored_alarm_keyring" --output "$scratch/expected210.lock"
```

Provision with the three original ALARM signatures and a disposable TEST
signature over the exact JBIG archive. Use required signature checking inside
the owned builder. Retain both immutable image IDs, archive and signature
evidence, and independent inventory readbacks.

## Build and verify both pairs

Run on the selected native AArch64 builder. Use the immutable image IDs and
set `scratch` outside the recipe directories. Complete the JBIG pair and
comparison before signing its archive and provisioning the TIFF image.

```sh
build_pair() {
  local name=$1 image=$2 epoch=$3 lock=$4 attempt
  for attempt in 1 2; do
    python3 -B scripts/build/build_v2.py "$scratch/recipes/$name" \
      --image "$image" --mode native --network none --timeout 1200 \
      --source-date-epoch "$epoch" --expected-packages "$lock" \
      --reviewed-inputs "$scratch/recipes/$name-reviewed-inputs.json" \
      --output "$scratch/$name-$attempt" || return
  done
  python3 -B scripts/build/compare_v2.py "$scratch/$name-1" "$scratch/$name-2" --require-bytes
}
build_pair jbigkit "$minimal_image" 1791585070 "$scratch/expected206.lock"
# After deriving and checking the TIFF builder image:
build_pair libtiff "$tiff_image" 1782568888 "$scratch/expected210.lock"
python3 -B scripts/build/project-libraries/verify_packages.py \
  --recipes "$scratch/recipes" --jbigkit "$jbig_archive" --libtiff "$tiff_archive"
```

Retain phase logs, comparison and passive inspection results. The package
inspection checks build metadata, license notices, corresponding-source
members, generated TIFF inventory, SONAME links and direct dependencies. Join
the TIFF builder's installation receipt to the exact JBIG archive hash.

Exercise signed installation and restoration on an owned disposable root.
Verify full inventory and installed file ownership at each checkpoint.
Compile the [TIFF/JBIG consumer](tiff-jbig-roundtrip.c) against the installed
headers and run it on a new scratch filename. Check the resulting dimensions
and ISO JBIG compression with the installed `tiffinfo`. Exercise provider
replacement and restoration on a disposable copy of the intended maintenance
target with its original signed providers and representative dependents.
Record retirement of the owned builders, staging and test root.

## Local evidence and remaining qualification

On November 25, all four upstream objects matched the archived pins. Two
fresh materializations produced identical 27-file sets totaling 5,474,349
bytes. Both static recipe reviews passed. The three official codec archive
and signature pairs matched the extension pins and passed `gpgv` under the
pinned ALARM signer. The derived 210-package lock matched its declared hash.
The historical bubblewrap and JPEG archive/signature URLs returned HTTP 404.
Minimal206 excludes bubblewrap and the extension uses the verified JPEG pair.

Both recipe bodies ran through prepare, build, check and package into
disposable x86_64 staging paths with the ARM guard replaced in the local
harness. JBIG's two upstream unit suites and 15 synthetic comparisons passed.
All three TIFF CTest cases passed. The staged C consumer roundtripped a 32×4
JBIG TIFF and staged `tiffinfo` confirmed its dimensions and compression.
All four SONAMEs matched and TIFF linked to the staged `libjbig.so.2.2`.

Provisioning the native TIFF builder, all four native package builds, native
installed ABI checks and signed restoration remain pending. Public
redistribution also needs review of the linked GPL/Berkeley distribution
basis and the missing historical TIFF uvcode generator provenance.
[Source and licensing design](../../../docs/workstreams/maintained-jbigkit-libtiff-project-source-filter.md)
