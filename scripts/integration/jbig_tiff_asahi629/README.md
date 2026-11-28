# Asahi629 JBIG and TIFF replacement rehearsal

This lane starts after the original TEST-signed Asahi629 replay reaches its
629-package rollback checkpoint in a disposable, offline AArch64 guest with
16 KiB pages. It swaps exactly two providers in one local ALPM transaction,
restores both original providers in one inverse transaction, and exercises
the installed consumers before, during, and after the swap.

The source and passive input checks are available. The signed ARM16K swap
and runtime remain **NOT RUN**. A preboot actor reached the control-image
copy and stopped on host memory pressure before QEMU. The earlier [341-package and Minimal206
results](../../../docs/validation/project-libraries-native-20261125.md) and
the [scoped Qt result](../qt612_r132_replacement/README.md) have their own
inputs and receipts. This lane uses vendor Qt from the original Asahi629
composition.

## Retained inputs

| Role | Package and selection |
| --- | --- |
| Original JBIG | `jbigkit 2.1-8`, archive `ecaddb099f4a…` and original ALARM signature `f00be593f9ab…` |
| Original TIFF | `libtiff 4.7.2-1`, archive `02a5d2d74019…` and original ALARM signature `8dae1efda531…` |
| Project JBIG | `cachy-asahi-jbigkit 2.2-1.1`, retained archive `98636579a965…` |
| Historical project TIFF | `cachy-asahi-libtiff 4.7.2-1.1`, retained emulated rebuild `085e8293b170…`, passive evidence |
| Guest qualification TIFF | `cachy-asahi-libtiff 4.7.2-1.2`, audited Minimal206 archive `f6df34ab9ddd3…` |
| Rollback checkpoint | 12,346-byte lock `f335e8430a1d…` and 362 protected boot and mount entries `b4d84a4eacba…` |
| Historical project checkpoint | 12,374-byte lock `1e69e2ebe1f1d021fe85a1b0a0f0aaddc8897ff142e7783197419bd8f093b9a6` |

[inputs.py](inputs.py) contains the full byte counts and hashes. The original
archives reside in the retained ALARM cache. The project archives come from
the earlier Minimal206 work. The TIFF archive is the local 4 KiB emulated
rebuild with the earlier native receipt's shared-library hashes. The hosted
maintained 341-package build's distinct archive digests do not select these
bodies.

The TIFF ELF links `libjpeg.so.8`. The exact Asahi629 seed contains
`libjpeg-turbo 3.2.0-2` with ALPM provision `libjpeg.so=8-64` and the pinned
library bytes. The Asahi629 successor adds that dependency and advances
the release to `4.7.2-1.2`. Prepare the new recipe with
[jpeg_recipe.py](jpeg_recipe.py) using the exact previously materialized
TIFF recipe directory.

```sh
lane=scripts/integration/jbig_tiff_asahi629
python3 -I -B "$lane/jpeg_recipe.py" \
  --materialized "$historical_materialized_tiff_source" --output "$fresh_tiff12_source"
```

The corrected TIFF archive, provider payloads and projected replacement
lock are pinned in `QUALIFICATION_TIFF` in [inputs.py](inputs.py). Use
`--qualification` to check these inputs. Staging and guest admission require the new version,
the exact JPEG dependency in `.PKGINFO`, and the corrected PKGBUILD digest
in `.BUILDINFO`. The default passive audit still takes the historical
archive and reproduces its original projection.

The passive audit joins the original completed Asahi629 transport, seed,
result and terminal receipts. It authenticates seven original ALARM
signatures and checks the four provider archives, exact installed archive
members and **84 versioned TIFF imports** across these seven unchanged
objects.

| Unchanged package | Direct consumer paths |
| --- | --- |
| `lcms2 2.19.1-1` | `usr/bin/tificc` |
| `gtk4 1:4.24.1-1` | `usr/bin/gtk4-rendernode-tool`, `usr/lib/libgtk-4.so.1.2400.1` |
| `openjpeg2 2.5.4-1` | `usr/bin/opj_compress`, `usr/bin/opj_decompress`, `usr/bin/opj_dump` |
| `spandsp 0.0.6-7` | `usr/lib/libspandsp.so.2.0.0` |

The eighth pinned ELF is the `pipewire-audio 1:1.6.9-1` BlueZ HFP mSBC
plugin. Its loader closure goes through SpanDSP, TIFF and JBIG. The
retiring-SONAME assessment covers the seven named direct consumers and
this plugin. It checks both `libjbig.so.2.1` and `libjbig85.so.2.1` in that
scope. A full reverse-ELF census of all 629 packages and arbitrary dynamic
loads remain open.

```sh
lane=scripts/integration/jbig_tiff_asahi629
python3 -I -B "$lane/inputs.py" \
  --stage "$historical_preview_transport" --official-cache "$alarm_archive_cache" \
  --project-jbig "$jbig_archive" --project-tiff "$tiff_archive" \
  --rollback-evidence "$original_asahi_evidence" --terminal "$original_asahi_terminal" \
  --seed "$original_raw_asahi_seed"
```

The audit defaults to the original transport's pinned ALARM certificate.
The historical transport is suitable for passive readback. A future launch
requires fresh Preview TEST media from the
[Asahi629 retained runner](../../install/asahi629_trial/README.md), the
same cold control and boot receipts, R132 RTC kernel and config, and the
same raw seed. No Qt replacement media is used.

## Stage and select a future run

The separately reviewed library TEST certificate must be distinct from the
Preview and vendor keys. Supply `test-certificate.gpg` and one detached
`.sig` per project archive. The canonical test review has `fingerprint`,
`not_before`, `not_after`, a `certificate` byte pin, and a `signatures`
map from the two project package names to signature byte pins. A byte pin
contains `bytes` and `sha256`. Use a fresh nonce and enough certificate
lifetime for the retained actor's full run allowance.

```sh
python3 -I -B "$lane/stage.py" \
  --preview "$fresh_preview_transport" --nonce "$fresh_nonce" \
  --official-cache "$alarm_archive_cache" --project-jbig "$jbig_archive" \
  --project-tiff "$tiff_archive" --test-inputs "$library_public_test_inputs" \
  --test-review "$library_test_review" --test-review-sha256 "$library_test_review_sha" \
  --output "$fresh_scoped_stage"
```

This command verifies the two project signatures and produces the unissued
stage. The retained Asahi629 binding uses the same nonce and Preview
manifest. The coordinator selects the exact original binding and stage in
a canonical `ROOT_ASAHI629_JBIG_TIFF_SELECTION_V1` record with `issuer`
`Root`, `approval_status` `UNAPPROVED`, `nonce`, and exact `authority` and
`stage` byte pins. The `stage` pin is the digest of
`stage.UNISSUED.json`. The original binding must separately carry the
retained runner's issued `Root` value. Once the coordinator schedules the
run, the owning actor enters the existing offline, read-only controller
environment with the same zero-capability, no-new-privileges, disk-headroom
and nonce-claim checks. Mount the stage and both authority records
read-only, and supply the actor’s private writable `/tmp` tmpfs for signature
preflight.

```sh
python3 -I -B "$lane/runner.py" \
  --authority "$issued_asahi_binding" --authority-sha256 "$issued_asahi_sha" \
  --stage "$fresh_scoped_stage" --selection "$issued_pair_selection" \
  --selection-sha256 "$issued_pair_sha"
```

The runner reuses disk setup, PID 1, supervision, Asahi trust, output and
retirement from the pinned controller. Only the scoped input packer and
result reviewer are supplied to its rehearsal method. The scoped runner
requires a reflink for the control-root and Asahi target copies. The exact
source, destination and retained options are checked before each copy.
The selected copies use GNU cp's compatible `--sparse=auto --reflink=always`. A
filesystem that cannot reflink either copy produces a HOLD with no full-copy
fallback. The controller still checks the cloned bytes against the input
hashes before preparing the guest. The host owner records actor memory
accounting and host swap counters alongside its existing PSI guard.
Two digest-checked
worker copies add the checkpoint after the original rollback query, before
the target API mounts and keyrings retire. The original evidence exporter
carries the compact scoped result in `evidence/result.json`.

## Acceptance and independent readback

- Both original and project archives verify with Required TrustedOnly.
  Libalpm refuses a private unsigned copy of the candidate while the
  original lock remains intact. Each successful preparation accepts only
  its two expected versioned provider conflicts. An ambiguous commit
  requires discarding the writable clone.
- Each checkpoint requires 629 exact package rows, both original
  dependency install reasons, 362 protected entries, exact consumer
  ownership and bytes, and unchanged ALPM consumer descriptors. It
  verifies the selected provider libraries and symlinks and absence
  of stale provider paths. An ordinary runtime probe failure at the project
  checkpoint still attempts exact restoration and produces a HOLD.
- Run all eight loader checks and the JBIG C roundtrip, LCMS `tificc`
  conversion, GTK headless TIFF memory-texture pixel check, OpenJPEG
  lossless TIFF→JP2→TIFF with pixel verification, SpanDSP fax page read,
  and PipeWire plugin load under UID/GID 65534 at all three checkpoints.
  These are the application checks in scope. The PipeWire test requires
  the exact loader chain and resolves the plugin factory entry point.
  The guest records bounded per-command exit and combined output evidence.
  Stopped readback replays the command sequence and runtime checks from
  those bytes.
- The official `tiffgt` viewer and its exact bytes must be present at the
  original and restored checkpoints. It is deliberately absent from the
  candidate and remains a **package parity gap**, including on this
  composition where `freeglut 3.8.0-1` is installed.
- Require a fully restored lock, the two exact ALPM journal groups, natural
  QEMU and outer actor retirement, and agreement with independent stopped
  ext4 readback. A passed scoped run would qualify only emulated AArch64
  16 KiB for these bytes and probes. Physical M2, real Bluetooth audio and
  release admission remain open.

After the owner verifies outer retirement, record the stopped disk pin,
nonce, QEMU and outer-container terminal facts, and the two empty absence
observations using the schema in [readback.py](readback.py). Pass the exact
canonical record and its digest. The reader checks the result ext4 UUID
derived from the nonce, the original Asahi evidence, and the scoped
transaction, trust, loader and runtime evidence.

```sh
python3 -I -B "$lane/readback.py" \
  --stage "$fresh_scoped_stage" --disk "$stopped_result_disk" \
  --observation "$stopped_observation" --sha256 "$stopped_observation_sha"
```

## Source controls

```sh
for test in test_inputs.py test_jpeg_recipe.py test_runtime.py test_lane.py test_reflink.py test_host_telemetry.py; do
  python3 -I -B -Werror::ResourceWarning "$lane/$test" || exit
done
```
