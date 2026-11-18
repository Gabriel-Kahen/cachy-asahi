# First Qt 6.12 GUI server pair on a hosted ARM runner

Two completed `ubuntu-24.04-arm` jobs passed the same 14 GiB outer free-space
gate and physically allocated the same 12 GiB owned ext4 backing file. They
use GitHub's ordinary hosted group and Ubuntu image `20261111.182.1`.
The successful carrier step also required at least 16,188,764,106 bytes on
the outer filesystem after checkout and before materializing its own inputs.

| Retained attempt | Job | Empty private ext4 | Private ext4 after carrier |
| --- | ---: | ---: | ---: |
| llhttp R125 | 134563460059 | 12,556,378,112 B | 12,011,122,688 B |
| md4c R128 | 134591565463 | 12,556,378,112 B | 12,011,118,592 B |

`actual-domains.json.available_storage` is measured on the fresh loop mount
after daemon setup. `evidence/report.json.actual_host.filesystem_available` is
measured in that loop's `work` directory after the 544,634,853-byte carrier
copy. Neither is a reading of the host filesystem before reservation.
Both actual reports show zero host package mutations and natural owned
retirement. The historical closures retained proof that the outer thresholds
passed. They did not retain the exact outer free-space counter.

The retained Original archives are under
`artifacts/development/orchestrator-resume-20261114` in the operating
checkout. Each exact hosted owner report pins the deployed policy.

| Evidence | R125 SHA-256 | R128 SHA-256 |
| --- | --- | --- |
| `public-evidence.Original.archive` | `76ee15b95f3edd48b695d0f6df309ca1db8f27ad01371977819a94c328d88ac9` | `aba33b1f9b8bc0abe178aea2ab448c900ca25e052b5a4b7f808a471120b9f678` |
| `owner-report.json` | `7d1cde4730b88a40a5444332af85c3099f718d75f4e9c581df76e8d90ff75458` | `52454905b4081c2ea5040b20462c6b5205992f5c28049380a4f40235b7663db8` |
| `command-002.json` (`fallocate`) | `70291c84db9aecca7e8d6aee23f6c3946776903409b70357ba9f3c5f1df1f332` | `c3ac3bbfb34a80e2f8ced4ca2389566b8528f20c7d16ce8c49b0cc06be5addbc` |
| `owner/policy.json` | `9f01c7921cf3c5a2ff95b6bc6d9a2b72ab8010b34afc17dd9b625547252c2fc0` | `9d0ab18e51c3a2ba836b9359f0f2ab82ca317c4068f6bb4dc386a0aeae1ea232` |

The independent public readbacks are R125 Source
`4b2aae4de42adc8ad0ad501dc9089c3b58751c1b` and R128 Source
`eed0513b957ef265b334a7762bdfba4f50afd500`. In each readback,
`owner/native349_carrier.py` checks the carrier reserve against its fresh
outer output parent. `owner/hosted_owner.py` repeats the outer check after
existing-tool preflight, allocates `storage.img` through the naturally
retired command, and checks exact length plus physical blocks before mount.
Only that workflow's runner-owned storage is mounted and later retired.

## Order for a fresh Root-operated stage

1. Use a separately registered, finite `ubuntu-24.04-arm` workflow and the
   exact selected launcher Source. Complete checkout first. Select the
   independent bulk input packet by whole pins before materialization. The
   current full packet is 1,657,692,271 logical bytes, or 1,752,637,011 bytes
   with its separately derived offline cache. Charge both the temporary
   transfer store and the verified bodies to the private ext4 in step 3.
2. In the already authenticated controller scope, create the fresh
   `$RUNNER_TEMP/<owned-stage>` output. Complete the existing host-tool and
   10 GiB available-memory admission. Call
   `capacity.require_before(controller_output)` immediately before the
   existing exclusive `fallocate` of 12,884,901,888 bytes to
   `controller_output/storage.img`. Read it back immediately with
   `capacity.require_after(controller_output, before)`. Retain both
   observations and the natural `fallocate` receipt. They bind the same
   outer directory inode, device and mount, and require 2,147,483,648 bytes
   available after allocation. Measure `volume` separately after mount and
   again after the input copy.
3. Preserve the existing loop identity, ext4 mount, private daemon, owned
   runtime and ordinary-user read-only confinement checks. After the loop is
   verified and before launching the ordinary payload, use
   `capacity.require_transfer_volume(controller_output, after, logical_bytes)`.
   The current conservative transfer budget is 3,572,382,886 bytes including
   two materializations and 64 MiB slack. Acquire directly into the private
   `volume/work` transport directory, with its Git/temp store and verified
   stage also on this mount. The old carrier's outer-filesystem preflight
   applies to its old placement and is not a suitable entry for the bulk
   volume. Finish scoped credential and temporary-store retirement before
   launching the ordinary payload. Keep the quota volume for daemon data,
   the one settled verified input set and all outputs. Authenticate all signed
   base inputs and recreate exact 349 on that daemon. Build the 356 image
   through the maintained `pipeline.builder_image_plan`, with seven exact
   signed additions under `Required TrustedOnly`, the separately selected
   TEST trust input and no host package transaction. Read back the signed
   installed inventory. Label the final image
   `org.cachy-asahi.qt612-reference.nonce=<stage nonce>` and retain its immutable
   image ID. Use the genuine baseline/authentication deadlines independently
   of the 18,000-second component stage. The older 35-minute runner envelope
   cannot host this stage.
4. Have the Root supervisor authenticate the exact family stage binding and
   pass the same live private socket, image ID, pinned 356 inventory and source
   cache into `executor.run_first_pair`. Pass the loaded maintained family
   `pipeline` and the existing bounded owner `Commands` instance. Set
   `QT612_FAMILY_SOURCE_ROOT`, `QT612_FAMILY_SOURCE_MAP_SHA256`,
   `QT612_FAMILY_BINDING_PATH` and `QT612_FAMILY_BINDING_SHA256` from the
   separately authenticated selection. The supervisor supplies
   `authenticate_Root_stage_binding`, `require_domain`,
   `require_signed_inventory`, `qualify` and `lifecycle`. The qualifier runs
   in its separate owned 2 GiB domain. Lifecycle requires the private
   authenticated signature of the newly qualified archive and its own
   disposable lifecycle image. An available TEST key for the 356 inputs
   does not itself qualify those new outputs.
5. Retain the exact two package archives, provenance and build/check logs,
   comparison, qualification, and scoped retirement receipts before
   unmounting. Stop on a hold. Confirm same-name absence twice after each
   naturally completed build. The controller retains responsibility for
   exceptional owned-daemon and storage retirement.

The generated build remains one CPU, one compile job, 4 GiB RAM, no extra
swap, 4 GiB private tmpfs and 512 PIDs. The two serial builds use 6,900 seconds
each. Comparison, qualification, lifecycle and cleanup reserve remain
120, 1,200, 1,800 and 90 seconds. The five stages have separate bindings.
Source expansion, compiler objects, package staging and checks all consume
tmpfs during each build. Actual peak space, memory and time for Qt remain
unmeasured. Allocate them under the existing gate and retain observations
before drawing conclusions about the complete family.

Run the offline controls with
`python3 -I -B -Werror::ResourceWarning -m unittest discover -s scripts/ci/qt612-family-hosted -p 'test_*.py'`.
They read a local mount and exercise fenced model commands. The new route
has no registration or issued Root binding.
