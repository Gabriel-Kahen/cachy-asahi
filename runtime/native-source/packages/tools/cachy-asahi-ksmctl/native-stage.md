# Separate candidate native stage

Status: proposed invocation, not executed here. Existing `scripts/build/build.py`
already accepts this explicit recipe. No second builder, shared manifest change,
CI change or modification of the original four recipes is needed. The native CI
entry point and existing lifecycle runner intentionally enforce the original
four packages; do not add a tools entry to their locked input set or disguise
this candidate as one of those packages.

Use the coordinator's **accepted refreshed bootstrap receipt** from native run
38200957061 (source revision `70f08aa`) while its immutable image is available.
Expected current input SHA256 is
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`;
the refreshed baseline includes Perl `5.42.3-1`. Acceptance/image availability
were not verified by this worker. Bind the actual new `packages.lock` and image
ID from that receipt, require exactly 341 sorted rows, and retain their hashes.
Do not substitute the old image ID or old package-lock digest. The older run
38189520114 records historical evidence only; an image ID from a deleted hosted
job is not a retrievable registry reference.

Freeze the complete candidate directory after the policy/doc additions. Generate
the full `input_sha256` map with `package_checks.recipe` to a new directory
outside the recipe, independently review it, and freeze those exact bytes. The
map includes every recipe file; putting the map inside the recipe would create
a self-reference. Keep its SHA256 with the accepted bootstrap/lock and source
revision in the stage handoff. Re-check the map immediately before execution.

Run from repository root on the provisioned native ARM Docker host. Set
`KSM_IMAGE` to the accepted receipt's immutable image ID/digest, `KSM_LOCK` to
its reviewed package inventory, `KSM_REVIEW` to the frozen candidate input map,
and `KSM_OUTPUT` to a new external evidence directory. These values must come
from actual receipts; the placeholders are not available infrastructure.

```sh
python -B scripts/build/build.py packages/tools/cachy-asahi-ksmctl \
  --image "$KSM_IMAGE" --output "$KSM_OUTPUT/build-1" --mode native \
  --source-date-epoch 1791748800 --network none \
  --expected-packages "$KSM_LOCK" --reviewed-inputs "$KSM_REVIEW"
python -B scripts/build/build.py packages/tools/cachy-asahi-ksmctl \
  --image "$KSM_IMAGE" --output "$KSM_OUTPUT/build-2" --mode native \
  --source-date-epoch 1791748800 --network none \
  --expected-packages "$KSM_LOCK" --reviewed-inputs "$KSM_REVIEW"
python -B scripts/build/compare.py "$KSM_OUTPUT/build-1" \
  "$KSM_OUTPUT/build-2" --require-bytes > "$KSM_OUTPUT/compare.json"
```

Each build gets a distinct fresh constrained container and verifies native host
architecture, image architecture, complete unchanged package inventory, all
reviewed source inputs, generated metadata, package metadata and payload.
Retain both complete evidence trees and comparison exit status. Require equal
archive bytes, payloads including types/modes/owners, `.PKGINFO` and `.BUILDINFO`;
the comparator reports buildinfo equality separately, so explicitly inspect that
field too. Failure is unfinished work, not a skip. ARM execution still does not
establish M2 or 16 KiB execution; the 16 KiB conversions are fixture tests.

## Separate install/removal acceptance still required

The original four-package lifecycle runner cannot accept this fifth identity.
The coordinator must supply a separately reviewed disposable-container stage;
no such stage was implemented or executed here. Do not run host pacman or mount
host sysfs into it. Use the same accepted 341-row base and one hash-bound native
archive. Verify dependency closure without an unreviewed network resolver, mask
inherited hooks, and record complete before/installed/removed inventories and
filesystem snapshots including type, mode, ownership and content hashes.

Require exactly the five reviewed installed payloads: CLI mode 0755; README,
provenance, NOTICE and GPL license mode 0644, root-owned regular files in the
paths listed by package(). Reject `.INSTALL`, services, timers, config, sysfs
writes, protected platform paths and unexpected metadata relationships. Run
installed help/version and unsupported-management rejection without reading
sysfs; fixture-test installed reporting with 4 KiB and 16 KiB inputs. Remove the
candidate and require baseline package inventory and package-owned paths restored,
with original four package records and user fixtures preserved. Existing base
files at any candidate payload path must be treated as a conflict, never replaced
silently. Retain transaction logs and all hashes. No native installation/removal
or hardware result is claimed until those receipts exist.
