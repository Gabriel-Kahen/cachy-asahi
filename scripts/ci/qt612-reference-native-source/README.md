# Qt 6.12 serial native producer

The concrete producer binds frozen F recipe commit
`69a02851b87ca29daf2e197101b66bf75ff61889`, package
`cachy-asahi-qt612-base-source-reference-6.12.0-2-aarch64.pkg.tar.xz`.
Predecessor F `7748d413…` and the original `1cb3eba9…` preparation remain immutable.
This implements source/input admission, dependency-image and serial build plans,
reversible ordinary-builder projections, smoke/stage receipts and pair finishing.
**No native Qt build, GPG, signing, installation or Root grant has run here.**

## Frozen recipe and complete input admission

`f_intake.inspect_serial_recipe()` verifies the independent sealed handoff,
14 active file/mode pins, all 13 ordered source aliases/checksums, the 51,220,268-byte
Qt upstream archive, four zero-fuzz patches, 91 serial configuration settings,
173 notices, exact package identity and normal dependency declarations.
`f-serial-recipe.lock.json` supplies independently frozen pins. The predecessor
lock/API remain available as historical DATA, not an alternative producer target.

The isolated build view contains the unmodified F 14 plus its exact upstream
archive as operand 15. `reviewed-inputs.json` hashes all 15, matching unchanged
`package_checks.recipe()` behavior. No file is filtered from review. The immutable
archive is already present for normal offline makepkg source verification.

`validate_base_provider()` streams the exact 517 base input references and fixed
lock/bootstrap/inventory operands. It does not turn detached signature bytes into
current GPG acceptance. Six incremental official archive/signature pairs are
whole-pinned in `dependency-candidates.lock.json` and their actual PKGINFO joins
are checked. Baseline 349 plus seven additions gives exactly 356 packages, with no
foreign `qt6-base` binary installed as a self dependency.

**Current real dependency HOLD:** supplied catalog md4c is 0.6.0-2. Frozen F requires
`md4c>=0.5.3` and `<0.6`; that candidate is rejected. A correctly pinned aarch64
md4c archive, signature and independently selected metadata remain required.
The other six additions are double-conversion,libb2,libice,libsm,xcb-util-cursor
and xdg-utils. `libgl` is provided by baseline libglvnd; it is not a missing-name
waiver. Final normal `pacman -T` and makepkg checks still run inside the image.

`prepare.native_gate(source_root=...,source_map_sha256=...)` now admits a COMPLETE
valid unissued producer preparation. It verifies the whole Source namespace,
modes/map, fixed F contract, current 517 provider and all seven incremental inputs
before returning `COMPLETE_QT612_PRODUCER_INPUTS_DATA_ONLY`. Missing/wrong inputs
still refuse. This positive DATA result has `actor_enabled=false` and no Root
acceptance. It replaces only the previous unconditional preparation refusal.

## Normal signed image and ordinary clean pair

`dependency_image_plan()` emits an owned-image Dockerfile with explicit seven
archives, `Required TrustedOnly` signature policy, no scriptlets, exact inventory
comparison and a non-root builder. It has no host package-manager operation,
network sync, unsigned installation, --nodeps, --nocheck or broad skip.
Actual immutable parent/output images and current public trust remain Root roles.

`project_builder()` and `project_entry()` retain complete inverse checks against
the pinned normal build_v2/entry bodies. They retain architecture/image/inventory,
source checksum, generated SRCINFO, ordinary dependency and check gates. New
seams supply fixed nonce/attempt labels, exact XZ output, 4 GiB memory=memory-swap,
1 CPU, compile parallelism one and MAX_JOBS=1 and pre-Docker Root capacity gating. The original full
comparator runs with `--require-bytes`; archive, payload, PKGINFO and BUILDINFO
must match. Neither success flags nor architecture declarations qualify ARM/M2.

The entry retains Qt stage/configuration/source-notice receipts before container
scratch disappears. It removes only makepkg's final `--clean` so those proofs can
be copied; `--cleanbuild`, source verification and check() remain. Scratch remains
bounded inside the read-only-root container's 4 GiB tmpfs and is destroyed by natural
`--rm` retirement. No clean scratch persists between the two serial attempts.

`serial_pair()` requires an explicitly selected owned-executor adapter, domain
and read-only checks, empty container census, natural/reaped/complete commands,
and twice-absent attempt 1 before attempt 2. There is no default executor or role
issuer. `run_pair()` additionally requires actual fresh Root capacity/runtime
before any operational callback. The adapter must preserve the maintained
controller's executable, cgroup, PID/PIDFD, daemon/storage and cleanup checks.
Its `run(...,env=...)` receives an environment delta; only separately Root-selected
capacity/runtime references and public hosted context may be inherited. No env
snapshot is public evidence.

## Failure evidence precedes cleanup

An executor must implement `retain_public_failure_evidence` before the first
build. Any build/comparison/qualification failure invokes it BEFORE the exception
returns to caller cleanup. The episode stays `ProducerHold`, even when retention
succeeds. Retention failure preserves the primary exception capsule and marks
public retention incomplete. Exception text is not emitted; capsules contain its
class, byte count and bounded-message digest/truncation flag.

F owns the separate artifact transport/allowlist implementation. Bind that exact
reviewed helper in the owned adapter; do not collect cache, image, context, keys,
Root control documents or arbitrary private files. Public evidence must be whole,
allowlisted and finite. Oversized/missing/truncated evidence stays incomplete;
no truncation-and-success interpretation is available. This avoids checking
payload success before attempting to retain its useful failure evidence.

## Pair receipt qualification

`finish_pair.qualify_pair()` checks distinct fixed clean identities, actual native
build receipts, image/inventory/recipe pins, comparison, check-log smoke marker
`PASS_QT612_OFFSCREEN_API_SMOKE_ONLY`, 91-setting configuration, 173 notices, stage
contract and current XZ package bytes. It streams bounded archives (512 MiB
compressed, 2 GiB expanded, 128 MiB/member, 100000 nodes), checks payload modes/hashes,
links, all licenses and AArch64 ELF/header/module/tool/plugin closure against the
stage and normal validation reports. Neither F's stage record nor a MODEL receipt
alone supplies native execution, cryptographic acceptance or actual archive bytes.
Actual full native pair qualification is NOT RUN; MODEL seams test its predicates.

## Separate experimental resources and Root execution boundary

The earlier 18 GiB RAM / 72 GiB disk `resource-PROPOSAL.json` remains byte-identical.
NEW `resource-EXPERIMENTAL.json` is unissued and unmeasured: controller 512 MiB/1 CPU/
64 PID, owner 2 GiB physical+AS/1 CPU/256 PID, daemon 6 GiB / 4 CPU / 768 PID, Qt builder 4 GiB/
1 CPU/PID512/j1, no additional swap, 12 GiB preallocated storage, 14 GiB available disk,
10 GiB available RAM and 2 GiB host reserve. Builds are serial, pair 14400s, controller
work 14850s / scope 14940s, cleanup 90s. Root must bind the actual once profile later.
A bounded OOM/capacity/time failure is HOLD, not evidence that the recipe fits.

The finite observed-Docker-only 2 GiB VA exception and normal 512 MiB child/controller
bounds remain separate from physical cgroup bounds. Source85 diagnostic evidence
remains PENDING; no read-only guard is relaxed. Root's later Source93 host-domain
observations are not Qt build evidence. Root still supplies fresh kernel/domain,
filesystem, daemon, signed inventory/GPG, capacity and hosted-run truth.

Projected actor entry independently verifies current Source bytes, joins the
input-plan hash and requires two externally selected Root-issued fresh documents
with the exact experimental policy, recipe/source/run/attempt/nonce and actual
ordinary ARM context. Templates remain unissued; no helper authenticates Root
from JSON labels or mints approval. Publication, dispatch and all Root roles stay
with the coordinator. Source/legal/current trust, old official 0bd04f correspondence,
native16K/M2, performance and release gates remain held.

## Preparation and focused controls

```sh
python3.14 -I -B -Werror scripts/ci/qt612-reference-native-source/producer.py \
  --framework /absolute/pinned-framework-checkout \
  --f-root /absolute/frozen-F-serial-checkout \
  --archive /absolute/qtbase-everywhere-src-6.12.0.tar.xz \
  --provider-json /absolute/complete517.DATA.json --provider-sha256 WHOLE_SHA256 \
  --candidate-map /absolute/candidate_materials.json \
  --output /absolute/fresh-producer-Source
```

Add `--md4c-json` and its independent `--md4c-sha256` only for the missing valid
provider. Preparation streams existing base inputs and copies only the small
recipe/runtime/metadata plus the pinned 51 MiB upstream source; no baseline archive
copy occurs. Source constructors, shell/AST checks and MODEL controls run no actor.

```sh
python3.14 -I -B -Werror scripts/ci/qt612-reference-native-source/test_data.py -v
python3.14 -I -B -Werror scripts/ci/qt612-reference-native-source/test_producer.py -v
```
