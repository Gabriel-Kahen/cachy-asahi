# Native ARM same-job development wiring

October 12, 2026. **Separate controller/workflow implemented and committed. First native development trial completed FAIL; targeted source corrections are in progress. Hardware and visual acceptance remain NOT RUN.**
The current initial job owns the reviewed four-package integration. These later
stages use a separately reviewed source packet toward required R1–R5/M5–M9; their source tests
do not establish native execution, full-port delivery, M2 compatibility or gains.
Coordinator owns source acceptance, Git, scheduling, dispatch and actual results.

## Current owner interfaces and prerequisites

| Follow-up | Existing owner interface | Required before wiring |
| --- | --- | --- |
| KSM diagnostic package | Explicit `scripts/build/build.py packages/tools/cachy-asahi-ksmctl` plus `compare.py --require-bytes`; committed 15-file map `manifests/reviewed/ksmctl.json` | Accepted refreshed 341-package builder and rechecked committed map; native package inspection remains required |
| ARM-C01 | `scripts/experiments/stage.py`, wrapping `arm_c01.py` and independent receiver; reviewed `scripts/experiments/stage.lock.json` | Accepted 341 base or verified 345 installed handoff, exact reviewed source/exporter lock and retained zlib archive; independent source review is closed |
| Frozen release client | `scripts/client/stage.py run` against the same actual 341-package builder | Corrected endpoint/exact-37-test source packet must be independently accepted; native tests remain NOT RUN |
| Generic software desktop guest | `scripts/virtual/controller.py --contract --contract-sha256 --output` | Accepted installed baseline, source/controller contract freeze and actual free-space check; VD1/VD2 source review is closed |

ARM-C01's [final independent review](../reviews/arm-c01-review.md) closes all
reproduced findings within its correctness-only scope: **91 local tests PASS,
zero skips**. The reviewed six-source/test-file plus exporter lock is
`98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5`.
Its earlier 54/89-test receipts and earlier stage hashes are historical. Native
execution remains NOT RUN. The accepted KSM candidate is
commit `e79f73aedc13f7875fb5dcf79faddafd6334571b`: 36 source/fixture tests passed
under coordinator verification, and its committed map binds all 15 recipe inputs.
The virtual controller/review is commit
`9cef9c292e37b5c5a61fa84c8061494b87cbf52a`: 29 portable tests (14 core, 15
controller) passed; VD1/VD2 are independently closed. These accepted source
packets have no native KSM/guest/frame result. Rehash each complete packet before
wiring; this document is not their executable freeze.

The virtual tooling lock currently hashes to
`7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25`
and the controller's reviewed `LOCK_PIN` matches. Its refreshed base binding is
the current authenticated Perl input snapshot
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
Its committed audit hash and reviewed `AUDIT_PIN` are
`3a7c30ba244a874625da994f896ae080a2b60f092b04f5f2d6caa70239e4f41d`.
The refreshed lock/audit and exact 341-package inventory must be accepted together;
package count equality cannot substitute for those hashes. The old base/tooling
audit remains historical. The 19 declared additions still require actual native
tooling-image verification before claiming 360 upstream plus four originals.

## One runner job and explicit image lifetimes

The new [separate workflow](../../.github/workflows/native-arm-development.yml)
and [controller](../../scripts/ci/development/controller.py) use one standard
native ARM job. They invoke the unchanged acquisition/bootstrap/original build
algorithms through `native_arm.main(argv, integration_consumers=callback)`.
The optional callback runs after genuine original-build PASS is persisted and
after initial integration stages, before final installed-image removal and the
initial final summary. Each follow-up has independent status; the original
four-package predicate remains unchanged. The parent checks initial exit,
summary and owned cleanup separately before accepting its own aggregate.

The historical dispatched source `e75ead78a89ff7f84b864a032b34ea6f49c028d5`
and lock `a115acf811a40274eb3fd76b7c0029d0f943c114fc9e382a2b297cb481c9de40`
bound 153 sources/125 fixtures. Run **38205521065 remains FAIL**: original/fixture
builds, TEST signing, 499 native source tests and lifecycle handoff passed, but
installed-image Config comparison refused changed Cmd/Entrypoint/Labels and
repository `repo-add-baseline-A` failed. The next checkpoint,
`932cf45818edd37eccfe1d22b74ca9b1e8ecdf61`, bound 157 sources/125 fixtures with
lock `e8fad9905d743c3287fbed9ca4041272e925bc4ba4aab339ecdc4430d05b3dac`.
Sixth actual native run **38212287407 is terminal FAIL**: 560 native source tests,
installed-image Config verification and final removal/absence passed. Its desktop
component passed all 22 commands, but two ANSI-bearing command logs failed public
export; repository positive phases passed, while its negative-case inventory
projection needed correction.

The coordinator independently reviewed those publication corrections and adopted
initial lock `be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`,
binding **159 sources/unchanged 125 generated fixture records**. Worktree and copied
suites each passed **331 CI/125 integration tests, zero skips**. Commit
`81aabca9a9657a74deb3780430bd55dd3deabc6f` passed coordinator Git blob/mode and
fresh detached preflight checks and was pushed. The seventh initial run **38214941784 is terminal FAIL**. Coordinator-decoded
evidence reports desktop export, lifecycle, onboarding, source checks, TEST
signing and fixtures PASS, including **588 native source tests, zero skips**.
Repository's first eight cases passed; case nine's missing database signature
was rejected by pacman with a specific local `integration.db.sig` retrieval
error, but the generic diagnostic classifier refused that wording. The release
owner is assigned a narrow typed-case/precondition correction. The committed
`be5363` map remains the historical accepted source checkpoint; any corrected
initial map requires a separately reviewed development packet rebind. The
aggregate must preserve the initial FAIL even when independently accepted
341/345-image predicates permit consumers to execute.

A later independent evidence review also found that positive repository logs
112/126/134 returned exit zero while reporting chroot EPERM and
`error: command failed to execute correctly`. Inventory/payload transitions
therefore do not establish error-free positive transactions or complete hook
execution. The release owner is auditing the pinned libalpm cause and a positive
ancillary-error gate. The coordinator permits review of adding only `SYS_CHROOT`
to this disposable repository container's existing five capabilities if the
built-in private-root ldconfig requires it; no such launch change or native
acceptance is supplied by this checkpoint. All other stage results remain
separate from this unresolved repository result.
The initial source files remain held unchanged.

Future executable files under `scripts/ci/development/` are explicitly excluded
from the initial scanner; the separate workflow is outside its source list.
This worker does not mutate either shared lock, Git or workflow dispatch.

These local Docker IDs cannot be handed to another hosted job through `needs` or
a JSON output: another job has a different daemon. Never publish/export these
images to bridge jobs; cleanup of visible key state does not erase parent layers.

Run serially, in this order:

1. Initial integration and its public evidence. Accept actual immutable base
   image/341-package lock and independently verified original installed image/
   345-package lock. Keep the exact archived input/source pins, original archive
   and payload maps, source commit and Config receipts.
2. KSM clean build/rebuild against the unmodified 341-package **builder** image.
   This stage produces package artifacts; it never adds a fifth package to the
   original installed image.
3. ARM-C01 in explicitly labelled **base-only 341-package mode**, with the same
   actual lock as base and expected inventory. This implemented stage claims no
   installed handoff. The owner also supports installed 345 mode with its six-file
   handoff envelope; that optional interface is documented below and is not wired
   into this controller.
4. Frozen release-client tests against the accepted 341 builder, with the actual
   same-job bootstrap and exact source pins; no package installation or downloads.
5. Virtual controller against that same accepted 345-package image. It alone
   owns its separate tooling derivative, native extension, independent image
   verification, preparation and one finite TCG trial. Its cleanup preserves
   the supplied baseline image.
6. Publish each explicit public bundle and final status, inspect matching
   virtual frames, and finish the job. Do not delete a shared baseline while
   another declared consumer still needs it. Remove only newly owned stage
   objects; retain public failures before cleanup.

There is no new coupling between independent follow-ups: an ARM-C01 failure
need not suppress a separately valid KSM/virtual attempt, but must remain FAIL in
the aggregate. Virtual and installed-mode ARM-C01 cannot run without the actual
accepted installed handoff. KSM/base-mode ARM-C01 may use an accepted base image
after an unrelated lifecycle failure only with explicit prerequisite status;
their success cannot turn initial integration green. Missing resources/inputs
produce named FAIL/NOT RUN, never a skipped package presented as complete.

## Concrete initial outputs to bind

Let `NATIVE` be the new native evidence root, `INTEGRATION` the separate integration
root, `CHECKOUT` the accepted checkout and `INPUTS` an owned retained-input staging
directory. All paths below become absolute paths on that same runner. Source,
input/cache, native evidence, integration and follow-up outputs remain disjoint.
Copy and rehash regular singly linked files; do not hardlink the stage inputs.

| Consumer input | Actual producer location |
| --- | --- |
| Immutable builder ID and full base inventory | `NATIVE/image-id`, `NATIVE/packages.lock`, `NATIVE/bootstrap.json` |
| Exact authenticated input snapshot | `NATIVE/inputs.lock.json` plus acquisition/signature/audit receipts |
| Installed image ID, complete inventory and image/Config verification | `INTEGRATION/work/lifecycle-raw/{installed-image.json,installed-packages.lock,commit-receipt.json,committed-config.json,committed-image/result.json,container-removal.json}` |
| Original lifecycle receipt | `INTEGRATION/work/lifecycle-raw/lifecycle/result.json` |
| Original native archive/payload rows | `INTEGRATION/work/fixtures-raw/archives.json` baseline rows; exact files under `INTEGRATION/work/archive-inputs/baseline/` |

Use **original** baseline rows, not upgrade fixtures. Every consumer verifies
versions, full payload maps, actual archives, accepted image ID, source commit,
complete installed lock and Config provenance. Keep source-execution and
baseline-source commits distinct where the owner interface supports them.
The current ARM stage verifies installed receipts against its `--source-commit`;
a same-checkout combined run satisfies that equality. Reusing an earlier image
under a later source commit requires an explicit owner contract correction,
not forged receipt commit fields. The virtual host contract already declares
both `source_commit` and `baseline_source_commit`.

## KSM native build invocation

Use the committed [15-file reviewed map](../../manifests/reviewed/ksmctl.json),
SHA-256 `f933ccfcfb52ca97ea809d904344f6ec72eb5907ef458b5c2e7f7f1797dc1d44`.
Recompute the map with the existing read-only recipe inspector and require exact
equality before execution, including no missing/extra recipe files. Copy and
rehash the committed map into `INPUTS/ksm-reviewed-inputs.json`, outside the
recipe. All 15 current files matched that committed map at this documentation
checkpoint. Keep the original four-package lock unchanged.

```sh
python3 -B scripts/build/build.py packages/tools/cachy-asahi-ksmctl \
  --image "$BASE_IMAGE" --mode native --network none --source-date-epoch 1791748800 \
  --expected-packages "$NATIVE/packages.lock" \
  --reviewed-inputs "$INPUTS/ksm-reviewed-inputs.json" \
  --timeout 300 --output "$KSM_EVIDENCE/attempt-1"
```

Repeat into fresh `attempt-2`, then run:

```sh
python3 -B scripts/build/compare.py "$KSM_EVIDENCE/attempt-1" \
  "$KSM_EVIDENCE/attempt-2" --require-bytes > "$KSM_EVIDENCE/compare.json"
```

The standard builder bounds each attempt to 4 CPUs/4GiB RAM, 512 PIDs and a
4GiB `/tmp` tmpfs; the outer driver gets a 360-second cap per attempt. Preserve
both provenance/build/validation records and exact archives after failure or
success. Require `bytes_equal`, `installed_contents_equal`, `pkginfo_equal` and
`buildinfo_equal` true for the exact single archive, plus comparison exit zero.
Inspect version `0.1.0-1`, GPL-2.0-or-later license, `python>=3.11` dependency,
five installed files, ownership/modes and absence of hooks/protected paths.
The script-only `arch=any` declaration does not establish native execution.

This is a GPL diagnostic, so initial `sign_fixture.py`'s four-name/MIT restriction
must continue to reject it. Native builds use the general build validator, which
binds its reviewed metadata. A later signed install/remove test needs its own
reviewed licence/package/signing contract; do not weaken the initial signer or
silently add KSM to four-package lifecycle/desktop predicates. Help/version and
fixture tests need no live KSM sysfs; no enable/pause/disable, host kernel write,
policy activation or memory/performance claim belongs to this build stage.

## ARM-C01 stage invocation and retention

Use the independently reviewed [ARM-C01 source lock](../../scripts/experiments/stage.lock.json),
SHA-256 `98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5`.
Copy and rehash it into `INPUTS/arm-c01-source.lock.json`; set `ARM_SOURCE_PIN` to
that full hash. Before future wiring, the coordinator checks every frozen file
and mode against its accepted Git packet and clean checkout. Reproducing the
candidate lock, when needed, is a separate local operation:

```sh
python3 -B scripts/experiments/stage.py --source-root "$CHECKOUT" \
  --freeze "$INPUTS/arm-c01-source.lock.json"
```

The adapter freeze binds `arm_c01.py`, `corpus.py`, both core/corpus tests,
`stage.py`, `test_stage.py`, and unchanged text-exporter SHA-256
`1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c`.
Its source tarball is retained zlib 1.3.2, 1,502,830 bytes, SHA
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
Local desktop `/tmp` is not available automatically on GitHub: stage/hash-check
the actual archive under `INPUTS` before execution.

Generate a pinned `handoff-pins.json` mapping exactly the six installed producer
files above to actual hashes, then invoke:

```sh
python3 -B scripts/experiments/stage.py --source-root "$CHECKOUT" \
  --lock "$INPUTS/arm-c01-source.lock.json" --lock-sha256 "$ARM_SOURCE_PIN" \
  --source "$INPUTS/zlib-1.3.2.tar.gz" --source-commit "$SOURCE_COMMIT" \
  --image "$INSTALLED_IMAGE" \
  --base-packages "$NATIVE/packages.lock" --base-packages-sha256 "$BASE_LOCK_PIN" \
  --expected-packages "$HANDOFF/installed-packages.lock" \
  --expected-packages-sha256 "$INSTALLED_LOCK_PIN" \
  --handoff-dir "$HANDOFF" --handoff-pins "$INPUTS/handoff-pins.json" \
  --handoff-pins-sha256 "$HANDOFF_PINS_SHA" --output "$ARM_EVIDENCE"
```

Reserve a 1,000-second outer launcher allowance for the 900-second stage trial,
bounded cleanup and export. It has 2 CPUs/4GiB RAM, 256
PIDs and owned 2GiB tmpfs; child root/inputs are read-only, capability-free and
network-free. Require four clean artifact sets, both byte-rebuild pairs, actual
LTO evidence and the complete 336 positive plus 32 rejection checks, with the
strict owner receiver consuming actual command/input/configuration records.
The closed source review does not replace those actual native execution checks.
Require CLI exit zero and final `result.json` status PASS, verified owned
container absence and evidence export PASS before accepting the stage.

Retain adapter `public/` text evidence and `public-status/` separately. Its concrete
`public-artifacts/` contains `development-ARM-C01-outputs.tar.gz` and
`archive-manifest.json`, explicitly bound to strict receiver hashes: 38 approved
files (four builds' 12 binaries/archives and 16 notices/configuration files,
nine public corpus files and their manifest). The adapter enforces 64MiB
uncompressed and 8MiB compressed limits. Require that entire explicit directory
also fits the publication wrapper's 16MiB expanded/8MiB compressed bundle limits;
oversize required material fails retention. Do not replace this implemented
artifact exporter with a second arbitrary-tree export. Split text/status into
bounded named bundles when necessary;
never send arbitrary `trial/`, temporary homes or raw input trees to a generic
exporter. Receipts must reconstruct artifact/corpus/command identity after the
runner exits. A missing/oversize required artifact fails retention, not silent
omission. Build elapsed time/hosted correctness is not an optimization gain;
16K execution, M2 measurements, PGO and release selection stay NOT RUN.

## Virtual host controller contract and invocation

Use the accepted closed VD1/VD2 review and refreshed tooling. Separately freeze the controller,
auditor, five core files, tests and input/lock/audit metadata. The host contract
must have the fields in [the owner's concrete controller schema](virtual-desktop-guest.md#native-controller-added-after-the-first-integration-freeze),
including accepted installed image, both source commits, all four baseline rows,
full source pins and the exact ten file aliases:
`base_inputs_lock`, `base_lock`, `installed_lock`, `lifecycle_receipt`,
`installed_image_receipt`, `committed_config`, `committed_verification`,
`commit_receipt`, `tooling_lock`, `tooling_audit`.
Each alias names a hash-bound file staged beside the contract. Baseline archives
and the exact signed tooling/keyring cache are private regular inputs there.
Set `audit_tooling_sha256` to the accepted auditor SHA-256
`f2005ea8366f64cd81aa7fb7dbae9e60c835da77164adba4d8e434af262fda13`,
matching the current controller's `AUDITOR_PIN`. The linked schema example has
an older literal auditor hash; use it for field names, and derive every source
pin from the accepted packet and current controller constants. In particular,
`core_sha256` must equal the exact five-file `CORE` map and
`controller_sha256` must bind the final accepted controller bytes.

```sh
python3 -B scripts/virtual/controller.py \
  --contract "$INPUTS/virtual/controller-inputs.json" \
  --contract-sha256 "$VIRTUAL_CONTRACT_PIN" --output "$VIRTUAL_EVIDENCE"
```

The owner controller installs only the verified extension inside a disposable
tooling image, uses expiring TEST local trust there, removes private visible
state, restores Config and independently verifies the immutable result. It then
prepares the complete generic guest and runs one proof. It preserves baseline
images and owns cleanup of its derivative, private tag, containers, copied root,
disk and temporary keys. No host package installation, device/socket passthrough,
KVM/FUSE/loop mounts, production trust or image publication is introduced.

Bounds: 55 minutes overall; preparation and TCG each have a 20-minute internal
deadline (outer container grace is bounded); guest boot 10 minutes; QMP commands
10 seconds. Container ceiling 4 CPUs/6GiB with no added swap; TCG guest 2 vCPUs/
4GiB. Preparation uses only CHOWN/DAC_OVERRIDE/FOWNER/FSETID, runtime cap0 and
read-only root. Tooling installation/read-side phases have their owner's separate
reviewed vectors. Require actual disk/free-space receipts before copying/population:
twice the source footprint plus 1GiB, then staged footprint plus 1GiB, and the
declared 8GiB sparse raw disk. Do not trim the base or add swap/paid resources
to conceal insufficient capacity.

Publish only the controller's explicit public projection: bounded stage/guest
receipts/logs and the two hash-bound `minimal.ppm`/`overlay.ppm` frames. Preserve
first error and cleanup status. Use a separate frame bundle with headers,
dimensions, byte counts, frame hashes and capture/log bindings. Never publish
the raw disk, rootfs, image layers, tooling cache, keys or private workspace.
Each workflow-log bundle keeps the existing 16MiB expanded/8MiB compressed limit;
required frames over budget are a named retention failure. Inspect both actual
matching frames after capture and write a separate hash-bound review result.
Automated `CAPTURED_REQUIRES_VISUAL_REVIEW` is a valid stop point with visual/
compositor acceptance still REVIEW REQUIRED; it is not graphics/hardware PASS.

## Separate source packet and job budget

[packet.py](../../scripts/ci/development/packet.py) independently enumerates the
initial sources and all executed extensions. It binds the exact initial source
and fixture maps, all experiment/virtual/client source files, 15 reviewed KSM
inputs, all development Python sources/tests and this workflow. Seven metadata
pins bind initial integration, authenticated inputs, original recipes, ARM-C01
stage lock, virtual tooling lock/audit and reviewed KSM map. The packet excludes
its own `packet.lock.json` from the recursive map, then independently validates
that file's committed bytes/mode against Git. Runtime requires exact selected
Git/current/packet path sets, bytes/modes, HEAD and full `GITHUB_SHA`; cached Python
and hidden executable exclusions are refused. Candidate freeze is not committed
source acceptance. The coordinator creates/reviews/commits the separate packet;
this worker only uses ephemeral copied-tree candidates for checks. The future
workflow runs original CI boundary tests, including signer refusal cases, plus
the development tests after packet verification and before provisioning. The
initial native source-suite stage independently reruns its unchanged source tests.

The workflow requests **180 minutes**, while the initial phase has a 50-minute
controller deadline. KSM has two 360-second drivers, a 120-second comparison and
120-second owned cleanup; commands grant bounded TERM cleanup before force-stop.
ARM-C01 gets 1,000 seconds plus 90 seconds cleanup grace. Client gets 420 seconds
plus grace. Virtual acquisition has a 600-second total bound and 15-second idle
operations, collects all 41 outcomes and retains owned-partial cleanup failures;
the owner launcher gets 3,420 seconds plus 90-second TERM grace. These are ceilings,
not measured runtimes. The budget includes publication, setup and cleanup margins.
GitHub's current [hosted job limit](https://docs.github.com/en/actions/reference/limits)
is six hours; the chosen 180 minutes is below that limit. Actual runner capacity
and disk checks still control stage acceptance. Use the same public standard
runner and serialized concurrency, with no artifact/cache service or image export.

Exact public directory selectors prevent a component from publishing another
private descendant. Text retains the unchanged credential policy; binary selectors
verify complete package/capture/artifact contracts before publication. A failed or
oversize required bundle fails the aggregate. Late cancellation, inconsistent
cleanup and interrupted status persistence stay FAIL. The always-run workflow
step retains the authoritative terminal summary separately from earlier observed
summary markers. Captured virtual frames leave aggregate
`CAPTURED_REQUIRES_VISUAL_REVIEW`, never visual or hardware PASS.

Before that future dispatch, retain every source/input blob, close owner reviews,
check all source keys/bytes/modes against Git and an actual clean checkout,
regenerate fixtures, and freeze separate reviewed follow-up locks. Do not add
new moving source directories to the initial freeze merely to suppress drift.
Run appropriate owner suites and source/package inspections after final changes.
The future parent retains every failed stage's public bundle and names unmet
dependencies; checksums alone cannot substitute for retrievable evidence.

Final reporting separates initial integration, KSM native package acceptance,
ARM build/correctness, virtual capture and visual review. None passes exact-M2,
16K Asahi, accelerated graphics/audio, suspend/power, management policy, measured
performance, production trust/publication or the full-port A01–A15 gates. Those
remain independently owned mandatory work. The separate controller/adapters have only local portable/mocked execution here.
No native job, Docker build, live guest trial, Git mutation or shared lock write
was performed for this development packet; the earlier metadata-only commit probe
is documented separately in the initial workstream.

## Current source acceptance dependencies

The virtual owner corrected exact empty-entrypoint/null-Labels normalization and
empty-command inheritance, with **31 portable core/controller tests PASS**.
Coordinator reports independent closure for controller SHA-256
`63a5dd2185bd263bb8b7699bf7ac3bec1c5746329259c386dc9d93090e73dd64`;
all five core/auditor/input pins remain unchanged. The older 29-test packet above
is historical. The future host contract must derive its nine accepted source
hashes from the separately reviewed development packet, not file-change detection.

The client owner corrected local-daemon binding and exact 17 Portable/20 GPG case
identity enforcement, with **39 local adapter tests PASS**. Its current adapter
hashes to `00d4f5fb14158c22da1575f0527e59791d60536bff4f365b6b60995942c6c73d`.
Coordinator's final independent closure is pending; no runnable development freeze
or native 37-test acceptance is supplied by this report.

## Final copied-source handoff

The final owned clean selected-source copy at
`/tmp/cachy-development-copied-final-iccxg3xv/source` passed actual packet
`freeze()`, `snapshot()`, copied `scan()` and metadata `bindings()` checks against
the newly adopted initial lock. The candidate is
`/tmp/cachy-development-copied-final-iccxg3xv/packet.lock.json`, SHA-256
`e37b732f9c332d6b532c8fcb2a90b005ab5c06ac84387d9d928c3580651b18ba`.
It binds **211 source files, 3,845,391 selected bytes**, all **159 initial sources**
and the exact unchanged **125 generated fixture records**. The canonical compact
source-map SHA-256 is
`a890068c2217a77e3d34847fdd41a208c983b09e90fe0e50bcfe49e3f148f473`.
Initial metadata pin remains
`be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`.

The complete copied development suite passed **143 tests, zero skips**. Its log
is `/tmp/cachy-development-copied-final-iccxg3xv/development-tests.txt`; its complete
receipt, seven metadata pins and all 13 held file hashes/modes are in
`/tmp/cachy-development-copied-final-iccxg3xv/regression.json`. All 12 development
Python files and the development workflow match the independent review's final
hash table. A final read confirmed all 211 selected worktree file bytes/modes
still match this candidate. All four workflow shell blocks pass `bash -n`; full
YAML/actionlint validation was not run because those tools are unavailable.

Direct shared-worktree scanning still correctly refuses existing Python caches;
this worker removed none. The owned copy explicitly omitted generated caches and
revalidated every selected byte/mode. Actual runtime Git preflight is **NOT RUN**
for this uncommitted candidate; its mocked refusal tests passed. The coordinator
must independently adopt the packet, commit it, prove its Git blobs/modes and
fresh-checkout preflight, then dispatch. Development sources and workflow are now
**HELD at the recorded hashes**. Native development execution remains **NOT RUN**;
virtual capture remains subject to visual review, and all hardware/performance/
production/full-port gates remain open.

Coordinator follow-up: the reviewed candidate `e37b732f…` was committed as
`108302c`, retaining the historical initial `be5363`/159-source map. Coordinator
fresh detached controller `--check-only` Git preflight and the complete
143-test development suite are in progress at this update. The first broader
trial is planned against the known initial repository FAIL; its aggregate must
retain FAIL while reporting independently accepted base/installed-image consumer
results. Current release-owner repository corrections are a subsequent coordinated
initial-lock/development-packet update. This worker's 12 development modules and
workflow remain held; no alternate initial or workflow predicate is substituted.

Successor source correction: the coordinator accepted the pinned libalpm audit
and assigned the repository-only launcher change. The fixed launch option now
adds exactly `SYS_CHROOT`; no generic rootcap allowance or other stage launch was
expanded. The actual repository command matches the owner's exact `0x400cb`
effective/permitted/bounding contract, with zero inheritable/ambient and NNP=1.
Peer review found no material defect. Worktree and copied suites each passed
**334 CI/137 integration tests, zero skips**. The ephemeral successor initial
candidate hashes to
`9cfbd847bd2969aadf700b1ebb9943680b064b0ec6570726cdd9389aa31db0bb`, still
159 sources/unchanged 125 fixtures; its copied preflight passed. Its complete
receipt is `/tmp/cachy-repository-chroot-copied-atuj7npt/regression.json`.
The original CI launcher/tests are held, and coordinator shared-lock adoption and
211-file development packet rebind remain pending. The committed `108302c` packet
continues to describe the historical `be5363` source map, not this successor.
Corrected native repository execution remains NOT RUN.

## First actual broader trial and virtual prerequisite diagnosis

Coordinator-run **38218102399**, source
`108302cff3d7be59800747773017cad688489904` and packet `e37b732f…`, completed
**FAIL**. Its strict decoded public bundles are retained at
`artifacts/ci/38218102399/development-decoded`. The authoritative aggregate
preserves initial repository FAIL and independently records KSM PASS, ARM-C01
FAIL, client FAIL and virtual NOT RUN. KSM completed its two native builds;
ARM-C01 and the client case are assigned to their owners. Publication and final
owned-image removal/absence passed. This is no full-port or hardware acceptance.

The actual virtual adapter receipt reports `virtual-prerequisite-refused` with
an empty prerequisite object; acquisition reports NOT COMPLETE with **zero input
outcomes**. Inspection of its retained unsigned fixture archive rows and the
committed-image verification rows reproduces the precise mismatch: all five
original fields are equal for all four originals, while the verified rows also
contain the TEST signer's `signature_sha256` annotation. The initial controller
writes `fixtures-raw/archives.json` before `lifecycle()` annotates its in-memory
rows during TEST signing. The adapter's exact equality compares the earlier
unsigned rows with the later signed verification rows and refuses before network
acquisition. The virtual owner independently requires its contract baseline to
match the full signed verification rows, so dropping the annotation would merely
move the refusal later.

The local retained-JSON/source reproduction is
`/tmp/cachy-virtual-prerequisite-38218102399-5u2ejp9l/reproduction.json`; it records
all four row differences and evidence file hashes. It performs no native trial,
Docker operation or network fetch. The correction is limited to the virtual
adapter/tests: preserve the full signed baseline while independently binding
all original fields, each detached-signature hash and signer archive/signature
receipt; publish finite diagnostic codes/phases without exception contents.
Ten other development Python files and the workflow still match their committed
historical packet. The four corrected initial sources remain held pending
coordinator acceptance and a separately reviewed combined packet rebind.

## Virtual signed-baseline source correction checkpoint

The corrected adapter keeps the full six-field signed baseline in the owner
contract. It requires exact equality of all five original fixture fields and
accepts only the `signature_sha256` annotation. Each annotation matches the
bounded, singly-linked public signature submitted in `lifecycle-inputs`, the
archive/signature pair in the TEST signer receipt, its exact primary VALIDSIG
fingerprint and the controller's already accepted cached signer receipt. Missing
cached authority, a substituted signature plus its recomputed annotation, changed
original fields, extra fields, symlinks and private markers refuse. The existing
actual 341/345 inventory, image/source, Config, READY and cleanup gates remain.
This reconciles producer records; it performs no new cryptographic verification.

The adapter now retains only exact finite refusal codes, with fixed fallbacks for
arbitrary exception contents. Its phase is one of preflight, input-copy,
acquisition, owner-execution, owner-receive or complete. Acquisition records
explicit execution NOT RUN versus ATTEMPTED and planned input count, so an empty
preflight receipt does not imply a transport failure. Per-input transport/hash
failures retain fixed codes without URL/error text. ResourceWarning checks also
confirm HTTP error response bodies are closed. The actual retained unsigned and
signed rows, public RSA signature bytes and signer receipt are inline regression
fixtures; tests do not depend on an `artifacts/` directory in a fresh checkout.

**58 focused tests PASS, zero skips**, independently repeated at the stable hashes
below with ResourceWarning treated as an error. Peer review found no remaining
material blocker. The copied focused suite also passes. The first complete
153-test worktree and copied runs each report **two failures and one error** in
held ARM base-adapter tests:

- `test_arm_success_uses_explicit_base_mode_and_retains_only_owner_public_bundles`
- `test_cancelled_owner_still_retains_failure_and_propagates_for_initial_cleanup`
- `test_recovery_rejects_private_accepted_text_even_with_updated_self_hash`

A separate actual read-only `arm_lock(root)` call reproduces `arm-source-drift`.
The ARM owner's in-flight `arm_c01.py` and `test_arm_c01.py` differ from the
unchanged accepted `98617adc…` lock. The first two tests therefore never reach
their mocked owner; the third subsequently has no `self.owner`. No held base
adapter, test or source gate was changed to bypass this refusal. In the owned
copy only, restoring those two files to accepted commit
`108302cff3d7be59800747773017cad688489904` produces **153 full development tests
PASS, zero skips**. This isolated compatibility proof does not certify the
current in-flight shared ARM graph.

| Held corrected virtual source | SHA-256 |
| --- | --- |
| `scripts/ci/development/virtual_stage.py` | `21d8a28c8da2e0aaf1a5d7780ce101ce11ad36894d81eed45d994b04126c4f6b` |
| `scripts/ci/development/test_virtual_stage.py` | `903be792d8442d1c701bb14b91819dd52a02a9201be6407908e3919c6e1296f2` |

Receipt/source-copy map and all test logs are retained at
`/tmp/cachy-development-virtual-copied-pb5fpu70/`; the current full-suite log is
`development-tests.txt` and the isolated accepted-ARM full-suite log is
`development-accepted-arm-tests.txt`. Both virtual files are **HELD**. Ten other
development Python files and the workflow match their committed historical
packet; all 159 initial files match successor `9cfbd847…`.

Coordinator adopted the initial successor and committed it as `a03c071` after
independent 334 CI/137 integration tests and source review. Corrected initial
run `38221511121` is in progress; no terminal result is supplied here. Historical
broad packet `e37b732f…` remains stale for the current source graph. The coordinator
must finish the ARM owner correction, freeze its compatible source envelope and
rebind the combined packet before another broader trial. This worker performed
no shared lock/Git/dispatch, Docker or network operation. The corrected virtual
native trial and visual/hardware/performance acceptance remain **NOT RUN**.
