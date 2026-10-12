# Native software integration execution

The connected V01–V09 batch validates development software in disposable native
ARM environments. It cannot accept either M2 Air, the Asahi target transaction,
16K runtime, platform recovery, performance, production trust or R1–R5 completion.

## First actual attempt: source preflight failure

- Source: `4128b22233d7c47da7e8aeb90e2ef87afcb97569`.
- [Native run 38198364798](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38198364798): **FAIL**.
- Reviewed integration lock:
  `d01fbf28be171f838e6bd92d6a89127875d5b1d701c0881f1c8f2826e2840670`.
- Signed input lock: `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`;
  original recipe lock: `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

The native ARM host executed all 211 bootstrap boundary tests successfully and
passed the runner probe. The full-source preflight then correctly refused the
checkout before input acquisition or package builds. Its local freeze included
two ignored host package archives under `packages/desktop/evidence/`; neither
was in the committed tree. Coordinator comparison found every other frozen
file's Git bytes and executable mode matched. This is a source-selection error,
not evidence of package installation or hardware failure.

The corrective task excludes generated package evidence directories from the
executable snapshot while preserving their historical records. Before rerunning,
the coordinator must compare every frozen file with the committed Git tree and
repeat preflight against a clean checkout. Hash checks remain mandatory.

Raw workflow logs and decoded bundles are retained locally under
`artifacts/ci/38198364798/`. Verified compressed bundle receipts:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `160dddcfeb3304230e03a0595e0d3683f2f93086e97d869916e98e96a371f525` | 1780 |
| Failed preflight evidence | `3cdd0541aee178dc05c61ff54c91bd36b059974957d52949fa0408c0d196bca4` | 56036 |

New original/fixture builds, signing, installed lifecycle, repository transactions,
onboarding, desktop checks and locked-userspace source suites are **NOT RUN in
this attempt**. The earlier successful four native package build pairs retain
their separate evidence in `native-arm.md`.

## Source-selection correction

Generated evidence directories beneath `packages/` are now excluded from the
executable snapshot; their files remain preserved. Two regressions check that
such evidence cannot alter a source freeze and that drift diagnostics identify
missing/extra/changed source paths without dumping content. The revised local
CI suite passes **213 tests**, with no skips.

Corrected integration lock:
`ac1fe1a05a8841da66824af496b81200376d32aa67320e6c48485b9373761408`.
It binds 100 source files and the same 125 deterministic fixture files. Local
preflight passes. The original signed input and recipe locks remain unchanged.
Clean committed-tree verification and a new actual native run are required;
this correction alone grants no executed integration acceptance.

## Second actual attempt: upstream input unavailable

- Source: `1c2d97bc9d2c82ac984b1297a808aba21d89745e`.
- [Native run 38199269315](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38199269315): **FAIL**.
- Corrected integration lock: `ac1fe1a05a8841da66824af496b81200376d32aa67320e6c48485b9373761408`.
- Original signed input and recipe locks remain the identities recorded above.

All 213 bootstrap boundary tests passed on the native ARM host. The runner probe
and full-source preflight passed. Before dispatch, the coordinator independently
checked every frozen file's bytes and executable mode against the committed Git
tree and repeated fixture/source preflight in a fresh detached checkout.

Input acquisition then failed with HTTP 404 before signature authentication,
image construction or package builds. The retained result only identifies the
HTTP error; it does not identify a filename. A subsequent bounded availability
audit identifies `perl-5.42.2-2-aarch64.pkg.tar.xz` and its detached signature as
the only two unavailable original URLs. The other 499 URLs return the expected
HTTP lengths; this HEAD result does not authenticate their bodies. All 501
retained local files still match their original pinned hashes. Current upstream
metadata advertises a newer Perl version; adopting it requires explicit
authentication, transaction review, a new coordinated snapshot and complete
native rerun. Original evidence must remain linked to its original snapshot.

Raw logs and independently decoded bundles are retained under
`artifacts/ci/38199269315/`:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `e5865947cd7f2d6738b564a4dc3850e87415f67f5fae176e3b9b5fd05edccda2` | 1781 |
| Failed acquisition evidence | `273df3994f55dfbab1235ca024425ab007d3142d437e07dd67a243878c2135e5` | 56043 |

Builds, signing, installed lifecycle, repository transactions, onboarding,
desktop checks and locked-userspace suites remain **NOT RUN in this attempt**.
The source-preflight correction has actual native evidence; the connected
integration batch still has no passing execution.

## Explicit builder snapshot refresh

The coordinator adopted authenticated Perl `5.42.3-1` after independently
rehashing the archive/signature, repeating exact-primary GPG verification in a
temporary public-only context, and comparing the complete signed `.PKGINFO`.
The migration proposal records 341 generic metadata entries and 1,582 satisfied
dependency relations with no missing relation, conflict or removal. All other
original rootfs, key and package bytes are retained. This is an explicit retained
transaction refresh, not a claim that every package came from today's sync DB.

- New signed input lock: `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
- Migration proposal: `d39c1b744ea54e282663e99932d58976336496426f7c3c6fd12b94526ff09a8f`.
- New integration lock: `b27a30d06aaa0870017adb1e37fe38c78384eea23234c6b8290d1b7536c785e2`.
- Original recipe lock remains `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

The complete original input lock is preserved in `input-snapshots/` under its
original digest. Both earlier execution records remain bound to that old lock.
The acquisition adapter now atomically retains every input's outcome before GPG
and reports bounded filenames/HTTP statuses without response bodies or URL
credentials. The coordinator reran all **217 local CI tests**, with no skips.
All eight original package builds and the connected integration batch must run
against the new snapshot before any new execution acceptance.

## Third actual attempt: rebuilt packages pass, integration fails

- Source: `70f08aaad0b03f343f533fa220a3d6cf6b35ae66`.
- [Native run 38200957061](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38200957061): **FAIL overall**.
- Input, recipe and integration identities are the refreshed hashes above.

All 501 inputs were acquired and byte-checked; the rootfs and all 248 dependency
archives passed signature authentication. Native bootstrap produced the exact
341-package inventory, SHA-256
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`.
All four original packages passed two distinct clean native build runs, archive
inspection and byte/payload/PKGINFO/BUILDINFO equality. The coordinator repeated
the strict comparisons against the retained artifacts; this is independent
receipt/artifact verification, not another set of ARM builds.

Fixture generation then failed because the copied source omitted mandatory
recipe-lock audit inputs under the Fish/Zsh/setup `evidence/` directories.
The source scanner's blanket exclusion corrected ignored archive leakage but
also removed 25 locked recipe files. A correction must retain those exact pinned
inputs and prove fixture generation from the copied source itself before a new
dispatch. Source preflight on the full checkout alone did not test this boundary.

The locked native userspace separately passed seven full suites: build/check
33, collector 3, release 19, benchmarks 28, setup 40, CI 217 and synchronization
9: **349 tests passed, zero skips**. The integration suite attempted 116 tests
and failed with 15 missing-input errors; it is not a passed suite. The desktop
local checker also failed: Hyprland's configuration verifier exited on signal 6.
Its terminal output was rejected by the generic text exporter's control-byte
guard, so the precise diagnostic was not retained. Both runtime failure and
diagnostic loss require correction; neither can be converted into a skipped
check or an accepted desktop result.

Signing, installed lifecycle, repository transactions, onboarding and installed
desktop stages are **NOT RUN** because fixture generation failed. Sanitized
summary and available failed-suite diagnostics are retained. Raw logs and
strictly decoded bundles are under `artifacts/ci/38200957061/`:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `52e8c7de04c40d67f8909a25d499527f041310de5a67fe8d91d2a8494f1425e5` | 1769 |
| Native package build evidence | `6ddc7ad98c220a678b3d388fc45d5f9a5bdc05c338ad948cac36e7c5ceb8b07c` | 1256108 |
| Failed fixtures | `c52171e663f506920bd0251f5094a8b421f87bc2b8a9151f45567e20d33d9368` | 900 |
| Native source suites | `7aca4898e30be8e53a1c13a0e31474c1590e83e69f553d2f8a64909da5d2d075` | 20984 |
| Failed integration summary | `4c040aee5dc36a50e8f445780a4e4380f4c6c5518c3b9c0f685be3b8a42768f3` | 982 |

## Copied-source and diagnostic correction

The scanner now requires every recipe-lock input in the source snapshot and
excludes unselected generated archives/logs. Both freezing and preflight derive
fixtures from a newly copied source tree. The coordinator independently reran
all 116 integration tests from that isolated 151-file copy; all passed, and the
125 generated fixture bytes/modes match the previous reviewed fixture map.
All **226 local CI tests passed**, without skips.

Known desktop terminal logs now have bounded escaped-text projections with raw
and projected byte/hash receipts. Credential checks apply before publication;
the generic exporter remains unchanged. Source-suite commands receive a private
mode-0700 runtime directory. This does not establish the cause or resolution of
Hyprland's native abort; a new execution must retain its actual diagnostic and
pass the verifier before desktop acceptance.

New integration lock:
`be827b7046049628d409a13eff4b5ee9bdbd7e9a0e92d1e411fae6e71bd0192f`.
Signed input and original recipe locks remain `3c16c37d...` and `20d846cd...`.
The next dispatch still requires committed-tree/clean-checkout verification.

## Fourth actual attempt: lifecycle component passes, handoff/repository fail

- Source: `e688ded697a6015d91a9df1717c01d7055567eed`.
- [Native run 38202483407](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38202483407): **FAIL overall**.
- Integration lock `be827b70...`; signed input and recipe locks remain unchanged.

The native host passed all 226 bootstrap tests and source preflight. Original
and changed fixture package build pairs passed, as did TEST signing and its
explicit public certificate/signature export. The locked native source suites
passed **474 tests, zero skips**, including all 116 integration tests. The
desktop local verifier passed with the corrected private runtime environment;
its bounded terminal projections were retained. This is parser/source validation,
not a graphical login or Apple GPU test.

The actual lifecycle component reports PASS with all checks passing and
`baseline_handoff_ready=true`; it exercised the signed package/helper lifecycle
and restored the original four packages. Its wrapper emitted READY for the
345-package inventory (SHA256 `3906ca525dac6bec9820db85ecbd9b8d66dc9af7c7b419a41941230807c8b456`).
The outer lifecycle stage nevertheless failed before publishing a verified
installed-image receipt. Its sanitized status does not identify the precise
refusal. Eight public package/version inventory files were also rejected by the
credential heuristic. Neither the component result nor READY certifies the
committed-image handoff; its source binding, configuration and independent
verification remain required.

The repository stage failed its first copied-base inventory command: pacman
could not resolve `/scratch/cache`. Repository installation, upgrades, negative
cases and rollback remain NOT RUN in this attempt. Installed onboarding and
desktop stages were not started because the handoff stage failed. Corrections
must retain strict trust/export guards, add concrete copied-root and inventory
projection regressions, and expose safe refusal diagnostics before rerunning.

Raw logs and strict decoded bundles are retained under
`artifacts/ci/38202483407/`. Key compressed bundle receipts:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native package builds | `e519cf0f78e3276ef19d29ef8763d812ade9b7b0211eef2eef7002691125d3ba` | 1256124 |
| Fixtures | `8969cd32b5ecaa0464fbb43b0df818959a8b24f9aaf3161e7028b4f4cce398cf` | 59527 |
| Lifecycle | `144ae9cdbf4c1c109a2d69d4787f788f78631d4fb9227377ecc3e1bca22ebc97` | 50016 |
| Repository failure | `af3d73af4660fdaf84b63c103e3e2ad58bc927c64d0bc03d09ddb49e9e18a164` | 49780 |
| Native source suites | `b49b0d8597b40ae020fa1a57880ece34315058068f62ec656d18dd04acd6d84f` | 28185 |
| Failed integration summary | `014df15d60d70fdffa6e5eaff6919ab9da362e17bf7f499d7a3960aff187f783` | 989 |

## Fifth actual attempt: precise handoff and repository refusals

- Source: `e75ead78a89ff7f84b864a032b34ea6f49c028d5`.
- [Native run 38205521065](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38205521065): **FAIL overall**.
- Integration lock: `a115acf811a40274eb3fd76b7c0029d0f943c114fc9e382a2b297cb481c9de40`, binding 153 source files and 125 fixture files.
- Signed input lock remains `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`; original recipe lock remains `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

Original and changed fixture package build pairs, archive comparisons and TEST
signing passed. All **499 locked native source tests passed, zero skips**. The
lifecycle component again passed and emitted READY for its 345-package inventory.
All eight strictly validated package-inventory projections exported successfully;
the generic credential guard remains unchanged.

The outer lifecycle verifier refused the committed image at
`derived-config-verification`, with refusal code `lifecycle-config` and differences
in exactly `Cmd`, `Entrypoint` and `Labels`. The bounded diagnostic names fields
without exposing environment values. This identifies the failed boundary; it
does not yet establish the cause or accept a corrected image. Empty command
metadata must actually be restored and independently verified before installed
onboarding, desktop or subsequent stages can use this image.

Repository execution progressed past the copied-base inventory to
`repo-add-baseline-A`. Its retained log reports that `mktemp` could not create
`/tmp/repo-tools.XXXXXXXXXX` on the read-only filesystem. Repository creation,
installation, upgrade, negative cases and rollback are not accepted. A bounded
private writable temporary directory is required while retaining the read-only
container root. The repository result's package-name dictionary also triggered
the generic credential heuristic; publication needs a validated semantic
inventory projection, not a relaxed text guard.

Installed onboarding and desktop stages were **NOT RUN**. No verified installed
image is available from this failed execution for the virtual guest or installed
ARM experiment. Raw logs and independently decoded bundles are retained under
`artifacts/ci/38205521065/`:

| Bundle | SHA-256 | Bytes |
| --- | --- | --- |
| Native probe | `65a1d8cb36bbb76b82a2b1c80fa2b35ef1a46632b65caf4015b8e9cac4bf13ca` | 1770 |
| Native package builds | `50bbd4e16711ee68e13db889caed9004db53bd58e6f660d3d49187301260a2b6` | 1256124 |
| Fixture archives | `a72e7635681015e68f1da37929971560e6877daf4fe8b3bdd1116c85d612d59b` | 35963 |
| Fixtures | `f979a113e6c73922abeb26a46c5b4c3ced59859ee9b28a36143bc6edeaf4dc98` | 59543 |
| Lifecycle | `153a1dd23128c148014dd521c4ea79d9b7cf2aaeeb4b8e0666504e07c1c8e86e` | 60840 |
| Repository failure | `5c9c70312bc201a156f4cdf043e0303178da40090c4fa1f29b52195ad41afc69` | 47188 |
| Native source suites | `1d46142c9d5576b4b9b2b4e264e05aa73a3a35b239bc740f0e858c057e506940` | 28851 |
| Failed integration summary | `f466b3057659ab944dac82370fc16e9bff8b80ec648e48f03f51d9dcc1d7cb04` | 1016 |

## Sixth-run source checkpoint

The reviewed correction restores portable image Config through bounded local
Docker API JSON and uses the documented exact empty-entrypoint reset sentinel.
Only that sentinel and null/empty Labels are normalized; full Env order/content
and nonempty commands/labels still compare exactly. A unique prechecked private
tag registers ownership before commit submission. Failed verification and final
consumer completion remove only the owned derivative and verify image/tag
absence. Ambiguous commit responses remain FAIL even after observed cleanup.
The [independent source review](../reviews/commit-image-review.md) closes the
previous ownership finding; it does not establish native handoff acceptance.

Repository creation receives a fresh private mode-0700 TMPDIR under its bounded
scratch mount. Its known inventory projection validates the complete accepted
base and exact generated source/image/nonce/script/daemon/upgrade contract while
retaining the generic credential guard. The
[repository review](../reviews/repository-runtime-review.md) records host-tool
and sandbox limits; actual native repository transactions remain required.

The coordinator passes **309 CI and 119 integration tests**, zero skips, both
from the worktree and a separately copied frozen source tree. The independent
reviewer also passed 150 focused checks. New integration lock:
`e8fad9905d743c3287fbed9ca4041272e925bc4ba4aab339ecdc4430d05b3dac`.
It binds **157 source files** and the same **125 fixture files**, byte-for-byte
and mode-for-mode. Input `3c16c37d...` and recipe `20d846cd...` locks remain
unchanged. The fifth run remains FAIL. Coordinator verification of commit
`932cf45818edd37eccfe1d22b74ca9b1e8ecdf61` checked every locked Git blob and mode,
then reproduced preflight from a fresh detached clone: **PASS**, 157 sources and
125 fixtures. [Native run 38212287407](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38212287407)
was dispatched on that exact commit on October 12, 2026 at 06:23 UTC and completed
at 06:28 UTC: **FAIL overall**. The execution findings follow below.

The optional same-job consumer interface preserves the existing CLI defaults
and keeps owned images alive until declared consumers finish. The separately
frozen development subtree/workflow is excluded from this initial snapshot and
has not received execution acceptance from these initial tests.

## Sixth native execution: installed handoff and software onboarding

Run **38212287407** authenticated the same inputs, repeated all four original
build pairs and fixture builds/signing, and passed **560 native source tests,
zero skips**. Coordinator rechecking of retained original archives/provenance
independently confirms byte, payload, PKGINFO and BUILDINFO equality for each pair.
The fresh committed image contains the exact **345-package** inventory
`3906ca525dac6bec9820db85ecbd9b8d66dc9af7c7b419a41941230807c8b456`.
Lifecycle and committed-image verification now **PASS**, including Config checks.
Final owned-image cleanup reports **PASS**, verified absence and no uncertainty.
The image was removed; its ID is historical evidence, not an available handoff
to another job.

Installed software onboarding reports **SOFTWARE PASS** in a bounded nonroot
container. This does not establish independent fresh installation or a Mac user
journey. The desktop component reports `desktop-container-verifier-pass`:
installed payload/inventory, Lua syntax, Hyprland default/optional config checks,
Waybar JSON, GTK3 CSS and the audited Mako subset passed. Its **public export
fails** because command logs 19 and 20 contain control codes. Desktop integration
therefore remains **FAIL** pending a validated publication correction. There is
no compositor/session, accelerated rendering or captured guest-frame acceptance.

Repository creation, TEST signatures and database signature checks progressed,
but its first untrusted-key negative case reports **FAIL**: `rejected transaction
changed inventory/payload`. Coordinator diff shows unchanged package rows and
payload snapshots; the compared inventory text also contains differing pacman
diagnostics and an import prompt. Clean diagnostic separation and strict inventory
verification are required. Remaining repository install/upgrade/negative/rollback
cases were not reached and are not accepted.

Raw logs, checksum-verified decoded bundles and the coordinator build-pair
receipt are retained under `artifacts/ci/38212287407/`. The authoritative summary
bundle is 1,051 bytes, SHA256
`4274b1a1854a36315824f850ffc8c131fb168550675c25f8f2b805cc2fec5a7f`;
lifecycle 65,570 bytes,
`b4ef43c03b607d1312d3962ea1bf6d21b74b63f2f9903b4269e18d011272fb51`;
onboarding 11,624 bytes,
`0385c74ec93045e92ef65ee3b87cd0ca36ca2e3bf5620b06409237b2fb403b9a`;
repository 71,854 bytes,
`4479baa306ff39dbcd5c4503fed5fc56cbd0ee3545c37c187a6259afc776dafb`;
desktop 20,213 bytes,
`8a4ab5c14800708c8df873623792d5f6075d27de335714c8c45048f1779a9807`.
All results are generic native ARM/4K userspace evidence. Both M2 Air hardware
records, supported full-port release, production trust and performance acceptance
remain **NOT RUN**.

## Seventh-run source checkpoint

The repository correction separates local package queries from registered sync
databases, validates exact bounded package maps and retains stdout/stderr hashes
separately. Negative cases still compare the full before/after inventory and
owned payload states. Explicit nonzero signature rejection includes GPG exit 2.

The desktop correction validates the exact successful receipt, container/input
bindings and both known Hyprland command logs before projecting only SGR terminal
presentation codes. Unknown controls/credentials remain refused by the unchanged
generic exporter. Receipt bytes/hash are rechecked before the same captured bytes
are staged; independent flag/nonce/credential replacement regressions are refused.
See the [focused publication review](../reviews/desktop-publication-review.md).

Coordinator tests pass **331 CI and 125 integration checks**, zero skips, in both
the worktree and a separately copied frozen source tree. Integration lock
`be5363dfb9f11b39f42fc419bebaa9cbaa11780fce1aa5cde2cedc25629766bb`
binds **159 sources and the unchanged 125 generated fixtures**. Every committed
blob/mode and fresh detached-clone preflight passes at
`81aabca9a9657a74deb3780430bd55dd3deabc6f`.
[Native run 38214941784](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38214941784)
was created at 06:55:19 UTC on October 12, 2026 on that commit and completed
at 07:00:02 UTC: **FAIL overall**. Its execution findings follow below.
The sixth execution remains FAIL; source checks and dispatch do not change it.

## Seventh native execution: desktop export and eight repository cases

Run **38214941784** passes **588 native source tests, zero skips**, repeated
original/fixture build pairs and TEST signing, fresh installed lifecycle/Config
verification, installed software onboarding and desktop configuration verification
including the corrected public export. Coordinator rechecking of retained original
archives/provenance confirms all four byte, payload, PKGINFO and BUILDINFO comparisons.
Final owned-image cleanup verifies absence without uncertainty. This is software
configuration evidence; the desktop receipt still records headless compositor
BLOCKED and graphics, application session, portal/audio and hardware NOT RUN.

The repository records these **eight case predicates PASS**: untrusted A rejection, trusted
full baseline installation, untrusted B rotation rejection, trusted full upgrade,
full rollback to retained A, tampered-package rejection, tampered-database rejection
and missing-package-signature rejection. Independent review finds that the three
positive pacman logs exit zero but contain chroot `Operation not permitted` and
`command failed to execute correctly` diagnostics. Their exact inventory/payload
transitions occurred; complete ancillary execution and error-free transactions
are **not accepted**. The positive predicate must reject these diagnostics, and
the private-root capability/helper requirement must be audited and corrected.
The complete repository sequence remains
**FAIL** at its ninth case, missing database signature. Pacman exits 1 after
requesting the absent local `integration.db.sig`, with a file-retrieval/download
library error. The generic signature/trust diagnostic predicate refuses that
wording before the after-snapshot. A case-specific missing-signature predicate
must bind the exact local endpoint, unchanged existing database and absent
signature preconditions, then preserve full negative inventory/payload checks.
Other retrieval failures must remain failures. Later revocation/healthy-key cases
were not reached and are not accepted.

Raw and checksum-verified decoded bundles plus coordinator build-pair verification
are retained under `artifacts/ci/38214941784/`. Summary bundle: 1,012 bytes,
`eb9339820bdcc22b4895249ea066d8ed28045e6b3725b38a82a5f71a57d74f83`;
repository: 107,987 bytes,
`7905b464a9a9ae8dbd62ee19a84ca4da3f8c5ac109ff8b67ff263c9f67df13ce`;
desktop: 20,816 bytes,
`52ab0e6b067ea3f7500ecd23c4cdc2addb5ca64186a3328a48551da667ae882b`;
lifecycle: 65,604 bytes,
`e9eb6cb7bd88c6a1a6431d04739e66527e18f9275481c90ef1b86460d8b132b1`.
These results establish no supported release, production signing trust,
full independent installation journey, measured optimization or M2 acceptance.

## First broader native development trial

The complete 211-source development packet
`e37b732f9c332d6b532c8fcb2a90b005ab5c06ac84387d9d928c3580651b18ba`
was committed at `108302cff3d7be59800747773017cad688489904`. Independent
committed-blob/mode checks and a fresh detached clone passed; all 143 controller
tests passed without skips. The workflow was registered through the one-file
[project PR #1](https://github.com/Gabriel-Kahen/cachy-asahi/pull/1), merged
at 07:28:02 UTC on October 12. Its merge adds only the reviewed workflow to the
updated default branch; execution uses the explicitly selected feature commit.

[Run 38218102399](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38218102399)
started at 07:30:25 UTC and completed at 07:35:28 UTC: **FAIL overall**.
The checkout/source preflight and controller boundary checks passed. The original
integration retained its repository FAIL, while original builds, fixtures,
signing, installed lifecycle, software onboarding and desktop configuration
checks reported PASS. The corrected repository successor was not in this run.

The same-job consumers produced these separate results:

- **KSM build pair PASS:** two actual clean native package builds produced
  `cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz`, SHA256
  `4ed661e2d9a4668c946aee385179b7a14167e2c2a627f6945021e4f315771faa`.
  The recorded comparison reports identical bytes, payload, PKGINFO and BUILDINFO,
  with both owned container absences verified. This does not establish native
  installation/removal, management writes, hardware or performance acceptance.
- **ARM-C01 FAIL:** four actual baseline/LTO zlib builds completed; 88 recorded
  cross-decoder checks passed before the trial failed. The terminal failure is
  retained; complete experiment acceptance and timing remain open.
- **Release client FAIL:** all 37 selected tests ran without skips; 36 passed.
  The checkpoint-permission fixture assumed a permissive umask although the native
  worker deliberately uses 077. The correction explicitly constructs the unsafe
  0644 fixture; it does not weaken checkpoint privacy validation.
- **Virtual desktop NOT RUN:** the prerequisite receiver refused the trial before
  acquisition/guest launch. No captured guest frames or desktop runtime are claimed.

Root retained the complete workflow log and strictly decoded all 23 bundles,
checking compressed lengths/hashes, fixed archive roots, safe unique regular-file
paths and extraction bounds: 1,084 members. Evidence is under
`artifacts/ci/38218102399/`, with `root-decode-verification.json` and the separate
terminal development summary. The final summary bundle is 2,395 bytes, SHA256
`01297f05ee10c7eaddde55a0267fcd03f55f8844c9ff9b6762b5c58ce70d046d`.
Independent detailed execution review and successor corrections remain separate
from this historical FAIL. Both M2 Air records and all full-port release gates
remain open.

## Corrected repository trial

Initial lock `9cfbd847bd2969aadf700b1ebb9943680b064b0ec6570726cdd9389aa31db0bb`
binds 159 sources and the unchanged 125 generated fixture records. The repository
launcher adds only SYS_CHROOT to its private-root capability contract; the runner
requires the exact six-bit mask. Positive transactions reject ancillary errors,
and the missing database-signature case binds its exact repository and diagnostic.
Root repeated 334 CI and 137 integration tests without skips, independently
regenerated the lock, and checked every committed blob/mode plus a fresh detached
checkout at `a03c0719893afe582a6e6364ff70f0e3e5b33fb2`.

[Run 38221511121](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38221511121)
was created at 08:05:48 UTC on October 12, 2026 on that exact commit. It is
**terminal FAIL**, completed at 08:10:17 UTC. It executed the original integration
alone while the broader compiler and virtual receiver corrections proceed;
historical broader run 38218102399 remains FAIL.

All **603 native source tests passed without skips**. Root independently checked
all four actual original build pairs, the observed exact six-capability mask,
the first ten completed repository case predicates and final owned-image absence.
Lifecycle, fixture/signing, installed software onboarding and desktop configuration
stages passed. The first three positive repository transactions now pass the
ancillary-diagnostic gate without chroot/helper errors; missing database signature
and revoked-A rejection also pass with unchanged negative snapshots.

The final healthy-B upgrade returns zero and changes all five test packages, but
starts with an invalid signature diagnostic for the cached revoked-A sync database
before refreshing B. The strict positive-error gate correctly refuses it. Complete
repository recovery remains unaccepted; the owner must address that private cached
database state without ignoring the diagnostic. Root retained all 12 verified
bundles and `root-execution-verification.json` under `artifacts/ci/38221511121/`.
Summary bundle: 1,020 bytes, SHA256
`0101a166f065703aea2dec15fdc42e9e2da4ca5b697933e5d1a576e49640e64b`.
No full-port release, production trust or hardware gate advances from this run.
