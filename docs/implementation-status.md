# Implementation and acceptance status

October 12, 2026. This record tracks the complete `outline.md` scope; an implementation artifact is not a passed release gate.

October 15, 02:50 UTC, current native software corrections:
Installer Source `53e7cfdb` and Data `f13db0ee` are published with held Code
`677d3ba9`. Six diagnostic changes pass semantic `9c629f75`, actual Source
`df7f0503` and Source/Data/plan `7d2657f6` reviews. A separate correction
`3a377032` fixes the review's confusion between workflow environment keys and
repository variable names. No writes occurred under the wrong names. Exactly
`MAINTAINED_COMPOSED_ROOT_PLAN_B64` and `MAINTAINED_COMPOSED_ROOT_PLAN_SHA256`
then read back their reviewed values. The execution ref advances normally to
Source53; the single changed trial is `38672786958`. Actual review `ad4dac01`
and Root seal verification authenticate its failed readout: start_success false,
receiver_preflight_only false, native_cleanup_pass true. All 501 acquisition
pins, 249 signatures, four original package pairs and seven initial components
pass; receiver private cause remains unexported, restaging is NOT RUN and
publication fails. No installer pass is claimed. See the [integration record](reviews/native-software-integration-20261015.md).

Updater Source `781d43c4` publishes three reviewed diagnostic transport changes.
Semantic `b771fc1d` and actual Source `7fee6d5a` pass, with 91 roles and 88 held.
Its single changed trial `38672326640` is Root-admitted as an authenticated
failed readout after actual review `af746428` and passive verification of
118 owned files, 30 inputs and 19 retained files. The bound diagnostic reports
compiler return 0 followed by `compile-elf / elf-read-type-link-size` refusal.
The exact rejected type/link/size operand remains unknown. Scoped original and
recovery cleanup pass; daemon/cache retirement remains unverified. This
establishes no accepted native package. A separate local Cargo reproduction
finds a normal two-link executable rejected by the old reader; a scoped
snapshot correction was independently reviewed. Four introduced descriptor,
destination-parent and error-retirement gaps were corrected in successor
`73587bc3`. Fresh independent review `3d81ac94` passes all four original
countermodels and finds no new bounded defect. Root commits its seven-file
91-role change as `b5869fa9`; actual Source review is pending before publication
and another trial. The actual CI operand remains unknown.

Kernel Source `2525f178` publishes seven retained-input changes after semantic
`b0ed311f` and actual Source `d27c6b00` review. All 126 roles and the 124-row
packet match. The separate 35-object acquisition and kernel role policy stay
held. Its single changed trial is `38672997567`; no new kernel result is claimed.

P0 run `38669119568` is retained and Root-admitted as an authenticated failed
readout under review `8ead91a3`: pipeline/run-pipeline, precise cause unknown,
cleanup uncertain, matrix NOT RUN. Absence of the old policy label does not
prove policy passage, completed preparation or P0 entry. KSM run `38670087832`
likewise retains ValueError/PRODUCER/UNKNOWN, zero reported RPC requests and no
producer route, with cleanup FAIL and ownership uncertainty; review `90c0e950`
does not establish runtime validation of the inline finalizer change.

The combined KSM retained-input supplier and three-method Path correction
passes fresh whole-candidate review `26e5f135`, including the synthetic 501 flow
on real Python 3.14 Path without fake context hooks. Root commits exactly seven
changes as `30f5efaa`, with 160 roles and 153 held. Actual committed-Source review
`f54943c1` passes, and Root publishes the Source by normal fast-forward with exact
remote readback. One changed native trial `38675975893`, attempt 1, is selected
with packet `b7021695`; no result is claimed. Historical failure and cleanup
uncertainty remain unchanged.

P0 diagnostic Source `78f605be` is published. Actual Source review `f5422a2e`
authenticates its four-file delta and corrected read-only freeze. The initial
overwide publication-proof refusal remains retained. Registration preparation
`6813374d` and independent review `fb4dc84f` pass. Root applies default workflow
`6b3f574f` and exactly two review/publication variable updates; all five literal
values and the workflow read back exactly. Both templates and recipe `ebd58126`
stay held. One changed trial `38676597240`, attempt 1, is selected. No P0 pass
is claimed.

Current client/repository convergence now passes all 48 host tests without skips.
Root commits separate Code `c6d43be2` and Source `ba63d6d9`: the new explicit
baseline has 160 initial rows, 267 selected roles and sibling helper custody.
Actual Source/Code review `418547fc` passes and both commits are published to
dormant refs; no Data, registration or native acceptance is claimed. The closed
receiver public-record diagnostic composition `22b2083e` passes 22 focused tests
and passes fresh whole-candidate review `1c4dd5da`. Root commits the six-file
composition as Source `fb3c3b7d`; its actual Source/Data derivation review is
pending before selection. Historical four-package evidence
does not validate the current client product. Full R1–R5/M5–M9,
installation/recovery, exact-machine and performance gates remain open.

October 14, native screenshot region and cancellation admitted:
Root accepts run `38666490804` on Source `6dd1a88c` after actual review
`d85b39c9` and independent review `01197222`. Five native ARM PNGs pass311,507
pixel comparisons with zero mismatches, including the4,307-pixel region.
Real region selection, stationary-click cancellation, four existing refusals
and scoped owned cleanup pass. Root authenticates199 independent-review files
and1,410 inputs. The external sentinel body was not retained; broader host
resource retirement remains unknown. Package lifecycle, M2/Hyprland/Asahi,
16K hardware, performance and full-port acceptance remain open.
See the [finite Root admission](reviews/screenshot-native-region-cancel-root-admission-20261014.md).

October 15, retained-input composed trial reviewed:
Source `148f8a98`, Data `2b312bf8` and Code `677d3ba9` run
`38668263227` passes all 501 acquisition pins, 249 input signatures, four
original native development-package build pairs and seven initial integration
components. Actual review `626bc101` and Root's read-only seal check authenticate
191 files, 72 inputs and 549 Git inputs. Installer preflight still fails at
`RECEIVER_ACCEPT / P0_REFUSED`; its precise private cause was not exported.
Scoped cleanup passes separately. Handoff acceptance/restaging and later
components remain unrun, and phase publication fails. See the
[Root admission](reviews/composed-retained-bubblewrap-root-admission-20261015.md).
The new three recovered-input chunks are supported by mandatory authenticated
seed control flow and downstream cache/signature evidence; raw Secret value
readback remains unavailable. The old nineteen names and timestamps are held.
Updater Source `51af5b59` trial `38668405842` is terminal FAIL. Actual review
`b917e90f` and Root's read-only final seal check authenticate 159 leaves.
The freeze reports a fresh outer controller hash, but its raw contents were not
exported. The first worker wrapper returns 1; container inspection succeeds
before the existing `worker-run-result / worker-nonzero-returncode` refusal.
Compiler return and deeper cause remain unknown. Scoped exported cleanup passes;
daemon disposal is not attested. Direct seed and signature receipts were not
exported. See the [actual review](reviews/updater-retained-bubblewrap-run-38668405842-actual.md).
The already-captured worker diagnostics need bounded terminal transport before
another changed native trial.

P0 run `38667054387` retains its unknown policy-source refusal operands and
cause. A separate confirmed static path mismatch is corrected in Source
`8d01dff4`: three exact changes, unchanged 269-file packet and passing read-only
freezer. Committed-source peer `7768a3ae`, default workflow `14131f8f`, paired
corrected templates and all five variable readbacks pass. The selected trial `38669119568` is terminal FAIL; its authenticated readout
and cleanup uncertainty are recorded above. No P0 acceptance is claimed.

KSM Source `c843b30e` is published with exactly three reviewed changes after
semantic peer `d463a1ae`, actual-source peer `c452de4a` and Root's complete
160-role Git/physical verification. Inline finalizers partially preserve pending
primary errors; generator-close restoration errors remain outward. Covered
secondary diagnostics can be lost. The single changed native trial
`38670087832` is terminal FAIL; its actual review is sealed as `90c0e950`.
The earlier `CALL_ASDICT` cause remains unknown and
its cleanup failure/ownership uncertainty remain recorded. See the
[committed-source review](reviews/ksm-first-cause-actual-source-peer-20261015.md).

October 14, complete static prerequisites pass hosted validation:
The primary workflow installs shell/editor/compiler and repository tools before
the affected suites, uses a private temporary home on an ordinary non-root
runner, and refuses skipped or empty tooling suites. The integration producer
now probes known repo-add versions with observable receipts and performs one
signed database command without a weaker retry. Private scratch cleanup stays
required. Independent review `c8c7b76d` passes624 tests in six tooling suites,
plus9 packaged-sync and13 topmem tests separately, all without skips. An additional
signed fixture passes with unchanged Ubuntu repo-add6.0.2 bytes. This corrects
the frozen author's inaccurate wording of646 tests "across six suites".
The release/client workflow step is held. Published Source `496e66da` passes
hosted run `38666032870`:842 tests total with zero skips, followed by successful
recipe inspection and syntax checks. Counts are9,13,33,40,363,157,3,28,87,109;
the final two suites are release and client. Root retains the complete log and
result under `artifacts/reviews/repository-ci-root-observations-20261014/`.
Frozen native inventories retain their historical selections; this
primary-source correction does not silently advance them.
See the [fresh review](reviews/static-full-prerequisites-fresh-peer.md).

October 14, repository compatibility correction passes hosted validation:
Hosted run `38660953536` failed because Ubuntu's repo-add6.0.2 rejects
`--include-sigs`; its release fixtures ran rather than skipping. The corrected
implementation selects the reviewed signature behavior for known repo-add
versions, never retries a failed database command with weaker options, and
verifies the embedded signature against the separately verified package
signature. Duplicate and malformed database field headers refuse. Ordinary
leading-percent description values remain supported.
Author validation passes87 release and109 client tests without skips; fresh
independent review `191e7d66` passes479 checks,87 release fixtures and a
separately re-signed duplicate-header refusal control. Root authenticates all31
review files and108 inputs. The client adapter changes only the two affected
source pins. Published Source `d7bbdf2e` passes hosted run `38663759551`:
87 release and109 client tests run without skips, followed by recipe checks.
Earlier unrelated setup/integration suites report one and four skips respectively;
the no-skip claim applies specifically to the release/client contract suites.
The retained log and result are under
`artifacts/reviews/repository-ci-root-observations-20261014/`.
Native ARM, target installation and M2 acceptance remain open.
See the [correction](reviews/repo-add-database-field-correction.md) and
[independent review](reviews/repo-add-signature-capability-nativeci-peer-correction.md).

October 14, admitted screenshot software results and continuing ARM work:
Independent Root review `01e19ab9` authenticates both completed screenshot runs,
11 evidence graphs and 366 files. Native ARM full capture `38656985498` passes
230,400 independently decoded pixels; x86 region run `38655970029` passes
311,507 pixels, including the exact 4,307-pixel crop. Four expected refusals
per run and scoped owned process/runtime/container cleanup pass. Native region
selection, live cancellation, broader host resource retirement and M2/Hyprland
acceptance remain open. The earlier failed runs retain their original evidence.
See [Root admission](reviews/screenshot-native-region-root-admission-20261014.md).

The [read-only endpoint recipient](release/endpoint-client.md) passes20 local
tests and eight independent countermodels under review `3c110325`. It verifies
copied generations, signed stable/promotion/withdrawal records and Source
associations without changing trust or installing packages. Snapshot identity
does not establish freshness. Current client adapter pins now match48 declared
tests, including explicit Source-delivery custody;41 portable adapter tests
pass. The exact no-skip CI runner passes release82 and client109 locally.
Independent adapter review `bbf1227d` passes41 portable tests and15 additional
controls, preserving28 functions and the original execution/cleanup boundaries.
Hosted execution of the strengthened workflow remains pending publication.

Changed updater run `38658811819` and independent library run `38659049827` are
terminal FAIL; strict actual reviews are in progress. Library scheduling does
not require an earlier successful P0 run; its same-job native/original/callback
and cleanup gates remain mandatory. P0 Source `fa3eb103` publishes the exact
two-file reviewed diagnostic successor; Root verifies273 Git/physical roles and
runs the read-only freezer successfully. Actual-source peer `47f8c635`, guarded
default workflow registration `21cfb9c6` and five literal variable readbacks
pass. One explicitly selected Source-branch trial `38660515263` terminates FAIL;
its closed footer reports pipeline/run-pipeline and literal `grant-refused`
with exception type UNKNOWN. That literal is diagnostic metadata, not proof
of Source origin or permission failure. Strict actual review is assigned.

The published exporter CI run `38658694908` succeeds, but its exporter/release
fixtures skip because Arch package tools are absent. Root's local exporter26
and recipient20 tests pass without skips. A strengthened CI candidate provisions
disposable-runner tools and rejects skipped or empty release/client suites.
Its first local execution passes release82 but exposes stale frozen37 client
adapter pins against current client48. The corrected local execution now passes
release82 and client109; independent adapter admission passes.
No passing CI result is substituted for those missing tests or native acceptance.

October 14, local repository exporter integrated:
The [repository endpoint exporter](repository-endpoint.md) materializes verified
signed stable bundles into retained local generations and atomically selects
the live route. Signed withdrawal records can select a generation without a
live package route. Preview is read-only; hosting and client trust remain open.
Independent review identified three defects in directory permissions, reused
generation withdrawal checks and double-slash path aliases; all are corrected.
Root's 26 tests and the final peer's 26 exporter tests, six independent
regressions, 25 release tests and 31 source-delivery tests pass. Positive stable
gate fixtures explicitly model hardware acceptance; no release or M2 gate is
passed by those tests. Final review receipt: `8ac64e52`.

Native screenshot run `38656985498` and region run `38655970029` are terminal
SUCCESS. Strict actual artifact admission remains pending; API conclusions
alone establish neither capture acceptance nor M2 compatibility. Updater
Source `567877de` passes independent actual-source readiness review `6fc3769d`;
its next trial still requires native host/controller freezing.
Composed run `38655108742` fails its compound container environment predicate;
the failed operand remains UNKNOWN. Pair and Zsh runs fail during direct
retirement; overall cleanup remains unestablished. Kernel run `38651732124`
reports a refused ELF segment with flags7; runtime memory permissions are not
established by that diagnostic.

October 14, screenshot region success pending actual admission:
One changed software trial `38655970029` completes SUCCESS on Source
`498231de`, after committed-source peer `8810c607` and exact560-byte plan
readback including final LF. Strict capture, cancellation, negative-case and
retirement retention plus independent actual review are assigned. No hardware
or full screenshot acceptance follows from the API conclusion alone; older
four-pixel failures stay unchanged.

Native screenshot Source `ef190a32` publishes the independently reviewed
GitHub log delegation correction and bounded owned DNS transport. Root
verifies13 Source roles and the exact three-file delta after peer `9f77095e`;
archive/member/package/helper hash chains, caps and runtime pins are held.
Committed-source plan admission and a changed native trial remain pending.
The older download-origin failure's exact cause stays UNKNOWN.

The composed trial `38655108742` is now running. Both changed Pair and Zsh
trials are terminal FAIL; strict actual reviews are assigned. A separate
product implementation has begun for local export of verified maintained
repository endpoints, reusing signed release/promotion/withdrawal contracts.
It is not a hosted repository or a production trust enrollment.

October 14, changed native trials and Docker compatibility integration:
Composed Source `0a948450` implements the pinned Docker28 omission contract,
with six exact changes and271 verified Source roles. Bound Data `dbb2e54f`
is its exact two-file child. Fresh registration peer `d86f0b33`, both literal
variable readbacks and Source execution-ref fast-forward pass. Trial
`38655108742` is queued; no new composed acceptance is claimed.

Pair Source `febc46ed` and Zsh Source `4cda000d` each contain four reviewed
guardian diagnostic changes, with held Data/Code. Fresh actual registration
peer `26df5b03` and four literal variable readbacks pass. A single atomic
fast-forward triggers Pair `38654854421` and Zsh `38654854640`. Pair is terminal
FAIL with strict retention assigned; Zsh remains queued at this checkpoint.

P0's reviewed default workflow is registered on main `4833a5cc` and all five
selection variables read back exactly. Root first dispatched against main in
error; run `38654103369` terminates with `Root Source context refused` before
launcher entry. Its request/log/metadata are retained separately. The corrected
source-branch run `38654196346` on `93e37b8c` also fails, reporting
pipeline/run-pipeline with exception type and refusal code UNKNOWN, matrix
NOT RUN, cancelled=false and cleanup_uncertain=false. These flags establish
no retirement pass. There are two dispatches and one intended Source attempt;
strict actual review and a concrete next correction remain pending.

Screenshot region Source `498231de` publishes the reviewed three-file exact
format/selector-retirement/trace-bound correction. All19 Source roles verify;
committed-source admission and a changed actual trial remain pending. The prior
four-pixel mismatch remains FAIL with cause unproven. Native screenshot's
secure API-redirect/DNS-worker candidate is under fresh independent review.

October 14, P0 diagnostic boundary source publication:
Source `93e37b8c` publishes exactly the launcher and P0 workflow changes after
fresh independent review `77e62a22` passes4,827 assertions and634 extracted
footer/SystemExit1 cases. Root verifies273 complete source roles, retains the
same269-file packet `bae75a18`, and reruns the read-only source freezer with
natural exit zero. No native actor or runtime grant executes during freezing.
Committed-source admission, updated default workflow and literal operational
variable readback remain pending before one changed P0 trial. The review is
bounded to the new diagnostic/validated-state path: if an injected helper fault
prevents initial flag validation, unobserved stored flags remain unknown and
cleanup uncertainty is preserved. The original read/merge path is held.
Old run `38645249560` remains failed with actual business cause UNKNOWN.

October 14, isolated library Source/Data publication:
Root commits diagnostic Source `18c08cc5` directly on held Data `2c9d61b7`,
with exactly three changed files and280 authenticated source bodies. Bound
Data `836f3964` is its direct child with exactly two administrative payload
changes. Finalization and pure held-Code/workflow plan parsers pass. Source
and Data are published to `codex/library-diagnostic-dormant-source-v1` and
`codex/library-diagnostic-dormant-data-v1`, with exact remote readback.
The existing worktree, runtime variables and execution branch retain their
prior state. New native library trial remains NOT RUN pending P0 admission;
old Signal14 business cause remains UNKNOWN. Fresh preparation peer
`62dea402` and Root execution preparation `1314e060` record this bounded scope.

October 14, KSM expression diagnostic publication:
Source `afae76af` separates the held kernel-record calls and retains the exact
historical acquisition donor. Independent proposal peer `73036fd7` and
committed-source peer `d8346d23` pass. Root verifies the eight-file delta,
159 locked rows and160 unique Git/physical source roles. The changed native
trial `38652336866` is running with packet `2aac0ffe`; the prior TypeError
cause stays UNKNOWN and prior cleanup ownership stays uncertain.
Library diagnostic preparation passes fresh peer `62dea402` and can prepare
isolated Source/Data commits before P0 runtime admission. Registration and
runtime execution remain pending. The screenshot selector-retirement proposal
is withheld after independent trace validation findings; a corrected successor
is being prepared while exact pixel acceptance remains held.

October 14, native FDK provenance acceptance and changed kernel trial:
FDK run `38647710278` on Source `843fff11` is accepted as one finite native
build pair with current schema-3 provenance. Fresh peer `ef085d96` passes
61 assertions and 13 refusal controls. Root authenticates 21 owned records
and 793 immutable inputs; only shared Git packed-ref metadata has changed
through unrelated publication. Fresh read-only Git and physical checks
confirm all139 FDK source roles unchanged. Both package archives are
1,210,196 bytes, SHA256
`f1192f7993540bf190cfc795222ef577b1975e3bb0bc9da27951c5d973686311`.
Package bytes, payload, PKGINFO and BUILDINFO comparisons pass, with separately
scoped container/image retirement. Installation, provider integration,
signed repository delivery, physical 16K/M2 execution and performance remain open.

Kernel Source `2901a1eb` publishes the reviewed permission diagnostic split;
acceptance still requires ELF flags4/5/6. Fresh committed-source peer
`f4f8661d` authenticates126 unique roles and the exact ten-file change.
One changed native trial, `38651732124`, is running. Two baseline-matched
worker test failures, one verifier skip and14 public bootstrap exclusions
remain recorded; the full suite is not green. Old actual permissions stay UNKNOWN.

Region run `38650296183` reaches a complete selection but fails the geometry
newline expectation. The emitted custom-format geometry has11 bytes without
newline. Its retained crop also differs at four pixels; no crop acceptance is
claimed. A pinned-source selector-retirement and format correction is being
prepared, with pixel checks held. KSM run `38647718228` fails with TypeError
at the kernel-record operation; exact expression cause remains UNKNOWN and
cleanup ownership is uncertain. An expression-split diagnostic is under review.
P0, composed Docker configuration and native screenshot download compatibility
fixes remain active. All R1–R5/M5–M9/A01–A15 requirements remain in scope.

October 14, actual failure retention and onboarding correction checkpoint:
Root authenticates325 P0 retained/proof leaves and925 inputs from review
`1b801500`. Run `38645249560` stays FAIL; exact refusal code, preparation,
image and P0 outcomes remain UNKNOWN, with matrix NOT RUN and no retirement
proof. The diagnostic proposal is withheld after independent review finds
inconsistent OSError classification and unsafe flag-key lookup; a successor
is being prepared without changing the runtime policy.

Region trial `38647392979` on Source `8e256c05` stays FAIL at bounded real
protocol readiness. Review `9e51835b` authenticates11 owned/271 external rows
and103 retained files. Four full captures/307200 pixels and the196-package
inventory pass separately. Owned selector reaping, runtime exhaustion and
container absence are recorded; image/cache/context retirement is unrecorded.
No region crop, cancellation or negative cases completed. The trace records
capability emission and correct globals, with initial motion before overlay
mapping and no later motion before readiness. A two-line ordering candidate
is under independent review; the precise compositor cause remains unproven.

FDK provenance trial `38647710278` runs against reviewed Source `843fff11`;
KSM diagnostic trial `38647718228` is queued against `86631378`. The changed
composed and native screenshot trials `38645554301` and `38645746453` are
terminal FAIL and their strict actual reviews are assigned. No identical
retry is submitted or failure upgraded by Source evidence.

Primary `0cc39264` corrects onboarding's frozen helper closure and count-test
fixture after independent Source review. All13 onboarding unit tests pass.
The selected release helper now accompanies its dynamic loader; a fixed
fixture verifies count propagation without depending on historical19/current25
suite growth. No full native onboarding result is claimed. Existing FDK/KSM
PR integration bases are this development branch, while their running native
Sources stay pinned independently. A complete base merge changes selected
packet rows and requires new Source closures before later native selection.

October 14, first P0 trial and parallel Source integration checkpoint:
manual ARM trial `38645249560` on Source `58b0d9e3` fails with the broad
Root-selection/preparation/P0 status. The exact stage and cause remain UNKNOWN.
The public result reports matrix NOT RUN, cancelled=false and
cleanup_uncertain=false; these fields do not establish an installation or
cleanup pass. A closed diagnostic correction is being prepared before a retry.

Changed composed trial `38645554301` runs against reviewed Source `96e2713c`
and Data `d8fa351c`. Native screenshot trial `38645746453` is admitted against
Source `079f146e`, after actual committed-Source peer `bed922c2` and exact plan
readback; it is queued behind the composed trial. No new success is claimed.

FDK provenance/reporting Source `843fff11` is published after the corrected
schema-3 workflow consumer and independent peer `5e4db0da` pass 145 inert
controls. Root authenticates 21/215 author and 15/238 peer records and all139
committed Source objects. The old accepted FDK pair supplies no backfilled
public package identities; a changed trial remains NOT RUN. KSM diagnostic
Source `86631378` is published after independent peer `12de6192`; Root verifies
all158 packet rows plus the packet itself. Its new trial remains NOT RUN and
the prior actual cause/cleanup uncertainty remain unchanged.

Region custody Source `8e256c05` is separately published with eight additions
and two replacements after peer `09dc8338` passes76 inert controls. Root verifies
all18 locked files plus the lock; actual region/cancellation trials remain
NOT RUN pending final Source registration. Both native screenshot and region
changes have separate draft PRs. Required target, hardware, performance,
maintenance and release gates remain open across R1–R5 and M5–M9.

October 14, P0 source freeze and composed registration checkpoint: the four
reviewed same-job P0 launcher files are published in `d10708f3`, followed by
metadata-only `58b0d9e3`, which commits the actual 269-file packet. Root's
read-only freeze returns zero on both commits; packet SHA256 `bae75a18` is
unchanged and matches committed bytes. All 273 runtime/workflow/administration
files match Git and checkout bytes. The 19 authorized package/signature secret
names are present; values were not read. Root selected the existing null-slot
templates with an explicit Source review decision. Final admission and variable
registration are underway; native observation, preparation and P0 remain NOT RUN.

The composed image-policy correction is published as Source `96e2713c` and
selection Data `d8fa351c`, with held launcher Code `677d3ba9`. Root authenticates
1,541 proposal leaves and 1,348 inputs, verifies all 271 committed custody rows,
and registers two plan variables with exact literal readback. The changed trial
has not been triggered. Explicit-null defaults are corrected; the old failure's
missing-versus-null cause remains UNKNOWN.

Native screenshot Source `079f146e` adds nine reviewed files on a separate
branch from the accepted x86 trial. Root authenticates the author and independent
review chains and verifies all twelve locked files plus the lock itself. The
commit is awaiting its actual-Source peer and publication/registration; native
ARM capture remains NOT RUN. The FDK provenance proposal is withheld after a
fresh peer identifies a schema-2 workflow consumer rejecting schema-3 records;
a separate workflow correction is being prepared. No failed trial is upgraded
to a pass by these changes. All R1–R5, M5–M9 and hardware gates remain required.

October 14, kernel/KSM and region review checkpoint: all original native trials
are now terminal. Kernel `38632413885` remains FAIL on Source `46f8cdb4`.
Review `c3c8f079` authenticates174 retained/proof leaves: baseline kernel command
returns0, output verification refuses CHECK_001_PERMISSIONS, worker returns1,
and candidate is NOT RUN. Actual permission bits/segment are UNKNOWN; no RWX
or kernel-role cause is inferred. Scoped cleanup, absence and daemon
preservation pass separately. A role-specific Source audit is underway.

KSM review `f605276f` authenticates25 leaves/14 inputs and the selectedSource
proof. Trial `38618847844` refuses at RECORD_KERNEL, the exact expression
platform.uname()._asdict(); its underlying TypeError remains UNKNOWN.
Producer codes are1, builds NOT RUN, cleanupFAIL with ownership uncertain.
A possible lazy processor/subprocess path is under Source investigation and
is not an actual-cause claim.

Region client proposal `b81e3aff` is blocked for adoption after fresh review
`1aa1ad9e` reproduces a cancellation cleanup gap: helper interruption kills
the wrapper before it can retire real slurp. Root authenticates6 owned/183
external review records. No region actor or capture ran; a separate custody
successor is being prepared. This component finding does not block the whole
development goal. P0's materializer component `706d7b3e`/peer `f8c4135c` passes
limited Source review; actual packet freeze, same-job observer/launcher,
runtime pins, templates and P0 execution remain separate pending work.

October 14, accepted native FDK development checkpoint: actual trial
`38623533412` completes SUCCESS on Source `220b4eb2`. Fresh review `a480fe8d`
passes36 checks plus4 pure malformed-vector controls. Root authenticates151
owned/20 external rows,139 committed Source objects and14 retained leaves.
Both native workers return verified zero/STATIC_PASS and the comparison returns
verified zero/COMPLETE. Scoped cleanup and image absence pass separately.
The selected Source gates native ELF screening and a classic AAC roundtrip;
xHE is configuration-only. Exact private package hashes/counts/logs are not
exported or replayed, and397 natural observations are not397 zero outcomes.
One native FDK development pair is accepted. Installation, M2, performance,
source/license delivery and repository publication remain open. Earlier failed
FDK trials stay failed. A bounded provenance-export proposal is underway.

Composed review `c1a94e18` authenticates382 leaves/41 inputs for actualFAIL
`38614475627`: IMAGE_HANDOFF/IMAGE_CONFIG/POLICY_FIELDS, initial controllerFAIL
despite seven componentPASS fields; downstream NOT RUN. Updater review
`0d883e79` authenticates19 leaves/23 inputs for actualFAIL `38617063734`,
worker-1/ValueError, deeper causeUNKNOWN and scoped cleanupPASS. Separate
Source diagnosis follows those actual boundaries; no broad acceptance follows.

October 14, pretrial workflow correction checkpoint: Source `857aa6aa` fixes
one P0 workflow read-limit constant. A focused exact-loop reproducer shows
published2408 truncating the66238-byte driver at66168; the new66239 bound reads
it exactly and still refuses an extra byte. External review `7bbdd652` passes
25 checks/six cases. Root authenticates20 committed selected rows and exactly
one changed workflow. P0 is NOT RUN; the actual packet and same-job trusted
runtime selector/materializer still require review and integration.

Region audit `6629f50d` authenticates112 leaves/26 inputs and establishes why
cursor IPC alone cannot provide slurp pointer capability in the selected
headless setup. A confined virtual-pointer client is under development.
Native screenshot feasibility `6453a461` authenticates55 leaves/58 inputs;
all196 ARM64 counterpart package names are metadata-feasible. Exact binary
closure and native execution remain separate. Wayland core sources are
retained against the existing runtime pins, with no source execution.

The original native queue is now terminal except kernel `38632413885`.
FDK `38623533412` completes SUCCESS on Source `220b4eb2`; its actual build,
smoke/comparison and cleanup review is pending. KSM `38618847844` and CLI
`38620204222` complete FAIL. Exact terminal retention is assigned before any
acceptance or further failure inference; no identical retries are launched.

October 14, P0 reader publication and library actual review checkpoint:
P0 Source `2408e967` publishes the two-file authenticated-empty-source correction
after external review `e3f5bd11` and392 focused checks. Root verifies20 selected
committed rows and exactly2 changed paths. Only pinned nonprivate empty bytes
are allowed; private/unselected/wrong-pin refusals remain. Full actual269
packet/runtime/template regeneration and preparation/P0 execution are pending.

Library actual review `78ae1e8f` and fresh external review `46f65dc1` authenticate
all110 retained files/89 inputs plus280 Source objects,3 Code and2 Data objects.
The exact run remains FAIL/controller1/no library frame or API artifact. Its
visible Signal14 OSError is distinct from the UNKNOWN first business cause,
signal owner, original producer return, callback entry and library phases.
The producer's PASS summary can be printed in finalization and proves no normal
return. Initial cleanupPASS and repository's default/unverified FAIL are
separate observations. No library build/reproducibility or hardware acceptance
is issued. A bounded diagnostic proposal will expose the missing stage facts.

Pair `38611783071` and Zsh `38611787402` are terminalFAIL; retained preliminary
readouts report guardian-worker-exit with empty results. Final separate reviews
are underway. The queue now executes composed trial `38614475627` without
restart; the changed kernel trial remains running.

October 14, accepted standalone screenshot checkpoint: fresh external actual
review `1299d10f` passes40 checks. Root authenticates all5 owned/91 external
rows, including87 retained files. One actual x86 standalone Sway/helper trial
passes its196-package inventory, three captures/230400 pixels, four refusals
and owned process/runtime/container retirement. This closes that finite trial;
successful region selection, native ARM archive execution and accelerated
Hyprland/M2 acceptance remain open. Base/final-image/cache/context retirement
is unrecorded. The earlier APT-failed trial remains a failure.

October 14, retained screenshot and library checkpoint: screenshot trial
`38634245640` completes SUCCESS on exactSource `453699c2`. Root authenticates
actual review `15d9e50f`, its13 owned/5 external rows and87 retained files.
The evidence records196 installed inventory rows, three real320x240 captures,
four expected refusals and owned process/runtime/container cleanup. A fresh
independent actual review is underway. Successful region selection is NOT
TESTED; ARM archive, Hyprland/M2, licensing and performance acceptance remain
open. Image/build-cache/build-context retirement is UNKNOWN_UNRECORDED.

Library trial `38610255544` completes FAIL on exactSource `32dea27b`.
Terminal retention finds no library frame or API artifact. Preliminary readout
records a visible signal14 OSError and controller1, with first business cause
and signal origin still UNKNOWN. Its original producer summary is not proof
of the later library stages or actual producer exit. Full actual review is
pending. The native queue advances to Pair `38611783071` without a restart.

P0 materialization finds three pinned empty evidence files in the actual
selected Source set that its reader rejects. A narrowly scoped reader
correction and actual packet/template materializer are being prepared; the
published Source and original deadlines remain unchanged in this checkpoint.

October 14, corrected software execution checkpoint: screenshot Source
`453699c2` publishes the two-file offline APT correction after external Source
review `99640471` and registration review `a4dabb3d`. The complete seven-file
selection, ten locked rows and lock self authenticate. The529-byte plan
`8581aa6a` reads back exactly before Source publication. Changed software
trial `38634245640` is running; installation, inventory, captures and cleanup
remain unaccepted until its actual terminal evidence is retained.

P0 preparation Source `58eb0ef2` publishes the reviewed12-target union
(9 changed,3 held) after peer `d94d0756` and368 focused checks. Root verifies
all20 committed selected files and exactly9 changed paths. It writes the
original authenticated input lock before image preparation and seeds the four
recovered public assets from the existing19 CI secrets under the original
preparation deadline. The complete actual269-path packet, runtime identity,
private templates and finite grant bindings still require regeneration and
review. Preparation, P0, native26 and hardware acceptance remain NOT RUN.
The screenshot trial occupies the third reserved slot; P0 awaits termination.

October 14, changed kernel diagnostic checkpoint: Source `46f8cdb4` and
packet `d33fc24e` publish ten reviewed replacements. All124 committed packet
rows verify; external review `66c43a2f` passes14 groups/105 assertions. Two
unchanged worker subtest failures reproduce on the baseline, so the full suite
is not green. Trial `38632413885` is running. The prior CHECK_001 conjunct
remains UNKNOWN; no output verifier rule or hardware gate is relaxed.

October 14, reviewed correction checkpoint: virtual SVG preflight now preserves
cancellation/exit identity after its bounded diagnostic. Source `269d3d95` is
published after independent review `481082d7`; eleven focused controls pass.
The prior guest still has zero accepted frames. Full maintained composition
and fresh runtime bindings are required before another actual guest trial.

Screenshot APT3.0.3 source tracing identifies --no-download shutting down the
queued local-file acquisition before its callback supplies an absolute path.
A two-file correction permits local acquisition inside the unchanged offline
Docker build, disables package repositories and preserves all196 package pins.
Independent Source review is underway; corrected installation/capture is NOT RUN.
P0's successor also wires the existing19 authorized secret chunks into an owned
verified cache and materializes the authenticated input lock before image prep.
Its final Source review and actual execution remain pending.

October 14, screenshot cause and P0 integration checkpoint: review `2e49b9d8`
and33 retained files authenticate trial `38628618206`. Base pull passes;
APT rejects a nonabsolute libexpat1 pathname, returns100 and Docker build
returns1. Installed inventory and captures are NOT REACHED; no trial container
is created, and image/cache/build-context cleanup is unrecorded. A minimal
pinned-runtime installation correction is being prepared without host installs.

Fresh P0 Source review reproduces a missing inputs.lock.json read before Docker
in the new preparation route. The sealed preparation proposal is not adopted;
a successor will materialize the already authenticated bytes before their hash.
Existing clocks, typed Session, Source/image/grant gates remain held. Actual
preparation, P0 and native26 acceptance stay open.

October 14, retained kernel checkpoint: review `ca3afe31` authenticates
completion `8062415f` and exact Source `3bec0e2e` for trial `38620355690`.
Producer and acquisition both exit0, producer/probe PASS. Baseline kernel
command returns0, but its worker returns1 after OUTPUTS/DATA_REFUSAL at
VERIFY_OUTPUTS/CHECK_001. The eight load-geometry/permission conjuncts map to
the captured verifier; the actual failing conjunct/operand is UNKNOWN.
Candidate work is NOT RUN and native compilation is NOT ACCEPTED. Outer and
child cleanup, owned absence and daemon preservation report PASS separately.
A closed predicate diagnostic is being prepared; no verifier is weakened and
no old failure is backfilled. Test-only Source `1ed00455` remains distinct.

October 14, screenshot terminal checkpoint: trial `38628618206` isFAIL
on exact Source `85a84f9f`. Its registration guard and checkout pass; the
build/runtime step fails and bounded evidence upload succeeds. Exact runtime
cause, image/capture progress and cleanup results remain unclassified pending
terminal retention. No retry is dispatched. The third-slot scheduling hold
for P0 ends with the pilot; P0 Source/admission/preparation checks remain open.

October 14, screenshot CI execution checkpoint: Root publishes Source
`85a84f9f` in draftPR26 after independent peer `5717c4ef` (53 inert controls)
and registration peer `46bf659f` (24 controls). Seven additions, ten locked
Git rows plus the lock, and four existing helper/license bodies verify exactly.
The runtime closure pins196 Debian packages and an immutable base image.

Only the guarded manual workflow is added to default main at `3ab577f9`.
Root reads back the exact529-byte plan `83f4176e` before publishing the Source
ref. Workflow384750899 launches one manual trial `38628618206`, now running
on the exact Source. Actual pre-dispatch project activity is one library job;
existing native queues stay untouched. P0 waits for this pilot to terminate.
Image build, real captures/pixel checks and capture cleanup remain unaccepted
until terminal evidence is retained. Always-upload can run after guard refusal;
built image/cache retirement is outside this CI result. ARM archive execution,
accelerated Hyprland and Asahi/M2 acceptance remain separate.

Kernel trial `38620355690` is now terminalFAIL on preceding native Source
`3bec0e2e`. Exact terminal retention is underway before any cause inference or
retry. The test-only successor `1ed00455`/212 passing unit tests does not
establish this native result. Full R1–R5 development remains active.

October 14, source and scheduling checkpoint: fresh platform-source review
`5ede0dd2` authenticates105 retained leaves and35 official retrieval records.
The selected systemd262/pacmanr9 recipe hashes still have no exact matches;
version/date/history records do not establish selected-build custody. Exact
source correspondence and complete licenses remain OPEN.

Queue review `02235206` confirms separate standard hosted VMs and runner-local
Docker endpoints. Root's19:28 snapshot records two active project jobs and
seven pending native trials. A bounded future pilot reserves at most three
project jobs; screenshot software may use the third slot before P0. Root will
wait for that trial to terminate before dispatching P0. Existing queue, refs,
plan variables and admission gates remain unchanged. Account/storage headroom
outside this observation is unmeasured; no throughput gain is claimed.

October 14, FDK smoke correction checkpoint: independent peer `bdf6102c`
passes21 focused groups and exact eight-file preimages. Root publishes
Source `220b4eb2`, packet `73a24d4f`, and verifies139 committed rows:
137 packet bodies plus packet and separately bound workflow. Seven packet
rows change;130 stay held. The four vendor include directories use-isystem,
while project-Wall/-Wextra/-Werror flags remain unchanged. Closed optional
compiler detail preserves original stage/status on ordinary parser faults.

Localx86 object fixtures demonstrate vendor-I failure, vendor-isystem success,
and continued project-warning failure. They do not establish the prior ARM
compiler's identity or cause. One changed-Source native trial `38623533412`
is queued. Native build2/comparison, installed behavior,16K/M2 and performance
acceptance remain pending; previous SMOKE_COMPILE failure stays UNKNOWN.

October 14, screenshot software checkpoint: independent peer `7881871a`
authenticates76 retained leaves and four actualx86 helper failure/cleanup
cases. Each exits1 without a PNG and preserves the protected directory and
sentinel. The helper matches the published Source bytes. Positive capture,
PNG pixel checks, ARM archive execution, accelerated desktop and M2 behavior
remain NOT RUN. Installed Hyprland's reported matching source path requires
DRM; exact binary/source build equivalence is unproven. No compositor was
launched on the user's desktop. A pinned Sway/wlroots software CI proposal
is being implemented in a separate lane; its image closure and execution
remain open.

October 14, kernel unit-fixture checkpoint: Root publishes test-only successor
`1ed00455`, packet `9307d5bb`, after independent composition `6001d7e7`.
The fixture includes the actual current_cache dependency needed by CLI help;
production workflow minimum10 and all runtime/stage code stay unchanged.
All212 tests in the four current kernel job suites pass, with zero failures,
errors or skips and empty owned fixture temp directories. The test and packet
are the only two changes;123 of124 Source rows remain held. Prior184/185
failure records remain unchanged. No additional native trial is dispatched.

Running native trial `38620355690` remains bound to preceding Source
`3bec0e2e` / packet `329078ba`. Local unit success does not establish its
native compile/cleanup result or any hardware acceptance.

October 14, CLI and kernel execution checkpoint: CLI Data `5f4f5086`
is the exact two-file child of Source `4c388cc7`, with Code `5d7e92e8` held.
External registration peer `405c6638` passes. Actual Code authentication and
Source workflow selection accept finalized plan `dd11f05c`, including all291
Source rows. Both variable readbacks precede execution-ref advancement;
one manual trial `38620204222` is queued. Prior cleanup failure remains open.

Kernel first-observed-child diagnostics pass peer `f31bf2fe`. Root publishes
Source `3bec0e2e`, packet `329078ba`, and verifies124 committed rows plus
packet after correcting the coordinator reader's schema assumption. Five
exact copies change four rows;120 runtime rows, stage and workflow remain held.
One trial `38620355690` is running. Focused review passes193 assertions;
the full suite remains184/185 with the identical baseline fixture failure.
Prior startup order/cause, new native compilation and cleanup acceptance
remain unestablished until retained terminal evidence is reviewed.

October 14, typed installer route checkpoint: Root publishes `3438c695`
after external `b57f1cd7` and adoption preparation `159dcc91`. Six existing
files change and two P0 variants are added. All27 selected committed rows,
including12 held keyless adapter targets, match reviewed hashes and modes.
The route uses the existing typed Session gate and original60-second entry;
its159-file logical P0 view remains separate from the physical original view.

Dedicated CI execution still requires the six-field Docker endpoint correction,
same-job image preparation, concrete Session admission and regenerated complete
Source packet. No P0, native26, ABI or hardware execution is established by
this publication. Full R1–R5 development remains active.

October 14, KSM statement diagnostic checkpoint: independent peer `65bc72f0`
passes both Python position modes. Root publishes Source `a90db716` and
packet `9a657738`, verifies all158 committed rows and the exact three-file
cascade, then dispatches trial `38618847844` once. The trial is queued.
Prior run `38609728294` still identifies only NATIVE_PROBE_BODY; its exact
statement, original cause and cleanup ownership remain unresolved.

The typed P0 Session correction passes external `b57f1cd7` at Source level.
Root is preparing its eight-file adoption against `530069b9`. The dedicated
CI packet has source review only; the concrete six-field Docker endpoint and
same-job prepared-image successor remain under implementation. Native P0,
26-case matrix, ABI, M2 and release acceptance remain open. CLI Data and
kernel first-observed-child diagnostics are under independent Root review.

October 14, diagnostic Source checkpoint: CLI producer-cleanup diagnostics
pass external `53dd39c0`. Root publishes `4c388cc7`, verifies291 committed
Source rows and four exact changes/287 held. The closed snapshot captures up
to64 existing entries as11 labels or UNKNOWN before private formatting;
Source-issued refusal identity preserves first cause and cleanup policy.
Actual prior private cause and uncertainty codes remain unknown. New two-file
Data/plan derivation is underway before a fresh manual-only trial.

Updater child diagnostics pass external `518bff4e`; Source `842a821e`
verifies90 runtime rows plus workflow. Stage `93b54ec3` and the two-copy
cascade preserve concrete RuntimeFailure and cleanup/deadline behavior.
Trial `38617063734` is queued. Native compilation, upgrade/removal, target
and release acceptance remain unproven.

The KSM native-probe statement diagnostic is frozen for external review.
The corrected typed P0 route and dedicated CI driver are being reviewed;
preparation identified a driver/transport socket-identity schema mismatch
for correction in a new packet. A same-job image preparation route is under
implementation, before the immutable60-second P0 stage. No P0 or native26
execution is claimed. Existing library38610255544 remains live; Pair, Zsh
and composed successors remain queued. Full R1–R5 development continues.


October 14, published corrections checkpoint: kernel alignment correction
`71f05ab5` passes external `2958a276` and125 committed Source/self rows.
Trial `38612473905` fails during parallel acquisition/producer startup before
compilation; completion `fdeb36c0` retains cleanup FAIL and unverified owned
absence, with bounded daemon preservation PASS separately. The verifier
correction was not exercised. Startup review continues.

Composed image diagnostic repair `1794d046` passes peer `ddbc9aa0`; its Data
`bb5f6dee` is the exact two-file Source child. Both actual parsers accept plan
`ae94875d`; variable readbacks precede execution publication. Trial
`38614475627` is queued. Actual prior IMAGE_CONFIG operands remain unknown.

Pair plan `442b43fe` binds Source `0e886ca6`; Zsh plan `caf0b177` binds
`ce7af5ef`. Both registrations verify exact variable readbacks before their
fast-forwards. Trials `38611783071` and `38611787402` are queued behind running
library `38610255544`. Corrected native acceptance remains open.

Keyless runtime Source `530069b9` is published after external `7ff86cb0`
accepts the selected early-cancellation successor. Root verifies12 new
adapter targets and3 held P0 targets. No runtime actor is executed. The
separate P0 route still needs its existing typed Session gate and concrete
CI binding. Native26, full signer API, installation, M2, performance and
maintained-release acceptance remain open under the complete R1–R5 goal.


October 14, implementation and execution checkpoint: Pair dictionary-result
correction is published as `0e886ca6`, Zsh as `ce7af5ef`, after independent
peer `ba37f3a5`. Each exact three-copy cascade and every Source/Data Git row
are verified. Separate execution registrations are being derived; no corrected
native result is claimed.

KSM TypeError-callsite diagnostics pass peer `e53059bb` and are published as
`a5d7e178`, packet `1cfc8ffc`. Trial `38609728294` fails; completion `236f152e`
retains the new callsite `NATIVE_PROBE_BODY`. This identifies a propagation
frame, not the exact expression or an earlier cause. Cleanup ownership remains
uncertain. Concrete probe/wrapper review continues.

Library Data `2c9d61b7` is the exact two-file child of Source `32dea27b`;
Code `9ea7c81a` stays distinct. Both actual workflow and bootstrap parsers
accept the finalized plan `24fa555a`. Root verifies variable readbacks before
advancing the execution ref, then observes native run `38610255544` running.
Separate static run `38610255427` passes. Draft PR25 exposes the Data change;
materialization/new native builds remain unaccepted until terminal evidence.

Kernel declared-alignment correction, composed IMAGE_CONFIG serializer repair
and the concrete P0 runtime route remain under bounded external review. P0
review found a direct-callable Session-type gap; its new narrow successor is
being prepared while the old packet stays frozen. No signer runtime, native
26-case matrix or M2 hardware acceptance is claimed. Full R1–R5 remains active.


October 14, reviewed implementation checkpoint: canonical library gzip correction
is published as Source `32dea27b`, packet `f425308c`, in draft PR24 after
independent peer `c84c8a5e`. All 278 committed Source hashes/modes are verified.
The 27 strict outputs, identical normalized tar content and existing caps are
preserved; successor Data/plan derivation is underway before a fresh ARM run.

Screenshot peer `6c02fc04` authenticates the current candidate's eight builds
and four byte comparisons, including desktop `0.1.0-2`, its 12740-byte archive
`0b22b778` and exact installed helper. Both builds ran in distinct recorded
containers on the same ARM CI job. Independent-machine reproducibility,
real capture, installation and M2 acceptance remain untested.

Kernel run `38583969397` is now terminal FAIL. Completion `253db2ed` retains
schema4 evidence: KERNEL naturally returned 0, followed by DATA_REFUSAL at
OUTPUTS / VERIFY_OUTPUTS / CHECK_001. Baseline worker returns 1; candidate is
NOT RUN. Cleanup, owned absence and daemon preservation pass separately.
The new exact predicate is under Source review; earlier causes stay unknown.

Concrete P0 Session routing and keyless early-cancellation successors are
sealed for external review. Dedicated CI entry preparation continues;
no signer runtime or native 26-case matrix is executed. Pair/Zsh dictionary
result correction and KSM callsite diagnostics are independently reviewed
before publication. The composed IMAGE_CONFIG diagnostic proposal needs a
new serializer correction after a concrete external key-type countermodel;
the blocked proposal is preserved, with no native cause inferred.


October 14, current native checkpoint (14:55 UTC): screenshot candidate run
`38571648129`, Source `92a3f061`, completes CI successfully. Completion
`05cd9495` retains two public frames; independent candidate/build review is
in progress. This is not real screenshot execution or M2 acceptance.

Library run `38560924092` fails strict JBIG output length validation:
expected 109999 bytes, observed 109846. No digest comparison or new library
build is reached. Identical-tar codec countermodels motivate a canonical
gzip correction under review; the native codec remains unknown. KSM run
`38561918431` reports TypeError at NATIVE_ENTRY, zero RPC and uncertain
cleanup. Its precise operand remains unknown; Source review continues.

Updater `38564810704`, composed `38566446597`, Pair `38572139973` and Zsh
`38573732820` have completed with failure; exact logs and metadata are
retained and assigned independent review. No old failure cause is transferred.
Kernel schema4 propagation correction passes peer `989652b4`, is published
as Source `a311de55` with packet `ef624894`, and trial `38583969397` is running.
FDK `38574961503` now fails at SMOKE_COMPILE with closed COMMAND_NONZERO
exit 1; producer PASS and build-2/comparison NOT RUN remain separate. CLI
`38578019953` now fails with initial VALUE_ERROR/PRODUCER_EXIT code 1 and
uncertain cleanup; materialization and new builds remain NOT RUN. Both exact
terminal records are retained for independent review.

Installer P0 entry and its two reviewed caller/bridge corrections are published
as Source `92d00c29` on the isolated runtime branch, draft PR23. The original
60-second contract and live SDK Session requirement are preserved. Routing
remains under implementation. External runtime peer `a84e08c5` passes P0
independently and finds one keyless early-cancellation classification defect;
a corrective successor is underway. No signer runtime or 26-case native
matrix is executed. Full R1–R5/M5–M9/A01–A15 development remains active.







October 14, signer static native PASS: binding `9bdab12b` selects receiver
`ea698489` and canonical manifest `51e44860`. Root verifies22 committed rows
and R/R/H/H correspondence. Trial `38564473706` passes all six compiler and
readelf/objdump commands with natural zero and descendant absence. Twelve
capture hashes and both output hashes join exactly. The3888-byte shim passes
static ELF structure checks; the2056-byte ABI object records116 compiled-header
values. Completion `23c1cb99` retains the digest-verified16-member artifact.
No output or GPG is executed. Compiled instruction review, runtime
kernel/loader behavior, full signer API and M2 acceptance remain open. FD
retirement passes; directories remain retained. The prior refusal's cause
remains unknown.

Composed Data `33e44387` is the exact two-file child of Source `993487a4`.
Plan `ceb0ac0c` passes the existing parser on real Code/Source/Data identities;
variable readbacks and execution-ref publication match. Trial `38566446597`
is queued. Pair plan `f6bc5ef8` likewise binds Source `392be2f2` and held Data
`ea1db6b5`; trial `38564566992` is queued. Updater's exact fixed-root-owned
/tmp01777 exception passes peer `8e888f85`; Source `2ce49ea1` preserves other
custody checks and all90 Source/workflow rows. Trial `38564810704` is queued.

Zsh clock-expression correction passes peer `ed1f1e82`; Root publishes
`398d05c2`, verifies66 committed Source rows and two held Data rows, and keeps
registration pending while later clock/module assumptions are audited. No
native acceptance is transferred from Pair. Screenshot current-input recovery
and kernel OUTPUTS diagnostics remain under independent review. Library
`38560924092` is running; KSM `38561918431` waits behind it. Full R1–R5/M5–M9
and A01–A15 development remains active.

October 14, Source and registration checkpoint: signer refusal diagnostics pass
independent peer `40088148`; Root publishes receiver `ea698489`, verifies all
13 Source rows plus manifest `51e44860`, and prepares the separate actual
workflow binding. Compiled outputs remain unexecuted and the previous work
refusal predicate remains unknown.

Library successor Data `362c4701` has exact Source parent `9f37d693` and only
two changed JSON files. Root verifies the 278 Source rows and distinct Code,
Source and Data identities, registers plan `fbe4705e` with exact readbacks,
then advances the existing execution ref. Trial `38560924092` is running;
its materialization and four new builds/two comparisons remain unaccepted.

Composed first-cause correction `576d64fe` and peer `b250f050` remain separate
from the diagnostic layer. Review found and corrected a policy-code naming
mismatch; successor `f482f6bb` passes peer `1957dcda`. Root publishes cumulative
Source `993487a4`, verifies all 271 captured files/266 Source rows and 14 held
metadata pins, and prepares a new Source-bound Data/plan before execution.
The historical later RUN failure remains unidentified.

Pair builtin-module handling passes peer `5c54ded7` and 35 independent controls.
Root publishes `392be2f2`, verifies 54 committed Source rows plus the regenerated
55-row lock `77bb28c0`, and separately authenticates both selected Data blobs
from `ea1db6b5`. File-backed behavior and required runtime provenance are held;
actual builtin metadata remains unobserved. Registration is pending.

KSM natural-return-1 route diagnostics pass peer `c07d5782`; Root publishes
`4f9bbf3c`, verifies 158 rows and packet `d7ba5558`, and queues trial
`38561918431` behind the library job. It distinguishes bounded route facts
while preserving natural return 1, original propagation and the old125 handler.
The earlier route, cause and ownership-uncertain cleanup remain unresolved.

Screenshot candidate trial `38559035451` passes bootstrap tests/probe, then
stops during acquisition: 493 inputs pass and eight package/signature URLs
return HTTP404 (Jbigkit, Libtiff, Vim and Vim-runtime). Native compilation is
NOT RUN. Completion `17ae04bb` retains both frames. A future build route is
being prepared using the reviewed current signed inputs and recovered seed
files; the old input snapshot and earlier pkgrel1 build evidence stay historical.

October 14, latest terminal checkpoint: updater's two recipe-pin correction
passes peer `f4adefca`, is published as `fa98df53`, and verifies all 90 Source
rows plus workflow. Trial `38558154233` now passes materialization of all 167
registry sources with exact regenerated archive hashes, then fails a later
ValueError before compilation. Cleanup/recovery pass; daemon disposal is
unverified. Completion `bbcfc6be` retains three metadata frames.

FDK corrected trial `38557145714` passes preflight, original 501-input producer,
eight builds/four comparisons and producer cleanup, then fails FDK build-1.
CONTAINER_ATTACH returns 4; the bound inner record has 397 compiler attempts
and natural returns, first natural return 0 and no first-failure record. The
exact builder cause remains unknown; build-2 and comparison are NOT RUN.
Completion `0d46686c` retains only public JSON metadata. Binary publication
remains NOT RUN; owned absence checks have separate scopes.

KSM corrected trial `38556638406` fails with natural/reaped producer code 1
and zero RPC; the reason is unexported and cleanup remains ownership-uncertain.
Completion `28f9ced7` is retained. No earlier cause is backfilled.

Library failure-only output diagnostics pass independent peer `e3943f5b`.
Root publishes `9f37d693`, verifies all 283 captured Source files/278 packet
rows, and retains all 27 expected output pins. Draft PR22 exposes this
successor; concrete Root-plan/Data registration is being prepared before a
fresh native trial. Composed first-cause and diagnostic proposals remain
separately under independent review. Parallel Source work remains actionable.

October 14, native successor checkpoint: source-delivery and screenshot changes
are published in `c53ad695` and `4c9b1a1`, respectively, on integration PR6.
KSM optional-import compatibility passes independent peer `1afd165e` with 103
controls. Root publishes `b5c42de9`, verifies all 158 Source rows and packet
`f8ae24f1`, and queues exact-Source trial `38556638406` (draft PR21). The
allowlist is held; denied imports are never delegated. The earlier rejected
root remains unknown, so no native cause or repair is claimed.

FDK's two workflow consumers expected 133 files against the unchanged
137-file packet. Minimal correction passes independent peer `3e69ab4e` and
18 controls; Root publishes `d82cfb5f` and proves all 137 Source rows, packet
`2d56b66f` and the workflow. Fresh trial `38557145714` starts on exact Source.
The earlier preflight's first runtime predicate remains unknown. This job
permits private build validation and bounded metadata, not binary publication.

All four latest kernel/Pair/Zsh/CLI terminal records now authenticate. Kernel
`38547085071` reaches inner KERNEL natural return 0, then refuses OUTPUTS with
DATA_REFUSAL. Its baseline worker returns 1; candidate remains NOT RUN and
cleanup/daemon preservation pass separately. Output acceptance remains open.
Pair `38546975061` records an AttributeError at `math.__file__` in its runtime
observer. Zsh `38546975187` records `native-original-guard-binding`, with the
failed conjunct unknown. Both retain empty result JSON, which establishes no
cleanup pass. CLI `38547424804` reports OWNED_CLEANUP_UNCERTAIN with every work
phase NOT RUN; its initial underlying cause remains unknown.

Parallel work continues on the proven Pair observer defect, updater's two
stale recipe-lock pins, screenshot native-build inputs, and bounded diagnostics
for kernel outputs, library output proof, Zsh, CLI, signer and composed
preflight. No full-release or hardware acceptance is inferred.

October 14, source-delivery and screenshot integration: Root publishes source
associations and recipient lookup/export in `c53ad695`, following author
`61e039ee` and independent peer `7051b4be`. All 104 canonical helper, release
and client tests pass with synthetic packages and temporary TEST GPG keys
outside the checkout. This proves the signed association/export behavior;
actual package source completeness, licensed public delivery and hardware
acceptance remain open.

The six-file screenshot candidate `0.1.0-2` passes author `0349de6e` and
independent peer `eb04404c` (72 focused controls). Root adopts the exact files
and verifies eight source checksums, syntax, all 36 default bindings, two
optional capture bindings, and eight isolated staged files. Existing workspace
shortcuts are preserved. Real compositor capture, the updated native archive,
installation/removal and both M2 Air sizes remain NOT RUN. The inventory now
keeps the earlier pkgrel1 native PASS as historical evidence rather than
assigning it to this candidate; grim/slurp provider closure remains open.

The latest kernel `38547085071`, Pair `38546975061`, Zsh `38546975187` and
library CLI `38547424804` runs are terminal FAIL and their exact evidence is
being retained. Signer `38551373141` fails before a natural shim result is
established; ABI compilation and inspection remain NOT RUN. Managed libraries
`38533034332` fail the materializer's existing derived-output length/hash
check; the specific output remains unidentified. Composed `38536780960`
passes seven initial components but fails a later preflight RUN boundary.
FDK `38537043450` fails preflight, updater `38537248373` fails launching its
data worker, and KSM `38541805780` retains GRAPH_LOAD/producer-unbound-import
with the rejected module root unknown. Separate bounded diagnostics and
proven Source corrections remain active; these failures do not yet require
physical M2 access. Full R1–R5/M5–M9/A01–A15 development continues.

October 14, 10:30 UTC: actual signer failure review `a8e0acac` and peer
`03a938ea` authenticate against all retained captures. The selected ARM-header
audit finds one mismatch among 116 ABI expectations: `O_NOFOLLOW` is 32768.
Minimal correction `b70d9854` and independent peer `1fb1210c` preserve all other
115 expectations and eleven receiver bodies. Root publishes receiver
`06557a7f`, verifies its thirteen files plus manifest against Git, and retains
canonical manifest `889347ea`. A concrete workflow/helper binding to this actual
ancestor is being prepared before retry. Corrected ABI compilation remains
NOT RUN; no output execution or numeric CPython flag observation is claimed.

The full-port software gap audit identifies two actionable M5/M6 behaviors
outside the current native corrections: explicitly invoked screenshot-to-file,
and package-to-recipient-source/notices lookup/export using the existing signed
release files. Desktop owns the screenshot proposal; Tools owns the connected
source-delivery proposal. Both work in isolated proposal namespaces, preserving
queued Source and shared manifests. Missing screenshot dependencies, real
capture, source completeness/publication, package lifecycle and full-port
acceptance remain open. Active kernel `38547085071` and library `38533034332`
trials and the queued package/installer/CLI work remain under observation.

October 14, 10:10 UTC: the minimal Asahi in-tree DTC correction passes author
`59d35faf` and independent peer `3daedacf`. Root publishes Source `1ab4269c`,
verifies all 124 packet rows plus packet `a36ce52b`, and launches native kernel
trial `38547085071`. Its result is pending; older failures remain unchanged.

Root adopts the reviewed Pair7/Zsh3 corrections and proves both committed
Source closures with the original Data rows held. Sources `b434bfdc` and
`b5ab31d2`, plans `1fccf9fc` and `9af3e105`, and exact variable readbacks are
published before atomic execution-ref pushes. Automatically triggered Pair
`38546975061` and Zsh `38546975187` are queued. No duplicate manual trials or
actual capacity claims are made.

The simpler CLI registered-route successor passes independent peer `6c48b4a8`.
Root authenticates 351 author leaves/22 inputs and 694 peer artifacts/733 inputs,
then creates actual Code `5d7e92e8`, Source `8871d325` and Data `3ce9bb70` from
verified base `1294a456`. All 1/291/2 selected Git blobs/modes and the parent
chain pass. External plan `a9b23f36` is registered with exact readbacks; native
trial `38547424804` is queued on the registered workflow. Draft
[PR20](https://github.com/Gabriel-Kahen/cachy-asahi/pull/20) exposes the isolated
implementation. Previously observed ARM tool pins must still reauthenticate in
that fresh job. Library builds, runtime, installation and hardware acceptance
remain pending. Full R1–R5/M5–M9/A01–A15 work remains active.

October 14, 10:00 UTC: concrete signer binding `a71981bd` passes independent
peer `c337e9fe`. Root publishes Source `377885cf`, verifies seven replacements
and fifteen unchanged receiver/workspace/manifest paths, then starts trial
`38545639655`. It completes FAIL, retained under completion `2604a075`.
The shim compiler returns 0 and produces a retained 3,888-byte unexecuted
output. The ABI compiler returns 1 at its `O_NOFOLLOW == 0x20000` assertion;
the four later inspection commands remain NOT RUN. Owned FD retirement passes,
directories remain retained, and no output or GPG is executed. A minimal
ARM-definition correction is being reviewed against the exact selected headers.

Kernel actual review `107ff545` confirms the new bounded DTC diagnostic and
pinned Asahi float-cell source trace. Minimal proposal `59d35faf` removes only
the explicit system-DTC argument, restoring the pinned tree's compiler; its
six-file hash cascade has an independent internal peer and is receiving Root
review. Platform source/configuration, compiler guards and deadlines are held.
No corrected native kernel compilation is yet established.

Pair/checker-root capacity successor `bc52cbd2` passes independent peer
`96ef5de6`, including exact seven/three copy maps, full 55/67 Source closures,
120 targeted replay outcomes and bounded independent ownership/planner controls.
Root integration and fresh native preflight/counters remain pending. The simpler
library registered-route successor `620c33cf` is sealed and under independent
review. Root verifies live workflow ID 382820833, retains the actual proposed-base
workflow, and prepares an isolated checkout; Code/Source/Data publication and
native execution remain pending.

October 14, 09:32 UTC: the ioctl include correction passes author `7ea55b9c`
and independent peer `4d106e48`. Root publishes receiver Source `1e8fd873`,
verifying its thirteen rows: two C files changed and eleven held. Canonical
manifest is `c9e7bb8f`. A separate concrete workflow/helper binding must now
reference this actual ancestor before the next six-command ARM trial. The
historical GCC failure is unchanged; no new compile or signing grant is claimed.

KSM refusal-record retention passes author `6fe0a948` and peer `8b2b5861`.
Root publishes Source `154b05d9`, verifies all 158 packet rows and packet
`25479e32`, and queues trial `38541805780`. This bounded decoder retains the
existing refusal record when stderr follows it. It does not establish the old
producer's exact cause or turn its ownership-uncertain cleanup into a pass.

Kernel compiler diagnostic successor `ba061dd0` passes independent peer
`bf790241`. Root publishes Source `bcdfa7a8`, verifies all 124 Source rows plus
packet `bdbca8de`, and starts native trial `38543396235`. It completes FAIL,
retained under completion `0c383957`. The baseline KERNEL return is 2; the new
bounded diagnostic exposes `apple/t8103.dtsi:498` float-cell syntax failure.
Producer/probe/provision and cleanup pass; candidate remains NOT RUN. Root finds
that the worker overrides Asahi's in-tree DTC with `/usr/bin/dtc`, while the
pinned in-tree grammar supports the floating literal at that line. Independent
actual review and a minimal tool-selection correction are in progress. The
historical unexported compiler cause remains unknown, and the earlier diagnostic
proposal remains blocked. Updater optional dependency
diagnostic `f1ddae68` passes peer `7719a603`. Root publishes future Source
`ddc83502` and verifies all 90 committed Source rows. No new updater trial is
launched; queued `38537248373` remains bound to its original `e3cab74a` and is
not inferred to have failed.

The simpler library runnable proposal passes bounded custody and business
controls, but its independent review holds the launch route until it uses a
registered workflow. The Pair checker-root/capacity successor is sealed for
independent review. Its future Pair policy uses 262144 calls and 786432 cumulative
grants with the original deadlines and acceptance gates; these Source controls
are not a native capacity measurement. Library `38533034332` remains active;
composed, FDK, updater and KSM retries remain queued. Full R1–R5/M5–M9/A01–A15
acceptance stays open.

October 14, 08:47 UTC: compiler registration successor `24220aa9` passes
peer `5b2d774f`; Root verifies four replacements and one guarded deletion and
publishes Source `6f87524e` using the existing registered observer workflow.
Native run `38537449008` completes FAIL, retained under completion `7601cf1f`.
The actual first GCC command returns 1: the shim's ioctl ABI assertions fail to
expand their macros. Later commands remain NOT RUN, outputs and GPG are
unexecuted, owned FD retirement passes and directory effects remain retained.
The existing selected Linux UAPI headers contain the required ioctl definitions;
a minimal include correction is being implemented, with capture hash roles
reviewed separately.

Current FDK recovery passes author `7d30866b` and peer `a5cc1e33`. Root publishes
Source `ff13575d`, verifies 137 packet rows plus packet `2d56b66f`, and dispatches
native trial `38537043450`. Updater recovery passes author `79f44dfe` and peer
`4c4d61af`; Root publishes Source `e3cab74a`, verifies all 90 Source files and
64+8 ready pins, and dispatches `38537248373`. Both trials are pending under the
shared queue. Draft [PR18](https://github.com/Gabriel-Kahen/cachy-asahi/pull/18)
and [PR19](https://github.com/Gabriel-Kahen/cachy-asahi/pull/19) expose the reviewed
changes. No new FDK/Rust native compilation or publication acceptance is claimed.

Installer diagnostic successor `eec668df` passes its peer checks and twelve
additional Root actual-definition cancellation controls. Root normalizes one
extra EOF newline in the test file with identical AST, rebinds only its packet
and workflow hashes, then verifies all 271 committed Source rows. Published
Source `014a3699` / Data `7ce78225` / plan `deb07ca7` is registered with exact
readbacks. Push-triggered retry `38536780960` is pending behind the active library
run `38533034332`. The failed predecessor and unknown historical handoff predicates
remain unchanged. Full R1–R5/M5–M9/A01–A15 acceptance remains open.

October 14, compiler follow-up: runnable six-command Source `81e6b632` is
published in draft PR16. Root authenticates author `95b9172e` and peer `7586cec0`,
verifies all seven new copies, and checks the frozen receiver/helpers are unchanged.
The manual dispatch returns HTTP 404 because the new workflow path is unregistered;
no compiler job starts. A minimal successor is using the existing registered
observer workflow path without changing the six-command runtime contract.

The simpler library baseline/driver components `379ec204` are sealed, with
158 focused controls and ten inert integration checks; Root authenticates their
forty indexed leaves and guide. Independent review identifies a live-custody
concern for an unreaped child. The runnable workflow and correction remain in
development, with no new native actor. Installer boundary diagnostic `e36cbbff`
is held: Root's actual-definition trace control reproduces swallowed secondary
cancellation. A successor preserves the original cause and sticky cancellation.

Kernel recovery/parser work is now visible in
[draft PR17](https://github.com/Gabriel-Kahen/cachy-asahi/pull/17). Source review
and actual failure evidence remain separate from native compilation, runtime
and performance acceptance. All required full-port gates remain unfinished.

October 14, 08:09 UTC: kernel `38531276470` completes FAIL, retained under
completion `afae9cd2`. The baseline progresses past configuration handling to
KERNEL, whose natural return is 2; the exact compiler error is unexported.
Candidate remains NOT RUN. Producer/probe/provision and cleanup pass. A bounded
diagnostic from existing captured compiler output is being implemented.

Pair `38531570132` and Zsh `38531574136` complete FAIL with retained completions
`912bf7cd` and `3c9aef5e`. Both acquire all 501 inputs successfully, then refuse
at native-shallow-checker-root before package builds. Their result members are
empty. The exact failed owner/group/mode bit is unknown; a correction is being
implemented to use positively owned job directories instead of assuming runner
home metadata. KSM `38531573783` completes FAIL, completion `9538c9b3`, with
producer child return 125 and zero recorded producer RPCs. Cleanup remains FAIL
with ownership uncertainty despite positive container/image absence and daemon
preservation; its precise producer failure is under review.

Library diagnostic successor `a4c4945c` passes peer `e564ee1a`. Root adopts only
three files from the admitted baseline, verifies all 278 packet Source rows,
and publishes Source `e2879768` / Data `39680f26` / unchanged Code `9ea7c81a`.
Plan `fd03e637` passes the existing selectors and exact variable readbacks.
Push-triggered native run `38533034332` is active. A redundant manual dispatch
`38533034570` was cancelled; it is not a separate validation result. Updater and
FDK current-baseline adaptations proceed in parallel with the runnable compiler
job, library CLI and installer-handoff diagnostics. Full acceptance stays open.

October 14, 07:56 UTC: the grammar correction passes independent peer
`247dfeca` and is published as Source `2b0cc2ac`, packet `7c91cc1e`. All 124
committed Source rows and the packet match. Fresh native kernel run `38531276470`
passes checkout and preflight and is executing; compilation is not yet accepted.

Shared cache correction `bf154021` passes independent peer `bd77f58e`. Root
adopts exact Pair/Zsh/KSM 2/2/5 copy maps and verifies all 55/67/158 Source/Data
rows plus their locks. Published Sources are Pair `721cbed2`, Zsh `1542ffb5`,
and KSM `5efd3e00`. Pair plan `ffe08935` and Zsh plan `2327bacc` are registered
with exact readbacks before execution-ref pushes. Pair run `38531570132` is
active; Zsh `38531574136` and KSM `38531573783` are queued under queue:max.
Native intake, build/comparison and cleanup results remain pending.

Compiler bootstrap/helpers are published as `1044f34c` in draft PR16 after
Root authenticates author `e6af1072` and peer `efa636be`. All sixteen committed
source files match; the original thirteen receiver files are unchanged. Static
CI passes. The branch still has no runnable workflow or active compile grants;
the concrete job binding is in development.

October 14, current follow-up: composed run `38526888627` completes FAIL with
Root completion `5a73a9df`. All seven initial integration stages, including
repository, pass; owned image cleanup passes. The subsequent repository handoff
and phase publication fail, and the original failing predicate remains unknown.
Independent actual review is tracing that boundary. This is integration progress,
not acceptance of the full composed operation.

Kernel diagnostic Source `2fac02d7` completes run `38527999980` FAIL, retained
under completion `e647d553`. CONFIG returns zero and the diagnostic localizes
refusal to BEFORE_CONFIG_PARSE. A pure check of the exact pinned configuration
finds that the selected parser rejects twelve legitimate mixed-case Kconfig
symbols. Grammar-only correction `94e82b3e` preserves symbol case and all guards;
independent review and a fresh native attempt remain required. The pure source
reproducer does not attest the unexported native configuration contents.

The shared Pair/Zsh/KSM cache correction `bf154021` is sealed and undergoing
independent review before these lanes restart. Library materialize diagnostic
`d9b294c4` is held: peer `cfc4349a` demonstrates swallowed secondary cancellation;
a successor is being implemented. The compile bootstrap/workspace proposal
`e6af1072` is sealed, and a concrete runnable job binding is being implemented.
No new compilation, signing, installation or M2 acceptance is claimed.

October 14, 07:19 UTC: library run `38510908030` and Topmem/Fish run
`38511520135` complete FAIL. Library completion `4d82b3ad` retains original
producer build/comparison PASS and the scoped library materialize failure;
four new library builds and comparisons remain NOT RUN, with cleanup PASS.
The exact materializer clause is unexported. Pair completion `db0a3de3` retains
an empty result member and the precise missing Context.replace call followed by
missing Context.unlink during error cleanup. A shared bounded bridge correction
is being implemented for pair, Zsh and KSM full intake; these lanes remain held.

The queue-only future Sources are published after peer `548490a3` and metadata
correction `b9ff0e8c`. All committed byte/mode rows pass. Composed Source
`fe69f03e` / administrative Data `c2a08b69` / plan `f55819ec` is registered with
exact readbacks and pushed once to its execution ref after the old leases finish.
Native run `38526888627` is active under queue:max. Library future Source
`242612c6` / Data `7b218109` and the other future lane plans remain separately
prepared; current failed runs are not reclassified.

Kernel actual `38523856782` completes FAIL with completion `c6d6d0cc`.
Acquisition, original producer, probe and provisioning pass; baseline's CONFIG
command returns zero, then its verified inner diagnostic reports CONFIG_DELTA
DATA_REFUSAL. Candidate remains NOT RUN and compilation unaccepted. Cleanup,
baseline preservation and owned absence pass. The exact configuration clause
and keys remain unknown; a failure-only diagnostic is frozen for independent
review. No private build logs or configuration were uploaded.

Compiler receiver Source `0e5d40ab` is published in
[draft PR16](https://github.com/Gabriel-Kahen/cachy-asahi/pull/16), with all thirteen
Source files and manifest verified after independent peer `11a3f79f` passes
eighteen fresh controls. The source remains inactive while concrete trusted
selection and factory/workspace bindings are implemented. Full R1–R5/M5–M9,
source correspondence, installation/recovery, measurements and both M2 Air sizes
remain unfinished; the development goal stays ACTIVE.

October 14, 06:45 UTC: kernel recovery Source `56bd0ab9` is published after
independent peer `437378f3` authenticates the seventeen-copy successor and passes
seventeen focused groups. Root verifies all 124 committed Source rows plus
packet `d4c440a4`. Native ARM run `38523856782` passes checkout and packet/host
preflight, then enters the original producer and kernel experiment. Its separate
kernel concurrency group preserves the library run and pending Topmem/Fish job.
No kernel compilation, runtime, target performance or M2 result is inferred.

The complete passive signer observation passes independent actual gate review
`30b16970`, including seventeen semantic corruption controls. Root authenticates
three leaves, the guide and 24 retained inputs, and accepts passive data under
receipt `9f46925b`. Selection and execution grants remain false. Receiver adapter
`65454e33` changes only three Source13 bodies, passes thirty focused cases and
preserves factories, six commands and original deadlines; independent review and
concrete trusted compile binding remain pending.

A minimal future native queue policy proposal preserves cancel/deadline/actor
gates while allowing multiple pending jobs. Mixed old/new policy behavior is
undocumented, so activation remains held until the existing pending pair starts.
All R1–R5/M5–M9, complete source correspondence, installation/recovery, measured
performance and both M2 Air sizes remain required. Development remains ACTIVE.

October 14, 06:25 UTC: the narrow empty-stdlib correction is published as
Source `1294a456`, after Root authenticates author `b7ea54d4`, independent
peer `8feab6ff`, all ten committed byte/mode rows and the scoped source changes.
Fresh passive ARM observation `38521634535` completes SUCCESS with natural
observer exit zero. Root completion `ff0b20d3` retains the exact four files and
verified artifact digest; independent full-envelope gate review is active.
The result is complete observation data, with selection, compilation and
execution grants still false. The compile receiver adapter is being implemented
against the complete provenance envelope and fresh same-job identity rules.

The six-output plan `370e8a91` is registered in separate future-lane variables
with exact readbacks; both static CI runs pass. Its execution ref remains held
while Topmem/Fish `38511520135` is pending behind library `38510908030`.
The finite kernel current-baseline adapter is under implementation, preserving
the existing actual dependency gate and original experiment deadlines. A smaller
library CLI is separately being implemented from reviewed plan `f4cd23cb`, with
explicit owned launch/log/cleanup work; it does not change the current run.
The bounded current systemd/pacman source search `a5c0a28e` finds no exact recipe
match. Full source correspondence, installation, R1–R5/M5–M9, measurements and
both-size M2 acceptance remain open; the development goal stays ACTIVE.

October 14, 06:04 UTC: the six-output Topmem/Fish/Zsh successor is published
as Source `e0cba793` on a nonexecution review branch in
[draft PR15](https://github.com/Gabriel-Kahen/cachy-asahi/pull/15).
Independent successor peer `56ec8053` passes fourteen focused controls and
resolves the two guardian counts without changing the remaining gates. Root
verifies all 67 committed Source/Data byte/mode rows and derives plan `370e8a91`.
The plan is not registered and the execution ref is not pushed; the existing
Topmem/Fish pending run remains preserved. Native six-output builds and
whole-operation capacity remain unverified.

Independent signer actual review `9988ff6f` authenticates four leaves, its guide
and 22 retained inputs, passing 51 checks including five corruption controls.
The current before-open stat proves size zero is the only failed predicate;
held content and the prior run's unrecorded condition remain unknown. A narrow
empty-stdlib sampling correction is in development. Full installation,
R1–R5/M5–M9, performance and both M2 Air sizes remain incomplete.

October 14, 05:57 UTC: signer diagnostic Source `896c0182` completes actual
`38518739152` FAIL with Root completion `c84e44bb`. Its same-observation stat
record proves the sole failed condition is an empty Python standard-library
`urllib/__init__.py` (regular 0644, root-owned, one link, zero bytes). Independent
actual review and a narrow role-aware sampling correction are in progress.
Compilation and signing remain unaccepted.

KSM recovery Source `db448727` is published after independent peer `53eb4ec7`
and verification of all 158 committed packet rows plus the packet. The workflow
is dispatch-only; no new native KSM result is claimed. Dispatch waits behind
library run `38510908030` and pending Topmem/Fish run `38511520135`.

Independent six-output review `daa57c2b` authenticates the proposal and passes
nine focused control groups, but finds two cleanup guardian counts still require
five containers while the closed roles require seven. A separate successor is
correcting those two checks and their hash cascade. The proposal remains
unadmitted; the active pair registration and job are unchanged. Full R1–R5/M5–M9,
installation, measured performance and both-size M2 acceptance remain open.

October 14, 05:35 UTC: the narrow package-field correction is published as
Source `a1762efe`, with all ten committed copy rows verified and independent
peer `0906a82d` passing 79 assertions. Actual observation `38515440452` advances
through the package parser, then fails the `file` guard while sampling
`/usr/lib/python3.12/urllib/__init__.py`. Root completion `4eea6b75` and peer
`cba78660` retain the precise path and sixteen-inventory/2,029-sample progress.
The failing stat condition is not recorded; empty-file attribution is unconfirmed.
A bounded same-observation diagnostic is in development. Compilation and signing
remain unaccepted.

The isolated KSM recovery proposal `a6c34ebd` is implemented: 158 selected Source
files and eighteen copy rows rebind the current 341/501 baseline and add the
registered cache handoff before the original producer. Root authenticates all
34 support leaves; independent integration review is active. Original 8-build/
4-comparison, lifecycle, cleanup, mutation and 8,460-second gates are retained;
no new KSM native result is claimed.

The three-package/six-output proposal has corrected private capacity arithmetic
and explicit coupled work/grant budgets after review found stale four-output
checks and insufficient grant capacity. These changes are unadmitted Source
preparation only: the active Topmem/Fish limits, job and registration remain
unchanged. Focused controls and full Source review precede any activation.
Library run `38510908030` remains live and Topmem/Fish `38511520135` pending;
no new shared-group dispatch replaces that pending run. Full R1–R5/M5–M9 and
M2 hardware acceptance remain incomplete, with the development goal ACTIVE.

October 14, 04:58 UTC: Root adopts the five-file capability correction after
independent peer `2f164000` passes 26 causal cases, preserves all 182 existing
methods and authenticates the exact cascade. Source `eaacbb42` proves all 271
committed byte/mode rows; Data `d7356a2f`, selection `93d2ce21` and proposed plan
`1b1f32e0` pass the unchanged bootstrap's selection validator and are published
on the review branch. The operational execution ref/variables still select
Source `5ea0987c`: the composed retry waits for queued Topmem/Fish run
`38511520135` to start, preserving that pending job. Library run `38510908030`
remains active. Neither result is inferred.

Signer diagnostic Source `3182cd2c` passes all ten committed copy rows after
independent peer `2c083505` passes 41 causal cases and 193 assertions. Actual
run `38513825858` completes FAIL with Root completion `0fb21628`. Its exact
untruncated diagnostic identifies adduser's ten-byte `Conffiles:` header, which
has no space after its colon; the parser requires a literal colon-space delimiter.
The header bytes and SHA are verified. The full field value and continuations
were not exported. A narrow metadata-parser correction is assigned; the prior
run's unrecorded field remains unknown. No compiler or signing grant is issued.

The finite six-output Topmem/Fish/Zsh proposal remains under implementation.
Its source preflight exceeds the previous four-output backend-call budget;
optimization and explicit bounded-budget evidence are being prepared. The active
pair's limits and job remain unchanged, and no six-output native pass is claimed.
Full installation, M2 hardware, performance and R1–R5/M5–M9 remain incomplete.

October 14, 04:41 UTC: independent actual12 review `9cfa0a0f` authenticates
42 leaves and its guide, all 22 retained completion files, and thirteen frames.
It proves the repository failure is the exact bare-name CapAdd equality clause,
which rejects the six recognized Docker `CAP_`-prefixed names. The top native-hook
ValueError callsite remains unknown; outer installer callback entry and nested
repository callback refusal are distinct. The proposed representation correction
passes all 158 source handoff tests; independent correction review and native
execution are still required. Root also authenticates signer actual review
`65ca40e2` (four leaves plus guide), preserving its provenance failure and unknown
field. These reviews do not change either failed job into a pass.

Zsh next-build work confirms the selected builder already contains pinned Zsh
5.9.2-1, requiring no dependency extension. A finite Topmem/Fish/Zsh successor is
being implemented with six builds and three complete comparisons, preserving the
current pair's gates and adding native ZLE/configuration fixtures. The current
Topmem/Fish job and registration remain unchanged. KSM's next isolated lifecycle
route is under bounded investigation against the current reviewed baseline.
Full package installation, hardware, performance and R1–R5/M5–M9 remain open.

October 14, 04:32 UTC: composed ARM run `38510386112` completes FAIL at
Source `5ea0987c`, with Root completion `6b4ed1d6` retaining 13 hash-framed
metadata bundles. Native build/comparison, fixtures, signer fixtures, lifecycle,
onboarding, desktop and source suites pass their scoped checks. Repository
validation fails: its resource observation records failed mask 128, with six
recognized `CAP_`-prefixed capabilities and no unknowns or duplicates. Independent
review is binding that observation to the exact Source predicate; repository
cleanup failure remains separate from final owned-image absence PASS. Full
composed acceptance and downstream installation checks remain open.

The reviewed library namespace fix is committed as Source `d0828a1b`, Data
`b9e85512`, plan `6413ada7`; all 279 committed byte/mode rows and both variable
readbacks pass. Native run `38510908030` is in progress. No library result is
inferred. Standalone Topmem/Fish Source `5c50316c` is published in
[draft PR14](https://github.com/Gabriel-Kahen/cachy-asahi/pull/14), with all 55
manifest rows verified against immutable Source/Data and plan `d90c9d85`
registered before first push. Static CI passes; native run `38511520135` is
queued. Its standalone package scope does not establish installation or M2
acceptance.

Signer inventory Source `961a93c8` authenticates ten exact copy rows after
independent peer `8ad3ee9e` passes 63 causal cases and 415 assertions. Actual
observation `38511588937` completes all 16 inventories, then refuses
`package-field-format` during provenance. Root completion `7199c081` retains
that failure; the precise package field is not recorded. A bounded diagnostic
is assigned. Compilation and signing remain unaccepted. Full R1–R5/M5–M9 and
hardware acceptance remain incomplete; the development goal is ACTIVE.

October 14, 04:15 UTC: Root's managed handoff suite passes all 154 tests in
98.686 seconds, without failures, errors or skips. Independent Root peer
`d41ef5c6` (36 authenticated leaves) confirms all 182 test/helper methods and
assertion counts are retained. The corrected Source `5ea0987c` proves all 271
committed byte/mode rows. Separate Data `a5f9e4b4`, selection `a62592b8` and plan
`34f6039b` are published and both variables read back exactly. Push-triggered
ARM run `38510386112` is confirmed in progress. No result is inferred yet.

The library startup fix advanced actual run `38508141673` beyond registration,
then capture-dependencies failed at GRAPH_NAMESPACE, callback-refused, cleanup
PASS. Root retains completion `e82503b5`; no project-library compilation ran.
The pure Source replay finds the held controller's normal builtins-module
representation meeting a dictionary-only check. The narrow successor `85fb2bbb`
has independent review `81252db2`; Root adoption and fresh execution are next.

Compiler cap successor `9ff74269` passes the earlier bound in actual observation
`38508542523`, then refuses inventory-owner in the GCC plugin inventory. Root
completion `22618fcc` retains the seven-inventory/908-sample-call progress; the
precise node and ownership term remain unknown. A bounded diagnostic is assigned.
The Topmem/Fish budget/retirement successor `41e4e448` has Source-only peer PASS
for both fixes; Root exact peer authentication and actual publication remain
pending. Full R1–R5/M5–M9 and hardware acceptance remain incomplete; goal ACTIVE.

October 14, 03:39 UTC: compiler observation `38506491884` retains the precise
`elf-strtab-cap` failure for held cc1: dynamic string table 1,293,706 bytes
against the existing 1 MiB bound. Root completion `4cb74e79` retains the header,
segment and dynamic facts. This is a parser-bound finding, not compiler
acceptance. A finite 2 MiB successor with other guards preserved is under review.

The combined resource/hook Source is committed as `73ff3525` after all 1,317
proposal and 276 external files authenticate, eight old/new copy joins pass,
and all 271 committed Source byte/mode checks pass. The fresh handoff source
suite runs 107 tests and fails two assertions plus three setup/model errors.
Root holds its native rerun; a bounded correction is assigned. Derived Data
files are uncommitted and no new operational plan has been registered.

The library startup successor (`50f226ea`, 40 authenticated support files)
loads the required genuine helper and labels registration precisely; independent
Root review is pending. The standalone Topmem/Fish proposal (`b7024ec5`, 377
Root-authenticated leaves) has two peer findings: an EOF read can exceed its
lifetime bound by one byte, and close failure can lose its first-cause deadline.
Those corrections are assigned before adoption. Actual checkout inspection
also finds seven already-present Topmem files exactly equal to proposed bytes;
Root retains them and explicitly reconciles 47 mutations without changing the
proposed Source manifest. Full scope and the development goal remain ACTIVE.

October 14, 03:22 UTC: the private library job is registered with distinct Code,
Source and Data (`9a6ad098`), exact plan `3a303b55`, and both variable readbacks.
Actual run `38505301319` completes FAIL before library compilation. Retained
startup is copy-view / callback-refused / OTHER, cleanup PASS; Source shows the
phase label also covers unlabelled library registration. The precise predicate
is unknown. [Root review](reviews/project-native-libraries-run-38505301319-root-review.md)
retains this failed result; no native library build or comparison passed.

The corrected interposer now passes independent Source review (`eeffc56a`,
53 Root-authenticated leaves, 35 inert cases). All five predecessor equality
countermodels refuse before foreign equality. Build prepares the coherent
resource/hook cascade; fresh actual execution remains required. The original
blocked proposal/peer remain preserved. The development goal remains ACTIVE.

October 14, 03:12 UTC: the isolated native project-library lane is published in
[draft PR13](https://github.com/Gabriel-Kahen/cachy-asahi/pull/13). Root authenticates
all 129 support files (`224c3f84`), adopts exactly 28 files with all old/new joins,
and verifies the committed 278-file packet plus its lock. Code `9ea7c81a` and
Source `d912be01` are distinct; the selected packet is unchanged across the later
read-only observer addition. Fixed-tool ARM observation `38504784744` passes:
GPGV `e4d7e8ce`, Docker `94128e4a`, Git `4cda0087`, with no tool invocation.
Root retains completion `ba54e0dd`. Data/plan registration and the four native
library builds/two comparisons are still pending. Public promotion remains open.

The resource-only diagnostic (`80cfacd3`) authenticates 1,170 support and 273
external files, preserving all resource guards. Independent review blocks the
first hook proposal (`8d2c55b2`) after reproducing foreign equality admission.
The exact-type successor (`80579bb6`, 37 Root-authenticated leaves) is under
independent review. The ELF diagnostic (`04b5483c`, 77 Root-authenticated leaves)
also awaits independent review before adoption and the next observation.
Both actual failure causes remain scoped to their retained diagnostics. Full
R1–R5/M5–M9 acceptance is incomplete; the development goal remains ACTIVE.

October 14, 02:38 UTC: diagnostic ARM run `38500392517` completes with
native acquisition/signature/eight-build/four-comparison checkpoint PASS, while
composed integration remains FAIL. Root completion `4a05d69d` and independent
peer `acebb2ea` (53 authenticated leaves) retain the thirteen public bundles.
Repository diagnostics identify `INSPECT_CREATED` / `INSPECT_RESOURCES`, also
failing resource ownership inspection during cleanup. The precise resource field
is unknown. The later hook identifies `GRAPH_OBJECT_BINDING`; its exact failed
term/callsite is unknown. The other six component-stage projections pass, and
final owned-image absence passes separately from failed repository-container
ownership/absence. Build investigates bounded resource observations; a separate
Source owner proves and adapts the required active executor interposition.

All sixteen consumer archives now complete passive inspection. Their 26 direct
JBIG/TIFF edges include 21 matching declarations and five old SONAME references
inside the two packages being replaced. The fourteen unchanged consumers have
no unresolved direct replacement-pair edge. Root authenticates all 27 actual04 files (`dee8591c`), all 18 independent
peer files (`5fb752e9`, bytes/hashes; peer modes unrecorded), and all 9 migration
files (`c59c53bd`). The complete inspection covers 87 ELF members and 2,459 tar
members, with 32 positive handle closures and no cleanup errors.
[Actual inspection](workstreams/maintained-reverse-consumer-elf-actual04.md) and
[migration classification](workstreams/maintained-reverse-consumer-migration-impact.md)
retain the evidence. Symbol binding, runtime and M2 ABI remain open.
No compatibility SONAME aliases are invented.

Compiler-helper discovery Source `2d107f64` is published after 91-file review.
Run `38501515886` reads the libexec `13/cc1` path and then refuses
`signer-tool-elf`; Root retains its failure artifact (`2c0ef5ba`). A bounded
header/predicate diagnostic is assigned. No usable compiler/signing admission
follows. Private project-library and Topmem/Fish native lanes continue against
explicitly recorded base revisions. Full scope and the development goal remain ACTIVE.

October 14, 02:20 UTC: the fresh whole maintained354 metadata query actually
PASSES (`e0ac1f90` / independently authenticated peer `500852dc`, 55 leaves).
The authoritative parent returns PASS and exits zero; guardian observes natural
exit, owned reap, group absence and cleanup, with no signals sent. Strict nested
validation covers 354 rows, 1,642 relations, 458 targets and four natural-zero
read-only CLI calls. Processing through final acknowledgement takes
2.339122 seconds in the original 300/304-second frame; final metadata sealing is
separate. Current25 postflight is recorded PASS. This closes the complete
whole-query metadata checkpoint, not archive/ABI/install/hardware acceptance.
Original actual01 remains failed and uncertain.

Root adopts the closed repository/hook diagnostics (`0bc41de7`, 599 leaves) as
Source `50e81e32`, Data `b8c2fdff`, plan `1490445e`; all 271 committed source
files prove. Exact remote plan and existing19 private input secret names read
back. Native run `38500392517` is in progress; static `38500392407` PASS.
The original341/501 selection and private-cache controller are unchanged.

The Source-filtered project recipes (`57891aa0`, 155 authenticated support
files) exclude nonessential image/reference fixtures and use generated tests.
They are source-reviewed; native compilation is NOT RUN and public promotion
remains blocked by recorded licensing/corresponding-source/output joins.
Tools prepares a concrete private native build lane. The corrected pair runner
has independent cutoff review (`82282f5f`), and Release/Desktop prepare its
registered hosted execution path. Ordinary compiler helper observation still
fails at the selected GCC path in run `38498603144`; current helper-layout
discovery is assigned. Sixteen-consumer inspection preserves three distinct
failures (dynamic padding, repeated check dependencies, tar links); reviewed
padding/metadata corrections have advanced six packages, while a link-header
batch diagnostic prepares the next actual attempt. Full scope and goal remain ACTIVE.

October 14, 01:49 UTC: the native checkpoint now has independently
reviewed retained evidence (`1040b56e`, 47 authenticated leaves): 501 acquisitions,
249 signature observations, eight builds and four equal comparisons. Composed
integration and repository-container cleanup remain failed/uncertain; Build is
adding closed diagnostics at the earlier repository and later hook boundaries.

The sixteen current detached-signature checks pass (`c779fd77`, 50 authenticated
leaves). The first actual passive consumer inspection refuses
`ELF_DYNAMIC_TRAILING` on gdk-pixbuf2; remaining consumers are NOT RUN. Exact-byte
and primary-ABI diagnosis identifies a parser padding restriction, and a narrow
reviewed successor is being prepared. Runtime/symbol/16K/M2 ABI remain open.

The corrected whole-query publisher passes independent Source review
(`d89156c7` / `15f705a7`). Root's actual dedicated parent returns FAIL/exit1 with
`PROC_VISIBILITY_INCOMPLETE`, unverified group cleanup and no accepted outer reap
(completion `09885505`). Later worker/envelope producer receipts report PASS,
but they do not override the parent's authoritative failure. A later absent
reported-PID observation is not whole-group absence proof. The first Root index
reader selected the wrong README for a relative row; the corrected read
 authenticates all six launcher leaves, and operational hash guards held.
A narrow proc-visibility diagnostic/correction continues.

ARM observer run `38496509297` now retains its failure artifact: current selected
GCC `13/cc1` path resolution is missing. Independent peer `5dd2cabc` authenticates
29 leaves; compiler version and missing final/ancestor component remain unknown.
Bounded current-driver selection replaces the fixed directory in a successor.
The previous observation cause is not backfilled. Full scope and goal stay ACTIVE.

October 14, 01:32 UTC: native retry
[38495479762](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38495479762)
finishes with a successful build checkpoint and failed composed integration.
All 501 frozen objects acquire; 249 signature commands return zero. Eight native
builds pass, and all four package comparisons report byte/content/metadata equality.
Root retains thirteen hash-framed bundles and 260 native evidence members;
completion `344c70cb` indexes 26 files. The startup marker identifies a
`SOURCE_REFUSAL` at `native-hook` / `GRAPH_FUNCTION`; the exact downstream cause
remains unknown. Callback entry is false, initial exit is null, and phase
publication fails. Owned-image cleanup reports PASS/absence verified, while the repository
container cleanup separately records failed ownership/absence checks; complete
composed acceptance remains FAIL, and hardware remains NOT RUN. Build reviews
the retained result and prepares a bounded corrective next step.

The read-only observer diagnostic successor `2f58097a` is authenticated across
73 files, adopted/published as `1def1ef8`, and dispatched in run `38496509297`.
Its result is pending. Whole-query publisher correction `d89156c7` has fake-only
controls and awaits independent admission. Fresh sixteen-pair signature
verification reports all sixteen natural-zero checks; its final receipt precedes
actual dependency decoding. No full-port acceptance is inferred.

October 14, 01:27 UTC: private frozen-input cache transport is independently
reviewed (`f6355048` / `b2c139cf`) and adopted as Source
`0744f413`, Data `ea1db6b5`, exact externally registered plan `bacdcb92`.
The user explicitly approved CI export; nineteen private repository secrets are
provisioned and their names plus the exact plan read back. Package bodies remain
outside public Git. The original 341 packages / 501 descriptors are unchanged.
Native retry [38495479762](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38495479762)
is running; its result is pending. Exclusive cache access during seeding and
rollback is an explicit operating condition. Historical HTTP404 failures remain.

The newer-package Source09 candidate is separately published as `9059b7c4`,
[PR11](https://github.com/Gabriel-Kahen/cachy-asahi/pull/11); all 271 proposed
files match committed bytes and modes, and static validation passes. This is
source publication, with no native upgrade or release admission.

The read-only ARM signer observation is published as `06a4c47b`,
[PR12](https://github.com/Gabriel-Kahen/cachy-asahi/pull/12). Registered workflow
run [38495158676](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38495158676)
FAILS at observation with a retained `Refusal` marker; no artifacts were uploaded.
The detailed refusal cause is unknown, and a narrow diagnostic successor is
assigned. No compilation, signing or hardware check is claimed.

Old-pair signatures/current cached-byte custody now have authenticated independent
peer `6ac2a074`. Source/license correspondence peer `3edb9f5b` confirms partial
evidence only: both retained ALARM recipe hashes remain unmatched. Tools develops
explicit project recipes instead of claiming upstream binary correspondence.
Performance's fixed-sixteen passive ELF checker is sealed and awaits fresh
sixteen-pair signatures before actual inspection. Release's concrete pair runner
is sealed for review. Whole-query publication review found falsey-cause and
clock-error preservation defects; adoption is withheld and a small correction
is active. Full R1–R5/M5–M9/A01–A15 scope and the goal remain ACTIVE.

The full-goal responsibilities R1–R5 are mapped in `docs/acceptance.md`, with owned tasks and corrective next actions in `docs/backlog.md`. The destination now explicitly requires the maintained ARM package repository, native performance engineering, integrated Apple stack, broader Cachy system experience, and complete installation/release lifecycle. Both Air sizes, published final measurements, independent onboarding/contribution, subsequent full-port maintenance release, other-ARM reuse and actual upstream submissions remain required; an early overlay release or feasibility decision would not complete the goal. This scope update does not change any recorded execution result.

October 14, 00:54 UTC: corrected passive intake actually PASSES for jbigkit
2.2-1 and libtiff 4.7.2-2 (`a3189f4a` / independent peer `eefdfef6`). Both
PKGINFO mappings, 23/49 archive members, four ARM ELF library declarations and
two pair links authenticate. The 17,193-byte report records libtiff.so.6 needing
libjbig.so.2.2 and libtiffxx.so.6 needing libtiff.so.6. This is passive declaration
evidence; reverse-consumer/symbol/runtime ABI, source/license, native installation
and M2 checks remain open. Its 0.029819-second processing/report interval excludes
preflight and final result publication. The earlier metadata failure is preserved.
[Intake review](reviews/maintained-jbigkit-libtiff-passive-intake-root-actual02-review.md).

The exact original jbigkit 2.1-8 and libtiff 4.7.2-1 payloads/signatures have also
been recovered from the October 12 project cache. All sixteen selected pairs
(32 distinct mode-0600 files, 66,649,640 bytes) match their frozen metadata;
custody `33c43cf2` authenticates 49 indexed leaves. Current old-pair gpgv checks
PASS (`19534961`), preserving jbigkit's digest identifier 8 and libtiff's 10;
independent retained review is finishing. This establishes local retrievability
and current signatures, not current mirror availability or acceptance of prior
HTTP404 runs. A private CI cache route for the unchanged original four objects
is assigned so the original build snapshot can resume; the newer-pair upgrade
and sixteen-consumer dependency/ABI work continue separately.

Root refused the first new-input adoption before any copy: four of 23 expected
old files referenced Source08, while Source09 is already integrated. Record
`91611201` preserves all checks; the corrected Source09-based proposal is under
independent review. Shared source, execution899 and historical ARM results remain
unchanged. Native observation adoption, build-pair capacity integration, whole
query invocation and exact upstream source/license correspondence continue.

October 14, 00:15 UTC: the isolated-startup host fixture is built and independently
verified. New binary `9252c517` is a pinned x86 PIE; all eight common02398 nominal
checks pass with real self-signals. Its original owned child is reaped,
postflight input checks pass, and publication completes in 0.071192 seconds
within the original 10+2-second frame. Separate Root teardown is clean.
Actual `4f689c31` and peer `971bb47b` cover this host result only; compiler-tree
disposal, ARM/16K/M2 and full-port acceptance are not inferred.
[Actual review](reviews/maintained-composed-02398-host-fixture-root-actual01-peer.md).

Replacement jbigkit 2.2-1 and libtiff 4.7.2-2 now have actual detached-signature
verification: two natural gpgv exits of zero, exact primary
`68B3537F39A313B3E574D06777193F152BDBE6A6` and digest identifier 10.
Receipt `24753627` records 0.009253 seconds in one original 120-second frame;
independent retained peer `8d519bd5` passes. The first armored-keyring failure
remains `0d55d488`. Strict Base64/CRC24 transformation of the same pinned public
certificate yields binary `9403f923`; no host trust or secret key is changed.
Ordinary trusted CLI evidence establishes these signatures, not guardian
ownership, full341 acceptance, source/license or ABI correspondence. Passive
package/ELF intake and the new input cascade remain separate tasks; historical
trial08 and execution899 are unchanged.
[Signature review](reviews/maintained-jbigkit-libtiff-trusted-cli-signatures-root-peer.md).

Passive pair intake actually ran next and FAILED (`4b9f9153`) after 0.033086
seconds with `METADATA_AMBIGUOUS`. A separate bounded read-only diagnosis
(`45a1499d`) retains jbigkit's 440-byte and libtiff's 732-byte `.PKGINFO`.
The latter contains five `makedepend` entries; Source `32c12a79` treats that
otherwise valid repeated build-dependency key as ambiguous. Its original Source
and peer seals remain unchanged. A narrow successor and independent review are
assigned; no pair ELF/ABI success follows from this failure. The operation used
CPU 15 seconds, address-space 512 MiB, file-size 4 MiB, 64 FDs and zero core size,
with explicit inherited trusted codec/runtime assumptions. No package was
extracted, executed, installed or loaded.

Corrected native checker `f44dd302` and live adapter `9cb66de2` are sealed with
independent Source controls; all 213 indexed files authenticate. Release is
implementing their concrete driver/capacity integration. Final terminal query
gate `0662cf11` binds the final query/runtime/envelope and strict terminal
packets, with 92 corruption refusals; independent adoption review and Root's
whole invocation/publication binding remain pending. Other native build,
installation, recovery and hardware results retain their recorded states.

October 13, 22:52 UTC: the coordinator re-read the current outline, roadmap,
goal, acceptance contract and package inventory and propagated them to all six
worker chats. Full R1–R5/M5–M9 and A01–A15 remain mandatory. Their current
scope hashes are unchanged from the prior verified full-port contract.

The independently reviewed common signal teardown correction is now integrated
as Source `89954b0b6a096ac688a227219e520c121e281138`, with all 271 selected Git
blobs/modes proved and exactly two bootstrap data paths in
`a7f5cde222076a5e3af151e3581929d54aa7e645`. External plan readback and both
published refs match. Static CI `38480580179` passes; fresh native ARM trial08
`38480581279` is FAIL: the initial input acquisition reports 497 PASS and four
HTTP404 failures (jbigkit 2.1-8 and libtiff 4.7.2-1, each payload/signature).
Eleven retained files bind three framed exports; independent retained review is
assigned. Native build and downstream stages remain NOT RUN. Historical trial07
stays FAIL. [Source review](reviews/maintained-composed-opaque-signal-teardown-correction-root-review.md).

A separately reviewed x86 host SIGCHLD fixture verifies the public default-handler
transition and retained waitability primitive. Its command interval excludes later
provenance/publication, and it does not admit the whole updater query.
[Fixture review](reviews/root-sigchld-waitability-fixture-root-review.md).
The prepared common02398 fixture's old supervisor is blocked: it reaps before
numeric group cleanup, permitting group-ID reuse. A minimal retained-pidfd
successor is assigned; no nominal actor permission follows from the old helper.
[Blocked helper review](reviews/maintained-composed-02398-host-fixture-root-review.md).

The guardian deadline successor passes independent bounded Source review; exact
query, gate, publication and whole-caller bindings remain pending. The sealed
query cause-transfer successor is assigned independent review. Native Topmem/Fish
build-pair and bounded package-checker implementations, signer-probe review and
separate transport/launch corrections continue in parallel. Both M2 Air sizes,
final measurements, installation/recovery, ongoing custody and a subsequent
full-port release remain open. The goal remains ACTIVE.

October 13, 23:36 UTC: the independently reviewed downstream signal correction
is published as Source `7fde499b5dcbe216c8e17eb07abe236978300f1c` and two-path
Data `a8222e2256f1dba944ab7fc7911ba83e02442ed8`. All 271 selected Git blobs and
modes are proved. Common02398 stays unchanged; launch/transport now share their
explicit polling/state contract and preserve body causes and uncertainty.
[Downstream review](reviews/maintained-downstream-opaque-signal-correction-root-review.md).
The execution ref remains Source89954b0; the new plan is derived but unregistered,
and no retry is dispatched while required package inputs remain unresolved.

Trial08 remains FAIL. Independent retained review authenticates eleven run files,
271 Source blobs and three framed exports: 497/501 acquisitions pass, with four
jbigkit/libtiff payload/signature HTTP404s before verification or compilation.
[Actual review](reviews/maintained-composed-38480581279-root-review.md).
A finite twelve-GET official-source lookup recovered none of the old objects.
Fresh unsigned metadata proposes jbigkit2.2-1/libtiff4.7.2-2; its exact tuples and
19 dependency/16 reverse-consumer nodes pass retained review. Four-object
payload custody, signatures, source/license, ABI and a newly selected complete
341 lock remain separate work. Two exact read-only host vercmp observations
report positive ordering for the three scoped declared relations; they do not
resolve the complete transaction or certify ARM ABI.
[Input metadata review](reviews/maintained-jbigkit-libtiff-input-custody-root-review.md).

Root implemented and independently reviewed the metadata-bound query result
gate: 27 synthetic corruption controls pass; three coherent predecessor graph
substitutions now refuse against pinned canonical seed/addition metadata. Final
query/runtime pins, terminal-mask correction and whole-payload publication/owner
reservation remain pending; no query actor follows from the gate.
[Gate review](reviews/updater-maintained-query-result-gate-metadata-correction-root-review.md).
Signer deadline classification passes bounded Source review; compilation and
native/runtime/API premises remain open. Package checker and four-build driver
implementations are sealed, with live integration and concrete original-deadline
cleanup corrections under review. The owned common fixture runner is reviewed
separately; an isolated-startup C variant is being prepared before compilation.

Full R1–R5/M5–M9 and A01–A15 remain required. Both exact Air sizes, final-system
measurements, installation/recovery, signing/maintenance custody, independent
onboarding and a subsequent full-port release remain unaccepted. The goal stays
ACTIVE while the bounded software implementation and execution tasks continue.

Latest coordinator update, October 13, 22:10 UTC. Root re-read the current
outline, goal, roadmap, acceptance matrix and package inventory. Full
R1–R5/M5–M9 remains required; the initial overlay is an intermediate result.

The fresh private host metadata query passes: maintained341 plus 233 additions
equals 574 records, with all 2,933 dependency relationships reported satisfied,
743 unique deptest targets and five natural zero-exit commands. The outer child
exited naturally in 2.372 seconds inside the original 300+4-second envelope.
Independent retained review authenticates all 18 actual files and rejects ten
corruptions. The synthetic local database emits six ignored-key warning types;
these grant no archive, size, hash or signature authentication. This generic
metadata result does not select the Asahi platform transaction or pass native
build, installation, source/license, 16K, hardware or release gates.
[Actual query review](reviews/maintained-desktop-resolution-actual01-root-review.md).

Maintained ARM trial07 `38468791930` remains FAIL at service construction:
`TYPE_ERROR / SERVICE_CANCEL_EXIT_SET_HANDLER_NONE_BAD_HANDLER_API`.
The closed observation reports a None handler argument and matching API error
text; native API origin and the reason for None remain unknown for this run.
Independent review authenticates nine retained files and 271 Source blobs.
A separate isolated x86 host fixture reproduces opaque-handler restoration;
its correction is being prepared and does not backfill historical failures.
[Trial07 review](reviews/maintained-composed-38468791930-root-review.md).

Reviewed hosted-job timing and retained-evidence sizes supply finite operational
observations, while compiled-build resource usage, sustainable capacity and
permanent human/signing custody remain unproved.
[Capacity observations](workstreams/native-build-capacity-evidence.md).
Signer execution-witness source and maintained updater inputs are under
independent review; native success is not inferred. Both exact M2 Air sizes,
final-system measurements, exercised recovery and subsequent maintained release
remain required. The development goal stays ACTIVE.

Checkpoint `a3fb4ae` has static CI PASS `38472330666`. A subsequent independent
six-case inert Source audit reproduces the opaque-handler restoration refusal
in transport and launch as well as body-error replacement. Those scopes remain
unchanged in current runtime source; a separately reviewed successor must close
them. No actual trial's origin or kernel behavior is inferred from this model.
[Downstream audit](reviews/maintained-downstream-opaque-signal-audit.md).

The maintained updater input successor passes independent metadata/Source review:
341+13=354, with only the documented Vim pair changed in the baseline. It retains
527 transport-object and 262 signed-payload descriptors; these are declarations,
not fresh acquisition or signature results.
[Input review](reviews/updater-maintained-native-input-root-review.md).
Its separate query preparation has correct 354/1,642 metadata joins, but actor
admission is blocked: the nested runtime reaps a child before signaling its
released numeric PID. An exact-function inert control reproduces that ordering
with modeled PID reuse; no actual foreign-process event is inferred. A bounded
ownership correction and separate original-deadline outer guardian are active.
[Query review](reviews/updater-maintained-transaction-query-root-review.md).

The conditional signer execution-witness review supports its stated filter/kernel
argument, while later guards lack fresh original-task lifetime proof. A separately
scoped probe/adapter correction remains unrun.
[Witness review](reviews/test-signer-monotonic-exec-witness-root-review.md).
The opaque-handler candidate's nominal x86 fixture passed, but independent
teardown-fault controls find first-error replacement and scope-retention defects.
That candidate remains unadopted while a separate correction is prepared.

Native build-pair preparation for the existing Topmem/Fish packages now runs as
an independent track. Its contract retains input authentication, provenance and
clean-build comparisons, while signing/lifecycle and full release duties remain
in their existing tracks. No new build or lifecycle result is inferred.

Prior coordinator update, October 13, 20:52 UTC. The reviewed maintained
45-root metadata proposal and finite ten-candidate source/evidence table are now
published in the repository. Exact bytes match author `56c4f8f` and peer `836e71b`;
only the documented Vim pair/builder bindings and descriptive editor fields change.
Existing roots/providers/snapshots and historical resolution records are preserved.
Fresh maintained dependency resolution is being implemented as a separate private
query. [Metadata proposal](../manifests/proposals/maintained-desktop-v1.json),
[source/evidence table](port/source-evidence-responsibilities.json).

Topmem03's errno13 process-executable readlink observation passes independent
retained review: 125 Source blobs, 33 support files and 27 corruption controls.
Its signer recovery still supplies no absence proof. Runtime correction and hosted
signal attribution remain active. [Actual review](reviews/topmem-corrected-caller-38463181445-root-review.md).
Full R1–R5/M5–M9 completion, current source delivery, named custody and target
hardware/release acceptance remain unproved.

Prior coordinator update, October 13, 20:42 UTC. The previous batch changed
source and yielded an actual errno13 signer observation, so software progress
continues. Static CI `38464516815` passes at checkpoint `d351474`.

Independent coverage review authenticates the existing 45-root/ten-candidate
crosswalk and keeps maintained341, platform261, generic574 and unadopted624
inputs distinct. A maintained-builder metadata successor and source/evidence table
are now under independent review. [Coverage review](reviews/full-port-release-coverage-root-review.md).

Independent recipe-correspondence review authenticates the finite official-source
search: 32 retained GET records, 733,770 bytes, 11 systemd and five pacman candidate
recipes, zero matches to the selected BUILDINFO hashes. Exact selected recipe or
authoritative builder custody remains required; a separately source-built candidate
would have a distinct identity and could not certify the historical tuple.
[Correspondence review](reviews/platform-sysusers-exact-recipe-correspondence-root-review.md).
The signer ownership fix, signal attribution, updater inputs and retained Topmem03
review continue in parallel. Full R1–R5/M5–M9 and all target gates remain open.

Prior coordinator update, October 13, 20:39 UTC. Topmem ARM trial
`38463181445` passes the fresh baseline 8/4/249, then fails with the closed
Source observation `io-failed / start / PROC_EXE_READLINK / errno 13`.
The failure identifies denied process-executable link access; its underlying
permission policy or dumpability is unproved. Addon counts remain zero and signer
recovery remains FAIL/refused, with no agent/keyhome absence proof. The six-file
retention is sealed; independent review and a process-ownership correction are
active. No historical cleanup or cause is backfilled.

Exact selected sysusers/pacman recipe correspondence remains unresolved after a
finite official-source search. Further source and builder custody is required;
other software tasks continue: hosted signal-wrapper attribution, maintained
coverage/input reconciliation and compiled updater input preparation. The full
R1–R5/M5–M9 goal remains ACTIVE; hardware and maintained-release gates stay open.

Prior coordinator update, October 13, 20:30 UTC. Caller-only I/O diagnostic
source passes independent review with five focused groups and 17 inert rows.
The signer and all other shared bodies remain unchanged. Source `9710bcf` verifies
125 Topmem rows and exact Source-variable readback; static CI `38463181409` passes.
Actual ARM trial `38463181445` is in progress, with no result inferred yet.
Fish successor `db98210` verifies 131 rows and remains undispatched while the
shared signer-start failure is investigated. [Source review](reviews/topmem-agent-start-io-failure-root-review.md).

A finite full-port coverage crosswalk is under independent review. It reuses
45 existing generic roots and ten development candidates; maintained builder,
platform image and the unadopted coordinated transaction remain distinct inputs.
Scope is unchanged and no release, target or ongoing human custody gate is passed.

Prior coordinator update, October 13, 20:26 UTC. The independently reviewed
handler-argument diagnostic is committed as Source `4327634` and Data `999e539`.
All 271 Git rows and exact external-plan readback pass; static CI `38462431970`
passes. Actual ARM trial `38462431231` again reports
`TYPE_ERROR / SERVICE_CANCEL_EXIT_SET_HANDLER`, cleanup PASS and hook entry false.
The argument refinement did not match; failed operand/predicate remain UNKNOWN.
Hosted Python wrapper compatibility is now being checked against primary source.
This failure is retained separately and does not change trial05.

Prior coordinator update, October 13, 20:16 UTC. Root re-read the updated
outline, roadmap, goal and inventory; complete R1–R5/M5–M9 remains the scope.
Static CI `38460396035` passes at source checkpoint `5662c67`.

The retained Topmem02 result now has independent review: all 125 Source blobs
and 33 support files authenticate, with 31 focused corruption controls passing.
The actual failure remains `io-failed / start`; refused signer recovery supplies
no agent/keyhome absence proof. [Retained review](reviews/topmem-corrected-caller-38458434811-root-review.md).

The conditional upstream hook/sysusers audit also passes independent review,
with 64 rule, 23 INSTALL and 31 hook mappings plus six fresh controls. Both
selected PKGBUILD hashes still differ from retrieved recipes. Exact recipe
history/builder transformations and generated constants are being investigated;
account effects and binary correspondence remain unfinished.
[Source review](reviews/platform-sysusers-upstream-semantics-root-review.md).
Signal-restoration and signer-I/O diagnostic successors are under independent
review. Neither is a runtime correction or successful native addon result.

Prior coordinator update, October 13, 20:07 UTC. Reviewed diagnostic source is
published and the complete R1–R5/M5–M9 goal remains active.

Maintained Source `35ff48c` and Data `0238541` have 271 verified Git rows and an
exact external-plan readback. Actual ARM trial `38458048861` reports
`TYPE_ERROR / SERVICE_CANCEL_EXIT_SET_HANDLER`, narrowing failure to the handler
restoration setter. Hook entry remains false and cleanup reports PASS. The
handler argument and exact builtin failure are unexported; focused source
attribution is being developed without changing restoration behavior.

Topmem diagnostic Source `1014a19` has 125 verified Git rows. Actual ARM trial
`38458434811` again passes the fresh baseline 8/4/249, then fails in signing
startup with `io-failed / start`; addon counts remain zero. Before/after signer
journal projections record a launch attempt without a bound agent. Signer
recovery reports FAIL/refused, agent/keyhome absence false and sticky uncertainty.
The owned baseline image is reported absent. This does not prove signer absence
or identify the errno/syscall; no virtual-machine disposal inference replaces the
missing proof. A bounded operation/errno diagnostic is in development.

Fish's reviewed workflow and shared diagnostic are committed at `3dc9a80`, with
131 source/policy/workflow Git rows verified. It remains undispatched while the
shared signer-start failure is investigated. Passive body semantics pass
independent review: 19 bodies, 54 control texts, two sysusers routes, 64 literal
rules and 32 unresolved IDs. The next upstream audit records unmatched selected
PKGBUILD hashes; generated constants, binary correspondence and actual account/
hook effects remain open. No hardware or release gate is passed by these results.

Prior coordinator update, October 13, 19:33 UTC. The complete R1–R5/M5–M9
roadmap remains authoritative and the development goal remains active.

Actual passive intake trial02 retains all 19 selected bodies (6,953 bytes) from
nine archives: 4,984 members and 100,188,160 decoded bytes. Parent and child exit
naturally with zero status, direct child reap, no TERM/KILL or cleanup errors.
Independent retained review passes three corruption controls. The earlier Root
frame01 used the wrong scope label and was refused before child launch; its failure
is preserved. The bodies supply text for hook/account review, not Source, license,
signature, account-effect, installation or image acceptance.
[Actual body review](reviews/platform-systemd-sysusers-body-intake-actual02-root-review.md).

The reviewed service-attribution source is published as Source `5a41a3d` with
Data `59332b3`; all 271 Git blobs/modes and the external plan were checked.
Actual ARM trial `38449904816` fails at construct-services with
`TYPE_ERROR / SERVICE_CANCEL_EXIT`, hook entry false and cleanup PASS. Independent
retained review passes. The enum narrows a Source routine; the inner predicate and
private clock domain remain unvalidated. A local owned-child Python 3.14 signal
context check passes and does not establish hosted Python 3.12 behavior.
[Trial04 review](reviews/maintained-composed-38449904816-root-review.md).

Topmem's isolated workflow Source `bf5ea66` passes all 125 Git row checks, source
proof and official 501-input acquisition. Actual ARM trial `38450105697` passes
the fresh baseline's eight builds, four comparisons and 249 signature observations,
then fails in the parent signing phase before addon execution. The selected export
reports `signing-failed`, addon counts zero and the owned image absent; full caller
and signer journals and the precise signing predicate were not exported. Focused
attribution is in development. Fish's 129 source files and separate policy are
published at `23cc3cb`, with 130 Git rows verified; native Fish acceptance is pending.
Its workflow preparation continues while the shared signing path is investigated.

Prior coordinator update, October 13, 18:29 UTC. Root re-read the current outline,
roadmap, goal, acceptance matrix and package inventory. The full R1–R5/M5–M9
scope remains required; hardware access does not prevent independent software work.

The reviewed FileFinder namespace correction is committed in Source `1b3a6dd`
with Data `b7dce9a`, and static CI `38444735727` passes. Actual ARM trial
`38444735786` now passes dependency capture but fails at service construction
with `TYPE_ERROR`, `source-refused`, hook entry false and cleanup PASS. Both
bounded exports and the launch result are retained. The inner TypeError predicate
remains unknown; inert constructor models pass and justify no API correction.
Safe phase attribution is the next diagnostic task. Earlier failures remain unchanged.

The corrected common caller contains late owned-state descriptor-close failures;
independent controls pass. Root publishes Topmem's 123 source files and selected
policy file at `70238b7`, with all 124 actual Git blobs/modes verified. The policy
retains the read-only ARM tool observations and binds the corrected producer.
Fresh consumer checks, native builds, TEST signing and lifecycle remain pending.
The workflow proposal is under independent review. A separate one-line body-intake
fix passes old-red/new-green source controls; its bounded 19-body actual runner is
being prepared. Neither track certifies full image assembly or M2 hardware behavior.

Prior coordinator update, October 13, 17:40 UTC. The updated outline, goal, roadmap
and acceptance matrix remain authoritative for the complete R1–R5/M5–M9 port.
Independent review rejected the first startup diagnostic proposal because a
secondary publication failure could escape its original FAIL result. A separately
sealed minimal correction preserves the original failure and sticky cancellation;
independent Source review passes. Root publishes Source8a28a8b and Data7764f58,
authenticates271 actual Git blobs/modes and registers/readbacks the new external
plan. Retry38438328328 FAIL narrows the refusal to capture-dependencies /
GRAPH_NAMESPACE; cleanup still FAIL, precise subpredicate/cause UNKNOWN. Its
static workflow38438328195 passes. Retained independent trial review29f393
authenticates Source271, both exports and the closed failure marker. A local
source model reproduces the namespace refusal when cwd equals the Source root;
precise actual predicate/cleanup cause remain unproved. The original run stays unchanged.
[Retry review](reviews/maintained-composed-38438328328-root-review.md).

The recovered NetworkManager and Perl archives now pass actual data-only intake
in a fresh constrained child: 3,601 members, 90,224,436 decoded bytes, no payload
execution, and removed spool. Trial01 retains an outer-guard deviation. Fresh
trial02 repeats with the exact 1210-second outer envelope and natural parent/child
zero completion; its source/counters are kept separate from trial01. All nine
original acceptance flags remain false. Other259 cryptographic admissions, full261
selection, image assembly and target installation remain open. Retained metadata coherence review of trial02 passes; Root observed natural
completion, and independent live process-disposal replay remains absent. [Runner source review](reviews/platform-real-two-intake-runner-root-review.md)
[trial01 review](reviews/platform-real-two-actual01-root-review.md) and
[trial02 review](reviews/platform-real-two-actual02-root-review.md) record the limits.

The full261 policy/real-reference adapter and corrected Topmem TEST producer
pass independent source review. The latter replaces the unselectable repo-add
assumption while preserving the original native and addon source/counter sets.
Actual ARM tool-policy observation, native library/signing and Topmem/Fish
lifecycle remain unrun. Source review corrected finite ELF-string, held-ancestor and cancellation
cleanup concerns in the observer. Exact reviewed inline workflowf01a80b is
published on its isolated branch. Actual read-only ARM38439375132 passes with
two tool rows,18 helpers and the canonical libzstd1.5.5; initial CLI log omitted
stdout, so Root retains the fresh complete API logs and candidate/final receipts.
Independent retained peer07f056 passes the observation and pure V2 schema
compatibility; policy selection, native library/signing and lifecycle remain pending.
[Actual observer review](reviews/topmem-arm-toolchain-observation-38439375132-root-review.md). [Observer review](reviews/topmem-arm-toolchain-observer-root-review.md).
The fixed261 dependency/hook helper and independent review also pass source
checks:259 components retain one cycle and two provider ambiguities;57 config
hashes supply no bodies. Exact systemd-hook plus18 sysusers body intake is next;
installation order and hook acceptance remain missing.
[Dependency/hook review](reviews/platform-install-order-hooks-gap-root-review.md).

[Topmem review](reviews/topmem-native-test-toolchain-correction-root-review.md),
[policy review](reviews/platform-full261-intake-policy-root-review.md) and
[diagnostic finding](reviews/maintained-composed-startup-refusal-root-review.md).

Prior coordinator update, October 13, 16:30 UTC. The goal is resumed and active.
Root publishes the reviewed trusted Source3 CodeCommit `677d3ba`, isolated
workflow SourceCommit `920b5f2` and exact two-path DataCommit `319aa5d` on the
maintained branch. All 271 committed source/packet/workflow/body blobs match;
external plan variables are registered and read back exactly. Static CI
`38428419578` passes at SourceCommit. The fresh read-only ARM observation
`38425616010` also passes with unchanged Git/Docker/Python hashes; its evidence
has independent review and supplies no live grant or native acceptance.

The first actual maintained composition `38428419937` is FAIL. The trusted
launcher returns controller exit1 and recorded J/E; accepted callback entry is
unobserved, initial exit is null, downstream KSM/ARM/client/virtual stages are
NOT RUN, and cleanup reports FAIL. The precise inner cause is UNKNOWN beyond
`callback-refused`; the callback flag alone does not prove the callable never
ran. Independent retained review authenticates both exported metadata bundles
and registration, without rerunning actors. A bounded failure-only diagnostic
is being implemented with existing authority predicates unchanged.
[Actual review](reviews/maintained-composed-38428419937-root-review.md).

Root selects the exact recovered-two consumer/runtime29/plan/index/signature
sidecar through a versioned development descriptor and runs its readiness CLI.
It validates the two retained signed associations before reporting261 metadata
references,18 missing inputs and nine false acceptance flags. Other259 crypto,
live Source grant and actual assembly remain unaccepted. The private retained
frame is required; this descriptor is not a shipped installation program.
[Selection record](reviews/platform-recovered-two-root-registration.md).

The streamed archive source passes bounded review but currently accepts only
modeled authentication. Its complete261 three-pass reservation exceeds the
2 GiB cap by103,959,208 bytes. A separate finite policy and real retained-input
adapter are in development. Topmem's before-cleanup caller passes source review;
its unselectable host repo-add assumption is being replaced by a concrete pinned
producer. Fish native lifecycle integration remains active. M2/16K, complete
install/boot recovery, maintained releases and performance gates remain open.

Prior coordinator update, October 13, 06:44 UTC. Maintained native trial
`38354516537`, from `0f6b202`, passes with eight completed builds, four matching
comparisons and 249 positive signature observations. Independent retained review
passes. The richer source-gated records show package/content/PKGINFO/BUILDINFO
comparisons, but private archives and full process journals were not exported for
independent replay. Its owned image has been removed; it cannot authorize a later
addon or composed run. [Native review](reviews/maintained-native-successor-38354516537-root-review.md)
records that boundary. The preceding failed trial remains unchanged.

NetworkManager 1.58.1-1 and Perl 5.42.2-2 target archives and signatures were
actually recovered into private retention, verified under the locked key and
checked for signed package metadata. Independent retained review passes. The
separate recovered-reference proposal preserves the original 259 associations;
the captured validator accepts 261 metadata references and leaves 18 named
prerequisites open. Its signature sidecar and source selection still require
independent review and Root adoption. No complete image, hook, ABI or installation
gate passes from these two inputs. [Recovery review](reviews/platform-missing-two-authenticated-recovery-root-review.md)
and [selection proposal](workstreams/platform-recovered-two-reference-selection.md)
retain the actual recovery and proposed selection separately.

Root registers the independently reviewed maintained composition on the separate
canonical branch `codex/maintained-composed`, commit
`91bb508f5bae2bac9a8b7c95c914c8bd40b22f52`. Its installer packet selects exactly
266 source files and 14 metadata pins; committed Git blobs and working bytes
match. Historical source selections on the primary branch remain intact. The
trusted maintained launcher and fresh whole-composition execution are pending.
[Canonical registration](reviews/maintained-composed-canonical-registration-root-review.md)
records the selected packet and limits.

Topmem's second lifecycle proposal is blocked by public-repository directory
permissions; the scoped correction is under independent review. Its actual
before-cleanup caller, disposable test signing key and both journal recoveries
are being implemented. Fish history's 12 package sources and separate development
manifest entry are registered after independent host controls; read-only recipe
and syntax checks pass. Native build/lifecycle integration remains active.
Streamed archive intake and fresh image staging remain active. All R1–R5/M5–M9
requirements, both Air sizes, 16K runtime,
full installation/recovery and final measured performance remain unfinished.

Prior coordinator update, October 13. The maintained native trial38350748733
is retained and independently reviewed as FAIL / NOT ACCEPTED. Prefetch has501
positive records; all249 sanitized signature records have integer exit0 and one
locked-primary VALIDSIG. Eight provenance/four comparison hashes are present,
but their private contents were not exported. The precise inner cause is UNKNOWN;
public recovery attests owned-image absence, with global daemon-cache absence
not claimed. [Failure review](reviews/maintained-native-successor-38350748733-root-review.md)
keeps those limits explicit.

A separate source-proven endpoint defect is corrected: the validator now uses
the captured broker policy to compare canonical socket endpoints. Source96 changes
only worker and metadata retention;94 inherited files remain exact. The new
packet16498f24 and workflow update retain the original clock, limits and Docker
pin. Independent four causal models and15 static checks pass. The richer closed
metadata records preserve first refusal codes and inspectable build/comparison
fields. Registration is followed by a separate fresh native trial; the first
failure cannot be backfilled from this source correction.

A fresh read-only resolver diagnostic directly observes the32-byte target
`/run/systemd/resolve/resolv.conf` from the same stat reply, with unchanged
51 calls/13 earlier CATs/16 nodes/3 frames and no link follow. Independent
retained review passes; all48 comparison remains FAIL and assembly cause,
runtime correctness and successful disposal remain unaccepted.
[Observation review](reviews/platform-resolver-fastlink-observation-actual01-root-review.md)
records this new fact separately from the earlier unexported target.

Fresh image staging assembly and bounded archive intake continue. Topmem's first
native lifecycle proposal has a blocking mount-custody defect and incomplete
executor/key bindings; a separate correction is active. Fish history module
implementation and an explicit maintained composed baseline continue in parallel.
Full R1–R5/M5–M9, both-model hardware and final performance evidence remain required.

Prior coordinator update, October 13. The read-only hosted ARM probe38347013591
passes and its retained output has independent review. It observes aarch64/4K,
workspace and temporary-directory metadata, and exact Docker/Git/Python hashes;
it runs no Docker/Git command or package operation. The observed Docker pin is
selected explicitly and must match again in the new native job.

Root registers the explicit maintained native Source96 route and workflow after
source review, with official501-input prefetch and one deadline starting before
checkout. Source verification exits0. Fresh signature verification, eight native
builds and four comparisons still require actual hosted execution; this is an
explicit successor and does not replace the original input/integration identity.
[Registration](reviews/maintained-native-official-prefetch-primary-registration-root-review.md)
records the primary paths and workflow changes.

The Zsh composed mode is registered after independent source review, with its
263-path selection and refreshed separate258/265 selections. Exact source rows
and metadata bindings verify. Actual original-context execution, callback/grant
selection, Zsh package pairs and installerP0 remain NOT RUN.
[Registration](reviews/zsh-composed-session-primary-registration-root-review.md)
records the conserved original authority and issuer rebind.

Both failed filesystem observations now have independent retained review.
The resolver remains an observed32-byte symlink with target NOT READ; its cause
is unknown. Image assembly has a reviewed source/data contract but remains
blocked by20 specific inputs. A fresh project assembler and Topmem native
build/lifecycle increment are under implementation. Full R1–R5/M5–M9,
both-model hardware tests and measured final performance remain mandatory.

Prior coordinator update, October 13, 04:32 UTC. Source7c6107a is published,
static CI38345043844 PASS. Exact committed checks cover12 new sources/89,152 bytes
(24 Git queries); the application's265 rows retain committed parent7e708f6 with
zero changed-path intersection and current hashes/modes verified. The original
MIT memory tool and reviewed trusted bootstrap sources are registered.

Actual all48 observation01 exits1 at a structural regular-leaf check. Its separate
same-predicate diagnostic identifies etc/resolv.conf as image symlink32 bytes,
0777/root/inode39/nlink1, versus archive regular65 bytes0644/root. It stops before
CAT of that inode after51 image calls/13 earlier CATs/16 selected nodes/three frames.
No completed48 report or success/disposal attestation exists. Its symlink target
and assembler cause remain UNKNOWN. The earlier fstab220/126 disagreement and
strict comparatorFAIL remain unchanged. [Actual record](reviews/platform-filesystem-regular-observation-actual01-root-record.md)
tracks both failures; independent retained review is active. The owned image
assembly/configuration contract is under investigation.

The exact read-only hosted ARM observer and workflow are registered after
independent31 controls and authenticated21 author/10 peer artifacts. Publishing
the workflow path starts the bounded precheckout probe; actual tool hashes are
pending. It runs no Git/Docker command, package operation or real clock/grant.
[Registration](reviews/native-arm-runner-observation-primary-registration-root-review.md)
records the trigger and trust limits. The guarded successor Source94 build
proposal is sealed and under independent Root review. An official-pinned prefetch
route is being added so hosted execution can obtain501 private inputs directly
without a new private repository/token or public plaintext carrier. Native ARM
build pairs and installer P0 remain NOT RUN for these candidates; full R1–R5/M5–M9
and both-model acceptance remain mandatory.

Prior coordinator update, October 13, 04:06 UTC. Root registers the original
MIT cachy-asahi-topmem development package, an explicit current-user process
memory replacement. Independent cold13 tests and four additional checks pass;
a local x86 CLI smoke exits0 in its visible process namespace. All five recipe
checksums and SRCINFO rows match, static recipe inspection has zero errors and
bash syntax passes. Native package pairs, installation/lifecycle,16K/both-Air
runtime and release selection remain open. The static workflow now runs its
functional suite and checks recipe syntax across all package categories.
See [the source registration](reviews/topmem-source-registration-root-review.md).

Root also registers the exact reviewed bootstrap/clock issuer and fresh-sibling
launcher source. Independent24 controls pass, including the old directory-offset
regression, cancellation/retirement and modeled full handoff; historical counts
are not added. Only the launcher's stale module docstring changes, with all other
AST nodes exact. Application258/265 packets remain unchanged. Final inline
workflow/data selection, observed runner pins and actual clock/grant/runtime
handoff remain pending. [Registration](reviews/broader-bootstrap-primary-registration-root-review.md)
records the trusted-source boundary.

The actual successor offline crypto audit now has sealed independent PASS for
501 pinned inputs,249 signature records and248 package metadata checks. The
[public summary](validation/maintained-builder-baseline.md) retains exact evidence
hashes and explicit x86/private-keyring/cleanup limits. The wrapper publication
finding is independently closed at source level. Guarded native build pairs and
the trusted hosted-runner observation are in final proposal review. All48 payload
observation is prepared with a fresh unapproved grant while independent review
completes; no image actor has run for that mode. R1–R5/M5–M9 remains required.

Prior coordinator update, October 13, 03:45 UTC. The updated roadmap and
package inventory were re-read; full R1–R5/M5–M9 remains mandatory. Workers
continue guarded native builds, the complete installer handoff, whole-subset
payload observation and a concrete next functional increment in parallel.

Published installer source head84c43a0 passes static CI38340335247 and has an
exact committed265-source proof (530 Git byte/mode queries). Root additionally
registers the independently reviewed early-entry controller/test revision and
258/265 packet variants. The peer cold93 controls and27 vectors pass; all265
current source hashes/modes and12 metadata pins match. Actual trusted bootstrap,
clock/grant/runtime delivery, native frames and installer P0 remain NOT RUN.
[Registration evidence](reviews/broader-controller-early-entry-primary-registration-root-review.md)
records the source-level handoff and preserves the separate publication reserve.

A fresh local offline audit of the explicit successor builder baseline completes
CLI0:501 pinned transport objects,249 successful GPG signature verifications and
248 matching package metadata records. Exact unchanged native source and recipes
were used with the versioned successor lock; this x86 crypto/data result is not
a native ARM build, original-baseline acceptance or public distribution approval.
Root retained97 execution artifacts and a separate private-GPG disposal receipt;
independent retained-evidence review now passes (recorded in the later update). Guarded native build-pair
execution is the next baseline task. Historical frozen-input failures remain FAIL.

The strict all48 regular-payload comparison remains FAIL. A fresh diagnostic
identifies its first disagreement at etc/fstab: image220 bytes versus archive126,
with the same0644/root ownership. It stops before that file's CAT, after12 image
calls/two earlier CATs/two frames/four selected nodes. Independent review verifies
the failure; its configuration/source cause remains UNKNOWN. The worker is
preparing an explicit all48 observation mode that records differences while
retaining structural, cap, drift and complete-schedule failures. It cannot accept
the image or turn the strict comparison into PASS. The previous single-LICENSE
match remains separate. Full341 payload/trust, ABI/hooks/16K and M2 gates stay open.
See the [actual diagnostic review](reviews/platform-filesystem-regular-batch-diagnostic01-root-review.md).

Prior coordinator update, October 13, 02:52 UTC. Published source bc18be6
passes static CI38338117122. Committed FDK133 plus workflow/batch/Zsh checks
cover274 Git queries. Corrected carrier/cleanup projection and borrowed Zsh
adapter are registered; actual FDK9/updater10 retain four frozen Vim404 failures.

Prior coordinator update, October 13, 02:05 UTC. Private installer packet
mode implementation passes33 existing controls and18 new source/snapshot/private
Git controls. Its exact selected union is265 files; the legacy union remains258.
The Session graph source passes92 and independent review, preserving original159/
view160/fixture125/recipes4/inputs71 and actor schemas. Private controller wiring,
bridge-to-graph binding, issuer rebind and final per-run registration are active;
actual native P0 remains NOT RUN. These source holds are not primary admission.

The external bootstrap close-fault correction passes42 controls and independent
old8/new12 causal vectors. Its specific source failure is closed; descriptor
retirement stays UNKNOWN and cleanup fails after the modeled close fault. Data-only
external envelope delivery and final265/clock/J registration remain unfinished.
The frozen-four carrier's initial86 tests pass but independent review reproduces
close-first-cause and allocation-handoff gaps. Corrections are in progress before
adoption; no retry or signature bypass is admitted. Actual FDK9/updater10 remain
input-acquisition FAIL on the four frozen Vim objects. Exact source/license delivery,
public carrier, shared cache interfaces, payload batch and Zsh Session adapter remain
active software work. No physical-machine or complete-release gate has changed.

Prior coordinator update, October 13, 01:28 UTC. The native installer bridge
source2 is published at `653df4c`; exact committed Git byte/mode proof and static
CI `38331928767` PASS. Fresh92 controls and independent constant/code substitution
checks close the self-namespace comparison defect, preserving all source, Config,
restrictive profile and deadline gates. Live Session graph/callback integration,
final issuer rebind and actual native P0 remain pending, with a bounded worker
now implementing the graph extension. This does not admit full installation.

Independent review closes the composed recovery P1 on exact corrected parent
sources: fresh187 controls PASS and causal old11FAIL/new12PASS. The same J reaches
recovery and bounds selectors/retention; legacy calls retain empty kwargs. The
Root-private258-file clock-literal candidate also passes187 controls, but is not
live registered. External bootstrap construction and final265-file installer
composition are pending; original159/view160/fixture125/recipes4/inputs71 stay fixed.

A bounded FDK controller seeding hook is under implementation for only the four
unchanged frozen Vim objects, before the producer but after complete source
verification. It leaves original acquisition/signature checks intact. Exact public
carrier/source-license/retention delivery is a separate active task. The next S01
selection and borrowed Zsh Session adapter are active software work. No actual
hardware, performance, complete payload/trust/install or maintained release gate
has changed; full R1–R5/M5–M9 remains mandatory.

Prior coordinator update, October 13, 01:23 UTC. The revised roadmap keeps
R1–R5/M5–M9 mandatory. Reviewed KSM diagnostics are published at `bbc7d6a`, with
actual committed154-file proof; kernel inner-result diagnostics at `cd0cb58`,
with actual committed120-file proof. Other KSM150 rows and the kernel workflow
remain unchanged. Static CI passes for both commits and updater `0e07db1`.
These are source advances; KSM6 and Kernel7 retain their recorded failures and
unknown actual causes. Next retries need frozen-input recovery.

FDK9 `38326770829`, from `9ed0efa`, fails original input acquisition:
501 observations = 497 PASS + four HTTP404. The exact Vim9.2.1164-2 archives
and signatures are missing upstream; GPG/original builds/FDK are NOT RUN.
Its committed133-source binding and seven public failure files pass independent
review. Scoped image absence passes; worker cleanup/absence remain unaccepted.
All four exact objects are retained locally, totaling9,790,183 bytes. A curated
seed/controller-cache interface and source/license/retention delivery are being
implemented; frozen versions/signature gates remain unchanged.

Updater10 `38330541760`, from `0e07db1`, authenticates the reviewed86-file
source then fails input-authentication:527 observations =523 PASS and the same
four HTTP404. No compilation runs and no directory refusal leaf is observed.
Nine bounded public records are retained. Scoped cleanup/private removal and
recovery report PASS; broader daemon disposal remains NOT ATTESTED. Independent
actual review is active. This run does not identify updater9's private directory
branch or change updater8's ELF UNKNOWN history.

S01's actual read-only three-query image probe completes
PREFLIGHT_GRAMMAR_MATCH_ONLY at the published `f9bb04c` reader pin. Independent
review passes this narrow scope: root stat/list grammar, exact source/image/tool
pins and final report custody. The report records2,701 returned/report bytes;
raw image/tool hashing I/O is excluded from that ledger. An initial sandbox
UID/GID metadata refusal is retained; the same selection succeeds in the intended
Root namespace. Full walk/CAT/correspondence,259/261 tuples,26 signer joins,
installed trust/ABI/hooks/16K/M2 and full341/345 installation remain unaccepted.
A new bounded selection is being prepared; the three-query grant cannot expand.

The composed parent review finds recovery omitting its existing absolute J.
A source correction is in progress with causal expiry controls. The clock issuer
passes independent bounded source review; live registration/external runtime and
grant construction remain pending. Installer bridge85 source controls pass, but
live self-namespace comparison reveals marshal reference-encoding sensitivity;
a correction is being verified without weakening code custody. Actual native P0,
ABI/fixture26, full candidate installation and physical-machine gates are NOT RUN.
The Session-only Zsh adapter and FDK cleanup diagnostic are separate active lanes.
There is still actionable software work; this is not a machine-only stop.

Prior coordinator update, October 13, 00:06 UTC. The updated roadmap's full
R1–R5/M5–M9 scope remains mandatory. The Session-owned original source view is
published at `14aa7a9`: 95 source tests pass, including refusal of extra or
noncanonical directory entries. The composed parent, finite workflow clock,
stage deadlines and repository phase publication are being integrated; actual
external repository authority and the full candidate transaction are unaccepted.

KSM6 `38321651221`, from `97363ea`, fails with natural producer exit125 and zero
RPC requests. Scoped owned image/container absence passes, but cleanup FAIL and
mutation UNCERTAIN remain. Independent review authenticates the source and run;
the private refusal leaf is UNKNOWN. This run does not observe the proposed
180-second inventory request. A source-issued bounded refusal diagnostic is in
development. Updater9's independent review confirms its retained directory-tick
failure and cleanup/recovery results without identifying the private branch.
The directory-leaf correction passes87 source tests and independent review;
workflow registration and a new actual trial remain pending.

FDK's initial descriptor-identity and modern compiler-observation corrections
pass source review. A corrected private registration candidate has133 selected
files,44 stage files and23 recipe inputs;57 outer-controller and14 packet tests
pass. It fixes both workflow count guards and obsolete synthetic success
fixtures without weakening the production completion gate. Independent complete
registration recheck is active; FDK8 remains FAIL with its inner cause UNKNOWN.
Kernel's finalization and nonfinite-JSON correction passes160 selected tests
and independent review. Its registration must bind the new FDK dependency;
Kernel7's failure and unknown inner cause remain unchanged.

Zsh's six source findings close in94 tests and independent review, published at
`978635b`; live Session reuse and native addon acceptance are unfinished. Guest
SVG diagnostic integration is published at `76d94d4`, and Root's seven-source
controller pin update at `b2f3d16` passes127 source tests. Static CI passes for
the Zsh, KSM source, original-view, guest and ARM-installer commits. The latest
pin commit's static run is in progress. The guest4 abort remains an actual FAIL;
no subsequent ARM guest/frame/MIME-cache observation is claimed.

The native ARM tiny-transaction profile and complete-phase checks are published
at `8e1b06b`:87 source/model tests pass. Actual native P0, libalpm and transaction
matrix are NOT RUN; a bridge to the actual native owner is being implemented.
Read-only image reader report custody has a sealed correction with30 author
tests and25 independent controls; Root recheck precedes any real probe. S01's
259/261 tuple coverage,26 signer joins, payload/issuer trust, full installation,
both M2 sizes,16K execution and final measurements remain open. These source
changes neither pass those gates nor establish release/maintenance capacity.

Prior coordinator update, October 12, 23:05 UTC. Full R1–R5/M5–M9 remains the
completion contract. The reviewed updater ELF/read predicate and exception-tag
corrections are published at `2433f26`; 160 fresh source checks pass. Native
updater9 `38319260369` authenticates that exact86-file source, then fails the
outer tick at private-scan/private-directory-identity during worker1. Its17
public records verify against the committed workflow receiver. The worker
reports cancellation during makepkg; no compiler natural return or independent
container state is observed, and its diagnostic remains UNKNOWN/state-unavailable.
This trial does not identify an ELF validation leaf. Scoped cleanup/private
removal/recovery PASS; peak growth is12,788,715,520 bytes and the storage latch
is false. Independent run/check diagnosis is assigned; updater8 history stays
unchanged.

The S01 core and read-only image reader are published at `f59ec6e` after root
472-record authentication and independent review:105 current methods,63 core
controls and118 reader controls pass. Interrupted resource disposal and shared
archive/image ledger findings close within the documented bounded-attempt
limits. Exact4-file Git proof passes; static CI `38320110768` PASS. Actual
read-only image/debugfs observation is being prepared separately. Coverage is
still at most259/261; the two missing tuples and26 signer-fact joins remain open,
with payload/issuer/installation/hardware acceptance false.

The KSM code-custody correction passes333 independent fresh tests,30 graph,
15 wrapper/exit and five additional closure controls. Root registers the
154-file prospective source, adding driver/test2 and rebinding existing
consumer/executor/RequiredPaths3, with149 previous rows and the workflow
unchanged. Independent registration review and committed native KSM6 dispatch
remain pending. FDK initial-unknown descriptor correction is held for independent
recheck. Zsh's six source findings have a held94-test correction; independent
review is active. Kernel failure diagnostic review finds finalization fault
first-cause loss and acceptance of nonfinite unused JSON; correction is assigned.
The Session-owned original160 view, native ARM installer profile and guest SVG
observation integration remain active source lanes. Actual external repository
authority, full native installation and M2/16K/final measurements remain unaccepted.

Prior coordinator update, October 12, 22:30 UTC. The revised roadmap requires
R1–R5 and M5–M9; full-port acceptance remains open. Updater7 `38307993177`, from
`f7217a1`, remains FAIL after controller validation: the compile gate returns1
before compiler launch. All16 public records and scoped cleanup/recovery verify.
Independent review reproduces stale observer pins; the minimal correction is
committed/published at `ea9ab8c`, with an exact86-file Git/source proof covering
4,213,032 bytes. Updater8 `38314402583` is FAIL after source authentication, controller validation
and compiler invocation. The bound compiler returns0, then compile-elf records
ValueError/UNKNOWN and refuses acceptance; the exact private ELF predicate is
unexported. All18 exported records verify against the committed workflow receiver.
Worker/container exit1, no OOM; scoped cleanup/private removal/recovery PASS.
The outer NOT RUN pair label does not mean the compiler was never invoked.
Independent actual-run review verifies all 18 records and reproduces the fixed-leaf
reporting gap. Ten existing ELF/read predicate tags are in source implementation;
actual8 ELF cause remains UNKNOWN.
Kernel7 `38308563102`, from `25b0213`, passes producer, provision and native logic
probe. The baseline Docker START query returns1; independent worker exit,
compiler invocation and inner cause remain UNKNOWN. Candidate is NOT RUN;
scoped cleanup and daemon preservation PASS. A bounded fixed inner-result
projection is selected for source development. Earlier kernel failures remain.

KSM5 `38303811300` remains FAIL: exact341-package inventory returns after
67,529ms, then reply fails; precleanup producer exit1, mutation UNCERTAIN and
cleanup FAIL. The proposed180-second caller adaptation preserves existing
6600/1650/8460 limits. Its323 author methods pass, but peer review reproduces a
missing refusal when the same granted function has changed code. A bounded
code/globals/closure custody correction is assigned before registration.

Installer evidence namespace, runtime-fixture and writable-adoption corrections
pass source review. Actual smoke04 passes the readonly barrier and signed tiny
pair. The expanded current01 trial fails private authentication before commit:
GPG reports a socket path too long under the long project fixture path. Its nine
guards pass;16 other transaction methods are NOT RUN. Fresh current02 uses the
original short default/tmp fixtures and passes all26 selected methods:17 actual
tiny transaction cases plus nine source/isolation/timeout guards,0 skips,
22 worker invocations,10 committed and11 commit-started. Parent namespaces and
protected host metadata remain unchanged. The root process scan is limited to
the old project fixture path and cannot certify default/tmp process absence;
fixture teardown and the actual process-group timeout check are separate evidence.
Independent actual-record review passes with explicit process-scan, three unreadable
host-metadata subtree and temporary unretained crypto-input limits. Exact reviewed
installer source is committed at `d6bf57f`. The bounded early path-refusal
correction passes34 independent source checks and is adopted locally. Fresh
current03 passes the same26 actual cases:22 invocations,10 committed,11 started,
0 skips,11.315s; independent retained-evidence review passes. The improved same-exec
scan matches24 exact GPG-home/contract paths and finds no matching process/read
errors, within its stated limits; broad process absence remains unproven. This
adds rejection of long workspace paths, not support for them.
This admits only the selected disposable any/x86 fixtures; real ARM/full-port
installation and M2 checks are NOT RUN. Historical failures remain recorded.

Camera cancellation source is committed after independent review; runtime/backend
admission remains absent. FDK prior descriptor repair still permits adopting foreign FD identity after
initial-query failure; a bounded permanent-unknown correction is assigned. Repository adapter correction is held with61 fresh methods and
an exact243-file source replay,0 actors; independent61-method graph review PASS. The exact25 repository runtime/collector/phase/adapter/callback source rows are
committed/published at `7a49856` with Git proof. Broader controller/packet/live
grant registration remains pending. Actual external authority is NOT ISSUED.
An explicit Session-owned160-file original view contract is in development;
it must preserve the original159/125/four-recipe boundaries while the full source
contains the Zsh candidate. Opt-in Zsh addon source is committed at `c45a44f`; same-job
native adapter source review finds six authority, disposal and stale-PASS issues;
bounded corrections are assigned. SVG preflight source is committed
at `0fd7a20`; actual guest integration/decode remain pending. Source integration is assigned
to compile/bind the fixed helper and retain one20-second pre-app observation,
without a MIME-cache rebuild or new app/frame acceptance.

S01's four original source findings are corrected, with38 core and47 reader
methods passing. Independent review identifies interrupted descriptor/child/pipe
disposal and combined-ledger custody gaps; bounded correction is assigned before
actual image reading. Coverage remains at most259/261, with exact NetworkManager
and Perl gaps,26 signer-fact gaps, installed trust false and full payload
correspondence unaccepted. No supported release, both-M2,16K or final
performance/power gate is closed.

Prior coordinator update, October 12, 19:43 UTC. Updater5 `38296615950` passes
86-file committed-source authentication, then fails worker1. Its bound diagnostic
identifies entry-guard/unexpected-mount before controller validation or compiler
launch. Parent/container returns are 1; scoped cleanup and recovery pass. All
15 public records and the independent actual-run review verify. Standard Moby
mount omissions are reproduced in source fixtures; the actual rejected path is
not exported. A narrow checked mount/private-IPC correction is in development.
Guest4 `38297144571` remains FAIL after the original integration and other broader
components pass. Root verifies 33 bundles, 1,623 members, 27 exports, 1,180 files
and 31 summary bindings. Its precleanup process event records client SIGABRT
with the compositor alive; the bound client log records a fatal SVG icon-loading
error. Cleanup passes and no frame is accepted. Independent actual-run review
and loader/dependency diagnosis are active. Kernel resource diagnostics pass
93 stage and 209 job checks and are held for peer review. Repository deadline
and mode/inode corrections pass 131 handoff and 24 provenance tests plus 68
independent controls; their integration is pending. Installer's latest review
closes the terminal SIGTERM/flush bugs but leaves interrupted capsule disposal
open. Complete release, both M2 sizes, 16K behavior and measurements remain open.

Prior coordinator update, October 12, 19:16 UTC. KSM4 `38294468323`, from
`0722dd9`, remains FAIL. Request 6 returns the expected 341-package inventory
before reply delivery fails with BrokenPipeError. Natural producer poll and
runner return are unobserved; cleanup reaps code 1. The recorded absence flags
are true, but owner failure keeps cleanup FAIL and mutation UNCERTAIN. The
producer's own failure is unknown; independent actual-run diagnosis is active.
Updater registration and strict modern workflow consumption pass 33 independent
checks, including 57 causal cases, for the exact 86-file closure. Both complete
bound diagnostic groups and fixed 4KiB selectors are required without weakening
compile/package/pair/cleanup checks. Git proof and actual trial remain pending.
Guest diagnostics are bound to packet `47610163` with five changed rows and
206 unchanged; root review is active. Installer's SIGTERM/flush correction is
held after 38 inert models; independent terminal-publication review is active.
Repository transport needs two source corrections for its cleanup deadline and
postexecution mode custody. All previous native failures remain recorded.

Prior coordinator update, October 12, 18:57 UTC. KSM's observation-only RPC
diagnostics pass 279 fresh tests and independent closed-pipe, return-code,
privacy and process controls. Root adopts the 152-file source packet `68c1bb02`
(seven changed rows, 145 unchanged); committed bootstrap and a new native trial
remain pending. KSM3 remains FAIL with uncertain mutation and unverified cleanup.
Kernel5 `38292740905` is FAIL: ownership validation advances, then
INSPECT_RESOURCES/docker-container-resources refuses before container start.
The exact resource conjunct remains unknown; cleanup and owned absence remain
unverified. Independent actual-run review is active. Updater's diagnostic helper
is registered in 23 recipe sources and the 64-package/8-root pin map; strict
workflow consumption and independent registration review remain pending.
Installer review reproduces default SIGTERM and delayed stdout flush leaving
false PASS after modeled success; correction is active and no new transaction
is admitted. Guest process diagnostics and seven-file repository transport are
held for coordinator integration. All M2, 16K, performance and full-port release
gates remain open.

Prior coordinator checkpoint, October 12, 18:40 UTC. Earlier records below
remain historical; this checkpoint supersedes their pending-work descriptions.

- Successor guest run `38283691844`, from `387217c`, passes the original generic
  integration aggregate and ARM-C01, client and KSM components. Root verifies
  33 bundles, 1,623 members, 27 export manifests, 1,180 exported files and all
  31 summary bindings. The reviewed empty-error-text compatibility correction
  advances past the previous IPC refusal. Generic ARM boots with 4K pages and
  software GBM renders; a 1024×768 virtual monitor is reported. The guest then
  fails the combined client/compositor exit predicate before any frame is
  accepted. Individual process exit codes and the client failure log are absent;
  the first exited process and rendering cause remain unknown. Scoped container,
  owned image, private workspace cleanup and evidence publication pass. Focused
  diagnosis and independent actual-run review are active. Earlier guest failures
  remain FAIL; this is no M2 graphics or complete desktop acceptance.
- FDK trial `38268251114` passes original producer acceptance, then fails source
  preparation. A replay demonstrates gzip serialization drift across zlib
  implementations. The reviewed raw-tar correction is committed at `765067d`;
  77 stage and 14 packet tests and actual 128-file Git/bootstrap/copy proof pass.
  Successor `38277573107` reaches build-1, then fails. All eight public records
  and scoped absence verify. The first build predicate and compiler invocation
  remain unproven. The held worker diagnostics pass 104 author and 38 independent source checks;
  the outer consumer passes 174 author and 29 peer fixture checks. Root binds
  stage40/job129; the inherited-HOME and prospective documentation correction passes 15 peer
  controls. Commit `6026697` and both actual workflow source/loader guards pass.
  Native trial `38289669230` still fails build-1: verified worker/builder exit 1,
  attach and validated container exit 4, first predicate CONTAINER_ATTACH.
  Both scoped absence checks pass. The eight public records verify; private
  builder log/provenance bytes are not exported, so package function and compiler
  invocation remain unestablished. Source/data diagnosis is active;
  FDK compilation, publication and runtime integration remain unaccepted.
- Updater's accepted workflow correction is committed at `ed76c11`, following
  507 author consumer cases, 39 independent cases and actual 85-file source
  verification. Trial `38277597310` fails worker-1 inspection. New observations
  establish worker CLI exit 1 and a matching exited container with exit 1 and
  no OOM indication. All 14 public files verify; scoped, private and recovery
  cleanup pass. The internal worker predicate and compiler invocation remain
  unattested. The held inner diagnostic helper passes 155 fresh source/fixture
  checks and 20 helper controls; root selects its exact 4KiB helper/selector
  interface for review. Actual parent binding, recipe/source registration and
  workflow acceptance are being implemented before another native attempt.
  Independent review of the frozen worker-side helper reproduces four blockers
  despite passing its 155 tests: command facts lost during log I/O, cleanup
  cancellation loss, durable final-close mismatch and contradictory CANCELLED
  fields. Those corrections and parent once-capture/binding pass a merged 186-test
  source suite and 47 independent controls. Coordinator recipe/helper/ready/source/
  stage/workflow registration remains before native admission; no corrected Rust
  compilation is claimed.
- KSM retry `38271066975` stops at the initial image baseline: query exit 0,
  six returned lines and no observed container baseline. Cooperative image
  preservation is held and independently passes 255 source tests and focused
  controls. A source-clock renewal, late-refusal gap and buffered-close late write are
  corrected in a held proposal. Root fresh-capture checks pass all 264 tests,
  zero skips, with owned fixture sockets. Independent final review passes 14
  focused controls; root adopts the 152-file source packet `0623a4d6…`.
  Committed source/bootstrap proof passes at `f7ee4a7`. Native successor
  `38286983453` advances into the producer phase, then reports BrokenPipeError,
  producer mutation UNCERTAIN and cleanup FAIL. Initial image preservation PASS
  is an authenticated executor declaration; its raw private journal is unavailable.
  Owned cleanup/producer completion cannot be inferred. Independent source and
  actual-log review plus causal reply controls select finite RPC/cleanup observations
  before another retry; KSM build/lifecycle/export remain NOT RUN in this attempt. That failed retry ran no producer,
  builds or installed lifecycle; baseline fixtures do not change its result.
- Kernel diagnostics are adopted at `bae171e`: 202 job and 115 stage tests,
  89 independent focused checks and 14 poison cases pass. Actual Git/bootstrap
  and fresh-copy proof verify the 26/117-file closure. Trial `38279898941` returns
  verified child diagnostics: `PROVISION_COMMAND` / `INVALID_DATA`, provision
  return UNOBSERVED and child exit 1, before probe or compilation. Cleanup FAIL,
  final baseline preservation and owned absence UNVERIFIED remain authoritative.
  The exact inner predicate remains unknown. A closed operation-level
  diagnostic passes 78 stage and 205 job source tests with zero skips, plus
  independent typed-slot and cleanup controls. Commit `2e0dc0d` binds stage 26
  `387e72fc…` and job 117 `9ca9414c…`; actual Git/source/bootstrap proof passes.
  Successor `38288838400` fails INSPECT_OWNERSHIP/docker-container-ownership
  after a returned container ID, before start; cleanup fails the same check.
  Its public schema4/diagnostic2 projection verifies; the failed conjunct remains
  unknown without raw inspect. Primary Docker/Moby source and two causal controls
  establish null/empty Labels incompatibilities in ownership and derived-config
  comparison. The narrow correction passes 85 stage, 205 job and 48 independent
  controls; stage26 `0ef3ad17…`/job117 `647d4dd0…` are adopted before committed
  proof and the next ARM trial. The prior timer explanation was
  withdrawn after confirming the existing renewal; those timers are unchanged.
- The actual inert 624-archive payload audit passes. The corrected ELF scan
  remains FAIL with 27 missing-provider requests and 22 firmware parser refusals;
  the reviewed 52-test provider correction resolves 4,509 earlier omissions.
  Independent residual classification passes 531 data checks. A bounded recursive
  transaction packet is being resolved for 21 provider roots; no extension archive
  is authenticated or adopted. The metadata resolver retains a failed 377-node
  tentative transaction; independent review selected canonical-path, nonfinite
  metadata and hook-policy corrections. Runtime ABI, hooks and M2/16K acceptance
  remain open. Resolver follow-up identifies unused malformed ownership rows;
  camera review identifies a special-file open before type refusal. Both narrow
  source corrections are selected. A synthetic-preview supervisor is in development;
  actual preview, capture and hardware checks remain NOT RUN.
- Repository URL and phase corrections pass 252 author source tests and focused
  independent controls, then are adopted at `9340d00`. Actual Git verification
  catches one historical public JSON mode mismatch; correction `510e8c3` preserves
  its bytes and the old private copy. All 47 paths and 17 transitive bindings now
  verify. Complete same-job raw admission/custody, 341-package metadata and
  provenance remain required; native authority is not inferred from public data.
- The offline copied-root worker passes 38 checks: 19 modeled checks, 17 synthetic
  pipeline cases with ten actual tiny libalpm commits, one namespace barrier and
  one owned-child timeout. Independent review adds ten checks, including another
  actual tiny commit, and identifies child-source and evidence-directory custody
  gaps. The held correction passes 35 controls (28 modeled, seven harmless loaders);
  independent source/custody recheck reproduces CLI cancellation and staged
  foreign-receipt overwrite edges. Thirty-two corrected models pass; final peer
  recheck remains before another actual tiny transaction. ARM, the full
  package transaction, trust, hooks, first boot and complete installation remain open.

| Stage | Source implementation | Required execution evidence | Acceptance |
| --- | --- | --- | --- |
| 0 Baseline | Collector, acceptance method and MIT license implemented; base choice retained | Native ARM VM builder executed; exact Asahi base snapshot and M2 Air inventories remain | INCOMPLETE |
| 1 M0 overlay audit | Pinned upstream audits and original development set reviewed; original source findings resolved | Complete chosen-base ARM dependency transaction and final recipe review | INCOMPLETE |
| 2 M1 builds | Four original recipes pass static inspection; build/inspection tooling passes local tests | Four original packages passed two clean native ARM builds, inspection and byte comparison; chosen Asahi target transaction still open | INCOMPLETE |
| 3 M2 integration | Baseline/protected-stack boundaries specified | Exact-model installation/removal, desktop/audio/resume/application-state checks | NOT RUN |
| 4 M3 updates | Signed staging/release tooling passes local synthetic/ephemeral-key tests and independent review | Real signed artifacts, consistent upgrades, induced-failure recovery on target | NOT RUN |
| 5 M4 performance | Frozen-plan measurement, telemetry and comparison harness implemented; six source findings independently resolved | Repeated controlled before/after timing, power, suspend drain, thermal and functional evidence | NOT RUN |
| 6 Maintained system | Installation/contributor drafts, release policy and packaged setup/removal helper implemented | Independent clean install, subsequent release, accountable maintainers | NOT RUN |
| 7 Overlay qualification and ARM reuse | Separate model records; actual native builder reuse and upstream drafts recorded | Both Air sizes, overlay reports, reusable component on another ARM target, actual upstream work | NOT RUN |
| 8 Complete ARM port (M5–M8) | Expanded package transaction preview, tool candidates, virtual desktop controller, offline development release client and ARM-C01 experiment implemented or source-audited; platform/install integration remains open | Broader native builds/runtime, complete licensed dependency coverage, target platform integration, measured tuning and A12–A15 evidence | INCOMPLETE |
| 9 Full-port acceptance and maintenance (M9) | Acceptance contract now covers all five responsibilities | Same-release both-size final validation, independent installation/recovery and subsequent complete-port release | NOT RUN |

## Verified local work

- Six project development chats dispatched on GPT 6.1 Sol with high reasoning, plus independent source reviews.
- Host/Docker are x86_64/amd64. Collector capture and the small onboarding C program ran locally; neither establishes M2 behavior.
- Coordinator's integrated test run: build/inspection 33, setup 40, baseline collector 3, release 19, benchmarks 28, native CI 45, setup synchronization 9: **177 passed**, no skips. These validate source behavior and controlled fixtures, not hardware acceptance.
- Four original recipes pass non-executing metadata/checksum inspection. Two host assemblies per recipe were produced by owners; payload comparisons and packaged CLI regressions are recorded separately from native execution.
- Independent reproductions closed four initial build/release findings, two setup findings and six benchmark findings. Desktop launcher documentation was corrected.
- Source-only ARM audit authenticated the dated rootfs and all 248 dependency package/signature pairs. This is data authentication on x86_64, not ARM execution or an accepted Asahi target transaction.
- Authenticated input cache and full audit retained privately at `/home/gabe/.local/share/cachy-asahi/private-inputs/`; upstream bytes are not published in Git.
- Free standard native ARM CI is implemented for the verified public repository, with a manual probe followed by hash-bound builds. [Actual execution record](validation/native-arm.md): static CI and the native ARM VM probe passed; first job failed metadata order; corrected full rerun passed all four native build pairs and byte comparisons, with retained evidence. Static CI has documented shell/release skips, separate from the full local test run.
- Read-only SSH attempt to configured `gabepi` timed out. No target Mac connection found in local SSH configuration.
- A source-only Asahi kernel checksum correction is actually submitted as
  [upstream draft PR #99](https://github.com/asahi-alarm/PKGBUILDs/pull/99).
  Independent checksum/diff/syntax review passed; compilation and hardware were
  not tested, and maintainer acceptance is not claimed. See the
  [submission record](upstream/linux-asahi-config-checksums.md).

## Complete-port development and connected native integration

- The generic ARM desktop/application preview resolves 45 minimum roots to a
  574-package inventory without replacing the 341-package builder baseline.
  This is a private print-only libalpm transaction, not an installed Asahi
  target. The original 232/233 authentication failure is preserved. A separate
  refreshed proposal authenticates all 233 additions after explicitly adopting
  the builder Perl refresh and proposing a new FDK archive. A separate FDK
  source-built candidate now has a reviewed complete selected-source packet,
  independently reconstructed inputs and 75 passing portable checks. Native
  builds, provider substitution, PipeWire runtime and installation remain open;
  the original broad private source packet remains uncleared. See
  `docs/port/desktop-coverage.md` and `docs/workstreams/port-resolution.md`.
- Cachy-update's actual Rust tray and shell updater have a development recipe,
  adapted behavior and independently authored licensed icons. Its reviewed Linux
  source/dependency/build-script closure and portable materializer are committed
  with exact input pins. All 167 registry archive checksums match; four historical
  macOS notice blockers remain excluded and refused. The separate hosted wrapper
  and actual Rust compilation are still pending. The separate KSM status
  candidate retains GPL provenance and passes local read-only/page-size fixture
  tests. Two clean native package builds now reproduce byte-for-byte in the first
  broader trial. Native installation/removal and required management functionality
  remain unfinished.
- ARM-C01 implements two baseline and two LTO zlib builds with cross-decoder,
  corruption, artifact, receipt-binding and cancellation checks; 91 local tests
  and independent review passed. The first native attempt compiled all four
  baseline/LTO builds, then failed during correctness checking. Timing and M2
  performance remain NOT RUN; partial compilation does not accept the experiment.
- A disposable generic virtual desktop route and controller are implemented,
  with 19 separately authenticated tooling packages and 29 local tests, including
  independently reproduced cancellation corrections. Actual
  guest boot, Hyprland/Wofi execution and captured-frame review remain NOT RUN;
  this route cannot accept Apple GPU, audio, suspend or platform behavior.
- The offline development release client passes 37 local tests with temporary
  real GPG signatures and independent race regressions. Production trust,
  supported release promotion and native onboarding remain separate gates.
- Connected V01–V09 execution has seven retained native failures. The first
  passed 211 host boundary tests but refused an incorrect source freeze. The
  corrected run passed 213 host tests, runner probe and full-source preflight,
  then failed fetching superseded pinned Perl inputs. The third authenticated
  the refreshed inputs, reproduced all four original native build pairs and
  passed 349 locked-userspace tests with no skips. Its fixture generation and
  integration suite failed on omitted locked audit inputs, and the desktop
  configuration verifier aborted. Installed lifecycle, repository transactions,
  onboarding and installed desktop stages did not begin. The fourth run passed
  fixture builds/signing, all 474 native source tests without skips, and the
  signed lifecycle component. The outer installed-image handoff and repository
  stages still failed; neither installed onboarding nor desktop ran. The fifth
  run passed all 499 native source tests without skips, package build pairs,
  signing and the lifecycle component. Its validated package inventory exports
  passed, but the committed-image verifier rejected differences in Cmd,
  Entrypoint and Labels. Repository creation reached repo-add, which could not
  create its temporary directory on the read-only root. Installed onboarding
  and desktop still did not run. Reviewed corrections pass 309 CI and 119
  integration tests locally, plus committed-blob and fresh-clone preflight.
  The sixth native run, `38212287407`, passes 560 native source tests without
  skips, fresh installed-image/lifecycle verification and installed software
  onboarding. It remains FAIL overall: repository rollback inventory text
  includes pacman diagnostics, and desktop publication refuses ANSI control
  codes despite its component checks passing. The owned image was removed with
  verified absence. Remaining repository transactions and actual desktop/session
  acceptance remain open. The seventh run passes 588 source tests without skips,
  installed lifecycle/software onboarding and desktop configuration verification
  including its corrected export. Eight repository case predicates pass through
  install, upgrade, rollback and signature rejection, but independent review
  finds zero-exit chroot errors in positive transactions; complete ancillary
  execution is not accepted. The aggregate still fails at the
  missing database-signature diagnostic classifier; later cases remain unrun.
  See
  [the actual execution record](validation/virtual-arm.md).

- The first broader native development trial, `38218102399`, builds and
  reproduces the KSM package twice. Its compiler experiment fails on truncated
  input handling; the 37-test client has one corrected permission-fixture failure,
  and virtual preparation refuses a signed-receipt interface mismatch. All remain
  separately recorded from the initial repository FAIL. The subsequent corrected
  original integration, `38221511121`, passes 603 native source tests without skips,
  ten repository cases, clean initial install/upgrade/rollback diagnostics and
  owned-image cleanup. Its final upgrade still reports a cached revoked-A sync
  signature error despite exit zero; the aggregate correctly remains FAIL.
  [Independent repository execution review](reviews/native-repository-run-review.md)
  verifies the actual checks. Further source corrections and separate FDK/updater
  native trial wiring continue; no complete-port milestone is accepted.

- The corrected original integration, `38227121568`, passes 620 native source
  tests without skips and all eleven repository transactions, including the
  clean final B upgrade after resetting the revoked-A cache. Its aggregate
  remains FAIL: the generic credential guard rejects nine evidence filenames.
  Corrected, purpose-validated public projection is still required; the raw
  reset receipt was not exported. Transaction PASS does not establish accepted
  publication, production trust or target recovery.
- The separate FDK trial, `38223759349`, passes all 501 input acquisitions but
  fails in the original producer before FDK compilation. Its exact failing
  operation remains unknown. The reviewed correction preserves delegated log
  bytes and finite phase diagnostics; 104 tests pass in both the workspace and
  exact copied 128-file packet, with committed Git byte/mode proof. The corrected workflow
  consumption and subsequent hosted execution are recorded below.
- The corrected FDK trial, `38230760444`, passes source/native prerequisites
  and all 501 acquisitions, then fails with the bounded diagnostic
  `producer-base-probe-runner-failed`. Its seven public files independently
  revalidate and owned-image absence is confirmed. The precise delegated Docker
  call/predicate remains under investigation; FDK compilation is NOT RUN.
- The updater native controller is committed after 136 source tests and
  independent process-cleanup review. Its 85-file committed closure is verified;
  the separate workflow is reviewed and registered. First native trial
  `38232511202` actually materializes all 168 inputs and reproduces the reviewed
  source/vendor hashes, then fails with RuntimeFailure while the native receipt
  remains at input-validation. Rust compilation is NOT RUN. Both cleanup and
  recovery report PASS, with nine captured public files independently verified;
  the exact validation/launch fault remains under investigation.
- The corrected platform proposal helpers pass 236 tests in a fresh committed
  checkout. The separately proposed coordinated Python transaction resolves
  all 55 target roots in metadata, while the original protected-version
  transaction remains FAIL. These are source/data results: 218 baseline payload
  archives remain unavailable, and installed ABI, hooks, coordinated platform
  updates and M2 recovery remain unaccepted.

- The corrected broader trial `38237127237` retains 31 authenticated public bundles / 1,508 regular members. ARM-C01's 505-command recorded correctness graph, four builds and 79 retained artifacts are consistent; all 37 native client tests pass and KSM builds reproduce. The eight sample CLI outputs outside the artifact bundle are not recovered evidence. All eleven repository cases, installed lifecycle/onboarding and desktop configuration pass, but the initial aggregate remains FAIL because the integration source suite fails. Repository binary-evidence publication is separately refused. Virtual tooling and disk preparation succeed; a QEMU capability guard stops before guest launch. Its tooling closure omits both concrete 2D virtio GPU modules. All reported owned-image/container cleanup passes. [Independent component review](reviews/native-development-execution-38237127237.md) records the limits and pending corrections.
- The updater scan correction is committed after 163 source tests and independent review; actual Git collection/verification binds 85 files / 3,915,170 bytes. Its diagnostic workflow passes 147 consumer fixtures. The FDK diagnostic workflow passes 30 fixtures and a closed 802-code schema. Actual finite reruns [FDK38239523997](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38239523997) and [updater38239531158](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38239531158) are dispatched at `756881b917ef68c614fcfb081debadf82282e80b`, serialized by the existing native-build group. Neither dispatch is a passed native result.
- The frozen kernel controller is committed after 140 source tests, exact 24-file source/Git acceptance and full output/cleanup corrections. Its separate hosted job proposal passes 93 source/runtime fixture tests; packet registration, default-branch workflow registration and actual kernel compilation remain pending. The 147-test KSM lifecycle is also committed with exact 14-path Git bindings; the separate native executor is still being implemented. Physical M2 execution, installation/recovery and performance remain NOT RUN.

- The diagnostic reruns now have verified terminal results: FDK38239523997 remainsFAIL at the exact base-lock inventory predicate, with501 acquisitions and owned-image absence verified; codec compilationNOTRUN. Updater38239531158 passes materialization/all527 acquisitions but the filesystem storage tick interrupts image bootstrap; its scoped cleanup and recovery bothFAIL, private-data removal is not confirmed, Rust compilationNOTRUN. Root validates seven FDK and eleven updater public files against the reviewed schemas and source pins. The owners are implementing bounded corrections; successful receipt publication is not successful execution.

These are distinct development results. No complete-port milestone or hardware
acceptance is granted by their local test counts or source reviews.

## Open inputs

- Exact M2 reference machine connection/access; 13-inch and 15-inch have independent gates.
- An upstream minimal-image candidate now has a retained 261-package inventory
  and seven separately authenticated current platform archives. Its image
  authentication, kernel source correspondence, complete target transaction and
  protected-stack integration remain unaccepted; generic native CI package
  build/comparison results are separately verified.
- Original project license is MIT. Excluded upstream configurations have separately recorded unresolved license notices.
- Final review and selection against the actual Asahi target dependency set; four original development candidates are selected, with no release selection.
- Release signing identity/custody and hosting destination, after package and hardware gates permit publication.

These are explicit unfinished gates. Source-only work, synthetic signing tests, container architecture declarations and documentation do not complete them.

### Native continuation — 2026-10-14 13:12 UTC

The independently reviewed kernel output diagnostic is published as Source `842878635d5fff38cfefa138e75e28fc0954ac16`, packet `b65bb028cc2dc33bf4047db479822fb003c45be5184818537b09c8493d2bcfee`. Root authenticated 219 author/peer paths, adopted exactly seven files, and verified all 124 packet rows plus the lock from raw Git and the remote branch. Native ARM trial [38569875890](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38569875890) has started. The prior output predicate remains unknown; this diagnostic does not change output acceptance or establish M2 compatibility.

Pair trial [38564566992](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38564566992) was cancelled while pending after an independent Source countermodel reproduced foreign equality objects being accepted in mutable ModuleSpec name/origin fields. It never executed and supplies no build evidence. Pair Source `392be2f203e533b0e33974e520371fc51aafac62` and the unadopted Zsh compatibility proposal remain historical; separate exact-string corrective successors are under review. Actual builtin metadata remains unobserved.

### Reviewed native successors — 2026-10-14 13:29 UTC

Screenshot recovery Source `92a3f0612c558b91accc15cd6495d98d6463b943` is published. It selects the already reviewed maintained input set and reuses the four recovered public ARM package/signature seeds through the existing CI secret references. All 72 recipe files are held and verified from raw Git. Real YAML parsing, four shell syntax checks and all 363 unchanged bootstrap tests pass. Two local test attempts remain recorded: the first encountered full `/tmp` storage; moving all fixtures to disk then violated six intentional `/tmp` guard requirements. The successful runner used owned `/tmp` for that guard-dependent suite and owned `/var/tmp` for other fixtures, with product code and tests unchanged. Native trial [38571648129](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38571648129) is pending; all three previously pending trials remained pending after this dispatch. Current screenshot package build/capture and M2 checks remain unaccepted.

Pair exact-string correction Source `eef0710d0c1161287938fce5fe23bed777784f29` is published. Its two helpers reject foreign ModuleSpec name/origin equality objects before comparison. Independent review closes 16 genuine-type countermodels; all 54 Source and two Data rows are verified from raw Git. The successor plan `5255523f022ecc9421881b90ab298ca2fb432ef091ec60834021ba53b808be22` was registered and read back before the execution ref advanced. Native pair trial [38572139973](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38572139973) is pending; the separate static-validation run 38572140122 passed. The earlier pending trial remains cancelled, with no execution evidence.

Zsh Source `cb645f34b7f80d182699e501738250b7d1d0c43d` is published to its review branch after independent review of four files and raw Git verification of 66 Source and two Data rows. It retains the exact observer/guardian clock correction and adds the builtin carrier and exact-string spec fields. Execution-plan registration and a fresh native trial remain pending; actual builtin metadata remains unobserved. The blocked compatibility proposal and earlier failures remain historical.

### Zsh registration and exact source disposition — 2026-10-14 13:42 UTC

Zsh Source `cb645f34b7f80d182699e501738250b7d1d0c43d` now has a registered plan `bb80b74ce2c1ecc39c55cbb1364fda711a89cc151e48356bde1d44d27e25833b`. Root authenticated 69 administrative artifacts and 11 input pins, checked the committed Source proof and accepted review chain, and verified exact variable readbacks before safely advancing the execution ref. Native trial [38573732820](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38573732820) is pending. Separate static validation 38573732886 passed. These facts do not establish builtin metadata, cleanup, six package builds or M2 compatibility.

The bounded official-source correspondence review and external peer are accepted as an OPEN finding for `systemd262-1/aarch64` and `pacman7.1.0.r9.g54d9411-2/aarch64`. Four retained metadata bodies authenticate, but both candidate recipes differ from the required BUILDINFO hashes. Eight retained official retrieval records supplied no exact selected-build linkage. Root authenticated the 45 author leaves and three peer leaves; it did not reread package archives or reverify signatures. Exact source correspondence and complete licensing remain open. See [source review](reviews/platform-source-correspondence-next.md) and [external evidence review](reviews/platform-source-correspondence-root-review.md).

### FDK diagnostic and signer runtime preparation — 2026-10-14 13:49 UTC

FDK diagnostic Source `7c51adff8716e153967d53586a0dbe666c2f9958` is published with packet `b440a7c8303fe5d524e2a3cd68203ac0bd298a0f8af255eb7907886c0b8a2fef`. Independent review passes 14 fresh groups / 339 assertions. Root authenticated 428 author leaves, six peer leaves and 570 peer inputs, adopted exactly eight files, checked their syntax, and verified all 139 Source rows from raw Git and the remote ref. Native trial [38574961503](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38574961503) is pending. The earlier build-1 inner cause remains unknown; its 397 natural-return observations do not prove 397 successful returns. The new fixed failure categories preserve existing acceptance, first cause, cancellation, cleanup, budgets and private capture custody.

The successful signer compile trial 38564473706 has now passed bounded static instruction/filter review and a finite runtime-plan review. Root authenticated the 36 author leaves / 104 inputs and four external-peer leaves / 121 inputs. The plan preserves the actual 26 test identities, original 8/13-second witness, independent 60-second P0 and 1800-second matrix limits, and disposable TEST-key custody. No compiled output, GPG, P0 or native matrix was executed. A concrete P0/no-key runtime adapter is being implemented in a separate proposal; its Source, runtime admission and native results remain pending.

### CLI first-observation successor — 2026-10-14 13:56 UTC

The CLI first-observation correction is published as Code `5d7e92e897f1b7a7baaf4b60b9768d3c5e41111e` (held), Source `ad2ed5eb1c7e12aefb535a518eeee74d01c6c25b`, and Data `e848d2d3ef23b9394cfc080ee234831aa944cbe1`. The external reviewer closes the original overwrite P2 with 61 focused controls: an established observation stays frozen, a wholly absent pair can recover, and partial state is omitted from diagnostics. Root authenticated 638 author files / 1326 external bindings and 12 peer files, adopted exactly three cumulative Source bodies and two Data files, and verified all 291 Source rows from raw Git. The Data commit is a direct child of Source; Code/bootstrap remain held.

The registration proposal is under preparation. This CLI workflow is manual-only: advancing its execution ref does not start a trial, and a single manual dispatch is required after exact plan registration/readback. No fresh CLI trial has run on this Source. Historical run 38547424804 remains failed with uncertain cleanup and unknown underlying cause; synthetic observation controls do not backfill that cause.

### CLI trial and kernel terminal evidence — 2026-10-14 14:12 UTC

CLI plan `b2ce63404672cbc1279fd99fe77bd03afdc41ed71a0677b4e9bdd0ca085e2be2` is registered and exact readbacks verified against Source `ad2ed5eb1c7e12aefb535a518eeee74d01c6c25b` and Data `e848d2d3ef23b9394cfc080ee234831aa944cbe1`. Root verified the historical plan/ref, safely advanced the execution ref to Source, and issued one manual trial [38578019953](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38578019953), now pending. Its exact API workflow ID, event, ref and Source identity were verified; the API global display name remains native-arm-runner-observation while this Source YAML declares project-private-libraries-cli-v1. No duplicate dispatch occurred.

Kernel trial [38569875890](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38569875890) finished FAIL. Completion `537d47f8d69d827ba287c5a919ad56b44aeb1acfada352dd33850ca00ea17782` retains 13 regular leaves, zero API artifacts and zero evidence frames. Public status reports producer/acquisition/probe/provision passes, baseline worker exit 1, candidate NOT RUN, and owned cleanup/daemon preservation PASS separately. It provides no detailed inner diagnostic or accepted compilation; this run does not prove the previous trial’s natural-zero/output-refusal facts recurred. The current Source emits inner schema4 output_failure but two downstream consumers still accept only inner versions1/2/3. A bounded compatibility audit is underway; that Source gap is not treated as proof of the actual private failure cause.
