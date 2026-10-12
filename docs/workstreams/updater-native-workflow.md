# Separate finite updater native workflow

Status: **Updated workflow draft against held stage `64ce7f…`; bounded consumer checks pass, independent final review and coordinator committed closure pending. The earlier hosted trial38232511202 remains FAIL before compilation; this correction has not run natively.** Only `.github/workflows/native-arm-updater.yml` and this document belong to this assignment. No initial/development source, package, wrapper, shared lock, Git registration or dispatch is changed here.

The [wrapper contract](updater-native-stage.md) owns private materialization, authenticated source/runtime/broker operations, two native builds, scoped resource recovery and guarded public projection. The package's 64-file checkpoint, ready-map `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2`, eight root pins, base snapshot `3c16c37d…`, thirteen-package extension and exact 354-package inventory remain its prerequisites. This workflow does not replace those gates. The unresolved macOS notices and package/vendor publication blockers remain open.

## Runner and exact provenance

The workflow is manual-only, restricted to the named public repository, with `contents: read`, pinned checkout `3d3c42e5aac5ba805825da76410c181273ba90b1`, credentials persistence disabled and the existing `native-arm-build` concurrency group with cancellation disabled. It selects the standard `ubuntu-24.04-arm` runner. GitHub documents this public runner as a new VM with four CPUs, 16 GB RAM and nominal 14 GB SSD; standard public runners are free. [GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

Actual free capacity must satisfy the wrapper's 10 GiB output/8 GiB Docker checks and 18 GiB requirement on a shared filesystem. The advertised capacity does not establish those checks; insufficient actual space refuses before the private trial. This workflow does not remove host software or shared Docker data to create space.

The caller supplies a reviewed full `source_commit`; it must equal `GITHUB_SHA`, the explicitly checked-out ref and the source helper's actual Git HEAD/blob/mode/closed-inventory checks. Before each CLI invocation, the shell independently checks `stage.py` against its reviewed literal digest. Freeze authenticates `source.py` before its first import and binds package/helper/stage bytes, budget, host/boot/socket and executable identities. Its fresh controller stays outside the checkout under an owned 0700 `/tmp` control directory, with an independently recorded controller hash.

The coordinator accepted the corrected ten-file owner checkpoint `c159cc3`, with **136 source tests PASS, zero skips** and independent UN1 closure. The subsequent scan-race/finite-diagnostics owner correction reports **163 source tests PASS, zero skips**. This workflow now embeds the corrected literal bootstrap hashes: `stage.py` = `64ce7f7c93dd0b37971d0810801241dbd10df6098c14b0106c63d284fbd0ca9a`; `source.py` = `259b13b210123d90f824f21bf7662785d50c7586519a78451ab62e97ec577d5f`. The corrected broker is `0291f10d605d50914f5551787839c823ace8fe96439f9940eb56a569fad6d98e`; its bytes are bound by the controller's complete committed source closure. The workflow does not execute the broker directly or substitute its wire protocol. These implementation/source results do not establish corrected native execution or compilation. Run and cleanup use the same external controller pin. Cleanup independently hashes the current bounded ownership record after the run has exited and passes `--ownership-sha256`; it never infers authority from an arbitrary directory or process name.

## One aggregate deadline

The coordinator clarified that the earlier 180 minutes was a generic ceiling. The draft uses a **116-minute job timeout**, below the wrapper's documented two-hour outer-lifetime requirement. The first trusted step records a monotonic deadline **115 minutes later, before checkout**, reserving one minute relative to the configured job timeout. This measures time since that step, not GitHub's VM provisioning/decommissioning latency.

Every subsequent ceiling is recomputed from that same deadline:

| Phase | Maximum and reserved remainder |
| --- | --- |
| Checkout/bootstrap/freeze | Bootstrap step at most five minutes; freeze process at most 270 seconds plus 13 seconds force-stop, with 550 seconds still reserved |
| Private native run | At most 110 minutes including 190 seconds deferred TERM cleanup; subtract another five minutes for recovery/public handoff before choosing the TERM deadline |
| Owned recovery | At most three minutes including a 13-second force-stop margin; reserve two minutes for public verification |
| Public verification | At most two minutes including a 13-second force-stop margin, bounded by the remaining aggregate deadline |

If the clock cannot leave the cleanup/public reserve and at least 60 seconds of execution plus the 190-second native teardown allowance, the run refuses before invoking the wrapper or creating raw output. The phase ceilings are not summed into a larger allowance. The wrapper's 6,900/7,100-second internal constants stay unchanged; this workflow can cancel earlier and does **not** guarantee a full worst-case native budget. TERM/KILL, failed recovery, ambiguous ownership, capacity failure or cancellation remain failure outcomes.

The private trial uses the job's dedicated ephemeral local Docker daemon through the wrapper broker's fixed endpoint and reviewed command shapes. No host package installation, service/updater execution, global process/GPG kill or Docker prune is added. Registered resource absence and scoped raw cleanup are the wrapper's evidence. Ephemeral runner disposal remains a platform dependency, particularly for unregistered intermediate/cache layers and stalled hosts; job timeout is not a measured hypervisor disposal or forensic erasure guarantee. [GitHub cancellation behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)

## Recovery and public evidence

The always-step first invokes bounded authenticated `cleanup`, immediately after run exit. Its stdout/stderr, the controller, ownership record and run/freeze streams remain private. Recovery PASS attests cleanup only and cannot promote a failed or cancelled native run. No post-cleanup project/guard/bundle operation is invoked through `public_worker.execute()`: its original operations already ran while the private authenticated snapshot existed.

The small post-exit consumer authenticates the same controller/source and reuses verified checkout bytes for the existing public-tree checker, selector declarations, generic credential guard and bundler. It supplies no replacement projection or credential policy. Before emitting evidence it verifies:

- Strict duplicate-key/nonfinite JSON rejection and exact bounded owned, singly-linked JSON file sets; complete PASS export manifests; no rejection/extra entries; exact byte/hash accounting and limits.
- Canonical terminal source/ready/controller identities, finite outcome fields including the exact legitimate `RuntimeFailure` class, finalized state and cleanup/retention/cancellation predicates. Missing or incomplete recovery evidence cannot produce workflow PASS; valid original diagnostics remain eligible for retention when the recovery pair was revoked. On non-PASS outcomes, retention may be absent as in the producer’s early recovery failure; any present retention value stays boolean and PASS still requires it true. If forced termination leaves no complete original terminal file pair, the independently validated recovery terminal is retained alone; no guarded group/original bundle is emitted without the original terminal binding, the summary records native evidence `NOT ATTESTED`, and the aggregate remains FAIL.
- Only the projector's fixed guarded receipt names plus `projection.json`/`materializer.json`; each captured receipt must round-trip exactly through its authenticated pinned selector sanitizer. The finite inverse handles only the selector’s declared public transformations (counts, Cargo identities, inventory, tools, acquisition and package metadata), enforces its list/node/depth limits, and supplies inert data without filesystem reads. Exact serialized equality refuses extra fields and boolean/integer confusion. Materializer metadata must equal its pinned sanitizer output. The projection manifest has exact fixed fields, limits/retention policy, ordered accepted/missing selector names, and byte/hash accounting for every retained receipt. No private/vendor/cache/source/log/package/key subtree fallback.
- Existing public bundle size/hash against the original terminal and exact regular tar members/content against guarded JSON, without filesystem extraction. Global PAX metadata and member metadata other than finite numeric mtime are refused.
- A successful native pair and all three comparison booleans with zero comparison errors before accepting an original stage PASS.

The optional terminal diagnostic triplet is `failed_phase`, `runtime_reason`, `runtime_returncode`; optional `tick_operation`/`tick_reason` must occur together with `runtime_reason: tick-failed`. The consumer invokes `diagnostic_projection()` from the externally authenticated stage bytes and requires exact equality for the five captured fields. Its exact phase/reason/tick enums are the [owner’s finite schema](updater-native-stage.md#public-failure-diagnostic-schema); no local permissive string validator is substituted. Return code is null or a literal integer from -64 through 255, never a boolean. Missing diagnostics remain compatible with historical success/failure/recovery receipts. Diagnostics do not alter source/controller authority, original/recovery roles, retention requirements or aggregate PASS predicates. Unknown/partial/poisoned diagnostics refuse evidence before any bundle is printed.

Captured JSON passes through the unchanged authenticated credential guard again. Publication uses bounded free-log evidence markers only: bundles rebuilt from re-guarded JSON for the guarded and canonical terminal/recovery groups. The original tar bytes are never transmitted, including opaque padding or header fields. Each marker records the rebuilt bundle digest; the terminal retains the verified original bundle digest as an input reference. No artifact/cache upload, image export, registry publication, binary/package/vendor source or raw output is selected.

Workflow PASS requires the original native and recovery terminal PASS predicates, actual zero run/cleanup exits and the native step's successful outcome. Public recovery success alone is insufficient. Every terminal continues to say publication **NOT ACCEPTED** and hardware **NOT RUN**. Rust native compilation is not installation, target dependency acceptance, tray/updater runtime behavior, M2/16K compatibility, performance or production publication.

## Verification and remaining handoff

Four shell blocks pass `bash -n`; all three embedded Python bodies pass AST parsing. **147 isolated consumer fixtures PASS**: bound success, failure/cancellation and missing recovery, wrong identities, unknown fields, symlink/hardlink/unlisted files, bundle/content drift, credential content, comparison/cleanup failures, duplicate keys, nonfinite constants/numeric overflow, boolean schema/error-count confusion, foreign tar members, global/member PAX metadata, opaque input padding that never reaches rebuilt output, legitimate `RuntimeFailure`, missing original with successful/failed recovery, missing both terminals and invalid recovery, empty/partial original and recovery pairs, actual optional retention on early failure, all pinned selector transformations/materializer round-trips, coherent unknown-field attacks in native/projection/materializer/nested package/units, inventory digest/type drift, out-of-range inverse counts and reordered missing selectors. These fixtures use private temporary JSON/tar data and authenticated helper bytes with host/source authentication mocked; they perform no Docker, materialization, native build, installation, service, trust or network operation.

All 40 clock-expression boundary fixtures PASS, including native refusal below the 550-second minimum remainder; no timed teardown is claimed. Eight unchanged owner Python files still match committed `c159cc3` bytes and executable modes; the two owner-changed files match held stage `64ce7f…` and test `9dfc1a…` at mode `0644`. This worker did not change them. Local receipts are `/tmp/cachy-updater-workflow-check-0mc69ljr/consumer-results.json`, `syntax.json`, `deadline-results.json` and `owner-source-proof.json`. Full YAML parser/actionlint checks are **NOT RUN** because those tools are unavailable; workflow keys/actions/expressions received a manual source review. Independent review closed after the duplicate/nonfinite JSON and raw tar metadata corrections; it independently repeated the four shell/three Python syntax checks and reviewed the original 27-fixture receipt. The coordinator then reproduced UW1 (`RuntimeFailure` refusal) and UW2 (missing original terminal discarded valid recovery); those corrections now include empty/partial original pairs. UW3 additionally reproduced arbitrary extra bytes in a named guarded JSON receipt despite a coherent self-hashed manifest/bundle; exact pinned-sanitizer round-trips and finite metadata bindings close that gap. The actual early-recovery optional retention field is preserved only for non-PASS outcomes. The original 48 isolated fixtures still pass, including symmetric empty/partial recovery replacement. The correction adds 99 finite-diagnostic cases: every admitted phase/runtime reason/operation-specific tick reason, return-code boundaries/null, rejected booleans/wrong types/partial fields/unknown enums/poison, new recovery diagnostics, historical success without diagnostics, and unchanged strict PASS cleanup requirements. All 147 cases pass and emitted terminal bytes equal the independently captured input terminal bytes. Final independent review of this corrected bootstrap/schema handoff remains pending. Coordinator clean-checkout acceptance, registration and dispatch remain required. This worker performs none of those mutations or any native trial.

## Coordinator source acceptance

The coordinator accepts workflow SHA256
`9638f48e601159f09207a5096381484e959372ea0e62259e235d43f3576ad9ed`
after the independent final UW1–UW4 closure, symmetric recovery checks and
48 isolated consumer fixtures. The coordinator repeated all 48 fixtures and
the actual yaml-cpp parser/structural assertions; they pass. The reviewer also
verifies the unchanged 85-file committed closure and ten stage files.
[Independent final review](../reviews/updater-native-workflow-review.md) records
strict PASS retention, coherent poison refusal and failure/recovery boundaries.
Registration and actual hosted execution remain separate next steps; source
acceptance grants no native, installation, publication or hardware PASS.

## Registered workflow and first actual native trial

The one-file [registration PR3](https://github.com/Gabriel-Kahen/cachy-asahi/pull/3)
merged at 09:50:24 UTC on 2026-10-12, main commit
`91e75780eade61732c3f06b7a318ce86ee12860e`. Its isolated registration head
`ea2711b9eb39ebe82904db6d54f9a214c6613810` changes only the 290-line workflow;
source and roadmap files on main were not part of that PR. The coordinator
verified the development source at
`ea274b800be2d701511cf23692afb53482b2f709` using actual `source.collect()` and
`source.verify()`: all 85 committed files/modes and 3,875,628 bytes match.

The first actual [ARM trial38232511202](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38232511202)
was created at 09:50:48 UTC and completed **FAIL** at 09:51:56 UTC. Source
bootstrap/controller freeze passed. The materializer actually downloaded all
168 inputs, completed all 167 registry sources and reproduced the reviewed
sanitized/vendor hashes on Ubuntu Python3.12.3/zlib1.3. Its fixed public receipt
reports PASS and 323,117,153 vendor bytes. The native pair did not compile:
its projected receipt remains STARTING at input-validation, and the canonical
terminal reports RuntimeFailure, native compilation NOT RUN and 49 elapsed
seconds. This does not identify the precise validation/launch fault.

The original terminal records private deletion, retention and cleanup PASS;
the subsequent recovery receipt is PASS and explicitly does not attest native
compilation. Three bounded public bundles were retained: guarded 25,061 bytes
(`0de38693bf45e5505c6bb04d182c6a37449e218195fcb4e8dc198915ddb081ae`),
terminal 965 bytes
(`db436d7f93a855a845444cf40b77da2393ddd32a3611f290b84c844e9f4c0e52`),
and recovery 846 bytes
(`afd1baec99658c5f76dddc4b22f775192528567925729060948b20c1fc290fba`).
The coordinator independently revalidates all nine captured public files,
manifest hashes, exact selector schemas/metadata and terminal role bindings in
[the retained public verification](../../artifacts/ci/38232511202/root-public-verification.json).
Private controller/original private bundle bytes were not exported and are not
independently consumed by that check. The aggregate remains FAIL; the updater
owner is investigating against these bounded observations before any rerun.

## Corrected finite dispatch

The coordinator committed this corrected workflow in `ca414c8`, then verified the actual 85-file source closure at dispatch commit `756881b917ef68c614fcfb081debadf82282e80b`: **3,915,170 bytes / exact Git blobs and modes PASS**. Root replayed147 fixtures and actual yaml-cpp contract parsing PASS. Proof: `artifacts/reviews/fdk-updater-corrected-dispatch-source-proof-20261012.json`. [Trial38239531158](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38239531158) was created2026-10-12T10:57:15Z with that exact commit, workflow `78f9d914…` and stage `64ce7f7c…`; it initially waits behind FDK in the serialized build group. Dispatch is not compilation or acceptance.
