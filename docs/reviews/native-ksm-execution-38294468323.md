# KSM4 native execution 38294468323: independent diagnosis

Disposition: **PASS for retained archive/source attribution and bounded diagnostic
controls; actual execution remains FAIL.** The source proof passes and the new
records narrow the failed boundary to RPC6 reply delivery after a successful
broker inventory return. They do not establish the producer's primary exception
or a specific hosted timeout cause. Producer acceptance, both KSM builds,
comparison, lifecycle, management and public export remain NOT RUN; ownership is
UNCERTAIN and cleanup remains FAIL. No M2/16K, KSM activation or performance result
follows from this review.

## Exact retained authority

Actual checkout/log/terminal references identify commit
`0722dd9a409b6001bfbb26a3cce4e6b56e8a576d`, packet
`68c1bb02ea10317cb6b65140fc133fab1c9e2e834de11a7bfd665ba4abbfd179`
and unchanged workflow
`ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`.
Independent Git blob/tree-mode reads authenticate all 152 packet rows and their
2,284,026 bytes, plus the 30,596-byte packet itself. The copied committed tree
has 153 files; packet source modes are 149 at 0644 and 3 at 0755. No shared checkout
substitution or PYC is used. Exact identities are in
[source-capture.json](../../artifacts/reviews/native-ksm-38294468323-root-peer/source-capture.json).

The compressed log ZIP was independently reread: SHA
`dc89f8697e0b7dcbcbb02e41ae3bc1208bf2099a1bee3667a32bd6cf8b10adc6`,
seven unique regular bounded members, 54,907 decoded bytes, valid CRCs, no
traversal/link/encrypted members. Every member matches the retained index and
extracted bytes. The combined workflow log is 27,056 bytes, SHA
`c6ebe7bb7ac60edf80b511411a3f91ebc6166439a2fdd21441eb7cf360bf127e`.
Its sole terminal record matches retained terminal-status.json and the coordinator
report. [Archive checks](../../artifacts/reviews/native-ksm-38294468323-root-peer/archive-checks.json).

All 91 printed workflow command lines match the committed inline block. The
prelaunch committed bootstrap proof has exact source/packet/count fields. An
independent replay of that exact block intercepts only the final executor execve;
its unchanged source/Git checks and fresh 152-file bootstrap byte/mode inventory
pass. No executor, Docker or native producer is launched by the replay.
[Bootstrap evidence](../../artifacts/reviews/native-ksm-38294468323-root-peer/bootstrap-peer/README.md).

## Actual public observations

| Boundary | Retained observation |
| --- | --- |
| Terminal |FAIL / producer / BrokenPipeError; cancellation false |
| Source startup |pipeline-source-verification; no source failure reason |
| RPC |6 requests, not saturated; RUN6 at REPLY_FAILED |
| Broker request return |code0;6,674 stdout bytes; SHA89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f |
| First/last failure |BrokenPipeError at REPLY / PRODUCER, both RUN6 |
| Last CLI record |IMAGE_INSPECT at ordinal 6;code1;118 stdout bytes; SHAdd8466657aad6267dcd2870ef7320fcd8169fb29440acc83e26b736f328bbaa2 |
| Producer handle |started true; natural_poll_code null; runner_return_code null |
| Owned reaping |COMPLETED; reaped_code 1 |
| Returned cleanup |containers_absent true; owned_image_absent true; error_category null; owner_failed true; status FAIL |
| Acceptance/publication |producer NOT RUN; mutation UNCERTAIN; public export NOT RUN; published false |

The6,674-byte request-return digest matches independently rehashed historical
341-package lock bytes. This identifies the broker-returned inventory value;
it does not prove those bytes reached the shim/producer or that its private
packages.lock was written. The broker records its result before sending the RPC
response, and that send then failed.

The last CLI slot is mutable through cleanup while the request ordinal stays6.
An independent exact-source control completes a RUN result, fails its reply,
then performs cleanup: the slot becomes IMAGE_INSPECT/code 1/118 bytes while the
successful RUN request return remains. Source accepts code 1 with exact folded
absence text for its final owned-image absence query. Thus this CLI record may
be expected later cleanup, not a failing inner operation of RUN6. The actual 118
bytes and image target were not exported; their hash does not supply their text
or prove this attribution. [Closed-schema and overwrite controls](../../artifacts/reviews/native-ksm-38294468323-root-peer/diagnostics-peer/report.md).

The Runner calls the synchronous service before its normal producer poll. A
reply exception skips that poll/return path, then its existing finally disposes,
reaps and drains. Actual natural_poll_code and runner_return_code therefore
remain unobserved, while reaped_code 1 is a separate cleanup observation. Do not
promote it to an originally observed natural exit or infer its exception.
The producer NOT RUN label is the unaccepted initial phase value; started true
proves it is not evidence that no producer process started.

Returned absence booleans are source-bound declarations of completed cleanup
queries, distinct from sticky owner failure. The private journal/IDs/query bytes
are unavailable for independent replay, so they are not complete private
ownership/absence proof. Baseline preservation PASS covers six protected
identities, not owned-object acceptance or the nine unowned images, which remain
NOT VERIFIED. Legacy build-cache absence stays NOT ESTABLISHED.

## Caller-timeout candidate and its limits

The unchanged original native_arm.run delegates no-log commands to
subprocess.check_output. Its inventory invocation requests timeout 60. The
unchanged shim CLIENT_TIMEOUT 2600 applies inside that child; it cannot override
the producer's outer 60-second wait. Broker RUN wraps before-run baseline checks,
image ownership, create/inspect/start, natural container-state verification,
removal/absence and after-run baseline checks before returning the response.
The producer's 60-second limit covers that whole shim call, not merely the
container's inventory command. Runner service polling is synchronous and cannot
observe the producer's natural poll while that callback is executing.

Four bounded harmless controls use the exact captured original run AST, exact
shim and exact Service.handle with a modeled delayed request. The run still
requests 60; an explicitly labeled test-only .12-second subprocess boundary
stands in for the caller deadline. It kills the shim while the modeled request
continues to return the known 6,674-byte inventory/code0; the exact service then
raises BrokenPipeError and records RUN/REPLY_FAILED. A two-second test boundary
with the same delayed reply succeeds. These are controlled local Python/socket
fixtures with no Docker/native producer or package execution. They demonstrate
this mechanism can produce the observed diagnostic pattern; they do not prove
KSM4 exceeded its actual 60 seconds.
[Reproducible causal controls](../../artifacts/reviews/native-ksm-38294468323-root-peer/causal-peer/README.md).

The native step header is18:58:16.3288020Z and its terminal line is
19:05:36.2611824Z on October 12, 2026, an overall interval 439.932380 seconds. The
combined-log terminal timestamp is19:05:36.2611954Z; the step exits1 immediately
afterward. This interval includes source bootstrap, all producer work and
cleanup. No RPC6/caller-start/return timestamps or primary producer log were
exported, so it cannot allocate a60-second wait or identify TimeoutExpired as
the actual producer exception. KSM3's underlying cause remains unknown.

## Finite next observation

Before repeating a native trial, select a minimal closed observation that
separates the original caller failure from the later response EPIPE: candidate
command family, requested caller timeout, bounded elapsed milliseconds and
closed original caller exception category at the existing original run boundary.
Keep raw argv/log/paths/IDs private. Preserve the original 60-second budget and
mandatory ownership/cleanup checks. Also label whether the last CLI observation
was made during request handling or cleanup, so a retained ordinal cannot imply
an unavailable chronology. New wrapper/projection/source grants require separate
review and coordinator binding; none is implemented here.

The proven fixture is sufficient to justify this observation, not an actual
cause-specific transport fix, timeout widening, response retry, early success
reply or acceptance bypass. If a later actual record establishes caller timeout,
review the complete request's work and cleanup reservation against the existing
caller budget instead of silently extending the frozen producer limit.

Independent diagnostics validation passes 14 focused/captured controls with zero
skips, 42 malformed/type/extra/cap negatives and the 900-byte closed actual record.
Causal controls pass 4/4 with zero skips. All152 source rows/modes remain unchanged,
owned socket fixtures are removed and no PYC is retained. The diagnostics peer's
initial synthetic absence-text length assumption failed; that log is retained,
and a source-accepted118-byte fixture passed without a guard change. The 174 retained KSM3
files/document remain unchanged, as does review873b and its evidence. No source,
shared map, workflow, Git mutation, native dispatch or actor rerun occurred.
Actual KSM4 remains FAIL; its primary cause and complete private cleanup proof
remain unresolved.
