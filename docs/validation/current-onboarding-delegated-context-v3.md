# Current onboarding v3 delegated poststart DATA

`payload/native/delegated_context_v3.py` supplies a separate private delegation
API. It makes no actor calls, metadata requests, GPG calls, resource grants or
Root decisions. The existing signed Root trust, normal ALPM, Source, resource and
strict owner supervision requirements remain in force. Frozen owners are unchanged.

The caller must first authenticate the Root delegation through the existing trust
boundary and supply its selected whole SHA256 to
`validate_delegation(raw, expected_sha256, now=None)`. The canonical JSON contract
has schema 3, kind `ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3`, issuer
`Root`, approved true and scope `CURRENT_PRIVATE_STAGE_ONLY`. Those fields are a
declaration inside authenticated input, not authority manufactured by this helper.
Tests use inert invented contracts and public-key placeholders only.

The contract pins `binding.source` (40 hex), `binding.ref`, a byte/hash
`binding.source_lock`, stage and nonce. `run` and `job` are NULL, attempt is 1,
and all three `image_ids` are NULL before dispatch. It contains issuance/expiry
epochs and `programs` entries `context`, `owner`, `image`, `image_executor`, a
`policy` descriptor and nonempty `materials`. Every descriptor has exactly
`member`, `bytes`, `sha256`: a safe relative member of the same closed Source.
No private home location is accepted as a material descriptor.

`capability` explicitly names operation `first-login-enrollment-ui-current-v2`,
stage, `allow_provisional_context`, `allow_provisional_image_checks`,
`allow_pair_adoption`, and positive integer limits `max_command_seconds`,
`total_seconds`, `builder_cpus`, `builder_memory_bytes`, `builder_pids`,
`command_rows`. Each requested limit must be at most the corresponding integer
ceiling in the pinned policy's `stage_capabilities[stage]`. There is no new 180s
command or 1800s total limit: the actual reviewed finite stage policy is the
basis. This does not enlarge any frozen actor's own bounds or establish actual
owner/daemon resource isolation. The image executor must separately prove both
resource domains and obey the same policy.

`context_limits` equals policy `context`, with integer keys
`metadata_query_seconds` (1–30), `metadata_max_bytes` (1–1048576),
`max_context_age_seconds`, `max_delegation_seconds`. These limit only metadata
acquisition/observation and contract freshness, not package build commands.

`hosted` pins repository, workflow_ref, workflow_sha, job_key, job_name,
runner_environment (`github-hosted`), runner_os (`Linux`) and runner_arch
(`ARM64`). The Source commit/ref and controller workflow revision are explicit
separate selectors. Matrix jobs need their complete concrete GitHub job name.

## Poststart integration

`capture_context(raw, sha256, source_root, *, environ=None,
jobs_response=None, now=None)` checks the actual canonical Source root against
the complete fixed map/lock aliases, all file bytes/modes and closed membership.
It excludes only root `.git` metadata. Limits match the current v3 constructor:
256 files, 64 MiB/member, 128 MiB total, 1 MiB/map. It checks its executing body
against `programs.context`; it imports no produced Source code. Reads compare
device, inode, mode, links, uid, gid, size, mtime and ctime, excluding read atime.

It reads only the explicit hosted environment allowlist in `ENV`, never runner
credentials or arbitrary environment entries. `GITHUB_JOB` is a job key, not an
invented numeric ID. A reviewed caller supplies this bounded response abstraction:

```python
{"url": "https://api.github.com/repos/OWNER/REPO/actions/runs/RUN/jobs?filter=latest&per_page=100",
 "status": 200, "body": b"actual complete response bytes",
 "received_epoch": actual_integer_epoch, "elapsed_ms": actual_integer_duration}
```

The helper has no network implementation. The caller's reviewed acquisition must
perform that exact public metadata request within its separate finite budget;
no token or token-derived alternate endpoint is accepted. It must not synthesize
the response from environment fields. Hashing a caller-supplied body is not
independent provider authentication. The result is deliberately provisional under
Root's explicit private delegation. The response must be complete in one page
(at most 100 jobs), fresh, uniquely match pinned job name and actual runner name,
and join Source SHA, numeric run, attempt 1, numeric job and fixed provider URLs.
The selected job must currently be in progress without a conclusion.

The returned context includes `binding={source,ref,run,job,attempt,source_lock}`,
stage/nonce, actual `source_root`, whole delegation/program/policy pins, the
allowlisted hosted values, original UTF-8 response body and whole body pin.
`validate_context(delegation, context, *, now=None)` replays every join and checks
freshness; callers pass the previously authenticated delegation, not a replacement
chosen by the context itself. `issuer` is `DELEGATED_CONTEXT_PROGRAM_V3`;
`Root_final_acceptance` is NULL, and independent_component_acceptance,
hardware_acceptance and release_acceptance are false.

`resolve_material(delegation, source_root, role)` and `material_reference(...)`
derive a real path solely from the validated root and reviewed member. They do
not rewrite historical Root proof bodies to claim those newly derived locations.
Consumers still read/hash their actual inputs at use time. Newly produced output
receipts are separate poststart DATA, not retroactively pinned Source members.

## Pair adoption integration

For a UI delegation permitting pair adoption, `pair_policy` pins the complete
backend `producer_delegation_pin`, uppercase 40-hex `test_fingerprint` and a
`test_public_key_role` in its Source materials. The backend delegation exists
before its future job IDs are known. `adopt_pair` takes the consumer context,
whole producer delegation bytes, actual producer context, whole pair JSON bytes
and whole TEST proof JSON bytes. Both contexts must replay, have the same actual
Source/ref/run/attempt/map, and identify the backend producer stage; their actual
job IDs may differ.

Pair kind is `DELEGATED_CURRENT_ONBOARDING_PAIR_V3`; proof kind is
`DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3`. Both use schema 3, issuer
`DELEGATED_CURRENT_OWNER_V3`, producer binding/nonce, reviewed owner `program_pin`
and `policy_pin`, with the same unset/false final acceptance fields as context.
The pair's `archives` contains two complete byte/hash pins which must be equal,
and `matching_pair` is true. The TEST proof joins whole `pair_pin`, the selected
`public_test_key_pin`, `fingerprint`, `trust_scope=TEST_ONLY`, and exactly two
`verifications` rows. Each row joins its whole archive/signature pins, retained
strict primary `status` text and natural `supervision` receipt. The parser rejects
bad/expired/unknown signer status and requires the exact primary fingerprint and
explicit TEST trust, using the current family's existing strict status contract.

This validates the reviewed owner's retained verification observations; it is
not a new detached signature verification. The reviewed owner still performs
actual strict GPG/trust checks, actual archive comparisons, normal ALPM and
natural supervision. The new owner/route adapter must produce these receipts
from those actual operations and explicitly consume the delegation; an arbitrary
receipt's `issuer` or program hash alone cannot authenticate its acquisition.
The adoption result remains delegated TEST-only DATA, never Root issuance or
independent image/component/hardware/release acceptance. Existing gates expecting
literal old Root observations must not be satisfied by relabelling these fields.

Tests: run `python3 payload/native/test_delegated_context_v3.py` from the family
directory. All fixtures and provider responses are temporary inert DATA. Real
poststart acquisition, image executor/owner integration, Source export/dispatch
and Root's final independent decisions are separate work.
