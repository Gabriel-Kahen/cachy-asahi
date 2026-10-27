# Exact retained Git DATA transport

`scripts/maintenance/retained_git_transport.py` provides `deliver(...)` and a small
HTTPS CLI. It performs one depth-one exact-commit fetch into a fresh private DATA
directory disjoint from the executable checkout. It never checks out, imports or
executes fetched source. Hooks, attributes, filters, submodules, global/system Git
configuration, environment credentials, replacement objects and lazy fetching
cannot supply executable behavior through this API. The caller must trust its
installed Python/Git and source-owned API, and retain exclusive child wait custody.

## Source attribution and deliberate changes

This implementation adapts these MIT-licensed project sources under
`artifacts/development/offline-batch129-input-transport-integration-fix-development-20261027/`:

| Source | SHA256 | Reused contract |
| --- | --- | --- |
| `proposal/owner.py` | `5e43a7f5623cfb6ecb65c1acd238a4a0526b057f0658d601c688ff9b5b900480` | One fetch, external fresh DATA, finite 400/480-second allocation, retained failures |
| `source/scripts/ci/setup6-retained-helpers/legacy_prefill.py` | `05a91a91efd69b3b2e06561f5bbf08bdbb105998d42dbf133e75fd1fe25945ac` | Full filesystem membership, commit hash, reconstructed recursive tree, every Git/blob/SHA256 join |
| `source/scripts/ci/setup6-retained-helpers/carrier-profile.json` | `4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c` | Existing source-only `schema/actual/source/ref/files/modes` descriptor; unchanged input format |

Canonical dependency `scripts/virtual/owned_process.py` has SHA256
`80547f753dc7d13819d727783c669d10a56b7bf832dc05084b5c4b5302cb79d9`.
Its `prepare()` runs before every launch; its reserved-child `supervise()` owns
every subsequent wait, probe, retirement signal and reap. This module never polls,
waits or signals the transferred child itself. UNKNOWN/ECHILD can never pass.

The reference profile binds commit
`ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad`: all 1,154 materials,
1,046,432,165 body bytes, including 1,148 package/signature files. Transport cannot
replace that closure with a selected-package subset. This packet validates the
profile metadata only; it does not read, download or execute that existing large
carrier. Historical 13–15-second fetch successes and two 120-second failures are
context for an operator allocation, not an upper latency bound or network cause.

Changes from Batch129: delivery materializes raw blobs instead of Git checkout,
uses the shared supervisor instead of local group/wait code, pins one immutable
profile before any destination mutation, and finishes the whole Git/filesystem
proof inside the transport. There is no seed helper, package cache mutation,
GPG/ALPM, native owner, build, install, trust or release admission here. Existing
native owners retain their original preparation/authentication gates after DATA
delivery; importing this API does not grant permission to execute delivered code.

## API and clean-checkout use

After integration, no historical packet is a runtime dependency. Imports require
only the standard library and canonical sibling `scripts/virtual/owned_process.py`.
From the repository root:

```sh
python -B scripts/maintenance/test_retained_git_transport.py
```

Use a caller-reviewed profile and independently held whole-profile SHA256. The
profile's source must equal the separately supplied 40-hex expected commit. Its
complete file map uses exact `bytes` and SHA256 descriptors; executable modes are
derived from the immutable Git tree, never guessed from the local umask. Ref and
optional modes labels are retained descriptive inputs, not mutable fetch refs.

```python
receipt = transport.deliver(
    url="https://github.com/OWNER/REPOSITORY.git",
    expected_source=reviewed_commit,
    profile_raw=reviewed_profile_bytes,
    profile_sha256=independently_held_sha256,
    destination=Path("/absolute/private/NEW-delivery"),
    executable_root=Path("/absolute/closed-executable-checkout"),
    policy=transport.reference_policy(),
)
data_path = receipt["data_path"]  # full ordinary DATA plus data/.git
```

The executable root must contain this source-owned module. The destination and
its parent must be absolute ordinary paths, with an owned parent not writable by
group/others. The destination must not exist, even after a failed invocation.
The fresh root is mode 0700. Existing output is never adopted, retried, resumed,
repaired, overwritten or deleted. Failure raises `Error` and retains whatever was
created; preflight refusal creates nothing. Root identity loss fails closed and
writes its receipt through the still-held original directory descriptor.

The CLI accepts only public credential-free standard-port HTTPS, without query,
fragment or redirects. File/SSH/remote helpers are disabled. Example:

```sh
python -B scripts/maintenance/retained_git_transport.py \
  --url https://github.com/OWNER/REPOSITORY.git \
  --expected-source REVIEWED_40_HEX_COMMIT \
  --profile /absolute/reviewed/carrier-profile.json \
  --profile-sha256 INDEPENDENT_PROFILE_SHA256 \
  --destination /absolute/private/NEW-delivery \
  --executable-root "$PWD" \
  --policy '{"fetch_seconds":400,"transport_seconds":480,"outer_seconds":500,"reason":"Reviewed full-DATA one-fetch allocation; no latency guarantee"}'
```

The API's explicitly labelled `fixture_local=True` enables an owned local
`file://` repository for tests only; it is not exposed by the CLI. Local fixtures
never establish public transport, signature, native or production evidence.

## Bounds and raw receipts

The operator must specify finite `fetch < transport < outer <= 3600` seconds and
a reason; there is no unbounded/default retry. Reference policy is 400/480/500.
The transport clock starts on API entry and covers qualification as well as
fetch. Per-child caps include reserved retirement time. The outer value records
the caller's promised wrapper budget; the caller must enforce that outer clock
and provide its own shutdown/retention path. This API cannot guarantee retirement
after its hosting process or host is killed.

Profiles are at most 2 MiB; at most 4,096 materials, 128 MiB each and 2 GiB total.
Only bounded ASCII relative paths and ordinary Git modes 100644/100755 are
accepted; symlinks, Gitlinks, aliases, hardlinks and extra/missing files fail.
Every material is SHA256-checked, joined to its Git blob SHA1, and rechecked in the
final exact filesystem namespace, including mode. The complete recursive Git tree
is reconstructed and joined to the fully hashed expected commit. Bare `.git`
metadata remains present with an exact detached HEAD for existing explicit
`--git-dir` proof consumers; no worktree checkout/index/filter operation runs.

Diagnostic output is pipe-bounded at 4 MiB per command by the canonical
supervisor. Non-blob stdout/stderr are merged at spawn and preserved unchanged in
numbered logs; the receipt explicitly labels the merged stream and retains an
empty separate-stderr file. Blob stdout is a size-bounded regular file; its exact
raw bytes become the material after verification using no-replace link/unlink.
The numbered command receipt points to that material as its raw stdout, retaining
raw stderr separately. This avoids duplicating 1 GiB of material just for logs.
Git packfiles have a separate finite 2 GiB + 128 MiB file-size limit; the final
ordinary Git metadata aggregate has the same cap. A diagnostic cap never limits
a legitimate packfile. These are storage bounds, not measured Git wire volume.

`expected-profile.json`, numbered raw logs and `receipt.json` remain outside the
DATA subtree. A failure receipt retains raw ownership/reap/timeout/signal/census
facts, partial command rows and explicit failure status; incomplete logs are not
upgraded into complete output evidence. Success requires every supervised command
to pass naturally, with complete output, exclusive reap and the canonical group
observations. The receipt makes no global escaped-child or zombie-absence claim.

Directories are private caller-owned storage, not isolation from root or another
process with the same UID. Preserve exclusive access through proof and consumer
handoff. Source identity checks cannot substitute for signature authentication,
source/legal review, build/runtime validation or native/M2/release acceptance.
