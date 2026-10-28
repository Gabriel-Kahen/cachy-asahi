# Private coordinated platform preparation

`prepare_transition.py` connects an exact compatible data plan to actual private
ALPM preparation. It freshly authenticates every package input first. It never
commits, installs payloads, runs hooks/scriptlets, reads the host package DB or
changes boot/platform files. Existing planner and Python-only APIs are unchanged.

## Runtime and strict contract

Use Linux/POSIX Python with **libalpm16.0.1**, real `vercmp`, `gpg` and `gpgv`
already installed. The earlier planner-only Ubuntu/libalpm13 proposal cannot
qualify this adapter. `transaction.Alpm` retains its16.0.1 gate. The only new
bindings are `alpm_get_localdb` and `alpm_remove_pkg`, reviewed against the
installed header. No commit, download or archive-loader API is bound.

The strict contract has exactly these fields:

```text
schema_version: 1
transition_contract: REF
transition_report: REF
runtime_sources: REF
certificates: {alarm: REF, community: REF}
```

A REF is exactly `{path: ABSOLUTE_PATH, size: POSITIVE_INTEGER, sha256: HEX64}`.
Supply the known certificate labels needed by the packages. Public-certificate
bytes and expected primary fingerprints must match `authenticate_missing.KEYS`.
Arbitrary test keys, modified certificates and replayed success claims cannot
satisfy admission. No keyserver, default keyring or ownertrust change is used.

The transition report must be the exact planner CLI report for the referenced
contract, including its contract digest. The command recomputes the plan and
compares all operational fields exactly. Only source path relocation and the
CLI digest envelope are normalized; direct helper hashes must match. Require
`PASS-offline-data-plan`, true `software_data_bound` and no conditions. This is
metadata/data compatibility, not tested Apple platform compatibility.

The source manifest is a reviewed, checksum-bound JSON document:

```text
{schema_version: 1, kind: "private-platform-prepare-source-closure",
 files: {"scripts/platform/prepare_transition.py": SHA256, ...}}
```

Its exact16 repo-relative paths are `prepare_transition.SOURCE_FILES`: the
original15-source planner runtime plus the new entrypoint. It includes actual
verification, status parsing, process control, package-check, preview and release
implementations. Every hash is checked before assessment/authentication and
again before reporting. Executed entrypoint/planner paths must match the bound
runtime paths. Preserve reviewed hashes instead of silently refreshing them.

Before any project helper import, the entrypoint creates a fresh private
bytecode-cache prefix and propagates it to workers; bytecode writes are disabled.
This prevents existing PYC from replacing the source being hashed. `-B` alone
would still permit stale PYC reads. Cache scratch is removed at process exit.
Use a private `TMPDIR` for explicit custody of all temporary paths.

## Archive, policy and recovery admission

Every before and candidate package, including unchanged providers, needs its
exact archive, detached signature and original provenance row. Incomplete
coverage refuses even where the planner's narrower coverage would suffice.
Planner rehashing/PKGINFO inspection binds full version, architecture,
dependencies, provisions, conflicts, replacements and licenses. The protected
tuple, coordinated policy, before/candidate identities and recovery assets stay
bound in the final report.

Exact archive/signature/certificate bytes are copied only into fresh private
scratch. The maintained verifier freshly checks each unique combination using
only its pinned public certificate and expected primary. Retained claims select
the expected key but cannot replace fresh verification. Bad, expired, revoked
or missing evidence refuses before ALPM. Fresh records retain each side's
original provenance. Independent key-owner trust and installed-byte identity
remain unaccepted.

Existing safe catalog filenames are preserved independently of local cache
paths. A missing filename receives an explicitly metadata-only name derived
from package identity; no upstream filename observation is invented. Catalog
compressed size/SHA256 must match authenticated bytes. Nothing is downloaded.

## Actual private preparation

A separate fresh empty owned mode0700 directory contains a synthetic before DB,
one exact candidate catalog, empty root and private log/key/cache/hook paths.
ALPM reads metadata only. All planned changes are explicit roots; only exact
candidate versions exist in the private sync DB. Additions, upgrades, downgrades,
same-version reinstalls and explicit removals work. Exact policy authorization
comes from the revalidated plan, not a blanket protected-version exemption.

Flags are `NOLOCK | NOSCRIPTLET | NOHOOKS`; dependency/conflict checks stay on.
`NEEDED` is absent so reinstalls are actually prepared. All questions are denied
and fail the whole result. Unexpected providers/additions/removals or a final
package set/semantic metadata different from the candidate fail. Actual ALPM
errors are retained. Empty private root contents are checked after preparation.

The ALPM child has30 seconds wall time,20 CPU seconds,512MiB address space and
8MiB request/response limits. Copies have a512MiB aggregate bound plus existing
per-file bounds. Existing GPG helpers bound each command; the authentication loop
checks a300-second assessment budget and refuses an over-budget result. Planner
bounds stay unchanged. Oversized real inputs are refused, not silently omitted.

## Run and interpret

```sh
mkdir -m 700 /absolute/private-output
TMPDIR=/absolute/private-output python3 -I -B scripts/platform/prepare_transition.py \
  --contract /absolute/private-prepare-contract.json \
  --contract-sha256 HEX64 \
  --output /absolute/private-output/new-preparation.json
TMPDIR=/absolute/private-output python3 -I -B scripts/platform/test_prepare_transition.py -v
```

Output parent must be owned mode0700 without symlink aliases; filename must be
absent. Exit0 means actual private preparation matched the candidate. Exit2
retains an actual preparation failure. Exit1 refuses malformed, changed,
missing/unverified or unsupported inputs and creates no final report. Auth/ALPM
workspaces are removed on success/refusal; reports are mode0600, never replaced.

The internal metadata worker is a separate **unauthenticated host fixture scope**.
It cannot satisfy strict contract/signature gates and explicitly leaves package
authentication/production/hardware flags false. Synthetic tests exercise real
ALPM behavior only; fake signatures exercise refusal. Fresh verification of one
genuine retained archive is also not a complete authenticated transition.

Nothing establishes payload/file-conflict safety, scriptlet/hook behavior,
runtime ABI, installed bytes, native ARM, physical16K, M2 boot/graphics/audio/
speaker protection, session restoration, recovery or release acceptance. Each
13-inch/15-inch machine still needs exact physical/recovery validation. No PC
bootloader assumption or platform mutation is introduced.
