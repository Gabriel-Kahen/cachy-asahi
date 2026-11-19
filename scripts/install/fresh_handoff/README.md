# Fresh install offline handoff (development, held)

`handoff.py prepare` puts an existing offline candidate kit and an existing
recovery workspace beside one another, validates them again after copying, and
publishes one private directory with ordered operator actions. `verify` checks
that same directory after transport. Neither command installs packages, executes
Python from the candidate/recovery kits, enrolls trust, runs a native actor, changes a service or
writes partitions. This implements the offline preparation part of M8. It does
not implement or claim a macOS-to-first-login installation.

The candidate receiver remains `scripts/release/offline_kit.py`; predecessor
verification remains `scripts/release/recovery_bundle.py`. Their existing checks,
external trust requirements, metadata expiry and fixed recovery profile are
unchanged. Their recovery observations keep their historical classification.
This successor adds a distinct **fresh signature verification** of all 16 local
recovery archives using the existing `authenticate_missing.verify` API, its fixed
ALARM certificate pin and public-only disposable GPG homes. Local archive and
signature snapshots are bounded and rehashed before that call. No network,
global keyring or ownertrust is used. Coverage stays within the existing fixed
16-package profile. Retained assets and successful inspection do not demonstrate
boot restoration.

## Prepare

Use a trusted checkout that contains this command and whose owning tool/package
interfaces match `source_commit`. Obtain the two existing workspaces through the
procedures in [offline kit](../../release/offline_kit.py) and
[recovery bundle](../../release/recovery_bundle.py). Keep receiver state
outside all input/output roots. Each checkpoint remains external after transport.

Write an independently reviewed selection with exactly these fields (replace
**all** placeholders with actual externally selected identities):

```json
{
  "schema_version": 1,
  "purpose": "development-fresh-install-handoff",
  "source_commit": "<40 lowercase hex: existing interface/inventory commit>",
  "candidate": {
    "kit_sha256": "<64 lowercase hex: candidate kit.json>",
    "release_sha256": "<64 lowercase hex: candidate release/release.json>",
    "signer": "<40 uppercase hex: independently authenticated primary>",
    "namespace": "<independently selected development namespace>",
    "minimum_sequence": 1
  },
  "recovery": {
    "receipt_sha256": "<64 lowercase hex: recovery recovery-bundle.json>",
    "selection_sha256": "<64 lowercase hex: recovery selection.json>",
    "release_sha256": "<64 lowercase hex: predecessor release/release.json>",
    "signer": "<40 uppercase hex: independently authenticated predecessor primary>",
    "namespace": "<independently selected predecessor namespace>",
    "minimum_sequence": 1
  }
}
```

The two signer/namespace/floor selections are independent. The sequence floor
must reflect the receiver's actual policy; `1` above is an example, not a safe
default. Authenticate the selection hash separately from the transported files.
No trust identity is inferred from a certificate, package, receipt or download.
The two kit signers must match in this slice. Two independently verified but
different signers yield `SIGNER_TRANSITION_HELD`; a separately reviewed key
transition remains a distinct gate. The recovery archive signer remains the
maintained tool's fixed ALARM anchor, separate from either project-kit identity.

`--state-dir` selects the candidate receiver checkpoint directory. Pass
`--recovery-state-dir` with the independently maintained predecessor receiver
directory when the predecessor has its own namespace or earlier checkpoint.
Use the same two external directories for preparation and verification. If
omitted, both roles use `--state-dir` and must satisfy that checkpoint. Both
roles still require their independently selected namespace, signer and sequence
floor. Verification reads both checkpoints without advancing them.

```sh
python3 -I -B scripts/install/fresh_handoff/handoff.py prepare \
  --selection /absolute/operator-selection.json \
  --selection-sha256 "$EXTERNAL_SELECTION_SHA256" \
  --candidate /absolute/candidate-kit \
  --recovery /absolute/recovery-workspace \
  --state-dir /absolute/candidate-receiver-state \
  --recovery-state-dir /absolute/predecessor-receiver-state \
  --output /absolute/private-parent/fresh-handoff
```

The output parent must be caller-owned without group/world writes. Output must
be absent, outside both inputs and receiver state; symlink parents are refused.
Preparation uses an owned staging directory and the existing no-replace atomic
publication helper. Validation/copy failure leaves no published output and
preserves input data. This is not a power-loss durability guarantee. Existing
kit inventory size/member limits also apply to the combined directory.

The result contains `candidate/`, `recovery/`, `operator/`, the exact `selection.json`,
`ACTIONS.txt`, and `handoff.json`. The receipt binds every regular file/internal
alias, exact owning-interface hashes and lengths, and the composer source hash.
`source_commit` binds the existing interfaces and development manifest, **not**
the candidate packages' upstream source revisions; those remain owned by the
signed release's provenance/source associations. The interface list is not an
executable runtime closure. A separate finite runtime is staged under `operator/`:
17 Python runtime files and 15 interface witnesses deduplicate into 33 regular
files including the license, source lock and runtime receipt. No whole checkout,
Git metadata, private signing data or test fixture is shipped. `runtime.json`
binds the complete finite inventory. `source-lock.json` binds the selected commit
and exact interface bodies, allowing delivered execution without Git discovery.
The new handoff receipt is schema 2; schema-1 handoffs remain historical and must
be regenerated for this runtime/signature path.

This first slice requires identical protected platform names, versions and
architectures in candidate and predecessor. A coordinated platform change needs
its own qualified integration path. It is refused here. Even equal versions do
not prove unchanged firmware or actual device behavior.

## Verify and follow the actions

Save the returned `receipt_sha256` and `runtime_sha256` externally, alongside the
selection hash. The transported directory cannot authenticate its own receipt.
Authenticate the reviewed runtime entrypoint itself through the operator's
trusted delivery process before executing it. Its external inventory pin checks
transport identity; a script already running cannot authenticate itself.

After moving/copying the directory, the finite runtime can run with the original
checkout unavailable:

```sh
python3 -I -B /absolute/moved/fresh-handoff/operator/scripts/install/fresh_handoff/runtime.py \
  --runtime-sha256 "$EXTERNAL_OPERATOR_RUNTIME_SHA256" -- verify \
  --workspace /absolute/moved/fresh-handoff \
  --receipt-sha256 "$EXTERNAL_HANDOFF_RECEIPT_SHA256" \
  --selection-sha256 "$EXTERNAL_SELECTION_SHA256" \
  --state-dir /absolute/candidate-receiver-state \
  --recovery-state-dir /absolute/predecessor-receiver-state
```

The entrypoint checks the exact finite inventory and external runtime pin before
loading handoff helpers. Deleted, changed, foreign and aliased members are
refused. It does not fall back to source discovery. A matching trusted checkout
can still run `handoff.py verify` directly. Python, GPG/gpgv and archive tools
remain preinstalled host dependencies; no dependency installation is provided.

Exit zero means **offline data checks passed**. The JSON status is always
`HELD_DEVELOPMENT_HANDOFF`, and release/install/native/hardware flags remain
false or NOT RUN. There is no flag to promote this into a supported installer.
Expired metadata or stale receiver policy can make a previously prepared handoff
fail verification; preserving old files does not waive those checks.

`ACTIONS.txt` orders the journey: macOS backups and the maintained Asahi
installer; offline handoff validation; recovery retention; coordinator-admitted
native preflight and full Asahi transaction; authenticated enrollment preview;
reviewed installation; explicit first-login configuration; retained base session
and boot/session recovery tests. It names the existing tools and gives only
first-login read-only/selection preview argv. Native preflight requires its
existing in-process admission. The local transaction worker accepts disposable
fixture contracts; it is not a live-root installer. Production enrollment and
installation remain held because this checkout supplies no accepted release
set or production trust. No PC bootloader/hardware-detection path is introduced.

## Actual checks and boundaries

```sh
python3 -I -B -Werror::ResourceWarning scripts/install/fresh_handoff/test_handoff.py -v
python3 -I -B -Werror::ResourceWarning scripts/install/fresh_handoff/test_signed_handoff.py -v
python3 -I -B -Werror::ResourceWarning scripts/install/fresh_handoff/test_runtime.py -v
```

The local suite exercises actual copying, relocation after original inputs are
deleted, complete byte/alias inventories, external-pin refusal, protected-platform
mismatch, missing/tampered rollback assets, interruption cleanup, no replacement
of existing output, source drift and changed operator instructions. One integrated
case verifies a freshly generated disposable **TEST** candidate signer and real
release/package/metadata signatures, then refuses invalid metadata signatures.
The earlier custody suite retains explicitly mocked predecessor authentication
and fresh-archive checks using the existing recovery tests' **UNSIGNED TEST fixture**;
its copying, pinned recovery inventory,
metadata inspection and relocation logic run for real. This does not qualify an
actual release or independent predecessor trust.

The new signed suite uses real disposable TEST keys for both complete kits and
all 16 recovery archives. No authentication or signature verifier is mocked.
Only the production module's fixed ALARM anchor constant is substituted in the
TEST process with the explicit generated TEST fingerprint/certificate hash.
Both kits use the same existing release/envelope/package verification path;
fresh recovery checks use the maintained public verifier. Unknown candidate and
predecessor keys, wrong predecessor release/version, missing/tampered bytes and
invalid signatures with all transport layers repinned remain named refusals.
A genuinely signed cross-key candidate remains held.

The source-hidden test moves the handoff, hides the checkout, producer fixtures
and private signing home, isolates the network to loopback, and poisons Python
environment variables. The actual product CLI correctly refuses the TEST
certificate under its unchanged production ALARM policy. A separate TEST-only
driver verifies the runtime inventory, substitutes just the explicit TEST
anchor, and completes the full verification without mocking any verifier or
writing receiver state. The driver is never included in the operator runtime.
Separate runtime controls exercise the actual relocated entrypoint and refusal
before helper execution on changed/deleted/foreign/aliased runtime files.

Prior commit `3f6c3064` passed 63 tests with the explicitly unsigned predecessor
seam. Those results remain prior software facts; they are not retroactively
described as cryptographic predecessor acceptance.

The software journey copies the real Setup8 helper and actual Fish/Zsh package
templates into an owned temporary root. It runs first-login preview, a genuine
interrupted helper write, recovery preview/apply, repeat activation and removal,
checking preservation of existing user bytes. It checks actual installed Fish/Zsh
executable availability; it does not fake those programs. It does not execute
the shell templates, start a graphical session or perform a package transaction.

Native ARM builds/execution, 16K execution, selected target dependency solving,
platform hooks, production trust, independent macOS-to-Asahi setup, M2 Air
13-inch and 15-inch first login, failed-update boot/session recovery and release
acceptance remain **NOT RUN / held**. Asahi firmware, boot, kernel, Mesa and
audio ownership stays with the preserved platform stack. No shared manifests,
workflows or historical evidence are changed.
