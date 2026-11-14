# Fresh install offline handoff (development, held)

`handoff.py prepare` puts an existing offline candidate kit and an existing
recovery workspace beside one another, validates them again after copying, and
publishes one private directory with ordered operator actions. `verify` checks
that same directory after transport. Neither command installs packages, executes
transferred Python, enrolls trust, runs a native actor, changes a service or
writes partitions. This implements the offline preparation part of M8. It does
not implement or claim a macOS-to-first-login installation.

The candidate receiver remains `scripts/release/offline_kit.py`; predecessor
verification remains `scripts/release/recovery_bundle.py`. Their existing checks,
external trust requirements, metadata expiry and fixed recovery profile are
unchanged. In particular, recovery archive signatures remain **retained
observations**, rehashed and metadata-reinspected by that tool; this wrapper does
not freshly verify those signatures or broaden its recovery coverage. Retained
assets and successful inspection do not demonstrate boot restoration.

## Prepare

Use a trusted checkout that contains this command and whose owning tool/package
interfaces match `source_commit`. Obtain the two existing workspaces through the
procedures in [offline kit](../../release/offline_kit.py) and
[recovery bundle](../../release/recovery_bundle.py). Keep the external receiver
state directory outside all input/output roots. It remains external after
transport; no checkpoint or signing home is copied.

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

```sh
python3 -I -B scripts/install/fresh_handoff/handoff.py prepare \
  --selection /absolute/operator-selection.json \
  --selection-sha256 "$EXTERNAL_SELECTION_SHA256" \
  --candidate /absolute/candidate-kit \
  --recovery /absolute/recovery-workspace \
  --state-dir /absolute/external-receiver-state \
  --output /absolute/private-parent/fresh-handoff
```

The output parent must be caller-owned without group/world writes. Output must
be absent, outside both inputs and receiver state; symlink parents are refused.
Preparation uses an owned staging directory and the existing no-replace atomic
publication helper. Validation/copy failure leaves no published output and
preserves input data. This is not a power-loss durability guarantee. Existing
kit inventory size/member limits also apply to the combined directory.

The result contains `candidate/`, `recovery/`, the exact `selection.json`,
`ACTIONS.txt`, and `handoff.json`. The receipt binds every regular file/internal
alias, exact owning-interface hashes and lengths, and the composer source hash.
`source_commit` binds the existing interfaces and development manifest, **not**
the candidate packages' upstream source revisions; those remain owned by the
signed release's provenance/source associations. The interface list is not an
executable runtime closure. Tools run from the separately trusted checkout.

This first slice requires identical protected platform names, versions and
architectures in candidate and predecessor. A coordinated platform change needs
its own qualified integration path. It is refused here. Even equal versions do
not prove unchanged firmware or actual device behavior.

## Verify and follow the actions

Save the returned `receipt_sha256` externally. After moving/copying the directory,
use the same trusted composer bytes, matching owning interfaces and external
selection hash. The transported directory cannot authenticate its own receipt.

```sh
python3 -I -B scripts/install/fresh_handoff/handoff.py verify \
  --workspace /absolute/moved/fresh-handoff \
  --receipt-sha256 "$EXTERNAL_HANDOFF_RECEIPT_SHA256" \
  --selection-sha256 "$EXTERNAL_SELECTION_SHA256" \
  --state-dir /absolute/external-receiver-state
```

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
```

The local suite exercises actual copying, relocation after original inputs are
deleted, complete byte/alias inventories, external-pin refusal, protected-platform
mismatch, missing/tampered rollback assets, interruption cleanup, no replacement
of existing output, source drift and changed operator instructions. One integrated
case verifies a freshly generated disposable **TEST** candidate signer and real
release/package/metadata signatures, then refuses invalid metadata signatures.
Predecessor cryptographic authentication is explicitly mocked using the existing
recovery tests' **UNSIGNED TEST fixture**; its copying, pinned recovery inventory,
metadata inspection and relocation logic run for real. This does not qualify an
actual release or independent predecessor trust.

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
