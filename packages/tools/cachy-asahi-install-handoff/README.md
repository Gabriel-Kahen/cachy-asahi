# Install and recovery handoff tools 0.1.0

This original opt-in package delivers the exact finite handoff runtime from
`1c4c455b486fd0b0f1c7ae587130a2c05e7a9560`, without changing its verifiers or
platform policy. It prepares and verifies an offline candidate kit plus retained
recovery data, with ordered actions and explicit holds. It is not an installer
and does not qualify a macOS-to-first-login journey.

The package owns one launcher, its private finite runtime, documentation and
license files. It has no install hooks, automatic activation, partitioning,
trust enrollment, service setup, bootloader or hardware-detection logic.

## Explicit invocation

Authenticate the package and reviewed runtime entrypoint through the operator's
trusted delivery process. Obtain the runtime SHA-256 from an independently
reviewed `source-provenance.json`/runtime receipt. A script already executing
cannot authenticate its own entrypoint. The pin identifies bytes; it does not
authenticate a release signer or confer owner trust.

```sh
cachy-asahi-install-handoff --help
cachy-asahi-install-handoff --runtime-sha256 "$EXPECTED_OPERATOR_RUNTIME_SHA256" -- --help
cachy-asahi-install-handoff --runtime-sha256 "$EXPECTED_OPERATOR_RUNTIME_SHA256" -- prepare \
  --selection /absolute/operator-selection.json \
  --selection-sha256 "$EXPECTED_SELECTION_SHA256" \
  --candidate /absolute/candidate-kit \
  --recovery /absolute/recovery-workspace \
  --state-dir /absolute/external-receiver-state \
  --output /absolute/private-parent/new-handoff
```

All paths and trust identities remain operator-selected. The closed selection
schema and eight ordered actions are preserved in the private runtime source
`.../scripts/install/fresh_handoff/handoff.py` and upstream handoff documentation.
In brief, selection schema 1 requires purpose
`development-fresh-install-handoff`, exact 40-hex `source_commit`, and separate
`candidate`/`recovery` authority records. Candidate requires `kit_sha256`,
`release_sha256`, full uppercase `signer`, `namespace` and `minimum_sequence`.
Recovery requires `receipt_sha256`, `selection_sha256`, `release_sha256`, `signer`,
`namespace` and `minimum_sequence`. All SHA-256 values are exact lowercase hex.
The packaged source lock binds the original interface/inventory commit above;
package-source/upstream provenance stays owned by the signed release inputs.

Both kit signers must match; cross-key transitions remain held pending separate
review. Protected platform names, versions and architectures must match the
predecessor. Recovery uses the existing fixed ALARM public certificate and exact
16-package profile, with fresh local signature checks in disposable public-only
GPG homes. No production trust input is inferred from a download or certificate.

`prepare` returns external `receipt_sha256` and `runtime_sha256` pins for the new
schema-2 handoff, whose copied runtime is the same bounded tool. Retain those
pins separately from the transported directory. Verify from the installed tool:

```sh
cachy-asahi-install-handoff --runtime-sha256 "$EXPECTED_OPERATOR_RUNTIME_SHA256" -- verify \
  --workspace /absolute/moved/handoff \
  --receipt-sha256 "$EXPECTED_HANDOFF_RECEIPT_SHA256" \
  --selection-sha256 "$EXPECTED_SELECTION_SHA256" \
  --state-dir /absolute/external-receiver-state
```

The private runtime has 17 Python runtime files and 15 interface witnesses,
deduplicated into 33 files including license, source lock and runtime receipt.
It discovers paths relative to its own moved prefix, verifies the complete
finite inventory before helper imports, and uses the delivered source lock
instead of Git or checkout discovery. Python/GPG/archive tools remain host
dependencies. Candidate/recovery Python is data and is never executed.

Successful verification always reports `HELD_DEVELOPMENT_HANDOFF`; it does not
install packages, enroll trust or accept a release. Unknown signer/bytes,
missing/changed runtime, invalid signatures, mismatched predecessor/platform
versions and unadmitted key transitions stay explicit refusals or holds.

## Packaging and actual checks

The recipe requires existing `python>=3.11`, `gnupg`, `pacman`, `coreutils`,
`libarchive` and `bash`. `bubblewrap` and `util-linux` are check dependencies.
The check fixtures use `repo-add`, `vercmp`, GPG/GPGv and archive tools from these
installed packages. No dependency is downloaded or installed by a helper.

```sh
makepkg --cleanbuild --force --noconfirm
```

Normal dependency checking and `check()` stay enabled. Checks stage the actual
`package()` payload and exercise the launcher after moving its prefix with the
checkout/producer/signing home hidden and the network isolated. They use genuine
disposable TEST signatures for candidate and predecessor kits and all 16
recovery archives. Only the test driver's fixed ALARM anchor is replaced by an
explicit TEST fingerprint/certificate hash; no verifier is mocked. The product
launcher retains production policy and correctly refuses TEST certificates.
The original fixture's Git-context request is supplied the packaged source-lock
commit by an exact TEST-only context shim; this is source context, not trust.

The tests also refuse changed/missing runtime before helper execution and
remove only mapped package files while preserving caller-owned data. A separate
`--archive` check applies the same controls to the actual built/extracted archive.
These are staged/archive software checks, not an installed pacman lifecycle.

## Ownership and removal

The launcher lives in `/usr/bin/cachy-asahi-install-handoff`; the private runtime
is `/usr/lib/cachy-asahi/install-handoff/`. Exact file hashes, lengths and modes
are in `payload-map.json`, except its explicitly listed self entry (its own bytes
are pinned by the recipe). All private runtime bodies remain unchanged from the
source commit. `source-provenance.json` records the source/check archive hashes,
per-file pins, dependency declarations and runtime identity.

Removal deletes only package-owned files. It never removes operator handoffs,
receiver state, keys, package caches, user configuration or rollback assets.
There is no removal hook or implicit cleanup. Caller-owned handoff data should
be stored outside package paths.

Native ARM/16K package qualification, selected Asahi installation and hooks,
production trust, independent first graphical login and failed-update boot/session
recovery on M2 Air 13-inch and 15-inch, and release acceptance remain NOT RUN/held.
`arch=('any')` is a packaging declaration, not evidence for ARM or M2 behavior.
