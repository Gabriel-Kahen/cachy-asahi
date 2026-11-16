# Bankstown Qt3 private native adapter v1

This separate opt-in adapter connects the optional 333-package Qt 6.12.0-3
catalog to the unchanged Bankstown 1.1.0-5 native-profile consumer. It preserves
the original Qt 6.12.0-2 hold, parent binding, catalog implementation, Rust137
map, recipe, generic builder, and CI paths. Nothing imports or invokes this
adapter automatically.

## Current evidence

The implementation and portable controls are available. The 39 controls comprise
7 admission, 14 profile, and 18 builder controls. Builder controls use a synthetic
executor and native-host facts; they exercise the actual adapter and frozen
static package predicates under an audit fence that rejects process/network
operations. Profile controls use synthetic catalog/materialized-root fixtures
and maintained historical source pins. These are MODEL results.

Genuine retained-catalog inspection, materialized native-image verification,
Root admission, owned-executor selection, native build, installation, M2 testing,
and release acceptance are **NOT RUN**. No private archive search, Docker actor,
GPG operation, native compiler, or package installation was performed to produce
this implementation. Source/legal and key freshness remain **HELD**.

## External inputs and authority

Root must separately select a fresh admission JSON and deliver its SHA256 through
trusted custody. `issuer: Root` and a matching checksum alone do not authenticate
an untrusted document. There is no admission issuer, default executor, image
provisioner, archive acquirer, or authority-generating CLI here. The caller must
review and pin the adapter and executor before importing them.

`admission.validate_trial(raw, expected_sha256, now=...)` requires the exact
`ROOT_REVIEWED_BANKSTOWN_QT3_PRIVATE_TEST_V1` schema. The finite admission binds:

- An exact source commit/ref and closed relative material map, including all
  historical parent members, adapter programs, unchanged recipe sources/notices,
  the catalog, and complete final image inventory. Each material has a whole-file
  byte count and SHA256. The source map is the runtime identity; no Git command
  or `.git` mount is used to establish the declared commit.
- An existing immutable ARM64 Linux image ID, Root-owned executor code pin,
  explicit Unix Docker endpoint and engine ID, and finite resource limits.
- Canonical selected native files and fixed cargo/rustc/cc/ld roles. Root must
  explicitly review the complete non-ELF tool-support closure, including required
  CRT objects, linker scripts, headers, GCC subprocess/support files and Rust
  libraries. Passive ELF joins do not prove all compiler runtime behavior.
- A maximum 24-hour admission lifetime and bounded command/output/file limits.
  Legal/key freshness stay HELD; Root, native-component, hardware and release
  acceptance remain unset or false.

The final sorted `name version` inventory must include every exact catalog
package version plus actual makepkg prerequisites. The 333-package catalog alone
does not supply a complete makepkg image. This adapter neither installs packages
nor fills missing providers. A trial needs a Root-selected inventory and an
already materialized image containing the reviewed union.

## Passive profile projection

`profile.export_profile(admission_raw=..., admission_sha256=..., catalog_path=...,
root=..., output=...)` reads the explicitly selected catalog and existing
materialized root, then creates a fresh mode-0600 profile. It checks the historical
candidate/parent/Rust137 pins, all admitted material bytes, full 333-package
identity and closure observations, actual selected file bytes/modes, literal
symlink and hardlink resolution, actual AArch64 ELF facts, and selected ELF
providers/SONAMEs. It does not execute any selected payload.

The original catalog has no `schema` field and is never relabeled as a native
profile. The new profile is a distinct schema-1
`bankstown-1.1.0-5-native-toolchain` document with Rust 1.99.0 and the unchanged
`aarch64-unknown-linux-gnu` target. Root must select its resulting whole-file
SHA256 separately, after export; this avoids a circular admission/profile hash.

At runtime, `profile.py verify` requires `--root /`, rederives the projection
against the actual container filesystem, and checks Root's selected profile
SHA256. The original pinned `build_guard.py native-tools` then independently
checks the consumer profile before the unchanged container entry runs makepkg.
Logical links resolve inside the selected root; host symlinks cannot redirect
the passive inspection into another tree.

## Native builder integration

An externally reviewed caller imports `builder.py` and invokes:

```python
build_private_test(admission_raw=raw, admission_sha256=root_admission_sha256,
                   profile_path=profile, profile_sha256=root_profile_sha256,
                   executor=root_owned_executor, source_root=checkout,
                   output=fresh_external_output)
```

`executor.facts` supplies the admission-bound `code_pin`, `docker_endpoint`,
`engine_id`, and actual non-root `uid`/`gid`. The adapter also checks its own
Linux AArch64 kernel and process IDs. An optional `native_architecture` fact must
agree with the kernel. No synthetic facts may be used for a genuine trial.

`executor.run(step, argv, timeout, expected=0)` must return byte `stdout` and
`stderr` plus its actual `receipt`. The adapter joins argv, step, expected exit,
both output pins, exact requested `timeout_seconds`, finite
`supervision_cap_seconds`, and `supervision.seconds`. A successful receipt must
record natural reaping, two empty group censuses, complete output, and no
timeout, signals, ownership loss, emergency retirement or forced cleanup. The
executor owns real process custody and live resource enforcement; a fabricated
receipt cannot establish those facts.

The adapter snapshots only admitted materials and exposes read-only source,
recipe, controls/profile and exact inventory mounts, plus one writable artifact
directory. It fixes an offline, read-only, unprivileged container with bounded
memory/CPU/PIDs, a private tmpfs, sanitized loader/Python environment, and exactly
the two existing `BANKSTOWN_NATIVE_TOOLS_*` variables. It inspects image/engine
identity and create/terminal state. Cleanup uses the exact operation name and
verified ID/labels/mounts, then requires separate name and ID absence receipts.
Forced retirement is a HOLD; cleanup failure preserves the original exception.

After owned-container cleanup, passive validation reuses the pinned original
recipe/package predicates and only three pure metadata-binding functions from
the generic builder. It checks actual image inventory, generated/artifact
metadata, exact ten-file Bankstown payload and modes, original AArch64/16K/LV2
guard receipt, Root profile association, and source/notice bytes. Zstd package
DATA decoding requires Python 3.14's stdlib `compression.zstd`; Python 3.12
refuses that format rather than selecting an external decoder.

The result `PASS_PRIVATE_TEST_BUILD_DATA_ONLY` records this bounded build and
static validation only. It cannot grant source/legal, key-freshness, native
component, M2 hardware, installation or release acceptance.

## Portable checks

Run each test file separately with an available interpreter, from this checkout:

```sh
python3 -I -B -Werror scripts/port/bankstown-qt3-native-v1/test_admission.py
python3 -I -B -Werror scripts/port/bankstown-qt3-native-v1/test_profile.py
python3 -I -B -Werror scripts/port/bankstown-qt3-native-v1/test_builder.py
bash -n scripts/port/bankstown-qt3-native-v1/entry.sh
```

The test audit fences are installed before adapter imports. Running these
controls does not authorize or invoke a native trial.
