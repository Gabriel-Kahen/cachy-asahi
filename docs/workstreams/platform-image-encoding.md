# Portable direct-metadata filesystem pipeline

The checkout entrypoint is `scripts/platform/metadata_gated_ext4.py`. It loads the canonical portable intake/verifier and adjacent pinned metadata/encoder/raw-reader sources. No ignored packet, external source-lock file, frozen base bridge or generic-empty callback is needed. Keep the complete canonical48-leaf intake bundle beside its entrypoint. Historical archives/authentication remain explicit operator inputs.

```sh
python -I -B -S -Werror::ResourceWarning tests/platform/run_pure.py
python -I -B -S -Werror::ResourceWarning tests/platform/run_ext4_pure.py
python -I -B -S -Werror::ResourceWarning tests/platform/check_host_components.py
```

The common runner preserves13 intake methods and discovers14 new portable/profile methods. The dedicated runner selects only the new14. Guards forbid process/network/native-library actors, ignored-evidence reads and project PYC. Inert orchestration models test sequencing/refusal/publication; they do not authenticate archives or rerun historical22 metadata/native checks. The host checker without an explicit subcommand reports **NOT_RUN** before any native probe.

## Explicit dependency profiles

There are no built-in Arch library paths or host binary hashes. Metadata configuration has exactly:

```json
{"interface":"libarchive-3-linux-lp64-tar-xz-v1",
 "library":"/absolute/host/libarchive.so",
 "ldd":"/absolute/host/ldd","headers":[]}
```

Tool configuration has exactly:

```json
{"interface":"e2fsprogs-linux-regular-ext4-v1","ldd":"/absolute/host/ldd",
 "tools":{"mke2fs":"/absolute/host/mke2fs","debugfs":"/absolute/host/debugfs","e2fsck":"/absolute/host/e2fsck"}}
```

These are **unqualified path templates**, not runnable host profiles. Operators must select actual absolute paths. Headers are optional explicit references; no Arch include path is assumed. Capture records actual executable/library/ldd/Python/ctypes identities and the dynamic dependency closure on that host. Metadata additionally pins Python's DSO closure, requires Linux LP64/libarchive major3, refuses loader-override environments and missing dependencies. Old schema1 Arch pins refuse. Tool roles/versions are checked; no silent path/version fallback or installation occurs.

The interface names specify required APIs/options, not a claim that every libarchive3/e2fsprogs version or distro has passed. Missing symbols, unsupported XZ/options, warnings and changed identities refuse. No Ubuntu native profile has been qualified by this source-only proposal. Capturing hashes is identity evidence, never host qualification.

## Separate opt-in host component check

Run `tests/platform/check_host_components.py --help` for exact arguments. Two explicit subcommands exist:

- `capture` takes separately SHA-pinned metadata/tool configuration JSON and a fresh output directory. It executes local identity probes and writes schema2 profiles with status `CAPTURED_HOST_IDENTITIES_NOT_QUALIFIED`.
- `check` takes separately SHA-pinned captured metadata/tool profiles, explicit root-policy JSON and a fresh output directory. It rechecks identities, runs eight self-contained genuine compressed metadata fixtures and one small generated-root image/readback/e2fsck control. It reads no retained package archives and builds no126MiB package pair. Only an actual successful run may report `PASS_EXPLICIT_PINNED_HOST_COMPONENTS_ONLY`.

This check is a separate, bounded native integration lane; default CI does not invoke it or install/provision dependencies. One explicit capture/check has now passed for the separately recorded Linux x86_64 host profile; other host qualification remains **NOT RUN**. A future host job must retain its own real profiles/receipts; Arch results/hashes cannot substitute for Ubuntu results. An unsupported tool option/library API is an explicit failure, not a reason to relax metadata guards.

## Package pipeline and evidence boundaries

The native CLI requires five independently SHA-pinned JSON inputs: exact selection, authentication, schema2 tool profile, schema2 metadata profile and explicit generated-root policy, plus a nonexistent output directory. Use the entrypoint's `--help`. Exactly NetworkManager1.58.1-1 and Perl5.42.2-2 aarch64 are required before dispatch; a subset cannot receive a two-package result.

When explicitly invoked, the bridge uses public portable intake `run()`, independently verifies staging, obtains direct native metadata/member/header/hardlink joins, proves generated-root policy, then reads verified bodies and encodes a fresh ordinary file. The encoder uses the already compiled/pinned reader, not a late unpinned import. Helpers and entrypoint are checked again before final pending/fsync→marker-removal→rename receipt publication. Metadata rejection, source drift and failed cleanup cannot publish PASS.

Direct metadata remains exact ordinary USTAR only. Unknown PAX/carriers, AppleDouble, warnings, nonempty ACL/attributes/flags, sparse/encryption unknowns and inconsistent joins refuse. No metadata is manufactured from generic extension refusal. Historical owner-trust/source-license/full261/installed/native/boot/M2/release limits remain.

The raw reader and parsing/encoding algorithms retain their reviewed behavior; dependency capture and orchestration have changed. Historical real-pair evidence validates its historical source graph. **The limited host-component check has passed; full portable retained-package execution remains NOT RUN**. Pure tests validate checkout paths, guards and modeled sequencing, not native filesystem reproducibility. Actual Git-checkout validation is also separate from a fresh0644/0755 source projection; no Git operation was performed by this proposal lane. Root owns canonical adoption and separately authorized native/host CI dispatch.


Root-preparation component record (2026-10-27): the canonical-ready successor routes all native child commands through existing pinned `scripts/virtual/owned_process.py` SHA80547f75…, with prepare-before-launch, reserved supervision and bounded raw receipts. Metadata/tool probes require the bound runner and a new private actor-log directory; standalone pin-tools additionally requires `--actor-directory`. The CI sparse source set includes that supervisor. Exactly one capture and one check passed on the selected Linux x86_64 host: libarchive3.8.9, Python3.14.7, e2fsprogs1.47.4; eight metadata fixtures and a fresh16MiB generated-root/raw-readback/e2fsck control. This qualifies only those captured host components. No Ubuntu/ARM/M2/full261/package-pair/boot/release acceptance follows; the old126MiB pair was not opened or repeated. Original proposal source-only statements describe its preceding snapshot; the host-component result is separately sealed in platform-portable-encoder-root-preparation-20261027.


The optional RSS API adoption pins the current default-call supervisor to SHA256 `83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`. This pipeline does not pass `rss_interval`. The recorded eight-fixture/16MiB/69-inner/two-outer host-component qualification above remains bound to its original80547f75 source graph; no host capture/check or package pipeline was rerun for this pin adoption. Matching default API contracts do not transfer those receipts to a new source graph.
