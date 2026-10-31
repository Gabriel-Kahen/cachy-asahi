# Canonical Source102 zlib PGO entrypoint

`packages/experiments/cachy-asahi-zlib-pgo-v1/` contains the exact 18-file recipe
qualified in Source102, including pipeline SHA256
`907717f2f0ecfd126f43ac55b8805bfa871922a4c8f5ee8a1d38f5412f30d2e4`.
`scripts/experiments/zlib_pgo102.py` verifies and exports its exact closed source
view. It never launches a build, compiler, toolchain probe, training, package
operation, Docker or network acquisition.

Root's historical component record binds source
`3ee4b0ae221429385e738f4df01eac1b730f36ee`, tree
`20309eaeb580436c4b49f2bb1b35abc2e1c16d0d`, run 40592666471/attempt 1/job
122500619368. It qualifies generic ARM4K construction/correctness only. This
adoption copies source; it does not produce a new canonical native build or
transfer installation, generic16K, physical M2, performance, optimization selection
or release acceptance. The original Root record remains byte-pinned in the
versioned asset view. No current availability of its retired producer image is
asserted.

## Use after integration

From a clean repository checkout:

```sh
python -I -B scripts/experiments/zlib_pgo102.py verify
python -I -B scripts/experiments/zlib_pgo102.py export \
  --output /absolute/fresh-source102-view
```

Export verifies all canonical inputs before creating a fresh output outside the
executable checkout. It preserves all 39 original files and modes, including
`PGO-SOURCE.json` SHA256
`4733aecfa53b40ba4ed78eee2408978c3523ff5e45f9c55287d295cddb3dfc84`.
An existing destination refuses reuse; partial output remains unqualified. Do not
Git-initialize, add logs or run tests in a source view you intend to use for the
next preparation: its original planner requires an exact closed namespace.

The export result names the original byte-held preparation entrypoint and
versioned `build_v2.py`. Prepare offline with an explicitly reviewed compatible
native builder and its exact sorted package inventory:

```sh
python -I -B /absolute/fresh-source102-view/scripts/experiments/zlib_pgo_native_plan.py \
  --image sha256:REVIEWED_NATIVE_IMAGE_ID \
  --expected-packages /absolute/reviewed-packages.lock \
  --output /absolute/fresh-source102-preparation
```

This stages already-retained source data and emits `native-command.json`; it
does not execute that command or establish that the requested image exists.
Root owns subsequent supervised native dispatch. The emitted command retains
native mode, network none, source epoch, recipe map, source plan/catalog/cache and
explicit expected-package binding. All construction gates remain active,
including the exact installed-tool package/paths/modes/hardlink groups and payload
checks. A builder with different tools must fail; this version grants no generic
compiler-family exemption.

The canonical recipe is independently available to the existing `build_v2.py`
interface with the same explicitly reviewed source-plan inputs. The export route
also preserves the original preparation code's complete closed-source contract.
Retain the complete nested `artifacts/pgo-v1-evidence/` after future construction;
the top-level builder file map does not enumerate that tree on its own.

## Fixed source and experiment boundaries

The package identity remains `cachy-asahi-zlib-pgo-v1` version 1.3.2-1, aarch64,
Zlib/MIT, dependent on glibc with gcc/binutils/make/Python build inputs. It owns
only the experimental prefix `/usr/lib/cachy-asahi/experiments/zlib-pgo-v1` and
its license paths. No system-zlib replacement or release selection is introduced.
The archive is the retained zlib 1.3.2 object, 1,502,830 bytes, SHA256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
Its original source catalog, receipt and Zlib notice are copied without a new
acquisition or legal/trust approval.

All construction bytes are unchanged: generic `-march=armv8-a -mtune=generic`,
`-O2`, no LTO, fatal missing-profile/coverage diagnostics, seventeen native
profiles and a single sealed training result feeding two clean optimized builds.
Training remains 262,144 bytes with SHA256
`a6e84ea4cf12d2152fd408cea20bc2a395d4308f06683d13fc4909ae7ad46af6`;
separate held-out validation remains 4,194,304 bytes with SHA256
`e178d56b3a6d0af1900f8e3a1b668549793b48d0ae35c24e730b9a39992604bf`.
No held-out training, profile fallback or performance rule changes occur.

## Versioning and historical compatibility

`zlib_pgo102-profile.json` is itself SHA256-pinned by the new entrypoint. It maps
39 virtual Source102 names to exact canonical assets: 18 package leaves, eight
existing byte-identical support files and thirteen other original assets kept in
`scripts/experiments/zlib_pgo102-view/`. The original map, recipe, pipeline and
recipe-policy are copied verbatim; the adoption profile is a separate mapping.
The Root qualification record is pinned separately and is not injected into the
original closed 39-file view.

The four Source100-to-Source102 changes are `pipeline.py`, its `recipe-policy.json`
pin, two `PKGBUILD` checksum literals, and `PGO-SOURCE.json`. The remaining 35
original files are held. Existing ARM-C03 `arm_c01.py`/`pgo.py`, stage locks,
native-trial entrypoints, frozen source consumers, old archive bytes and historical
receipts are not rewritten. The versioned map refuses drift in any reused support
file; a later interface change needs an explicit new immutable view/version,
not relaxed hashes.

Run the new source/export controls after integration:

```sh
python -I -B -Werror::ResourceWarning scripts/experiments/test_zlib_pgo102.py
```

The exact recipe's three older passive suites must run on a disposable exported
copy: some controls temporarily hardlink a training fixture or create temporary
evidence outside the view. They must not mutate a frozen source packet or the
canonical recipe in place. Source/export fixtures and passive planning remain
distinct from compiler execution and native construction.
