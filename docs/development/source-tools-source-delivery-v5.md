# Current 0.5.0-1 source custody

This additive profile exports the exact merged SourceTools 0.5.0-1 recipe through
the unchanged generic `scripts/release/source_tools_source_delivery_v1.py`.
No additional exporter, entrypoint, package version or parser is needed. Schema 1
and the bundle's `delivery/*-v1` filenames identify the transport format; the
profile identifies package version **0.5.0-1**. The old profile remains unchanged.

Authority is PR388 head `0f2da0986e805c13424a28dce1d872f2ec65700a`, merged as
`34a91a4494b54497d9f50b5bc8f59b06f07ea7c8`. Every recipe blob is identical
between that head and merge. The profile records the exact per-file byte counts, SHA-256 values and canonical
Git modes for that recipe. The focused custody test checks the full input set
and separately pinned adapter before any export.

The profile pins **22 files**: the 20 PKGBUILD/SRCINFO source entries plus those
two metadata files. The export has **24 regular USTAR members**: those 22 inputs,
the externally pinned profile and the unchanged adapter. All source byte counts,
SHA-256 values and canonical Git modes are bound: launcher 0755, other inputs
0644. The retained private archive contains the same 11 MIT runtime files, matched
against `source-provenance.json` and `payload-map.json`, without extracting or
executing them. These delivery inputs total 607,417 bytes.

External pins (obtain these through your trusted channel):

- Profile `source-tools-source-profile-v5.json`: 3,662 bytes,
  `c1f3c13aa7c75c587055de0d619f27755a987a87baac16b9c783c40d273174cd`.
- Trusted maintained adapter `source_tools_source_delivery_v1.py`: 14,554 bytes,
  `0d4ff5d64b000453eb66f753808f6aeeb9a0c2fe5a1244a8e178b788178da976`.
- Resulting canonical `source.tar`: 645,120 bytes,
  `7cff44dcca183e4f2c276ecb6a80cf91b5c374d0f51432389ce86d721601f32f`.

## Export, move, verify and unpack

Supply absolute paths. Export/unpack destinations must be absent, beneath a
caller-owned parent without group/world write permission. Existing outputs are
preserved. Export creates private output containing `source.tar` and
`receipt.json`. The adapter retains its existing size limits and no-replace
publication behavior.

If a working checkout uses private 0600/0700 file modes, export a canonical-mode
COPY; never chmod the checkout. For example, from the repository root:

```sh
stage=$(mktemp -d)
git archive --format=tar --output="$stage/recipe-from-git.tar" \
  34a91a4494b54497d9f50b5bc8f59b06f07ea7c8 \
  packages/tools/cachy-asahi-source-tools-v5
(umask 022; tar -xf "$stage/recipe-from-git.tar" -C "$stage")
recipe="$stage/packages/tools/cachy-asahi-source-tools-v5"
```

Use the maintained adapter and this profile as separately trusted inputs. Here
`adapter`, `profile` and `export` are absolute paths; `export` names an absent
output directory. Check adapter bytes against the external pin before running it.

```sh
python3 -I -B "$adapter" pack --recipe "$recipe" --output "$export" \
  --profile "$profile" \
  --profile-sha256 c1f3c13aa7c75c587055de0d619f27755a987a87baac16b9c783c40d273174cd
```

For a move/offline handoff, copy `source.tar`, the separately trusted adapter,
and the profile to the new location. Keep the external profile, adapter and bundle
pins. Set `bundle` to the moved absolute archive path and `unpacked` to an absent
output directory. No original checkout or recipe is needed:

```sh
python3 -I -B "$adapter" verify --bundle "$bundle" \
  --sha256 7cff44dcca183e4f2c276ecb6a80cf91b5c374d0f51432389ce86d721601f32f \
  --profile "$profile" \
  --profile-sha256 c1f3c13aa7c75c587055de0d619f27755a987a87baac16b9c783c40d273174cd
python3 -I -B "$adapter" unpack --bundle "$bundle" --output "$unpacked" \
  --sha256 7cff44dcca183e4f2c276ecb6a80cf91b5c374d0f51432389ce86d721601f32f \
  --profile "$profile" \
  --profile-sha256 c1f3c13aa7c75c587055de0d619f27755a987a87baac16b9c783c40d273174cd
```

Unpack emits `recipe/` with all 22 exact inputs and `delivery/` with transport
DATA. Continue to use the separately trusted adapter; do not execute the bundle's
adapter, recipe, tests or archived helpers as part of delivery. Re-exporting the
unpacked `recipe/` through the same trusted adapter/profile produces the same tar.

## Bounded controls

```sh
python3 -I -B -Werror::ResourceWarning scripts/release/test_source_tools_source_delivery_v5.py \
  --recipe-root /absolute/path/to/current-22-file-recipe \
  --adapter /absolute/path/to/source_tools_source_delivery_v1.py \
  --profile /absolute/path/to/source-tools-source-profile-v5.json
```

The test checks adapter/profile pins before loading the trusted adapter; it only
normalizes a byte-verified temporary COPY. The input recipe is never chmodded.
`--adapter` and `--profile` default to adjacent files for ordinary integration.
All **10 controls passed**, zero failures/errors/skips: exact 20-source bindings
and MIT; private-11/provenance closure; deterministic 24-member export and receipt;
exact unpack/reimport with modes; moved standalone trusted-adapter verify/unpack;
all 22 member mutations; missing/extra/mode/old-recipe refusal; profile/bundle and
repinned member tampering; blocked execution/network/helper imports; interrupted
staging and preserved existing outputs.

This is offline byte custody. It establishes no signing/trust admission, legal
corresponding-source completeness, package build, installation, native/hardware
qualification or release acceptance. No recipe or bundle code was executed. The custody workflow does not perform a native build, ALPM transaction, Original
evidence retrieval, immutable Native Source publication or actual Native reader
execution. Those remain separate qualifications.
