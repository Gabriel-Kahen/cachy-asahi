# Retained native audio packages and finite source handoff

`intake.py` delivers the existing five finite source exports together with their
exact retained native package archives. It fills the gap between the existing
optional, structural archive binding and an actual portable delivery of the
recorded native bytes. It reuses `platform_audio_source_delivery.pack/verified`;
the existing source profiles, recipes, source mirrors and release tools are
unchanged.

`native-inputs.json` pins package filenames, lengths and SHA256 values for
asahi-audio 4.1-2, alsa-ucm-conf-asahi 10-2, speakersafetyd 2.0.1-3,
bankstown 1.1.0-4 and triforce-lv2 0.3.2-3. It also independently pins the three
compiled ELF payloads, the existing finite source profile, and the four project
API files used for static inspection. Its SHA256 is:

```
e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8
```

The package pins come from the native archive tables in
[data run 38789569155](../../../docs/validation/asahi-audio-data-native-20261015.md)
and [notice-bearing Rust run 38801968699](../../../docs/validation/asahi-audio-rust-notices-native-20261015.md).
The latter's compiled-payload table supplies the three ELF hashes. The profile
records those runs and their exact product source commits. Reading and matching
these retained bytes does not replay a native build or authenticate a signature.

## Export and recipient verification

Run from a trusted checkout containing the exact pinned project APIs. Supply a
directory holding the five original `.pkg.tar.xz` files; no decoding, download,
version substitution or automatic retrieval occurs. The source root supplies the
existing retained source/vendor/patch/notice inputs as data. The checkout revision
is an observed label; exact source hashes remain authoritative.

```sh
task_profile=e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8
task_private=$(mktemp -d)
python3 -I -B scripts/port/platform-audio-sources/intake.py export \
  --source-root "$PWD" --source-revision "$(git rev-parse HEAD)" \
  --archives /private/retained/audio-archives \
  --output "$task_private/handoff" --profile-sha256 "$task_profile"
```

The successful JSON result supplies `index_sha256`. Transfer the complete handoff
directory while preserving mode0700 directories and mode0600 files. Communicate
that index hash and the profile hash through a trusted channel. A hash obtained
only from the same untrusted download does not authenticate it. Verification
requires the trusted project checkout and its pinned APIs, but no original
source root, archive directory, Git access, native actor or network:

```sh
python3 -I -B /trusted/cachy-asahi/scripts/port/platform-audio-sources/intake.py verify \
  --handoff /private/relocated/handoff --index-sha256 TRUSTED_INDEX_SHA256 \
  --profile-sha256 e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8
```

`delivery.json` binds the exact relative namespace, byte lengths, SHA256 values,
private modes, native record associations, source bundle identities, complete
generic inspection errors, installation-review notes and source publication
holds. Its 41 material files comprise the pinned profile, five native archives
and seven existing delivery leaves per package. No private operator paths are
written. It imports project APIs only from the trusted checkout, never from the
handoff or source root. Package archives and ELF members are read as data; no
payload, artifact, PKGBUILD, upstream source or vendor code executes. The pinned
`.xz` packages are inspected through Python's standard library.

Every package is required. A wrong native archive fails preflight before output
creation. A later missing source can leave a private partial directory for
inspection, with no `delivery.json` or success result. Existing destinations are
refused and preserved. Missing associations, altered bytes or convenience copies,
extra material, links, special files, public modes and changed API files are
refused. The handoff is bounded to 128 filesystem nodes, 64 MiB total and 32 MiB per
file. Revision/profile/index pins must be supplied explicitly; the command
requires Python isolated mode even when invoked through `python` directly.

## Actual local validation, 2026-11-14

Python 3.14.7 exported all five actual retained native archives using observed
checkout `df7447050fe8d1efdb58d178b5e99067c70396aa`, then copied the complete
directory and verified it from `/`. The 41 material files total 25,866,296 bytes;
the 23,889-byte index SHA256 is
`70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c`.
Both fresh export and relocated verification returned
`VERIFIED_FIVE_NATIVE_BOUND_FINITE_SOURCE_EXPORTS` with all acceptance fields
false. No private output or native package bytes are committed here.

| Package | Source bundle bytes | Source bundle SHA256 | Preserved generic errors |
| --- | ---: | --- | ---: |
| alsa-ucm-conf-asahi 10-2 | 368640 | `941fe797d5642250e3d62416967ee4c90c55489bef688e82af220111fd919d31` | 54 |
| asahi-audio 4.1-2 | 2938880 | `1bf034fd1f92f36e3576b981138419d3ad232a8dfaf274ff4e4d49398a1ee5a2` | 10 |
| bankstown 1.1.0-4 | 6389760 | `24112eed621156288b7be30f63b03fece691cad3e1534c8e090a7dff6985b179` | 0 |
| speakersafetyd 2.0.1-3 | 7116800 | `27047fbe0e5b71e8a0b5a04fda49d5a78b738d577c170ccb4fb95a9a9649407a` | 5 |
| triforce-lv2 0.3.2-3 | 6707200 | `9157f0d38c24c8e9087f71856613084e4b2f794a1c49e96c2feb23374560164f` | 0 |

The 20 self-contained controls use explicitly synthetic tiny archive fixtures
only for intake mechanics. The 19 separately invoked integration controls require
the actual five-package handoff and refuse absent inputs. They exercise copied
folder verification, CLI relocation, missing/tampered binary and source inputs,
unbound finite source bundles, altered associations/errors/acceptance, exact
namespace, and output preservation. The relocated in-process check also refuses
original source reads, subprocesses and network operations.

```sh
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-sources/test_intake.py
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-sources/check_actual_handoff.py \
  --handoff /private/relocated/handoff \
  --index-sha256 70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c
```

## Remaining holds

Observed native archive/payload digest association is now delivered together
with the exact finite source inputs. Signature authentication remains
`NOT_PERFORMED`; compiled source correspondence is `NOT_ESTABLISHED`.
`complete_corresponding_source_accepted` and `legal_acceptance` remain false.
The existing Rust compiler/linker source correspondence, effective build flags,
runtime dependency source closure and relinking holds remain. Bankstown/Triforce
retain the limited retrospective wmidi 3.1.0 license association; Triforce retains
the nalgebra-macros 0.2.2 workspace source/text association limitation. Historical
toolchain recipe hash mismatches are not repaired by substituting newer recipes.
The original bundle metadata and instructions retain these details unchanged.

All generic protected-platform errors remain visible; this command grants no
installation exception. No native rebuild, package install, service activation,
audio execution, speaker-safety check, M2 hardware check, performance measurement,
publication or release admission was performed by this work.
