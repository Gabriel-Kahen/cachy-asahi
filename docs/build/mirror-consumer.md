# Build inputs from an authenticated source mirror

`scripts/build/mirror_consumer.py` materializes a selected retained package into a
fresh private context for the existing `build_v2.py` and `source_materials.py`
interfaces. It verifies the mirror first, then requires the exact release,
package/version/architecture/archive digest and PKGBUILD/SRCINFO hash pair.
Retained source and package Python, PKGBUILDs, notices and old verifiers remain
data. There is no build, Docker, makepkg, network, signing or installation action.

```sh
python -I -B scripts/build/mirror_consumer.py materialize \
  --bundle /absolute/path/mirror.tar --mirror-sha256 "$mirror_sha256" \
  --release-sha256 "$release_sha256" \
  --package cachy-asahi-maintenance --version 0.1.0-2 --arch any \
  --package-sha256 "$archive_sha256" \
  --recipe-sha256 "$pkgbuild_sha256" --srcinfo-sha256 "$srcinfo_sha256" \
  --output /absolute/path/private-parent/fresh-context
```

The caller authenticates all selection pins through the established release
trust process. The consumer does not perform signature verification. The output
parent must belong to the current user and be unwritable by group/others. The
new context and all subdirectories are `0700`. Recipe/evidence/SRCDEST files are
non-executable `0400`; the existing source-cache API requires its private files
to be exactly `0600`. No existing output is replaced. Input verification and
static staging happen before output creation; I/O failure during final writing
may retain a partial fresh directory. Only a successful receipt confirms output.

Current canonical single-release mirrors work directly. Retained histories
require the successor `release_source_mirror.py` implementation with
`verify_any`; adopt the frozen incremental-mirror proposal before using history
inputs. No archived verifier is imported as a fallback. The tests prefer the
canonical successor fixture helpers after adoption, with an explicit frozen
development-packet fallback before integration.

## Context contents

| Path | Input or purpose |
| --- | --- |
| `recipe/` | Exact selected recipe/local inputs; reviewed original profiles omit their transport-only `bundle.json` |
| `reviewed-inputs.json` | Exact file hash map consumed by `build_v2 --reviewed-inputs` |
| `retained/source-plan.json` | Original pinned HTTPS source plan, when required |
| `retained/catalog/` | Original catalog and its selected notices at their original safe relative paths |
| `retained/cache/` | Reconstituted private source-cache objects and exact receipts, with no acquisition |
| `source-material/srcdest/` | Exact HTTPS archive bytes staged by the existing `source_materials.stage` API; empty for local-only recipes |
| `source-material/` | Existing source-materials selection/plan/catalog/receipt/notice evidence for remote inputs |
| `evidence/` | Selected package archive, raw `.BUILDINFO`, provenance, source map and notices |
| `builder-request.json` | Concrete native invocation template and explicitly NULL actual selectors |
| `selection.json` | Relocatable inventory, identities, modes, hashes and non-acceptance fields |

The original archive bytes remain compressed even though their evidence filename
is `retained-package.pkg.tar`; the bounded archive reader identifies compression
from the content. `.PKGINFO` and format-2 `.BUILDINFO` identities are checked
against the exact selected package and recipe. The raw BUILDINFO bytes and
installed dependency lock remain retained evidence. They are not converted into
an asserted inventory for an unknown builder image.

For current/legacy reviewed original recipes, the consumer invokes the existing
`recipe_source_delivery.unpacked/source_set` validators and preserves their exact
PKGBUILD/SRCINFO pairs. HTTPS recipes preserve their full retained source map and
source-plan recipe hash map, catalog, source objects, notices and receipts. The
consumer uses only static `build_v2.recipe` inspection and existing offline
`source_materials.prepare/stage`. It never invokes retained recipe hooks.

## Relocation and verification

Keep the returned `selection_sha256` through the trusted export channel. After
moving the context, use a trusted installed copy of the consumer:

```sh
python -I -B /trusted/repo/scripts/build/mirror_consumer.py verify-context \
  --context /new/location/context --selection-sha256 "$selection_sha256"
```

Verification needs no original mirror/release/cache directory. It checks every
materialized byte and private mode, refuses missing/extra/link/special files,
rechecks exact profile/source-map/license/archive/BUILDINFO joins, and repeats
static recipe/offline staging checks on a private temporary snapshot. The
repeated stage must reproduce the pinned SRCDEST bytes. It also checks that the
trusted `build_v2.py` and `container-entry-v2.sh` bytes still match the request.
No source file in the context is imported or executed.

## Root's native invocation

`builder-request.json` contains an ordered `argv_template` for
`${TRUSTED_REPO}/scripts/build/build_v2.py`, with concrete `recipe/`, reviewed
input map, source-plan digest, catalog and cache paths. It fixes `--mode native`
and `--network none`. For local-only recipes it omits the remote-source flags.
The container-only makepkg commands are recorded as data:

```text
makepkg --printsrcinfo
makepkg --verifysource --noconfirm
LOGDEST=/out makepkg --cleanbuild --clean --force --log --noconfirm
```

Actual selectors remain NULL: pinned builder image, independently reviewed image
package lock and its digest, SOURCE_DATE_EPOCH, fresh build output, native host
binding and actual build record. Actual resulting archive digest/length and
BUILDINFO digest are also NULL. The template has NULL argument slots for image,
epoch, package lock and output. This is a held request, not a runnable command.

Root must create a separate actual invocation after authenticating those
selectors and choosing native capacity. Keep the pinned context unchanged;
filling its request in place would change the selection digest and the held
context contract. A context receipt/static inspection is not source-body review,
dependency availability, a successful native build, a reproducible artifact,
installation, M2 compatibility, legal permission or release admission.

## Limits

This bridge preserves existing recipe support and mirror/source bounds. It adds
no VCS/SKIP/epoch/split-package support and never substitutes unverified source.
Materialized files stay within 64 MiB per file, 512 MiB total, 16,384 files and
16,384 directories; metadata uses the existing 4 MiB JSON limit. Cache and staged
SRCDEST may both contain an archive, so this output bound can refuse a large
selection that fits the deduplicated mirror. Refusal does not raise the caps or
weaken source-cache privacy checks.
