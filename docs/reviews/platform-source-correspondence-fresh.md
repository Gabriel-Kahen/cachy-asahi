# Fresh official platform Source correspondence

Exact selected Source correspondence remains **OPEN** for Arch Linux ARM `systemd 262-1/aarch64` and `pacman 7.1.0.r9.g54d9411-2/aarch64`. This October 14, 2026 pass recovered neither matching PKGBUILD bytes nor authoritative selected-build transformation custody. It is a bounded access and repository-evidence finding, not proof that the missing records do not exist.

Evidence is retained under `artifacts/reviews/platform-source-correspondence-fresh-20261014/`. `authentication.json` authenticates four reused small BUILDINFO/PKGINFO bodies against the prior accepted inventory and seal `850e04f2a70a0627cb0e8ae834deb0448fc0afdc335f2be93c96e689f3dc4550`. Archives were not reread and signatures were not reverified. The prior receipt and the published root review remain unchanged.

| Selected package | Required PKGBUILD SHA256 from BUILDINFO | Authenticated BUILDINFO SHA256 |
| --- | --- | --- |
| systemd 262-1/aarch64 | `9ea4d4fa1341fa640f98cbf4bd9b42b7d7c77c2344db2a243b703a6b73b24433` | `8a850564e425c013cdf516327f4bf89992506f89202eae594f6f1a4f8e5350eb` |
| pacman 7.1.0.r9.g54d9411-2/aarch64 | `3064461fa0821e329e5c9fce4962016e358e1b0d5d259c5d18f7a77174c80219` | `09fb0c1f076f86969614996ce143b5acfa3a7948424baa628c9e484e63ab1f69` |

## Fresh retrievals

The three bounded lanes completed **35 credential-free GETs**, retaining **266,227 response-body bytes**: 28 HTTP 200, five HTTP 500, and two HTTP 404 responses. `result.json` joins their separate timestamped ledgers and verifies all retained bodies; the package lanes also retain independently hashed application-visible header files. The parent lane retains parsed headers inside its ledger. These are application observations, not TLS wire captures. No timeout was observed in this fresh pass; earlier timeouts remain historical evidence.

Both official package pages returned HTTP 200 and still selected the held versions, architecture and build times: [systemd](https://archlinuxarm.org/packages/aarch64/systemd), [pacman](https://archlinuxarm.org/packages/aarch64/pacman). Their four linked Source Files/View Changes requests, plus the systemd direct `/files/PKGBUILD` request, returned HTTP 500. Each failure body was 25 bytes, SHA256 `ab0bc2e5951f2ff353b68ec5e8853687e7d397c80ae953bed690f444eb077380`. These five observed failures establish access failure at retrieval time, not permanent Source absence. No selected build-log link was recovered from the inspected package pages or systemd candidate status/check responses.

Each package request used a 20-second socket timeout, a 4 MiB body cap and disabled redirect following. The parent used a 15-second socket timeout, a 4 MiB per-body limit and an 8 MiB aggregate pre-request guard, stopping at seven requests below its twelve-request allowance. That guard does not enforce the aggregate after adding a response; the observed 52,449 parent body bytes remain below 8 MiB. Its urllib helper permits default redirects; all seven retained final URLs equal the requested URLs. None of these settings establishes a hard total wall deadline. Network is closed in all three lanes.

## Immutable history and builder context

The systemd lane freshly pinned candidate commit `301752c301d8d27080323e8ceea17c1e90a7a726`, root tree `990b31d1e143bb5671968483ee7ad3bc6f6cb181`, core tree `4ba2b4bab85abc678c716ab778c48e251471c2ef`, and package tree `5972be3defdeb729bf1bcdd20b68c9c934079924`. Independent Git tree encoding and directory joins pass. Newly decoded `.SRCINFO` blob `58c668fd95cd01e92ee38c283a28d41848f0d4d5` contains 8,722 bytes and declares `arch = x86_64`. Candidate commit combined status has zero statuses and check-runs has zero checks. Its aggregate `pending` status does not establish an active build, and those limited public responses do not exclude private or external records.

The previously retained systemd recipe SHA256 `a3ac91580efa00668e2453b4fc890c32c4dbe899a196271e10b201cce1e9e4cc` differs from the required selected hash. That recipe body was not fetched again. Fresh tree identity, version and timestamps do not repair the missing recipe-to-build association.

The pacman lane read one ten-entry official path-history page bounded by the selected build time. Its first candidate remains `fd636a0077db0efe900d67d4de910c0d270fc8c4`, 2,671 seconds before the selected build. Its independently encoded root tree is `ca8030655161e398651850ff5014179d408e8202`. The GitHub commit-parameter tree response reports the commit SHA in its top-level identity field; this anomaly is retained, while tree entry encoding is checked against the commit's actual tree field. Chronology is not build custody. The retained candidate SHA256 `0043b86a639da6a67239cee8479b46e5ec43835c722ff3bdda8c1f34616ca651` still differs from the required hash; no new candidate recipe was requested or rewritten.

Fresh pinned README/CONTRIBUTING text and wiki documents explain ARM recipe modifications and `buildarch` scheduling. They supply no selected transformation implementation, invocation or complete input set. The wiki snapshot is commit `e6dce6a2ec860a7e25d9f099d448c6de3eb1d3db`, root tree `924c5ef4839d8de9eddebeed69280d82e293f28b`, with 27 entries. Only the listed contributor/developer text bodies were read. The parent also inspected one current public organization repository page with seven entries and no pagination Link header; this does not cover private, renamed, external or all historical builder locations.

Selected BUILDINFO declares devtools `1:1.5.0-1-any` for systemd and `1:1.4.0-3-any` for pacman. Exact-current `core/devtools` and `extra/devtools` lookups at PKGBUILDs commit `2fe589452f452eb4c5de9e8981b5964f20d1a5f0` each returned HTTP 404. This only establishes those two absent paths at that ref. It does not establish historical build-tool Source absence or recover the selected transformation.

## Validation and required next evidence

`authenticate-local.py`, `audit-builder.py`, the package retained-data checkers, and `assemble.py` validate the finite retained bytes and reported joins. Systemd reports 83 retained-data assertions. These are data-authentication checks, not implementation tests, signature verification, package builds or native acceptance. The package reports and `attempts.json` retain parser/search limitations and distinguish reused metadata from fresh retrievals. Documentation-only work does not require implementation tests.

The precise missing input, also recorded in `next-input-request.json`, is either immutable official selected PKGBUILD bytes matching each required hash, or an authoritative selected-build record joining the exact BUILDINFO to original/result recipe bytes and hashes, immutable transformation code and every selected transformation input. A plausible upstream tag, version match, architecture declaration, scheduling variable or guessed rewrite cannot supply that association. After it is recovered, source inputs, helpers, licenses, dependencies, actual commands and results still need their own audit.

No matching selected recipe license closure or actual selected build command is newly established. No recipe evaluation, package build, installation/removal, archive overwrite, maintainer contact, Git mutation, CI/native actor or canonical manifest edit occurred. Selected Source, full license closure, native build, installation, runtime, M2 hardware and full-port acceptance remain unpassed. This work does not change any prior hardware, performance or milestone result.
