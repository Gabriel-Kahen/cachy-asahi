# B18: bounded residual metadata closure packet

October 12, 2026. **Implemented and exercised as retained metadata only. The actual packet is FAIL/unresolved, not a prepared or accepted target transaction.** The original 27 ELF requests and 22 firmware refusals remain open with their original static FAIL. No shared manifest or protected stack was changed; no provider download, signature authentication, package/ELF execution, installation or hardware acceptance occurred.

The roadmap and package inventory were read before implementation. Ownership is limited to `scripts/port/platform-residual-closure/{resolve.py,test_resolve.py}`, this document and `artifacts/platform/residual-transaction-20261012/**`.

## Frozen inputs and selection policy

The input contract keeps **261 observed image anchors** and **201 proposed protected identities**, including Python `3.14.7-1`. It does not inherit the two unprotected NetworkManager/Perl updates from the strict tentative 624-package proposal or the coordinated proposal's Python `3.14.8-1`. Both 624-package proposals retain their separate prior status and remain unadopted. These image observations do not establish physical-target or installed-payload authentication.

All **21 direct roots** are pinned together by exact name/version/repository from the held residual classification. Candidate expansion uses only the captured core/extra catalogs; the captured Asahi DB supplies equal-version anchor archive declarations only. The program never adds a repository, fetches a URL or falls back to a host package database. **Only 12 of the original 27 exact consumer/version records occur in the strict graph; the other 15 are unrepresented and cannot close.** All 27 consumer/path/name records retain their OPEN status and are linked to the proposed provider selections; a selected metadata record does not close an ELF request.

Root pins select exact identities. Dependencies first inspect already-selected matching providers, then the captured catalog. Multiple distinct eligible package/version/repository identities remain ambiguous; exact-name, repository order and bare virtual aliases do not silently choose a provider. Versioned provides use their declared effective version; a bare provides cannot satisfy a version-qualified requirement. A second version of a selected anchor is a contradiction, and any protected-version replacement is refused. Declared conflicts/replacements cannot implicitly remove a package. Consistent cycles are recorded and terminate; duplicate identical dependency declarations are retained and counted, not mistaken for distinct provider alternatives.

The ASCII comparator is a mechanical adaptation of the official [pacman v7.0.0 version.c](https://gitlab.archlinux.org/pacman/pacman/-/blob/138cbae58448b7fde90335526add3029875784ee/lib/libalpm/version.c), source SHA256 `28ee2f7ee82e5f526c1179c800688bdaa097c0f36a0df190f770d13c0a64a552`. The audited v7.1.0 comparator differs only in copyright year; its dependency predicate and official golden pairs are unchanged. Epoch, separator-count, alpha/numeric and optional pkgrel rules follow that source. Missing pkgrel equality is not used to deduplicate versions. Literal multiple-hyphen SONAME versions are supported; empty components, non-ASCII and unsupported input shapes refuse. No native libalpm/vercmp subprocess is needed for this reviewed subset. This is not a libalpm transaction solver or proof of runtime ABI compatibility.

The adapted resolver is **GPL-2.0-or-later**, with Pacman attribution. The pinned source bodies and corresponding COPYING are retained in `version-audit/`; preserve those notices and the license when distributing the resolver. Test code is separately authored. Declared package LICENSE/packager metadata is not reviewed source/grant or accountable maintenance acceptance.

## Bounds and refusal behavior

Production ceilings are **21 roots, 1,024 selected packages, 16,384 dependency edges, depth 128, 120 seconds and a 16 MiB report**. Test overrides can only lower ceilings. Hash-bound inputs are ordinary single-link files, with bounded size, no linked ancestors, mode checks when pinned and descriptor identity checks before/after reads. Captured input bytes are rechecked before publication. Catalog streaming counts all consumed decoded gzip bytes, including hidden PAX/GNU headers and directory records, with a 1 GiB ceiling and deadline checks. No tar member is extracted.

Malformed or sparse catalog entries are explicitly unavailable and keep the packet unfinished; they do not silently reduce the provider universe into PASS. Paths must use canonical relative POSIX spelling. Unknown archive/signature pins, ownership, reviewed hook decisions, source revisions, license/grant reviews or maintainers produce explicit blockers. Observed 23 scriptlets and 32 ALPM hooks remain observations; they are not executed or converted into reviewed hook decisions. Metadata filenames and file catalogs do not establish actual payload identity, symlink resolution or installed ownership.

The executable writes only a fresh mode0600 report beneath the assigned B18 artifact directory. Resource or malformed-evidence failures produce FAIL. A complete synthetic caller-fact packet may pass the metadata checks while `transaction_accepted` remains false; the actual retained packet does not pass. In-process checks are complemented by the actual execution wrapper's 120-second outer wall/CPU limits, 2 GiB address-space limit, 16 MiB per-file limit and disabled core dumps.

## Actual retained-catalog result

The initial held source ran from a fresh authenticated two-file copy using Python `-I -B`. Actual child exit was **1**, stderr was empty, and the outer execution completed in **14.199613 seconds**. This is bounded execution timing, not a performance comparison. The 9,510,151-byte report is below the 16 MiB ceiling. Both held source files remain unchanged and no bytecode is retained.

The resolver examines **13,305 available catalog records**, selects **377 tentative metadata nodes** (261 anchors plus **116 candidate extension packages**, including the 21 direct roots), and records **1,594 dependency edges**. All 201 protected identities remain preserved; no protected replacement or selected-version contradiction was observed. The 19 first-level frontier directives each have a recorded witness in this tentative graph. The `gdk-pixbuf2 → glycin → librsvg → gdk-pixbuf2` cycle is recorded and terminates.

Six ambiguous edges remain:

| Consumer / requirement | Recorded alternatives |
| --- | --- |
| curl / ca-certificates | selected ca-certificates and ca-certificates-utils |
| systemd / dbus-units | selected dbus-broker-units and dbus-units |
| libglvnd / mesa | mesa and mesa-amber |
| libglvnd / opengl-driver | mesa, mesa-amber and nvidia-utils |
| qt6-base / mesa | mesa and mesa-amber |
| qt5-base / mesa | mesa and mesa-amber |

No alternative is auto-selected, particularly no PC graphics-driver substitution. The packet also records sparse `findnewest-0.3-4` as unavailable and six unsupported catalog records: incomplete dependency operators in `nextcloud-app-spreed`, plus relation-bound exhaustion for five texlive package records. These are source-format/reader-policy observations; they do not establish corrupt archives or failed runtime programs.

The actual packet has **three unknown anchor archive pins** (NetworkManager, Perl and protected Python) and **38 unknown signature pins**. Equal-version catalog declarations or retained inert archive observations supply the other anchor archive facts without proving installed-byte correspondence. Every selected node still has unknown reviewed hooks, source revision, license review, grant review and named maintainer: **377 blockers in each category**. No declared selected-package conflict/replacement or file-path ownership collision was observed at metadata level; actual archive, hook and installed namespace decisions remain unfinished.

The tentative extension's declared compressed bytes total **95,992,216**, with **65,656** declared signature bytes. Its 116 selected nodes exclude unresolved alternatives, so this is not a complete transaction budget or authorized download total. Known declarations across all selected anchors/candidates total **813,322,032** compressed bytes and **190,175** signature bytes; full aggregate pins and source-retention bytes remain incomplete. Root-only 34,989,696 bytes must not be presented as full closure cost.

## Validation and independent findings

The initial held source passes **42 synthetic tests** and **92 official version comparisons**. Tests cover ambiguity, effective versions, epoch/pkgrel, protected Python separation, contradictions/conflicts/replacements, valid cycles, package/edge/depth/time/report caps, unknown review facts, duplicate ownership, malformed archive declarations, canonical paths and bounded inert input handling.

An independent source peer reproduced four initial gaps: noncanonical ownership paths, an empty release, malformed unused archive declarations and a non-dictionary catalog row. All were corrected and rechecked against fresh captured bytes. The peer also verified the decoded-byte cap with small PAX/directory fixtures and the final empty-component guard. Earlier source captures and failing fixture/harness observations remain separate retained history; none is an actual target transaction result.

| Initial held record | SHA-256 |
| --- | --- |
| resolve.py | `78fa383a264acd5841ddfe1fbe0708cd223d1ebfe17b16600d62cbed9a6a1a66` |
| test_resolve.py | `9f490894ec2aaabe33f0277586473c629acb1585291cff6c2171f099bea60799` |
| Input contract | `681ab356f5a893fabbb2fefb5084c75e231a2761b54d090766d36ca02d86a42a` |
| Actual report | `bbec387c8d6599ac7eff803ff2cd73b64b1ad6a7ac7f43dffe9c8ff9bc1d217c` |

Next decisions are concrete: bind unique provider choices compatible with the actual Asahi platform; resolve or explicitly retain unavailable catalog records; recover exact missing anchor/signature pins; review file/hook/source/license/grant decisions and assign maintainers; then obtain an independently reviewed complete transaction packet before selecting archive authentication. Actual target transaction, rollback, ABI/loader/16K/M2 tests and installation remain NOT RUN. Camera still requires its explicit workflow/backend/owner scope; portal support does not supply it.

## Sealed-review correction

The independent `platform-residual-transaction-root-review.md` sealed the initial `4f73221e…` handoff as BLOCKED. Its receipt, old source, test source, report and workstream text remain preserved. The new `correction/` packet makes exactly three selected corrections:

- Directory ownership paths allow exactly one terminal slash. Interior empty components, repeated terminal slashes, dot and upward components refuse without normalization hiding malformed spelling.
- All metadata, including unused catalog/contract fields, is inspected for NaN and infinities. JSON nonfinite constants and numeric exponent overflow refuse; output serialization forbids nonfinite numbers. An iterative walk refuses cyclic/unsupported structures under depth128, 8,388,608 nodes, 1 GiB scalar bytes and deadline checks. Strings are length-checked before UTF-8 allocation. Existing ordinary-input, decoded-catalog, report and outer-process caps remain.
- `hooks=[]` is the only currently supported explicit no-hook decision. Unknown hooks fail; nonempty string lists fail as unreviewed hooks and unknown structured lists fail schema validation. No structured hook-policy acceptance was invented. Observed scriptlets/hooks remain unreviewed observations.

The three old-source false-PASS controls and corrected positive/negative fixtures are retained separately. These checks establish correction behavior only. Exact provider choices, archive/signature custody, licensing/grants, maintenance and target transaction acceptance remain unfinished. The original **27 OPEN ELF requests and 22 firmware refusals** remain; catalog selection cannot close the 15 original consumers absent from this strict graph.

The corrected source passes **54 synthetic tests**, including the three sealed-review causal controls and strict raw-JSON/nonfinite/depth/node/byte/cycle checks. Its actual retained-catalog replay exited **1** with empty stderr in **20.677987 seconds**, under the same 120-second/2 GiB/16 MiB outer limits. This is execution timing, not a performance comparison. The 9,510,151-byte corrected report is **semantically identical to the old report except elapsed time**: 377 nodes, 1,594 edges, six ambiguities, nineteen frontier witnesses and 201 protected identities preserved. No required ELF or firmware request was closed.

| Corrected held record | SHA-256 |
| --- | --- |
| resolve.py | `8f0734a9747712aaa6e1f255a740fae25159c8cd266b086f72731b4c44e7a03b` |
| test_resolve.py | `146dc3581890e187daad311ddc53506ec93a8cae93e9dc1d1d101bb3b19ece5b` |
| Corrected actual report | `398b17f64eea3a949439a53cee0ce1d5f46ce316b2670563b8e0245ece619ffa` |

The new correction handoff is separate from the old `4f73221e…` packet. All sixty old indexed artifacts were rehashed unchanged, and the old workstream/source copies are retained in `correction/history/`. The new packet awaits independent peer review; no target transaction acceptance follows from these corrections. The separate camera route/receiver packet now exists in `docs/workstreams/camera-feature-route.md`; physical acceptance remains NOT RUN.

## Unused ownership declaration correction

The independent `platform-residual-transaction-root-followup.md` verified the first three corrections but blocked source acceptance because malformed supplied ownership paths in unused catalog rows still permitted PASS. The previous `901d5d1f…` handoff and all20 indexed files remain unchanged, alongside the original60-file hold. Source/test/workstream copies are preserved in `correction2/history/`.

All supplied ownership declarations now pass `file_declarations()` at record ingestion, including unused rows. Lists are capped at200,000 unique string paths of at most4096 characters, with canonical relative POSIX spelling and exactly one optional terminal directory slash. Empty/interior-slash/dot/up/control paths, invalid containers/types, duplicate entries and exceeded caps refuse. A malformed unused catalog record becomes an explicit invalid-catalog-package blocker; anchors refuse directly. Unknown/absent ownership and other unknown facts in an unused valid record are retained without transaction blockers. Selected unknown ownership still blocks, and selected declared-file collisions remain reviewed separately.

The new source passes61 bounded synthetic tests, including unused-malformed counterexamples and tiny lower-bound count/length controls. Actual transaction acceptance, provider ELF/loader/runtime/16K/M2 validation, archive/signature custody and original27+22OPEN remain unfinished. The new `correction2/` packet awaits the same independent peer recheck.

The corrected ingestion source ran from a fresh authenticated two-file copy with Python -I -B under the same120-second wall/CPU,2GiB address and16MiB file limits. Actual exit1, empty stderr and30.408413seconds retain a9,510,150-byte FAIL report. Parsed report equality with the previous hold is exact after removing only elapsed time:377 nodes,1,594 edges,six ambiguities,nineteen frontier witnesses and201 protected identities preserved. Only12/27 exact consumers occur;15 remain unrepresented. No original request was closed, and timing is not a performance result.

| Ingestion-corrected held record | SHA-256 |
| --- | --- |
| resolve.py | `df71e3166025849785f1bdd4543f36938d7fd191dc8d407aa420a1b61968548e` |
| test_resolve.py | `6c8a1e159d21d41379d744fc64842cec3027629bbd92aa146fdb10c9c8280e99` |
| Actual report | `ce9f141bab83209d1fe55f1901b8ce0a0a42ac2096da59334ccd9b0a496361aa` |
