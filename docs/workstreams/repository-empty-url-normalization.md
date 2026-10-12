# Empty URL representation normalization

October 12, 2026. The coordinator selected the exact reviewed A356 source for
`scripts/port/repository-client-native/crypto.py`, with self-contained regressions
in `test_crypto.py`. The roadmap and package inventory were read. This scoped
adoption changes those two files and this document. Shared maps, review locks,
dependency pins, CI, Git and dispatch remain coordinator-owned; this change does
not establish native admission.

## Actual retained difference

Run 38259350917's public manifest binds 112 files totaling 274,894 bytes. Fish and
Zsh have exactly one physical `url = ` line in `.PKGINFO`; their DB descriptors
omit `%URL%`. This occurs in twelve package/repository pairs across six repository
labels, or twenty-four descriptors when both `integration.db` and
`integration.files` are counted. The [diagnosis record](../../artifacts/reviews/repository-empty-url-normalization-20261012/actual-relations.json)
binds package, PKGINFO, DB and descriptor hashes and the complete unchanged public
map. The deliberately tampered DB's descriptor inspection uses its byte-identical
healthy prefix after checking the exact expected appended marker; it is not
accepted as an ordinary gzip archive.

The predecessor `crypto.py` SHA256
`3e229ff4c543f462bc04c1a428ec4dfc0f029192885cfdd06821fcb2a85df967`
compares package URL `['']` to DB URL `[]` and raises
`db-package-relation-mismatch`. This is a representation mismatch, not changed
archive or database bytes.

The retained producer pins `scripts/integration/repository.py` at
`49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940`.
Its lines438–443 call `repo-add --include-sigs --sign` against the approved package
copies without rewriting URL metadata. The retained Fish/Zsh recipes omit a URL;
current recipe bytes match the retained source snapshot, with SHA256
`a3f0e5f693a48126086ff0e8279d8d833efb8e625dfa4644fdfd2c04ff0175fa`
and `a0d86c532654f01edac764ad39d1173bb981a13752ad0216ea49907cd49b53e1`.

## Pinned producer semantics

The native result records pacman `7.1.0.r9.g54d9411-2`. The upstream revision is
`54d94116164b0b2202c6061c4a59c6f3e70820d8`, resolved through the primary GitLab
commit API. At that revision, makepkg's `write_pkginfo` calls its key/value writer
with the URL even when empty; repo-add's URL entry formatter emits a section only
for a nonempty value. This accounts for the observed empty package field and
omitted DB section. See the pinned primary
[makepkg source](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/makepkg.sh.in#L472)
and [repo-add source](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/repo-add.sh.in#L116).

The [source snapshots and hashes](../../artifacts/reviews/repository-empty-url-normalization-20261012/upstream/sources.json)
retain original GPL-2.0-or-later notices. A bounded Bash replay uses only the two
pinned formatting functions and the exact scalar parsing statement: empty input
writes the package field but zero DB bytes; a nonempty URL retains its exact
value. It executes no package build, repository mutation, signing or installation.

The native installed repo-add bytes/hash are not recorded in the supplied packet.
The local executable is a CachyOS ELF from pacman `7.1.0.r9.g54d9411-4`, SHA256
`6a6e78829f6058528aeb2f67a092df09398be07b0dd0dad46cfac4207f8f785a`.
It is not used as native tool identity proof. The conclusion rests on pinned
upstream source behavior and the actual retained metadata, with that limitation.

## Adopted source change

The [patch](../../artifacts/reviews/repository-empty-url-normalization-20261012/normalization.patch)
adds one URL-specific validator and removes URL from the generic relation loop.
Only `database` and the new `url_values` function differ among function/class ASTs;
stdlib Unicode categories supply control-character validation.
Package parsing, archive bounds, crypto statuses, independent GPG verification,
certificate validity, signing phases and all other relation checks are unchanged.

| Input relation | Result |
| --- | --- |
| Package URL missing; DB URL omitted | Equal absence |
| Package URL exactly one empty string; DB URL omitted | Equal absence |
| Identical nonempty singleton URLs | Exact equality |
| Nonempty contradiction or one-sided omission | Refuse |
| Duplicate package URL, DB values or DB sections | Refuse |
| Present DB URL section with no value | Refuse |
| Whitespace, padding or control characters in URL values | Refuse |
| Malformed physical field/header/terminator | Refuse |

The only new equivalence is the exact empty package scalar and absence. Accepted
nonempty values are never trimmed, lowercased, decoded or otherwise rewritten.
Whitespace trimming of package field names is used only to detect and reject
malformed spellings. DB header recognition stays exact, preserving opaque values
in other fields. Unicode whitespace and Cc/Cf control categories are refused. Raw physical LF lines are checked because the existing
`splitlines()` readers can erase CR and Unicode separators before comparison.
General field normalization and repo-add's repeated-scalar last-value behavior
are deliberately not imported into receiver policy. URL cardinality refusal is
an explicit additional narrowing; it was not already guaranteed by list equality.
No archive, signature, DB or manifest bytes are rewritten.

The [reviewed source](../../artifacts/reviews/repository-empty-url-normalization-20261012/proposal/crypto.py)
and adopted [production source](../../scripts/port/repository-client-native/crypto.py)
have identical SHA256
`a3568741238738646593b2c972589f4ae92381611c88dea1c1c234c0e59a46f0`.
The unchanged complete actual public
map fails under predecessor code and passes the adopted source's full six-repository
structural audit, including both DB types and exact known negative differences.
This is structural verification; this diagnosis does not create a cryptographic
attestation, native authority or client admission.

## Validation and selection boundary

The separate diagnosis capture has **47 passing tests, zero skips**: 23 focused
URL/actual structural tests and 24 frozen collector crypto regressions. Its
[execution log](../../artifacts/reviews/repository-empty-url-normalization-20261012/all-tests.log)
records that run against the externally pinned actual 112-file packet.

Production `test_crypto.py` independently has **47 passing tests, zero skips**
(5.910 seconds): the original 24 crypto regressions and 23 self-contained URL
regressions. The new in-memory structural fixture covers all six repositories,
both DB types, coherent duplicate URL fields with rebound checksum/size, and
exact signed negative differences. Its signature and certificate placeholders
are explicitly unverified; these structural bytes never receive GPG acceptance.
Production tests import no diagnosis artifacts and do not claim that their
synthetic fixture is the retained native packet.

A separate real temporary TEST GPG/repo-add fixture passed through the actual
`python -I -B entry.py` bootstrap using a private copy of the exact seven source
files and temporary source map
`d8d85ebe1461533265732aa8a2f89fda9c90797603ff8e73403caac605f3f594`.
Its literal nonempty URL exercised the added `unicodedata` check after source
authentication: all fifteen snapshot checks and fifteen terminal checks passed,
current A authorization was `REVOKED`, and private-work cleanup passed. Native
history in this fixture remains modeled; the GPG operations are real.

The same isolated entry correctly refused a fixture with an explicitly empty
package URL because the local CachyOS ELF repo-add emitted a present empty DB
URL section (`malformed-db-url`, before GPG). That local output differs from the
omitted section in the retained native packet. It supplies a refusal regression,
not permission to accept empty DB sections or proof of native tool identity.

The focused tests include coherent duplicate package/DB URL values with rebound
archive checksums: held structural comparison accepts those duplicates; the
candidate explicitly refuses them. Edited metadata test cases receive no GPG
acceptance. Separate counterexamples retain checksum/size, embedded signature,
license/dependency, files DB inventory, aliases, unexpected fields and exact
negative-case refusals. Frozen crypto tests replay real temporary TEST GPG checks
against the candidate, with native history fixtures still modeled.

The [predecessor dependency record](../../artifacts/reviews/repository-empty-url-normalization-20261012/held-dependencies.json)
binds corrected `common.py` 92ca, held collector map 506382/review d9a26, and held
phase successor map f1d874/review 6f8cb. The existing 110-test source packet and
retained actual signature observation remain separate and unchanged. Coordinator
selection of the exact patch is complete. A newly reviewed collector source map
and receipt source pins, followed by an explicitly updated successor dependency
packet, remain separate integration steps. Neither predecessor map silently
accepts the adopted hash.
Native admission, installation and hardware acceptance remain **NOT RUN** here.
