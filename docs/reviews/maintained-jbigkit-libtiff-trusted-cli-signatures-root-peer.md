# Independent certificate representation and trusted CLI signature review

PASS for exact public-certificate representation and the two retained ordinary trusted GPGV detached-signature results. This peer ran no GPGV, process, signal, native library, FFI or archive decoder. Primary protocol documentation was read through the web tool. Root executed the two selected GPGV calls. No guardian, live resource cap, failed/hung descendant disposal, whole baseline/intake, package Source/license/ELF/ABI, ARM/M2 or full-port acceptance follows. Full R1–R5/M5–M9/A01–A15 remain required.

## Public certificate bytes

Original retained public certificate is `6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f`/3098 bytes. Root's transformation record is `c74260f6d1324d0991719cd041e2e72e44ea382d5649363011bb0e0149d387ab`. Its binary derivative is `9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae`/2228 bytes/0600. Strict independent decoding gives exactly those binary bytes; the original remains unchanged. This is the same public certificate in a different representation, not new trust material or an OpenPGP cryptographic proof from base64.

The selected certificate has LF lines, exact public-key begin/end markers, an empty armor-header region, canonical base64 and one checksum line. The peer's deliberately narrow selected-record parser rejects other framing rather than claiming to accept every legal armor variant. Independent bitwise and table-driven CRC24 recurrences both produce `008803`, matching `=AIgD`; reference vector123456789 produces21CF02. The initialization/polynomial and checksum-over-decoded-octets rule follow [RFC4880 sections6/6.1](https://www.rfc-editor.org/rfc/rfc4880.html#section-6.1). CRC detects representation corruption; it does not authenticate a key or signature.

Eighteen fresh malformed armor cases refuse: wrong delimiters, missing separator, unselected header, trailing record/text, alphabet/whitespace errors, missing final newline, CRLF in this selected grammar, non-ASCII, wrong/missing/duplicate checksum, noncanonical pad bits, oversize/overlong content and interior padding. Representation/input checks pass58 assertions, with no actor or crypto library call.

## Preserved failures and limited cleanup evidence

The first actual signature receipt is `0d55d48845f34e82cf95263b99e0f64d656442b915ffcca86bd5b82619ed2bcd`. Both indexed raw leaves authenticate. The original ASCII-armored keyring invocation reports invalid packet ctb=2d, ERRSIG and NO_PUBKEY. Signature crypto is FAIL, parent exit1, second command NOT_RUN. Its subprocess returncode remains `NOT_RETAINED_BEFORE_PARENT_ASSERTION`; this peer does not reconstruct it from status or parent exit. Root reports removing the empty first private home after sealing that failure. The original receipt's NOT_YET_PERFORMED cleanup field remains immutable; no retroactive success or process-disposal proof is added.

Fresh actual02 also retains a pre-actor receipt-shape KeyError: the old payload receipt uses `intake_plan`, rather than the expected indexed_artifacts field. That record states zero GPGV commands and no private home created. Root corrected this unsealed caller before the two actual commands. It remains distinct from the first actual GPGV failure.

One peer test initially changed a KEY_CONSIDERED fingerprint while intending to lowercase the VALIDSIG signing fingerprint. That auxiliary-field change is outside the Root gate's selected fingerprint check and was accepted. The harness was corrected to target VALIDSIG; it then refused. This is a retained harness targeting mistake, not a reported candidate defect.

## Exact actual02 inputs and command evidence

Root actual02 receipt is `247536273c9fd7910f7e022375226e87f63b9f85d9a13a40f55bdf3ea25aced1`/2064 bytes, with7 indexed leaves. Result is `6a2093014e0a8ca9aaff82aede5448b011a806b9e3e1e3f418dd1b29ba686230`/5688; selected caller is `1f2994bc0763cf320b5dd55309882fd5500b11fbce5290d39b67b2799928b170`/5700. All seven leaves, the exact underlying payload receipt `0c8a2396b64af74ed8f928a843a7efacc32a3b56e4fb15bdea0432c637401eae`, and its intake plan `77507b014e2fbda0e995ca28b5784e7d5faf4718a3a1ff02627bc8ecbbb0131a` authenticate. This authenticates the selected plan dependency, not every other payload packet leaf or all341 intake rows.

All seven input rows reauthenticate independently: original armor, binary derivative, GPGV executable, two compressed archives and their detached signatures. The tool `/usr/bin/gpgv` is `eb634c812e900c111bd33adb104f7781d736077b4afd6b0e202c650d24c3c59f`/384088/0755. Its loader/runtime/kernel and standard GPGV behavior are inherited trusted host prerequisites; this review does not invent complete runtime Source correspondence requirements.

| Selected archive | Archive SHA256 | Detached signature SHA256 |
| --- | --- | --- |
| jbigkit2.2-1/aarch64,49740 bytes | `1be37e2dc4b2029668838e9dc7068c5674199a883ca5a0f4c11c7d8005f626ba` | `a9a18e51c58154f771d8139f5f1c442eefb6756a2b94563af7da67c8e66a0b40` |
| libtiff4.7.2-2/aarch64,354120 bytes | `60308af15d83863b3ee1587922add34faca8d950b55aae29434de1423638a9f5` | `fbaa11aa24da920b08fd060172f99f70d2782e0778b0b286581585f66c705226` |

Each signature is566 bytes. Both exact argv records select `/usr/bin/gpgv --homedir <new-private-home> --keyring <binary9403> --status-fd 1 <selected-signature> <selected-archive>`, with signature and archive in that order. Selected environment is PATH=/usr/bin and LC_ALL=C, standard input DEVNULL, output retained in new exclusive files. The ordinary tool calls use one original work_end=entry+116/end=entry+120 frame, with remaining timeout rather than renewed per-command budgets. Both natural returncodes are0; both finish before the original work cutoff. Complete record elapsed0.009253373 seconds. Live output/resource caps, held-leader ownership and syscall hard-wall guarantees are expressly unproved.

Root rechecks all seven input bytes/modes before commands and after each command. The exact fresh public-only home is absent after the run, matching retained empty-home removal. This is bounded filesystem evidence and Source behavior, not a proof about failed-process descendants. No host keyring, secret key, agent, network or shared manifest/source mutation is selected or claimed.

## Status and cryptographic result

Each actual status file is374 bytes and stderr209 bytes. Both have exactly NEWSIG, KEY_CONSIDERED, SIG_ID, GOODSIG and one VALIDSIG. Every full VALIDSIG signing and primary fingerprint equals selected `68B3537F39A313B3E574D06777193F152BDBE6A6`; public-key algorithm1, hash10 and signature class00 match the retained result. No bad/expired/revoked/error status appears. UID text alone is not the acceptance identity.

[GnuPG's status documentation](https://github.com/gpg/gnupg/blob/master/doc/DETAILS#general-status-codes) defines VALIDSIG as cryptographic validity and identifies its full signing/primary fingerprint and algorithm fields. [RFC4880 section9.4](https://www.rfc-editor.org/rfc/rfc4880.html#section-9.4) maps hash10 to SHA512. These documentation reads explain the recorded fields; they do not assert a version-matched Source proof for the selected tool binary.

Exact extracted Root status-gate controls evaluate only literals and the pure status function, without importing or calling its subprocess actor. Twenty-four fresh malformed statuses refuse: each of twelve closed bad-status tags, missing/duplicate VALIDSIG, wrong primary/digest, truncated/extra fields, bad prefix, empty/oversize/overlong status, non-ASCII and lowercase signing fingerprint. Signature evidence and controls pass127 assertions. No author suite or actual verification was replayed by the peer.

The combined result is detached-signature cryptographic evidence for these exact two pinned archive byte strings under the selected public certificate and trusted tool. It does not establish archive member intake, source/license provenance, dependency resolver correctness, ABI compatibility, future loader behavior, installed packages, hardware, historical trial08 acceptance or all-baseline completion. Any operational wrapper adoption or binary-keyring pin integration remains a separate Root Source selection; original certificate and all prior failures stay preserved.
