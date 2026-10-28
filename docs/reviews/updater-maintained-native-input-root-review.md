# Independent updater maintained-input review

**Result: PASS for retained source metadata and input derivation; caller admission remains withheld.** This review authenticates proposal receipt `44c666fabd842d4eb82eb1f4eab141e5d0e2c66dbbd34cbc8ca291b33b4d6e7f`, its index `8055cb22f126cdeaf81aad87d33b40c2ac11272649fd070bee6047e59f40dc69`, all 324 leaves/15,738,429 bytes and the separately pinned guide `4d9b150913bf59df49e922635cd95ece25e38f669dd4988bb6efe719ec87bb83`. All seven derivation inputs also match their retained original paths. The root recomputed the joins independently, without importing author scripts or replaying the nested peer suite.

Current goal, outline, roadmap and package inventory were read and captured. Full R1–R5/M5–M9 remains mandatory and incomplete. The manifest still records updater native build, installation and hardware validation NOT RUN. This generic builder-input proposal neither selects the Asahi target transaction nor changes the protected platform stack.

## Input identity and derivation

The maintained base has 248 package descriptors and an exact 341-package final inventory. Base input `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` joins inventory `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`. Compared with historical base `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`, only Vim and vim-runtime change, both from 9.2.1164-2 to 9.2.1178-1. The other 246 full descriptors and all base fields outside packages are identical.

Exactly 13 disjoint additions retain their complete historical descriptors: bats, compiler-rt, git, libgit2, lld, llhttp, parallel, perl-error, perl-mailtools, perl-timedate, rust, scdoc and zlib-ng. The original extension is `988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776`. The derived extension changes only its three input/inventory binding fields; the unchanged historical metadata, including root pins, supplies no new consumer authority.

| Derived object | SHA256 |
| --- | --- |
| Provisional extension | `22dd1be31b016f1b17d98ed3f728651bb4fe3048eec87d1fd5a78e5568e55aee` |
| Merged source-only inputs | `a9437eaaa382decc67761add3ab69823e727a390adc87802504b5d2569fcf7ab` |
| Expected354 lock | `5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee` |

The merged input has 261 package descriptors and an exact 354-package inventory. Its full package map equals maintained248 plus the unchanged13. All other fields equal the maintained base except the explicit source-only status. Both old354 and new354 lock bytes were independently reconstructed; their sole inventory delta is the Vim pair.

The counts are descriptor coverage: three keyring objects plus rootfs/payload signature and 261 package/signature pairs total 527 transport objects; rootfs plus 261 packages total 262 signed payloads. Each payload has a nonempty size/hash/signature descriptor. No acquisition or signature verification occurred here. The 167 registry packages plus one upstream materialization belong to a separate Cargo/source lane and are not counted among the 527.

Historical transaction receipt `f48c3fa41de8df649260e3c16fa3361f0c4b65e28c70e431baee8d887bcf4490` remains bound to the old base/extension. Its passing dependency test and 13 signature observations cannot certify the maintained354 candidate. The new transaction receipt is null and all proposal authority fields remain false.

## Source/Cargo evidence and limits

The independent Source/Cargo subreview is sealed by receipt `878311efcfd24be4f9cd8fe2ef5a7f603f1d5980809980a65029fb4be84069c8`. All 86 retained Source files/4,248,868 bytes match their proof by SHA256, modes and recomputed Git blob SHA1 under recorded commit `0e07db1b9cd1f1fd960353ccecff91bd3367dbc3`. This verifies held blob identities; it does not independently authenticate the commit DAG. Cargo's 37 retained text/metadata rows, lane receipts, 21 reconstruction input identities and ready64 package/eight root maps also join.

The held Cargo.lock is `0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753` with 168 entries/167 registry packages; recipe `c191226dba5eaeb3b12bbf11dcad4662a92640a8fc46a51fee340ca15f9befef` agrees between Source and Cargo holdings. Upstream revision remains `e2b1b7144be71cf392809f48d1440f8da1d9c81a`, and prior exact-recipe receipt `b6596110026618a9b650e38d65d210d7bd34bd6872dc5abeadde3f0853615c3a` remains historical. Cargo, updater and baseline lane receipt pins are respectively `e262ee81f8804e33fcd0e2a33ed8490eb3e4166c2874e6598d339a2b01f1642f`, `c85d1334ce8a10415d783bd1ceec179eb404bf7c4c5c8db17a84bdb390a12845` and `455e4e2b4df956b838d8f139a279b6fd2da4d76a11e296fbddc16933ebad5880`.

The author's 1,641 external custody comparisons are retained reports, not replayed checks in this review. Historical `/tmp` archive/vendor/registry/notice paths were neither revalidated nor transferred to durable custody. Original/sanitized/vendor identities remain distinct; metadata joins do not reconstruct omitted archive bodies. Fresh native Linux selection, build-script execution and Rust compilation remain NOT RUN. Full-vendor redistribution and selected binary source/license acceptance remain open, including incomplete grants for block0.1.6, malloc_buf0.0.6, objc-foundation0.1.1 and objc_id0.1.1.

Root performed 1,282 named authentication/join checks and four pure corruption controls. The separate Source/Cargo review adds four controls. They reject non-Vim changes, altered addition descriptors, stale maintained pins, historical receipt admission, recipe/Cargo drift, false actor admission and successor Vim values against the still-historical public frozen354 map. These finite checks execute only owned review code over bytes/metadata; no retained source actor, original suite, build helper, native/API/signing operation, package operation, network or Git ran.

## Exact next bounded proposal

`artifacts/reviews/updater-maintained-native-input-root-peer-20261013/transaction-resolver-next-request.json` supplies the exact five input identities, complete 13 descriptors and finite acceptance requirements. The next worker should produce a distinct versioned maintained354 metadata transaction/dependency receipt. It must bind beca/fc853/22dd/a943/5c72, the resolver's exact source/version/schema and every result's provenance. Independently recompute dependency/provider/version relationships, conflicts, replacements/removals and unresolved or ambiguous cases over the retained maintained base/rootfs/addition metadata. Document supported version semantics and refuse unsupported syntax; do not copy historical resolver results or hide unresolved rows. Enumerate the new descriptor associations, preserving their distinction from acquired and verified objects.

That prepare receipt must keep acquisition, signature verification, pacman dependency testing, installation and Rust builds explicitly NOT RUN, and all admission flags false. It is proposed preparation evidence, not a receipt accepted by the current runtime. Before actor admission, independently review explicit versioned consumer support and then rebind updater-native's four literal inputs: base, extension, new receipt and expected inventory. Regenerate the public frozen354 tuples under the new identity, then propagate ready/source/stage/workflow/controller digests and retain actual per-run Source registration. Final successor hashes are not yet available.

Preserve the updater's 115-minute precheckout deadline, cleanup reserves, first cause, sticky cancellation and once-only recovery. Do not inherit the maintained template's clock/image. Updater10's four frozen404 failures and prior updater8/9 UNKNOWN histories remain intact; maintained template8/4/249 is separate from Rust evidence. Durable source/Cargo custody, fresh527 acquisition/262 signature observations, native selected graph/build-script/license gates, two clean Rust builds/comparison and owned cleanup remain required later. No new signer/service outcome is inferred.

This source-only next proposal can proceed without M2 hardware. Installation, 16K runtime, both M2 Air sizes, measured performance, maintained full-port releases and R1–R5 acceptance remain unfinished. Root integration and Source selection belong to the coordinator; this review supplies no dispatch authority.
