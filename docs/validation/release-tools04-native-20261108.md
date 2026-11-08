# Release tools 0.4 finite native component — 2026-11-08

Root qualified the finite native ARM package-component evidence for
`cachy-asahi-release-tools` 0.1.0-1 → 0.4.0-1 in
[run 42529364204](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/42529364204),
attempt 1, successful job `128879917081`. This is the exact scope of Root's
`ROOT_QUALIFIED_NATIVE_RELEASE_TOOLS04_FINITE_ALPM_COMPONENT_EVIDENCE_ONLY`
decision; the original strict-reader result and its narrower acceptance flags
remain unchanged.

The published closed Source is `f94c4ce6123468d1f991fc83fcba9090280b369d`,
ref `codex/release-tools-v4-finite-source`, tree
`c42c5613b09040d0f14dddc851452ec61c213909`, sole parent
`686958cf7a3248fc0ef33ad4b61ffd22a325c4e5`. Its 201 leaves include the exact
51-member source bundle and matching reader; seven leaves changed and 194 were
held. Source-map SHA256:
`bfee786c2dbcbad2e5dae8d5294784ad34c386b382700083e2ae8fb84e499c8f`.

The actual journey built each version once, with real makepkg `check()` output
(13 predecessor controls and 19 target controls). It exercised isolated
Required/Required TEST signatures, unknown-key and tampered-signature refusals,
installation of 0.1, upgrade to 0.4, all eight installed commands from `/usr` and
a moved prefix, downgrade to 0.1 and removal. The commands were `sbom`,
`source-export`, `recipe-pack`, `recipe-unpack`, `sbom-compare`, `endpoint-copy`,
`endpoint-pack` and `endpoint-unpack`. The transport journey used a genuinely
TEST-signed withdrawal and retained real CLI refusal of synthetic stable inputs.

The reader matched exact 349 → 350 → 350 → 350 → 349 inventories and
12 → 23 → 12 → 0 package payload counts, ALPM ownership and install-reason
restoration, unchanged global trust/configuration and preserved operator
exports. Source-bound owned-command retirement and TEST-home/agent/container/
image cleanup were required. This was an owned image-stage package journey;
it did not install the software on a supported Asahi/M2 target.

Artifact `13635839854` supplied one original ZIP: **799,864 bytes**, SHA256
`8d8ad9dbb7bfe5f8b8ec1f959421a0d249c0cff86916afc36bc48c4cb4922d10`.
Its sole ZIP member was `public-tree.tar`: **8,560,640 bytes**, SHA256
`19253544a485a05b84bc9780d823df4e9e9b1a3bceb7d96112605d625c6fc6ca`.
The exact matching reader was **110,992 bytes**, SHA256
`9a605c41f24f30d92c598da1e2f6f7ca59c20413833eb5b8977c11d1f1f13af6`.
Root acquired the body once and called that reader once, returning
`VALIDATED_NATIVE_RELEASE_TOOLS_ALPM_COMPONENT_EVIDENCE_ONLY` with no denied
actor events. Local decoding imported no artifact-delivered code, launched no
Source actors and made no network requests. The reader retained
`native: NOT_ADMITTED`, `native_16K: NOT_QUALIFIED`, `physical_M2: NOT_RUN` and
`release: NOT_ADMITTED`; Root's separate decision qualifies only the component
evidence described above.

There was **one build per version**. This journey establishes no repeat-build
byte reproducibility for 0.4. Native 16K, supported Asahi/M2 installation and
hardware behavior, production trust/signing, performance and release admission
remain unqualified. Development/release selection flags remain false.

The committed [evidence packet](../../packages/tools/cachy-asahi-release-tools-v4/evidence/release-tools04-native-42529364204-retention.tar.gz)
is **807,123 bytes**, SHA256
`7b5cee1e95e34d38b85701adabdc90b8cdcc24a80f9546fb4f247f639300eda8`.
Its ten members retain the whole original ZIP unchanged, genuine Source raw
commit/full map and identity, matching12 reader pins, strict-reader result facts,
and sanitized Root decision/body-proof facts. The packet's internal preparation
snapshot remains byte-for-byte unchanged from before this publication.

Private custody records remain local. The committed packet excludes private
HTTP/hop/header files, credentials, auth-status records and signed redirect URLs.
This static retention performs no artifact fetch, Source execution or reader
replay and grants no production release or signing authority.
