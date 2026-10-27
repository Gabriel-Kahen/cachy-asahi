# Native PGO102 construction and correctness component

Root qualified the finite generic ARM4K component from
[run40592666471](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40592666471),
attempt1/job122500619368/artifact12775406393. Exact102-file
[source3ee4b0ae221429385e738f4df01eac1b730f36ee](https://github.com/Gabriel-Kahen/cachy-asahi/commit/3ee4b0ae221429385e738f4df01eac1b730f36ee),
ref `codex/zlib-pgo102-tool-identity-native-v1`, has tree
`20309eaeb580436c4b49f2bb1b35abc2e1c16d0d` and sole parent
`e8ff4ee39ac81c8d30ca954cf3c1007ebe716e04`.

Two independent native builder environments share one fresh341-package producer
and native host. Each attempt records one training pass, 17 native profile files,
two clean optimized builds using its sealed profile without fallback, and 234
owned commands. Each matches 48 encodes, 96 cross-decodes, two probes and six strict
refusals. All eight payloads—libz.a, minigzip, example, probe, strict-gzip, zlib.h, zconf.h
and LICENSE—are byte-identical across attempts. Entire package archives need not
match: independent training seals and runtime provenance can differ.

The target is `aarch64-unknown-linux-gnu` under generic Armv8-A policy, on actual
**4096-byte pages**. Inputs of 16383, 16384 and 16385 bytes exercise data boundaries;
they do not establish execution on a 16KiB kernel. The 17-profile native decoder
transcripts and five complete ten-tool observation probes per attempt match the
trusted source policy. Historical tool FD checks remain recorded native claims.
The passive replay did not execute codecs, compiler, decoder, package tools or GPG
again. Ordered consumer-before-producer retirement is matched original
receipt/transcript evidence, without a new live daemon probe.

The [Root admission](../../artifacts/development/zlib-pgo102-root-component-admission-20261027/Root-component-admission.json)
is 3688 bytes, SHA256
`f77a61bc5b9cb9cfbc02173734234dae7e743501263afbfdfbe4b2c4a8e0d101`.
The [complete strict result](../../artifacts/development/zlib-pgo102-source-mode-corrected-strict-replay-v2-20261027/output/strict-result.json)
is 7506 bytes, SHA256
`d1bb7b1803dfc7d0ce9c9e4a4d97700f58e845b99f3f0c175b8f6d7a30bb2667`.
The [once-owned artifact](../../artifacts/development/zlib-pgo102-tool-identity-native-actual-20261027/Root-first-originals-40592666471-1/raw-originals/artifact.zip) is 29543390 bytes, SHA256
`1c083a597ec49e5639a9d4cddac2d08c0bbfd70f9b9dd892f25bb9224eac81d2`.
[The evidence record](zlib-pgo102-native-construction-20261027.json) gives exact
source/Git/raw-commit, original collection/HTTP body, strict-packet and all eight
payload byte/SHA256 pins. The [first profile seal](../../artifacts/development/zlib-pgo102-source-mode-corrected-strict-replay-v2-20261027/output/public-projection/attempt-1/native-build/artifacts/pgo-v1-evidence/profile-seal.json) and [second profile seal](../../artifacts/development/zlib-pgo102-source-mode-corrected-strict-replay-v2-20261027/output/public-projection/attempt-2/native-build/artifacts/pgo-v1-evidence/profile-seal.json) have SHA256 values
`19d5b5ea146888df74c24434bbaf74c9f8e3ab0ddf5dbd3775f2b08bfb12ec2a`
and `ac5546e6b7ea653d63106de4944b1ca0aa1d5baa47a670671274a4f6eb25d39d`.

The [0600 projection refusal](../../artifacts/development/zlib-pgo102-first-originals-root-plan-20261027/HANDOFF.md)
and [presemantic literal-path failure](../../artifacts/development/zlib-pgo102-source-mode-corrected-strict-replay-20261027/HANDOFF.md)
remain frozen. The corrected projection restored only the exact source-required
0644 modes in a fresh copy; original bodies, mode claims and reader/native gates
were unchanged. No original was reacquired.

This admission grants **no measured performance gain, optimization selection,
installed behavior, candidate16K, M2, production trust or release credit**. Prior
negative LTO receipts remain separate. No full-port milestone is completed.
