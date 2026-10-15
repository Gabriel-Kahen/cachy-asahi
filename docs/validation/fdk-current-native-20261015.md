# Current FDK native build pair — 2026-10-15

[Workflow run 38760088765](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38760088765) completed successfully. Both clean native ARM container builds of `cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz` recorded `built-package-static-pass`, `builder_host_arch=aarch64` and exit 0. The dedicated runner recorded `FDK_PAIR=PASS`, `EXIT=0`.

| Input or result | Identity |
| --- | --- |
| Workflow | `native-arm-build.yml`, ref `codex/fdk-native-current-v1`, commit `99f996087c5b5609805f904c33ddc50f8a948c89` |
| Original builder source | `a79c4ca92486854f9edb639cd970d2c90fda4b12` |
| FDK recipe/tool source | `804b418f14459e82031046fb28a0308b4cb9348e` |
| Upstream codec source | `a68a51aa45d86a43c7b228e3d45624af09dcdd8d` |
| PKGBUILD SHA-256 | `774803633213d77e9879005608ff23528b6780465c7bd00f3234430c9a7346df` |
| Selected-source archive SHA-256 | `1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4` |
| Package SHA-256, both builds | `237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247` |

Both builds used the same fresh job-local base image, `sha256:e4a49a653a3b365468102d4f546ba65b3fb6eaa1d1e4a64e8137b272b0df38b5`, and package-lock SHA-256 `fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`. Each ran with network disabled and `SOURCE_DATE_EPOCH=1791748800`. They used distinct recorded containers on one runner; independent-machine reproduction is not attested.

The retained comparison reports `contents-reproduced`, no errors, and equality of package bytes, installed contents, `.PKGINFO` and `.BUILDINFO`. Both package validations report `artifact-static-pass` with no errors. Both log tails contain these actual markers:

```text
PASS: native source compilation/link; codec smoke and package checks follow
PASS: classic AAC-LC ADTS roundtrip; 26 decoded mono frames at 48000 Hz
PASS: xHE API 1.0AOSP configuration lifecycle; encoding/roundtrip NOT RUN
```

Both also report `native-ELF-ABI-pass`: classic SONAME `libfdk-aac.so.2` with 18 exports and xHE SONAME `libfdk-xhe-aac.so.0` with 63 exports. Static ELF 16 KiB LOAD geometry passed for both libraries. The same record explicitly says `16k_runtime=NOT RUN` and `hardware_status=NOT RUN`.

Both 25-row provenance input maps equal the retained reviewed map. All 24 template-file hashes match Source 804 and the current canonical package directory; the remaining generated archive row matches the digest pinned in canonical `PKGBUILD`, `.SRCINFO` and source provenance. The package directory has no diff from Source 804. The archive itself was not retained or fetched again for this note.

Evidence was read from the existing [workflow log ZIP](../../artifacts/development/fdk-run38760088765/logs.zip). Its bounded `fdk-metadata` frame passed its declared size (20,777 bytes) and SHA-256 (`540e901f6bc50af5216b85f7725b0224086068a4feafe5ee8997bdc6783a81b9`) checks. It retains provenance, validation, comparison, input maps and capped log tails; no package binary or codec archive was uploaded. Package identity above is the recorded build/validation result, not a new local binary hash calculation.

This establishes the current recipe's native build pair and stated smoke/static checks. Core lifecycle/integration was deliberately not run. Provider substitution, dependency transactions, PipeWire AAC integration, target installation/update/removal/recovery, physical 16 KiB execution, either M2 Air size, xHE encoding/roundtrip, publication terms, signed release and measured performance remain unverified. Release selection remains false; Root owns the inventory update and Git publication.
