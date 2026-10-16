# Normal full574 owned build, probe and cleanup

[Trial 38826547564](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38826547564) passes one real native ARM full574 build/probe followed by guarded cleanup of its completed image and probe. All six original daemon image IDs remain present. Root accepts the retained readout after a separate independent metadata/source check. This extends the earlier [metadata-only cleanup component](maintained574-cleanup-component-native-20261015.md).

Source is `d303339162a237b0ce0651ecca2bab37d342abbe`; the dedicated workflow is `1133296d3535a1be24775fa64ba69233d8e42cab`. Wrapper SHA256 is `7305cffaf040db3dd16958671376ac4108b5808ceff6baca3e882fe6ede7e672`; unchanged helper SHA256 is `27ba4be42cf2bd41675073e07cccc917ae033f9d68b07a33cfd7f074ac27b760`. Root verifies all seven workflow source pins against the selected Git objects and the workflow body against SHA256 `fce0128b9b7a4b90cbf85a73d15323fd8f33fd73109ffae686e2458a3a7d9b15`. Before selection, 13 wrapper and 21 held-helper checks pass, alongside one bounded source peer review.

The hosted guard records Linux/aarch64, a native aarch64 local Docker daemon, UID/GID 1001, 4,096-byte pages, Docker 28.0.4 and `unix:///var/run/docker.sock`. Its earlier `native_build=NOT RUN` field describes the guard's metadata probe; the later trial separately records build PASS.

The original six-file seed and the additive twelve-file seed pass into the same existing dependency cache. Public asset Source remains `88a88bc5f3be3998e992881bf090137df16f1aae`, with 4,045,396 bytes copied. The seed does not authenticate signatures; unchanged builder signature gates remain required. The trial reports 1,153 acquired objects, 574 packages, build return zero and a completed probe. Exact recomputed/expected/installed inventory equality is enforced by the selected Source, with inventory SHA256 `cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`. Private lock files and individual signature records were not exported or independently replayed.

| Identity | Retained value |
| --- | --- |
| Token | `3caad825ac054630` |
| Image | `sha256:c703bb747b9acb917575f0523f66583c11cc848543ddec910357cb639779a986` |
| Probe CID | `4c08b75e6ee08a3b0025644222ecd915f99d3969ebf58946de71a95ce5cfbe0d` |
| Probe name | `cachy-asahi-574-probe-3caad825ac054630` |

The cleanup summary matches those build identities and reports completed-build status plus verified image/probe absence. All six before-image IDs exactly equal the six after-image IDs; the owned image is in neither list. The wrapper's exact Source enforces the token/tag/label/reference, private report, finished-build and identity checks before deletion. Root checks the exported identities and preservation lists, without independently querying the destroyed daemon. No cancellation or retention fault is reported.

Build and cleanup use the existing bounded process utility with 2,400-second and 240-second ceilings. A GNU 3,000-second TERM / 15-second KILL wrapper bound sits inside the dedicated 52-minute step and 60-minute job. These are selected ceilings, not measured performance or universal retirement guarantees.

Root retains `artifacts/development/maintained574-owned-normal-run38826547564/logs.zip`: 28,047 bytes, SHA256 `cb1ba0e03dabbbb9aa5e7a50f541cf12b7e587dbd777718e4c5dd75a1dc0428e`. Review decodes only two public JSON leaves: trial 2,430 bytes / `207f5ffe32e49d6f18bde56491903f25185245e2bf4a806cf1e55c0e5921c5f3`, runner 4,060 bytes / `534f3d5c80cb64954cddcd0e8542d05874e8d97206388f1ae0254dac73dabe2d`. Root's independent check verifies these hashes, native guard, exact Source/workflow/seed joins, counts, image/CID/token agreement, absence summaries and the complete before/after image-ID lists. No native actor or private payload replay runs during review.

This is normal completed-build/probe cleanup only. Active-build cancellation, running-probe interruption, unrelated daemon state, BuildKit/cache/layer/workspace erasure and historical callers' interrupted-bootstrap/probe gap are untested. Context/cache retention until ordinary runner teardown remains intentional. No native installer P0, complete source/license delivery, production trust, release, physical 16 KiB, Asahi/M2 or performance acceptance follows. All release flags remain false.
