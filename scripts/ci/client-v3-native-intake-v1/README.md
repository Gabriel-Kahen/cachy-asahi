# Runtime/client-v3 passive component reader v1

Implemented source/projection/reader code; NEW26 MODELED DATA controls. No real component artifact, original GET, native Source, native run or actual reader invocation is present. All default selectors remain NULL. Old Apps7/v2/updater readers and receipts are unchanged.

The CLI requires an explicit Root binding file plus its out-of-band SHA, genuine terminal run/complete sole-job/artifact metadata, a separately Root-published complete Source authorization plus DATA-only source directory, and one retained original ZIP. NULL selectors refuse before any Source, metadata or ZIP opens. Source and collected files are never imported, executed or extracted. Only current maintained derivation code is imported; it reads original Source bytes as hash-bound plaintext. A read/actor fence denies filesystem mutation, subprocess, network and ctypes while validating.

The reader independently checks full original ZIP closure/CRC/pins; complete Source blobs/modes/tree and the exact factory namespace; both actual twelve-file runtime runner contexts; both native build pairs, four distinct leased builders, complete provenance/evidence and source recipe joins; XZ package bytes, payload members, PKGINFO and BUILDINFO entirely in memory; 574/575/576 inventory relations; the five fresh/reinstall/remove phases and whole GPG transcripts; ordered consumer/dependency/producer/own-key retirement receipts. XZ is explicit for this component's pinned ALARM builder configuration. ZST, duplicate/aliased/truncated/overflowed inputs and unknown supplements refuse, with no child decompressor fallback.

The native factory now forwards actual complete runner bytes and derivation maps from BOTH dependency and lifecycle contexts. These bytes must be present. The reader never fills an absent observed runner from constants. It compares actual bytes to source copies and a trusted current derivation. This producer seam changes only the new versioned client-v3 factory; frozen sources are not rewritten.

Source-enforced receipts remain labelled: private574 payload/rawDB/user preservation maps are unexported; TEST signatures establish no release trust; container/image/agent retirement is not live-reobserved; distinct containers do not prove independent machines. The result grants NO native admission, Doc315 qualification, resource/group exemption, M2/16K/performance/release or genuine changed-version upgrade credit. The unchanged legacy workflow group may require canonical HEAVY_NON_KERNEL review. Root must independently classify and issue any new policy; existing Doc315 is not amended.

`projection.py` selects finite already-qualified DATA, omits executable/source copies and verbose logs, and preserves whole pins for omitted originals. Its JSON cannot substitute for the original ZIP on requalification. The selected raw bodies are base64 DATA, not code. The original remains unchanged. Failures retain source/artifact binding but never receive positive component/native credit.

Example FUTURE Root invocation (not run; replace only with genuine recorded operands):

```
python3 -I -B reader.py --binding-path ROOT_BINDING --binding-sha256 ROOT_BINDING_SHA --authorization-path ROOT_SOURCE_AUTH --source-root ROOT_SOURCE_DATA --run-path ROOT_TERMINAL_RUN --jobs-path ROOT_COMPLETE_JOBS --artifact-metadata-path ROOT_SELECTED_ARTIFACT --archive-path ROOT_ORIGINAL_ZIP
```

The Source authorization schema is `schema:1`, status `ROOT_PUBLISHED_CLIENT_V3_NATIVE_SOURCE`, actual `source/ref/tree`, and exact full `files` rows `{mode,oid,bytes,sha256}`. It is genuine only after Root construction/publication/readback, and its SHA must join the binding. A successful ordinary PR or MODELED test result is not a Source authorization. `model_data.py` and test fixtures are synthetic schema data only; they never construct or publish an immutable Source.
