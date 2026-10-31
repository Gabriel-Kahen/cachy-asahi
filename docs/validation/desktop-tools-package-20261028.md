# Desktop tools package candidate

The unselected cachy-asahi-desktop-tools 0.1.0-1 package provides offline staged
desktop-entry capture and exact inventory audit from a moved installation prefix.
It preserves the original static checker and exposes no desktop activation.
MIT source, license, finite exporter, payload/source maps and provenance are included.

The October 28 ordinary-user host package build passed 81 checks (54 original
static and 27 package/CLI). Independent decoding verified its exact six-file
payload, modes and root numeric ownership. Actual archive relocation, capture/
audit, icon-drift refusal and private removal preserving an unowned sentinel
passed. These retained host results are unchanged; no new native or ALPM result
is inferred. Runtime requires Python>=3.11.

PR304's first CI run40767071981 failed one exporter assertion comparing compressed
bytes across Python/zlib environments. Its first job123093968250 log was retained
once under `artifacts/development/desktop-tools-pr304-first-failure-root-20261028/`.
The decoded canonical source tar was identical in the local causal reproduction.

The October 31 correction authenticates each archive's independent byte pin, then
requires one complete bounded gzip member whose decoded USTAR exactly matches the
finite source namespace, ordering, metadata, modes and contents. The shipped
archive remains pinned by PKGBUILD. Re-export receipts describe their actual
compressed bytes; compressed encodings may differ across zlib versions. Two
exports under the same interpreter must still be byte-identical with fixed gzip
metadata. Content/metadata drift, duplicate/extra/missing/symlink members,
truncation, concatenated streams, trailing data and excess output are refused.
All20 focused source DATA controls passed on host Python3.14.7, managed3.14.6
and3.12.13. GitHub CI of this correction remains NOT RUN in this worker.

The original source archive remains29282 bytes, SHA256
`69d8c7bb3a13086d4b3ae5a46fa79db14ef4a034912bacb9f185ccc4d54b0ba4`.
The original host package remains28433 bytes, SHA256
`6e934317ad828898ace72b059bd3f5fcd0c5e83c9065f2588f8969c538a360bb`.
PKGBUILD and all14 expanded source files, including provenance, maps and all six
runtime payload files/modes, are held. Only the external exporter and its tests
change; this guide records the new source evidence. Local retained packets are
not automatically published evidence.

Finished development targets main. Native ARM pairs, signed ALPM lifecycle,
native16K, graphical launch, selected Asahi composition and physical M2 remain
NOT RUN. Performance is NOT MEASURED; release acceptance is NOT ADMITTED. No
services, hooks, caches or user configuration are installed by the candidate.
