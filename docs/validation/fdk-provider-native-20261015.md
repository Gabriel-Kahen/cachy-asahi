# FDK provider and PipeWire AAC native trial — 2026-10-15

[Run 38767307451](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38767307451), workflow Source `b74299722a5792de3538288cdf3762ea61bb8bd7`, passed the complete disposable generic ARM provider trial. The retained result records `status=PASS`, `provider_transaction=PASS`, `shipped_pipewire_aac_codec=PASS`, dependent removal refused, and upstream restored. The launcher reported `FDK_PROVIDER_PIPEWIRE=PASS` after its named-container absence check. No derived image was committed.

The job rebuilt the [current FDK recipe](fdk-current-native-20261015.md) at Source `804b418f14459e82031046fb28a0308b4cb9348e`, using the same-job native base. Candidate `cachy-asahi-fdk-aac-3.0.0-1-aarch64.pkg.tar.xz` SHA-256 was `237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247`. The trial authenticated and installed 29 pinned upstream additions, including `libfdk-aac 3.0.0-1` and `pipewire-audio 1:1.6.9-1`, without container network access.

Pacman successfully replaced upstream FDK with the candidate while retaining name/SONAME dependencies, exact expected inventory, package database consistency, package integrity and file ownership. Removing the candidate alone was refused because both `libfdk-aac` and `libfdk-aac.so=2-64` were required by `pipewire-audio`. Reverse replacement restored the original inventory and upstream ownership and bytes.

The actual installed PipeWire AAC plugin remained unchanged: SHA-256 `25ce30c727b37acea500aa49842f1a58e371fa70d5f0b50ae7526fb951855ab5`. All three retained codec logs—upstream before replacement, candidate, and upstream restored—contain:

```text
FDK_LIBRARY=/usr/lib/libfdk-aac.so.2
FDK_PIPEWIRE_CODEC_PASS packets=40 decoded=40 pcm_bytes=163840 nonzero=1 rate=48000 channels=2
```

The probe exercised the shipped plugin's AAC-LC RTP/LATM encode/decode callbacks without a daemon or Bluetooth device. Each invocation joined the resolved library to its package owner and hash. Classic library `/usr/lib/libfdk-aac.so.2.0.4` had upstream SHA-256 `aea9c8eadd91840d3e1670f1e246a2390b95bba4762a533de0591963a49b869d`, candidate SHA-256 `a606176781331d1c02089ec27618fe821e4289e809cadfa72e27442b8fe0b8db`, then the original upstream identity again. Restored xHE library `/usr/lib/libfdk-xhe-aac.so.0.0.0` also matched its pre-replacement upstream owner, path and SHA-256 `c39c21d060f81f4ebf413b0aa994039e54c166f807c54676692fc118c63f464c`.

Evidence came from the existing [Root-collected log ZIP](../../artifacts/development/fdk-provider-run38767307451/logs.zip). The bounded provider frame passed its declared size (7,869 bytes) and SHA-256 (`2b3f193e381656f6f99495ab307f891036ab35568cbcc4f1c1fac204a1bf7d56`) checks. It contains the result, input summary, three codec logs and the complete 43,240-byte trial log; no package binaries or private cache/GPG material are retained there.

Package scriptlets were disabled and hooks masked in this disposable test. This proves the stated generic ARM dependency/provider transactions and codec consumption. Bluetooth negotiation/transport, a PipeWire daemon graph, physical audio routing, Asahi speaker protection, xHE encoding/roundtrip, physical 16 KiB execution, either M2 Air size, target installation/update/removal/recovery, release publication and performance remain **NOT RUN**. Release selection remains false.
