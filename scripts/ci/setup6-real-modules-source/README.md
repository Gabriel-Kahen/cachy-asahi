# Setup6 real-module native source

This source-only emitter reproduces the exact240-file trial source
`d41d28d870227b0256a8980d3c305287fbfb6ffb`. It reads148 pinned files from
the original Setup5 real-module checkout `0bbf875369c816aab19945c3e4f63c9b1f0b61b0`,
all73 files of accepted Setup6 source `141ba835bb632483342c6a7f0246c7fe0f2bc5c3`,
and19 maintained payload files. The parent checkout contains other project
files; only the explicitly pinned148 are source operands. Every output byte
must match the fixed profile before any output is created.

```sh
python3 -I -B scripts/ci/setup6-real-modules-source/prepare.py \
  --original-checkout /absolute/original-checkout \
  --setup6-source /absolute/setup6-source \
  --output /absolute/fresh-source
```

The output contains native workflow/build/installation code as inert source.
The emitter does not run it, fetch inputs, use Git or an API, install packages,
or issue native acceptance. The emitted workflow separately pins its complete
384-file accepted Setup6 input carrier, six-module inputs and original574
carrier. Its original source/lifecycle/cleanup checks remain authoritative.

The subsequent result of native run39599122890 is recorded separately in
`docs/validation/setup6-real-modules-native-20261021.md`. Its reader-only
search-path correction does not change this frozen source. M2,16K, expanded
desktop and release acceptance remain separate.
