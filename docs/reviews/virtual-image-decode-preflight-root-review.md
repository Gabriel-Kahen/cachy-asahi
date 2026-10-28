# Independent fixed SVG image-decode preflight review

**PASS within the source/parser and controlled-host-fixture scope; no actionable source issue found.** This reviews the held preflight at receipt SHA256 `6a624a68b7d95fabdca04c5f204a3b91dff4b50db0958e9eef674d2cbd8fddb2`. The aarch64 helper is **UNBUILT**, no guest adapter adopts the parser, and no guest actor is admitted. Actual guest4 remains **FAIL/no frames**; its cache contents, GIO content type, provider execution and decoder/sandbox condition remain **UNOBSERVED**.

The owned outputs are this new review and [`artifacts/reviews/virtual-image-decode-preflight-root-peer-20261012/`](../../artifacts/reviews/virtual-image-decode-preflight-root-peer-20261012/). No source, controller, workflow, shared map or Git file is changed. Actual guest, ARM/native, Docker, GPG, namespace, device/media decode, hook and cache-generation actors are not executed. Compilation and explicitly interposed C fixtures use the existing host dependencies and prove only the labeled host controls.

## Exact held interface

The C source is `scripts/virtual/image_decode_probe.c`,10012 bytes, mode0644, SHA256 `e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a`. The parser/test source is `scripts/virtual/test_image_decode_probe.py`,20380 bytes, mode0644, SHA256 `db5337460e814a1b22046bb403161449e7f0d06c363d10997c6de9b621dbbb83`. The held guide is SHA256 `d65d069e2e28717a46db345a90976cbfe51c7415a46c5984d645bce3839aa90a`. All47 receipt-bound packet files are re-read, including separately retained original format-refusal outputs and the corrected follow-up. A fixture binary hash is not a guest binary pin.

The helper takes no configurable path or asset argument. It captures only the fixed Adwaita `/usr/share/icons/Adwaita/scalable/status/image-missing.svg` (256 KiB bound) and `/usr/share/mime/mime.cache` (16 MiB bound). Each snapshot retains nofollow parent/file descriptors, rejects nonregular/multiply linked/oversize inputs, reads exactly the recorded size and EOF, and rechecks file and named-path metadata. Accepted snapshots expose only size and SHA256; missing/refused/changed/I/O states carry no invented content hash. The file snapshots cover their individual capture intervals; they are not an atomic combined image snapshot.

For an available captured asset, GIO classifies the fixed filename and held memory bytes even if the cache is unavailable. Up to64 available format descriptors retain bounded safe ASCII names and disabled flags in sorted order. Duplicate/descriptive names are valid descriptor data, not provider identity. Exactly one GdkPixbuf memory-stream decode consumes the captured asset buffer; dimensions and numeric process-local GQuark/signed32 error code are bounded. Error strings are not exported. Stdout is one closed observation up to16 KiB. Exit0 means the observation completed, including an error observation; it does not mean accepted decode, client behavior or frame PASS.

The parser rejects duplicate keys, noninteger/boolean substitutions, malformed UTF8, size/depth/node excess, extra/private/PASS fields, inconsistent attempts, unbounded names/numeric fields and invalid descriptor ordering. `parse_bound_report` requires an external trusted report digest and exact context containing source/helper/runtime/package inventory/asset/image/tooling/guest hashes and run/attempt identifiers. No field is optional. It compares an accepted asset hash to the selected asset pin. A matching producer-supplied context is not authentication; the supervisor must independently select and bind those values.

## Future guest contract and source-based cache proposal

The held proposal allows one future invocation of `/usr/local/bin/image-decode-probe`,20 seconds,16 KiB stdout and16 KiB private error capture, under the same selected unprivileged virtual-proof account and client environment. Source and tooling identities are mandatory. Proposed CPU/address-space/open-file/core bounds and existing Glycin provider/process supervision remain subject to the coordinator's compatibility review. No sandbox weakening is selected. The aarch64 helper hash is deliberately null until root compiles and independently pins it; historical source/inventory hashes cannot stand in for a future runtime/image identity.

Six selected package archives and the separately held runtime payload pins distinguish archive contents from installed guest bytes. The payload contract includes the fixed SVG, Glycin SVG helper/config, update-mime-database executable/hook and XML input. Archive hashes and generator/provider inputs must be re-bound to the selected installed tooling image before any actor. The modern selected GdkPixbuf uses the Glycin/GIO path; this review makes no traditional pixbuf loader-cache assumption.

The sole cache-operation proposal is backed by the retained shared-mime-info hook SHA256 `f08efbcbac9d2bd18a805b8dcf3ed06d7763b97eca5935aa64d65593774b6501`:

```text
/usr/bin/env PKGSYSTEM_ENABLE_FSYNC=0 /usr/bin/update-mime-database /usr/share/mime
```

It is **NOT EXECUTED**. The proposal confines it to an owned disposable tooling image, keeps hooks masked, and requires pinned generator/XML inputs, a full before/after generated MIME-file manifest, command result and fresh image identity. No batch hooks, arbitrary provider install, host cache mutation or query-loaders workaround is selected. Cache creation alone cannot establish provider access, sandbox function or successful decode.

## Independent controls and limits

The following independent results are retained and re-read by the parent:

| Check | Actual result |
| --- | --- |
| Exact captured author parser/schema/source models | 18 PASS, zero failures/errors/skips |
| Independently authored inert parser/context controls | 32 PASS |
| Independent source/evidence identities | 69 exact file identities; six exact archive payload size/hash/mode rows |
| Production C compilation | Exact source, existing host GIO2.88.3/GdkPixbuf2.44.7, c11/O2/Wall/Wextra/Werror PASS; binary never executed |
| Independently authored host C interposition controls | 16 PASS |
| Parent revalidation | All16 fixture outputs re-parsed; ELF x86_64, decoder undefined-symbol controls, mandatory context and unadmitted20s contract verified |

The fixture peer's receipt is SHA256 `c770be57a7eb2d178ab575388b454201e5d9c5292b72cd0bfbad6b76da9726c4`; the source peer's receipt is `62a175e5b53c528dc3ed21341dfa33b5a81bbb8454b4488e5c1a7100eea2808e`. Scripts, argv, compiler/library identities, reports and exact manifests are under `fixtures/` and `source-peer/`. The parent verifies their sealed artifacts and source identities before sealing this review.

The independent host fixtures use unchanged production source/constants with explicit syscall/decoder interposition and deterministic non-media bytes. Their wrapper checks the exact memory buffer and one decoder call. The real decoder and Glycin namespace execution are not invoked. These controls test reporter branches and refusal behavior; they do not establish that any target SVG, host SVG or actual guest successfully decoded.

The sixteen cases cover synthetic success/error, missing/denied/hardlink/symlink/oversize/changed/truncated/trailing/read-error/close-error asset snapshots, inconsistent decoder returns, invalid dimensions and argument refusal before snapshot/decode. A production undefined decoder symbol remains present; it is absent from the interposed binary, whose wrapper contains no real-decoder reference. Interposed snapshot calls do not prove actual filesystem race behavior. Real GIO classification and format metadata may consult the host's own MIME databases; they do not use the fixture's synthetic cache bytes as authenticated GIO input. Host fixture wall supervision is30 seconds/CPU20, distinct from the future20-second guest contract; actual guest budget/provider compatibility is not validated.

The historical preflight shared baseline matches seven of eight live rows. `manifests/packages.toml` has changed from held `1a59c4a1b51c2edce6816de8f922ac257f953f5a8ec9076087dbbc1a54ad814b` to live `a05337fd4241cabc318e5472df661049a81ece871409d9979299e2b61e923543`. The source peer's first strict all-live check refused and is retained. Its corrected review preserves that historical baseline and records the current drift; it does not assert current manifest equality or roll back the coordinator's work. The held preflight/source/guide remain exact.

Cache hash means a captured stable file, not proof GIO used that file. GIO may consult other configured MIME data; its classification is a separate observation. Format descriptors do not prove a provider ran. Numeric GQuark values are process-local. Memory-stream loading differs from GTK filename loading. A synthetic16x16 fixture result is not a visual frame or a provider decode. The same finite wallclock/output policy must be enforced by the future supervising adapter and included in its authenticated runtime contract.

Root retains integration, registration, runtime/tooling/image selection, resource compatibility, ARM build, guest dispatch and acceptance ownership. Source/host fixture results do not promote decode success, mapped client, desktop frame, software rendering, M2/16K, performance, installation or full-port acceptance. The actual guest4 failure, kernel capability two-source hold and prior KSM/guest evidence remain unchanged.
