# Fixed Adwaita image-decode preflight

**Implemented and host-x86 compiled; source/parser fixtures pass. Not integrated or guest-admitted.** This provides the next finite observation for guest4's GTK SVG failure. It does not repair the image, establish an actual guest decode, or accept a desktop frame/M2 outcome.

The historical run is `38297144571`, reviewed at receipt `3a23f165d81c8c7567f8ea03eff2e682b42735aa3647109ba9413da126b4d0ce`. The actual 830-byte client log shows the fixed Adwaita SVG failed with an unrecognized format and Wofi aborted before cleanup. Cache content, selected MIME type, provider execution and sandbox/decode outcome remain unobserved there. The lock-pinned gdk-pixbuf2 2.44.8 uses the modern Glycin/GIO path; absence of a traditional loaders.cache is not established as the cause.

## Source and closed observations

| New source | SHA-256 | License |
| --- | --- | --- |
| scripts/virtual/image_decode_probe.c | `e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a` | MIT |
| scripts/virtual/test_image_decode_probe.py | `db5337460e814a1b22046bb403161449e7f0d06c363d10997c6de9b621dbbb83` | MIT |

The C helper accepts no arguments, configurable paths or asset selector. It captures only `/usr/share/mime/mime.cache` (16 MiB bound) and `/usr/share/icons/Adwaita/scalable/status/image-missing.svg` (256 KiB bound). It retains nofollow parent/file descriptors, requires regular singly linked files, checks bounded exact read/EOF and stable file/named identities, and records SHA-256 only for accepted snapshots. Missing/refused/changed/I/O failures remain observations with no invented content identity.

For an available asset, GIO classifies the fixed filename and held bytes even if the cache is unavailable. Available GdkPixbuf format descriptors are bounded to 64, sorted by name/disabled, with safe ASCII names up to 64 bytes. Duplicates and descriptive names are retained: the API does not promise uniqueness or identify a provider. Exactly one GdkPixbuf memory-stream decode consumes the captured SVG bytes. Successful dimensions are bounded; errors expose only numeric process-local GQuark and signed32 code, never raw messages. These APIs are available in the existing GIO/GdkPixbuf headers; no added library or package is required.

Stdout is one closed JSON observation, at most 16 KiB. Exit 0 means a finite observation completed, including a decode error; it is not a self-issued PASS. Arbitrary arguments return 64; internal/output failure returns 2. Caller supervision supplies the finite deadline and resource policy. A stable cache snapshot does not prove GIO consumed those exact bytes. Memory-stream loading differs from GTK's filename-loading path; successful stream decode alone does not establish the original GTK/client behavior.

The Python file implements `parse_report` and a **proposed-only** `parse_bound_report`. The latter requires a separately trusted report digest and exact external source/helper/runtime/package-inventory/asset/run/attempt/image/tooling/guest context. It matches an accepted asset hash to the selected asset pin. The supervisor must authenticate these values; matching a caller-supplied object is not provenance. The helper emits no context, accepted flag, render claim or private path. No current adapter adopts this parser.

## Fresh local verification

Existing host metadata is GIO 2.88.3 and GdkPixbuf 2.44.7, distinct from the target guest versions. The production C helper compiles with `cc -std=c11 -O2 -Wall -Wextra -Werror` and existing `pkg-config --cflags --libs gio-2.0 gdk-pixbuf-2.0` flags. The exact copied build and compiler/binary hashes are in `host-followup/host-build-fixtures.json`.

Actual host decoding is NOT RUN: this installed Glycin default entails sandbox namespaces, excluded by this task. Two explicitly link-wrapped decoder controls exercise one controlled failure and one synthetic 16x16 result while using real local file snapshots, GIO classification and format metadata. Both reports pass the strict parser and synthetic binding controls, and both refuse arbitrary arguments. They expose 29 registered descriptors/24 distinct names and observed `image/svg+xml`; the decode outcomes remain fixtures. The original build/output that incorrectly treated spaces/duplicate names as refusal is retained separately. The corrected source preserves these valid API descriptors without provider attribution.

All **18 fresh parser/schema/source unittest methods pass**, zero failures/errors/skips. Controls reject duplicate JSON keys, extra/private/PASS fields, malformed UTF-8, size/depth/node limits, non-integer/boolean substitutions, inconsistent observation attempts, bad dimensions/error bounds, bad names/order, altered source paths/limits/decode calls, wrong external contexts and report/asset digest mismatches. No real decoder, native guest, Docker, namespace, package/hook/cache generator, multimedia device or host configuration actor ran.

## Proposed finite guest contract

`artifacts/reviews/virtual-image-decode-preflight-20261012/proposed-guest-contract.json` is the exact proposal for root. It includes C/parser pins, selected package/archive and provider/generator payload hashes, fixed paths/limits, build argv and the future command `/usr/local/bin/image-decode-probe`: one attempt, 20 seconds, 16 KiB bounded output/private error capture, same unprivileged virtual-proof account and selected client environment. Existing isolation/provider sandbox policies remain intact. Proposed CPU/address-space/open-file/core limits require root review for actual provider compatibility.

The aarch64 binary is UNBUILT and its hash is deliberately unfilled. Root must compile/pin it in the owned fixture image and independently select the runtime, package inventory, image, tooling and guest identities before any actor. Current source/historical hashes in the proposal are references, not future runtime attestation. The archive SVG pin is `e66de83d084c5fc73430fe17950c6dad44ecb0ec59d30313ae1d57c9ea6d12c3`; installed guest equality is unobserved. The host SVG has different bytes and is not used as the target pin.

No guest/controller/prepare/workflow/shared-map change is included. Root owns registration, adapter event/capture binding, admission and dispatch. Decode success, mapped client, desktop frame, software render and M2 acceptance remain separate gates.

## Source-backed cache operation proposal

The retained shared-mime-info hook SHA is `f08efbcbac9d2bd18a805b8dcf3ed06d7763b97eca5935aa64d65593774b6501`. It names this exact operation:

```text
/usr/bin/env PKGSYSTEM_ENABLE_FSYNC=0 /usr/bin/update-mime-database /usr/share/mime
```

This operation is **NOT EXECUTED**. If independently bound cache/decode evidence warrants it, root can select only this operation inside the owned tooling image, pinning the archive generator/XML inputs and recording the full generated MIME-file manifest plus changed image identity. Existing hooks stay masked; no package-hook batch, host invocation, additional provider installation or query-loaders workaround is proposed. Generator/config/helper/asset payload identities were re-read from three exact archive pins without executing them or adding GPG verification. Cache creation alone is not claimed to resolve provider access or Glycin sandbox/decoder behavior.

The evidence packet is `artifacts/reviews/virtual-image-decode-preflight-20261012/`. Its sealed review receipt binds source, copied tests, host build/fixture records, prior evidence, runtime payload pins, proposal and this document. Historical guest4 remains FAIL/no frames; no ARM/M2, installation, performance or full-port gate is promoted.
