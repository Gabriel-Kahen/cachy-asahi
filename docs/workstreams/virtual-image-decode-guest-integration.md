# Fixed SVG probe: minimum guest integration proposal

Status: source/design review only; paths are proposed for coordinator selection. No production source edits, compiler, Docker, native guest, media decode, MIME-cache generator, namespace or GPG actor ran in this lane. The existing fixed C helper remains unchanged. No binary SHA is available until an actual owned ARM build.

The next guest should retain one bounded observation of the fixed Adwaita SVG, then run the original app/frame proof. Guest4 remains FAIL/no frames; its Wofi SIGABRT and GTK assertion are observed, but the cache, classification and provider cause remains UNKNOWN. This proposal does not rebuild MIME caches or assume a traditional pixbuf loader. A bound guest observation will guide the next separately selected action.

## Exact implementation paths and ownership

| Path | Proposed work |
| --- | --- |
| `scripts/virtual/image_decode_report.py` | New pure production parser extracted from the existing test module |
| `scripts/virtual/test_image_decode_probe.py` | Import production parser; retain fixture/source-control helpers and all 18 original test methods |
| `scripts/virtual/prepare.py` | Same-image helper compile, staged parser/contract, binary provenance receipt |
| `scripts/virtual/guest.py` | Boot identity checks; one minimal-phase preflight before Wofi |
| `scripts/virtual/run.py` | Verify prepared pins; retain event on failure; construct externally bound observation |
| `scripts/virtual/controller.py` | Independently validate/project observation using retained expected preparation context |
| `scripts/virtual/test_virtual.py` | Inert preparation/guest/run checks |
| `scripts/virtual/test_controller.py` | Projection and binding refusals |
| `scripts/ci/development/virtual_stage.py` | Closed event schema, mandatory once/order checks, external context validation |
| `scripts/ci/development/test_virtual_stage.py` | Hostile receiver and preserved original acceptance checks |

These are one new physical source and nine changed existing source/test paths. Keep `common.py`, `gbm_probe.c` and `image_decode_probe.c` unchanged. Runtime logic owners must return final source hashes before the coordinator rebinds controller CORE literals. The coordinator owns `scripts/ci/development/packet.lock.json`, `.github/workflows/native-arm-development.yml`, shared acceptance/source maps, workflow authority and final registration; no simultaneous manifest edits are proposed. Existing guides, receipts, maps and actual-run evidence are preserved by this design lane.

The committed C path uses an underscore: `scripts/virtual/image_decode_probe.c`, SHA `e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a`, 10012 bytes, mode0644. Its existing test SHA is `db5337460e814a1b22046bb403161449e7f0d06c363d10997c6de9b621dbbb83`, 20380 bytes, mode0644. Neither is currently registered in the development packet.

## Parser and preparation interfaces

Extract constants plus `need`, `integer`, `shape`, `decode`, `parse_report`, `validate_context` and `parse_bound_report` before `fixture()`. Preserve their closed schemas and bounds. Production imports no test module or unittest. Tests retain `fixture`, `encoded`, `source_controls` and source-control cases. Use `parse_report(raw: bytes)` in guest validation and `parse_bound_report(raw, binding, expected_context, expected_report_sha256=...)` in trusted outer validation.

Reuse the existing authenticated native-aarch64 preparation container, after its complete runtime/source verification and complete tree copy. Add compilation beside the existing GBM compile, writing only the owned staged tree:

```text
/usr/bin/pkg-config --cflags --libs gio-2.0 gdk-pixbuf-2.0
/usr/bin/cc -std=c11 -O2 -Wall -Wextra -Werror /runner/virtual/image_decode_probe.c -o /out/prepared/root/usr/local/bin/image-decode-probe <validated pkg-config argv>
```

The first command has15 seconds and16KiB combined output; compilation has60 seconds, both capped by remaining time in the original1200-second preparation deadline. Use finite argv without a shell. Accept pkg-config stdout only after successful bounded ASCII capture, so its digest represents exact returned stdout bytes despite the existing text-returning helper; retain the parsed vector and command-log digest privately. Do not claim a separate arbitrary raw-stdout digest from a merged log. Preserve existing GBM command/budget and preparation cleanup.

Exact retained gcc/pkgconf/GdkPixbuf archives match lock hashes/sizes and establish packaged compiler/pkg-config targets and GdkPixbuf2.44.8 headers/.pc. GLib2.90.1 is listed in the frozen input inventory; its exact archive headers/.pc were not available locally for this review. Before future compilation, capture and hash the actual same-image GLib/GIO/GObject headers/.pc and compiler/pkgconf resolved targets, and require pkg-config success. No older recovery archive substitution. Packaged compiler hardlinks are legitimate. No new package is proposed:341 base+4 originals+21 tooling remains366.

Add a closed `image_decode_build` object to private `prepare.json`, status BUILT only after compile success and byte verification. Record C/parser/runtime CORE hashes and map digest, contract hash, source commit/nonce, baseline and immutable tooling image identities, tooling lock/audit hashes, canonical installed inventory digest, compiler/pkgconf targets, selected header/.pc identities, exact argv/flags, command-log digest, and helper hash/size/mode/ELF facts. The implementation must close these named subobjects rather than export arbitrary metadata. Check ELF64/little-endian/current version/AArch64 machine183 and EXEC or DYN without executing the program; chmod0755 and record the helper source/binary in `fixture_changes`. No readelf actor is required for the minimum design.

Stage `image_decode_report.py` with guest/common under `/usr/local/share/virtual-proof`, the binary at `/usr/local/bin/image-decode-probe`, and a closed `image-decode-contract.json`. The latter carries source/parser/helper/inventory/tooling/guest/CORE identities, fixed asset pin, nonce and one-attempt declaration. Verify the staged fixed asset matches independently selected archive bytes SHA `e66de83d084c5fc73430fe17950c6dad44ecb0ec59d30313ae1d57c9ea6d12c3` (1042 bytes). Do not preselect a cache digest. Boot verifies installed helper, parser, contract and inventory before starting the nonroot actor.

## One guest attempt, output and cleanup

Invoke a dedicated `image_decode_preflight(env, root, nonce)` once in the minimal phase, after correlated IPC/configerrors readiness, positive monitor and exactly one Wayland socket, immediately after `env['WAYLAND_DISPLAY']` assignment and before the first Wofi `LoggedProcess`. Hyprland is already running. Use UID/GID23001 and the exact env object Wofi uses; do not add MIME/GDK/Glycin/sandbox overrides. No second probe in overlay phase. Existing phase finally reaps/drains the compositor on any preflight failure.

Run exactly `['/usr/local/bin/image-decode-probe']` through existing `common.bounded`, with combined stdout+stderr cap16384 bytes. This is stricter than two independent16KiB caps and requires no COMMON change. Use a14-second work timeout within one absolute20-second acceptance deadline, reserving5 seconds for existing process-group reap and1 second for validation/accounting. Check expiry before and after capture/parse/event preparation; no late completion is accepted and cleanup remains mandatory. This is not a hard real-time OS completion guarantee: launch/syscalls/scheduling can overrun. Do not widen any enclosing deadline.

Valid C output is ASCII by its fixed schema/whitelists. Require stdout ASCII before encoding, parsing, hashing and base64 transport, preserving exact bytes for valid observations. Replacement-decoded/nonASCII/malformed output fails protocol validation and receives no invented raw digest. Keep stderr as private bounded text; publish no stderr/free-text or raw-stderr digest. Do not use `guest.command`, which publishes command output.

The new event `image_decode_probe` has exactly eight keys:

```text
event, nonce, stage, elapsed_ms, returncode, error, report_sha256, report_base64
```

Stage is `minimal`; nonce is the selected guest nonce. Accepted elapsed_ms is an exact nonbool int0..20000. Failed observation uses null elapsed_ms, avoiding capped/invented timing. Returncode is an exact nonbool int-64..255 or null when unavailable. Error is null or one of `launch`, `timeout`, `output-overflow`, `protocol`, `identity`, `deadline`, `cleanup`. Valid transport requires returncode0/errornull, strict parser acceptance, base64 decoded size<=16384 and exact captured-byte SHA. On failure both report fields are null and app launch is refused. Preserve any original failure even if cleanup also fails.

A valid decode-error or missing-cache report remains an observation and continues the original proof. It cannot supply a new PASS gate. Original boot/GBM/IPC/configerrors/monitor/frame/phase/guest-pass/cleanup gates remain necessary; no M2 or performance claim follows.

## External provenance and receiver

Do not embed the final raw-image hash or final prepare-receipt hash in the image itself. Stage the helper/contract first, then mkfs and hash the disk as today. The external preparation receipt binds those resulting bytes. `run.py` checks the selected preparation receipt, disk/kernel and helper-build identities before QEMU.

The guest transports raw validated report bytes plus nonce. Trusted outer run derives the parser's exact ten-key expected context from authenticated source and preparation authority:

| Context key | Independent expected value |
| --- | --- |
| source_sha256 | Fixed committed C digest |
| image_sha256 | Verified final `prepare.guest_image_sha256` |
| tooling_sha256 | Actual immutable derived tooling image ID hex |
| guest_sha256 | Selected guest.py digest |
| helper_sha256 | Actual ARM-built binary digest from selected preparation receipt |
| runtime_sha256 | Selected common.py digest; entire CORE separately pinned |
| package_inventory_sha256 | Canonical366-package inventory, same representation checked at prepare/boot |
| asset_sha256 | Independently selected fixed archive-match installed asset digest |
| run_id / run_attempt | Authenticated outer workflow identifiers |

Existing virtual contracts do not contain run_id/run_attempt. Propose that the development adapter copies validated `GITHUB_RUN_ID`/`GITHUB_RUN_ATTEMPT` from its authenticated workflow invocation into the selected outer controller contract; the controller propagates them into the proof contract and compares the retained values. Missing or mismatched authority refuses this lane, rather than generating local IDs or trusting the guest environment. The coordinator must select the exact workflow/acceptance delta and independently bind these values on receipt; environment values by themselves are not remote attestation. No new forwarding source path is required if the current adapter entry runs under that authenticated environment.

Proposed projection signature: `project(raw, target, report, *, image_decode_context=None)`. Controller derives expected context from its selected contract and retained PREPARED receipt before moving prepared output. Neither run nor controller accepts an expected context supplied only by result.json. Export only validated `image_decode_observation` in existing result.json and the exact event in existing guest-events.json; no new public path is required. Retain/project a valid observation in finally even when a later guest app fails.

The receiver must validate exact event fields, base64/hash/schema/context, nonce, minimal stage, at most one attempt and placement before Wofi. Require exactly one valid observation before accepting original PASS; a failure before probe placement can retain FAIL with no observation. Only then exclude this observation from the original essential-event sequence. Preserve existing IPC probe/reply adjacency, process diagnostics and original proof gates. Controller allowlisting alone cannot admit the event. Existing UART/public byte bounds accommodate the<=22KiB base64 envelope and need no widening.

## Registration and validation handoff

Current observed packet is211 files, SHA `47610163e48bcdfa6f716fa9fea065e7f58e385232ca767bf3301a02865f9935`. With existing C+existing parser test+one new production parser registered, minimum211→214. CORE/prepare ASSETS/run source maps5→7; adapter PACKET_FILES9→11. Initial159 and generated125 stay frozen. These are baseline/proposed counts, not a registered packet or checksum; the coordinator recomputes the exact union, bytes, hashes and modes after implementation and concurrent lanes.

Proposed inert checks cover parser equivalence/all18 original cases; exact once/UID/env/placement; timeout/overflow/nonASCII/malformed/launch/nonzero/binary drift; cleanup and sticky failure; valid decode-error/cache-missing continuation; deadline expiry; duplicate/order/nonce/base64/hash/private-extra refusals; external source/image/tooling/helper/runtime/inventory/asset/run/attempt mismatches; failed-guest observation retention; and no-frame/no-GBM inability to gain PASS. No implementation tests ran because no implementation changed. Future actual ARM build, guest execution, decode outcome and cache/provider diagnosis remain NOT RUN/UNKNOWN.

Peer details and sealed observations are under `artifacts/reviews/virtual-image-decode-guest-integration-20261012/{build-design,guest-flow}`. Parent custody rechecks peer receipts and preserves the existing C, prior guides/receipts and current source snapshot. This proposal is ready for the coordinator's concrete path selection; it is not source adoption or execution authorization.
