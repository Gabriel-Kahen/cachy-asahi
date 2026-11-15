# XS v5 typed capability spelling and work-volume preentry

Source and bounded DATA models only. No actual Source construction/publication, Docker/image, lease, compiler, XS or new native role ran. V4 Source `c23a24a0cff3ce102e2f3240cc86a890b2ad4b0b`, failed run 43723410450/job 132840063834/Original 14165811876 and all old factories/Readers stay unchanged.

The genuine failure was an inspect representation mismatch: create requested `--cap-add=CHOWN`; both retained inspect records returned `HostConfig.CapAdd=['CAP_CHOWN']`; frozen `inspect_init` required `['CHOWN']`. All other old initializer clauses and mounts matched. It remained created/Pid0 and never ran; no consumer was created or XS loaded. The 8,584-byte inspect has SHA256 `39eb911a102ce8969f32bece90c13d8c98cf49b20b752f35fdbf4991fbc63cab`. Producer reported owned resources absent and initializer/volume removed, while preserving an error for its never-created-consumer absence parser. Outer receipts record preparation, derived-image, parent-image and GPG-agent absence. That failed role is not qualified.

V5 accepts only raw single-element lists `['CHOWN']` or `['CAP_CHOWN']`. It retains raw receipts; it does not strip arbitrary prefixes or normalize other fields. Empty, duplicate, mixed, additional or other capabilities refuse. Cap-drop ALL, NNP, read-only root, resources, network/device/identity/mount checks remain.

Source audit also found a latent copy-up order: v4 started chown before consumer creation and neither work mount used nocopy. Actual copy-up was not measured. V5 uses explicit `volume-nocopy` on BOTH mounts, creates and inspects both containers before initializer start, then retains its successful stopped inspection before consumer start. No capability, additional actor or time/resource budget is added.

Only `consumer/native_adapter/native.py` and hosted `xs/entry.py` are replaced. Exactly 12 of 13 consumer files remain unchanged. The old native.py is archived explicitly in `previous-v4/native.py`; its whole-body/generator SHA changes and must receive fresh Root review. The original `actor()`, operation/input/bundle/daemon policies, runner, probes and runtime ABI are byte-identical. The dispatch wrapper captures a bounded read-only preentry BEFORE any work write: ordinary uid/gid 1001, same directory identity, mode 0700 or 0755, empty and effective writable/search access. Unsafe/group-writable modes refuse.

The captured observation stays in memory while unchanged `actor()` runs. Only afterward does the wrapper write exclusive 0600 `work-preentry-v5.json` through a held directory FD into the already-created uid/gid 1001/0700 original `/work/output`. It never creates an alternate output directory or adds stdout. The bounded receipt joins the exact operation, native-generator, original runtime-observation and actor-result bytes. Export parsing explicitly includes and validates that new receipt. Existing actor stdout and JSON objects remain unchanged. Receipt races, missing output, identity changes or failed/uncertain actor outcomes refuse; existing files are never overwritten.

Outer operation/ref/alias is v5; inner consumer remains v1. Image sealing/preparation remain byte-identical v4 implementations under explicit v4-image-seal delegation. Their fresh actual qualification must still bind the NEW Source/run; no parent or old derived qualification is inherited. The exact false Entrypoint/Cmd contract, four captured Config values and driver/alias/helper/notice/349/layer limits are unchanged. Initializer two CPU / 4 GiB/no extra swap/256 tasks and consumer cap0/NNP/RO/offline resources, actor 300 s and producer 600 s/cleanup reserve remain unchanged.

The new 316-file Source archives five old bodies, changes dedicated workflow literals and the exact entry hash, and reconstructs the complete 311-file parent byte/mode/map/tree. Held 272, accepted package/runtime/compiler materials and all other software are unchanged. `profile.json` has NULL actual selectors and pins the two payloads, explicit delegation and image contract; it grants no authority. A new independent Reader/once binding is required for this changed native-adapter body and receipt/order.

Nineteen fenced controls pass: nine actual-parent DATA render/inverse controls and ten end-to-end adapter DATA models. Models execute the actual changed definitions with simulated Docker/UID facts, a DATA-only actor substitute and the genuine pinned passive TAR parser; they invoke no Source actor function, command process, daemon or lease. They cover both cap encodings, unsafe/duplicate/extra caps, copy-up flags/order, preentry before writes, wrong owner/mode/nonempty root, unchanged stdout/JSON, exclusive receipt and parse joins, foreign-label cleanup refusal and full 311 inverse. A model pass is not actual XS or image evidence.

```sh
python3.14 -I -B -Werror::ResourceWarning test_model.py
python3.14 -I -B -Werror::ResourceWarning test_source.py --previous-xs-source "$EXACT_CLOSED_V4_SOURCE311"
```

Root-only DATA construction after independently checking the final whole profile SHA:

```sh
python3 -I -B prepare.py --previous-xs-source "$EXACT_CLOSED_V4_SOURCE311" \
  --profile-sha256 "$REVIEWED_V5_PROFILE_SHA256" --output "$FRESH_DISJOINT_SOURCE_OUTPUT"
```

No constructor main or publication ran here. Root must issue fresh Source publication/readback, source/resource/runtime/once approval and separate actual image/initializer/consumer/Original/Reader operations. Old 311/v4 must never replay. Actual v5 compiler/XS, writable lifecycle, native 16K, M2, performance, current trust and release remain NOT RUN/unqualified.
