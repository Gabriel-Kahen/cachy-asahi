# GNU diagnostic log fallback

The two existing native owner retain steps now capture their original exit code, invoke one source-pinned data-only report projector before artifact upload, and return the original nonzero status. If retention succeeds but diagnostic projection fails, the step fails. The original five-minute retain timeout, native trial/cleanup/resource limits, actor roles and closed artifact export remain unchanged. No retry or upload override is added.

`summary.py emit` reads only the exact source proof, outer owner, inner owner, child result, ordered-cleanup and export reports. Source/workflow/run/attempt/token binding is checked; outer/inner image/token mismatch or missing reports stays explicit. Ordinary no-symlink/single-link files have the existing fixed caps (proof64KiB, child8MiB, other reports2MiB). This adds no package execution, imports from reports, host privilege, network, directory discovery or mutation.

One `GNU_FAILURE_LOG_V1` base64 frame contains <=16KiB of ASCII JSON and <=24KiB total line bytes. Its fixed projection includes report byte/hash identities, observed statuses/errors, both exact root-directory initialization receipts when present, copy cleanup/identity-before-initialization flag, bounded primary/cleanup exception causes and frames, five normal runtime result statuses, optional interruption status and ordered cleanup status. It does not include full node/capability/payload maps, commands/argv, environments, source data or stdout. For each command layer, the first nonzero/unretired observation (or final observed command) carries metadata and at most512 stderr bytes, joined to the original command row's exact stderr hash/length. Some nonzero owner inspect commands are expected absence observations: they are not labeled the primary failure. Raw stderr was already public in the existing closed artifact.

Exception projections retain at most two causes/four frames and clipped notes per selected failure. A fixed frame-budget fallback further shortens message/frame/stderr projections and marks `projection_clipped_for_frame`; report hashes retain their original identities. If projection itself refuses, the CLI emits a bounded diagnostic-error frame with `source_proof=UNESTABLISHED` and exits1. Missing/unreadable/malformed files never become passed stages. No diagnostic frame grants native, cleanup, hardware, security or release acceptance, even when it carries an observed PASS string. Full raw artifacts and independent Root joins remain required.

After collecting original logs once, a passive extraction command is:

```
python3 -I -B scripts/ci/glibc-gnu-failure-log/summary.py extract \
  --lane lifecycle --logs /absolute/original/logs.zip \
  --source FROZEN_40_HEX_SOURCE --run ACTUAL_RUN --attempt 1 \
  --output /absolute/fresh/diagnostic.json
```

Extraction accepts only safe bounded original log ZIPs <=32MiB compressed/decoded, timestamped finite frames with the exact expected run/source/attempt/lane, and one unique payload. Identical frames duplicated in aggregate and individual step logs deduplicate; conflicting/foreign/malformed frames refuse. An absent frame is UNOBSERVABLE. Neither extraction nor a log frame repairs missing artifact evidence.

Run portable controls with `python3 -I -B scripts/ci/glibc-gnu-failure-log/test_summary.py`. Synthetic data supplies no actual native credit. This corrects future failure retention only; the missing artifact and underlying lifecycle cause for38997857389/source68d4e50a750d9ed966654450552924488a38adfa remain unresolved.
