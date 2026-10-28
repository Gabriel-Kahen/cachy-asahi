# Screenshot software pilot 38628618206: retained terminal failure

Status: **actual run FAILED during offline image installation; screenshot runtime NOT REACHED**. [Run 38628618206](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38628618206), attempt 1, used Source `85a84f9ff5437e139a284c73d9c02767e14d474f`, ref `codex/screenshot-headless-software-v1`, workflow `384750899` and job `116074139939`. It ran from 16:01:54 to 16:02:18 EDT on October 14, 2026. No retry, cancellation, Source modification, private replay or additional dispatch was performed by this review.

The first concrete diagnostic is retained in `artifact/build.log`:

```text
E: Internal Error, Pathname to install is not absolute 'libexpat1_2.8.3-1~deb13u1_amd64.deb'
```

The observed chain is APT RUN exit 100 → Docker build exit 1 → driver's first failure `ValueError: build failed` → failed job/run. The offline APT resolver had reported 0 upgrades and 118 new installations before the internal error. This locates the failure; it does not establish the deeper cause of APT's pathname handling. No fix or changed Source is proposed or tested here; Root chooses the next cause investigation.

## Retained evidence and integrity

The [review packet](../../artifacts/reviews/screenshot-headless-software-run-38628618206-20261014/) and separate [retention namespace](../../artifacts/retained/screenshot-headless-software-run-38628618206-20261014/) contain terminal API run/jobs/artifact metadata, exact raw ZIPs, validated plain members, committed Source snapshots and Root publication proofs. Earlier sealed packets remain unchanged.

| Retained object | Bytes | SHA256 |
| --- | --- | --- |
| Actual artifact ZIP `11924577836` | 96,187 | `d718971b7886b8498d9a79a6bf642de766d52a63b940af72bc89888e03ca860d` |
| Actual job-log ZIP | 14,600 | `7427d73b870731bc9e5800495c2592e93ddb0ebaad160d0df8f88263b307f484` |

The artifact ZIP digest exactly matches GitHub's artifact API digest. Safe ZIP validation accepted twelve artifact files and nine log files after checking regular member types, canonical relative paths, no traversal/duplicates/symlinks/encryption, CRC/read length, entry/depth/size caps and bounded total expansion. Nothing from the ZIP was executed. Extracted copies are normalized to 0600 below 0700 directories; ZIP stored modes are retained as metadata and do not prove original runtime permissions. The original GitHub artifact expiry is October 21, 2026 at 16:02:14 EDT; the complete local retention is independent of that expiry.

The retained `root-plan.json` semantically matches the sealed 529-byte literal SHA256 `83f4176e9c036c846709b7c4593f8836cc289df7002a3c731af7dc18f40ed79a`; its pretty formatting is different. `runtime.lock.json` matches SHA256 `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05`. The default registration was the distinct workflow-only commit `3ab577f937af86e74e9f77578e4f260c37bb43ed`; it is not the trial Source SHA. Root's captured readback/publication proofs remain historical evidence, not assertions that no later dispatch occurred.

## Observed stage boundaries

| Stage | Actual evidence and result |
| --- | --- |
| Registered manual identity/guard | Exact run Source/ref/workflow/attempt; pre-checkout guard SUCCESS |
| Pinned checkout | SUCCESS; committed workflow/driver/Containerfile captured read-only |
| Docker host tooling | `docker --context default version` and `info`: exit 0; client/server Docker 28.0.4, linux/amd64 |
| 196 input downloads/hash gates | Passed by audited Source control flow before the retained runtime lock, plan and pull; individual downloaded deb bodies were not retained in this artifact and cannot be independently rehashed here |
| Pinned base pull | Exit 0; actual pull log digest `sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483` |
| Offline image build | `--network=none --platform=linux/amd64`; 100.99 MB context copied; APT internal pathname error, build exit 1 |
| Evidence upload | `always()` upload step SUCCESS despite build failure; exact artifact retained |
| Image ID / trial container create/start | NOT REACHED; no image-ID or container inspection evidence |
| Actual installed 196-package inventory | NOT REACHED; a 196-row lock is not an installed-inventory result |
| Sway/pixman/SHM runtime, helper captures | NOT REACHED; no runner result, compositor log or PNG |
| PNG dimensions/pixels/private paths/repeat/negative cases | NOT RUN; zero PNG suffix/signature members; no fixture was substituted |
| Trial-container retirement | Not applicable to this path: driver never set the trial-container name or issued create/start/remove |
| Pulled base, build cache/intermediates, temporary deb/context retirement | UNKNOWN / UNRECORDED; no image/cache/context deletion receipt. Hosted-runner disposal is not a directly observed cleanup result |

`ci-result.json` contains exactly four recorded Docker commands with codes `[0,0,0,1]`, empty `checks`, status `SOFTWARE_SCREENSHOT_FAIL`, and first failure `build failed`. The four command names are version, info, pull and build. No actual trial invocation or `SOFTWARE_SCREENSHOT_PASS` appears. The workflow guard and always-upload boundary worked; the runtime acceptance gates did not run.

The held base image and failed build intermediates/cache must remain a qualification, not be called cleaned. Registration, source auditing, input pinning and successful upload cannot stand in for an image build or capture result. This run establishes no successful standalone screenshot behavior, ARM archive execution, Hyprland compatibility, M2 hardware behavior or performance result.

The independent review lives in [peer-review](../../artifacts/reviews/screenshot-headless-software-run-38628618206-20261014/peer-review/). Root owns any future Source correction, registration update or retry; none is authorized by this failed-run receipt. The pilot is terminal, so Root's scheduling hold tied to its termination can be reconsidered separately from this failed software acceptance result.
