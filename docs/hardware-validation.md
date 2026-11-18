# Hardware validation record

Status: NOT RUN. No hardware compatibility claim is established by this repository.

Copy this template for each tested machine and version set. Keep logs in ignored local artifacts and publish sanitized evidence when appropriate.

## Environment

- Machine identifier and Air size:
- RAM/storage:
- Base distribution and repository snapshots:
- Boot component / firmware versions:
- Kernel, Mesa, Hyprland, Aquamarine, PipeWire, WirePlumber versions:
- Overlay source commit and installed package versions:
- Baseline comparison:
- Test date and operator:

## Checks

Record PASS, FAIL, or NOT RUN with reproduction steps and evidence for each check.

| Check | Result | Evidence |
| --- | --- | --- |
| Fresh graphical login and hardware rendering | NOT RUN | |
| Display scaling, brightness, keyboard, trackpad | NOT RUN | |
| Wi-Fi and Bluetooth | NOT RUN | |
| Speakers, speaker protection, headset, microphone | NOT RUN | |
| Browser acceleration, video playback, fullscreen | NOT RUN | |
| Lock/unlock and repeated lid-close sleep/wake | NOT RUN | |
| Session survives wake with applications preserved | NOT RUN | |
| External-display connect/reconnect, if tested | NOT RUN | |
| Package installation and removal | NOT RUN | |
| Upgrade and recovery/rollback | NOT RUN | |
| Idle/load power, suspend drain, sustained thermals | NOT RUN | |

External-display limitations must be reported against the exact kernel and device-tree stack used. Existing upstream feature limitations are not automatically overlay regressions.

## Prepare the draft machine evidence

Run `scripts/hardware/capture-baseline.py --require-m2-air` on each physical
Air before changing its installation. Use a private local directory for the
capture, optional [session observations](hardware-session-probe.md), frozen
acceptance contract and human review. The capture can contain operator names,
logs, local paths, monitor details and application names.

A separate reviewer must confirm the physical machine and model, inspect the
original capture and verify the exact release inputs and platform package
mapping. Obtain that review's SHA-256 from the reviewer through a trusted
channel. Calculating a hash from an unreviewed local file provides no
independence. Store these fields in the private JSON review:

| Field | Expected value |
| --- | --- |
| `kind`, `decision` | `physical-m2-air-baseline-review-v1`, `REVIEWED_PHYSICAL_BASELINE` |
| `machine_id`, `model_id` | An opaque per-unit pseudonym `m2-` followed by 32 lowercase random hex characters, and `apple,j413` or `apple,j415` |
| `reviewer`, `reviewed_utc` | Reviewer distinct from the capture operator and UTC review date in `YYYY-MM-DDTHH:MM:SSZ` |
| `baseline_sha256`, `spec_sha256`, `base_sha256`, `contract_sha256` | Exact byte pins for the baseline, original release spec before adding these evidence refs, its base file and the frozen acceptance contract |
| `session_sha256` | Exact session JSON digest if reviewed, otherwise `null` |
| `platform_packages` | Map `m1n1`, `uboot`, `asahi_scripts`, `kernel`, `mesa`, `hyprland`, `aquamarine`, `asahi_audio`, `pipewire`, `wireplumber` and `speakersafetyd` to the actual package names. Include `linux_firmware` when observed separately. |
| `boot_firmware_version` | Independently observed firmware version token without paths, names or serial numbers |

For the optional probe, supply the model ID, baseline SHA-256, release source
revision and `--execution-context physical` to `session_probe.py`. Verify the
frozen contract includes a positive integer `sleep_wake_repetitions`.

```sh
python3 -I -B scripts/hardware/prepare_release_evidence.py \
  --baseline "$PRIVATE_BASELINE" --contract "$PRIVATE_FROZEN_CONTRACT" \
  --review "$PRIVATE_REVIEW" --review-sha256 "$INDEPENDENT_REVIEW_SHA256" \
  --spec "$RELEASE_SPEC" --output "$FRESH_EVIDENCE_DIRECTORY"
```

Pass absolute paths. The output must be an absent directory directly beside
the release spec. Add `--session "$PRIVATE_SESSION"` when the reviewer pinned a
probe. The tool checks the 16 KiB capture, exact device-tree model, base and
artifact hashes, captured protected package versions, and optional probe
identity. It records both captured and planned release versions for the
platform roles. The reviewer remains responsible for checking the package-role
mapping, the firmware version and the physical claim.

After reviewing the output, append `draft.json`'s `evidence` rows to the existing
release spec. The `machine_record` ID can be referenced later by the existing
[release gate envelope](release/interface.md#stable-gate-envelope-version-1).
The machine record pins the original spec prior to adding evidence references.
Reprepare the draft when any release inputs or policy change. The sanitized
contract projection carries the frozen contract's digest and sleep/wake count.
Retain the full contract and raw records privately for factual review. The
draft leaves hardware validation at `NOT RUN`. Functional, lifecycle, recovery
and benchmark results require separate observations and approval.
