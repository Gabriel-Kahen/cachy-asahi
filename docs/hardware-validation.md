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

Run the capture as the ordinary desktop user on each physical Air before
changing its installation. Use a separate private directory and machine
pseudonym for the [13-inch Air](validation/m2-air-13.md) (`apple,j413`) and
the [15-inch Air](validation/m2-air-15.md) (`apple,j415`). Keep the capture,
optional session observations, frozen acceptance contract and human review
private. The capture can contain operator names, logs, local paths, monitor
details and application names.

Set `OPERATOR` to your name or pseudonym and `PRIVATE_BASELINE` to a fresh
absolute filename without symlink components. Run this from the repository root.

```sh
python3 -B scripts/hardware/capture-baseline.py \
  --operator "$OPERATOR" --execution-context physical --require-m2-air \
  --output "$PRIVATE_BASELINE"
```

Exit 2 retains the private diagnostic capture. Resolve the identity or page-size
failure before preparing evidence. After exit 0, confirm the captured model
matches the intended unit and that `pacman -Q` succeeded. Retain the exact
signed base package and repository artifacts for review and recovery. See the
[baseline contract](baseline.md) for the protected platform and test counts.

For an optional [session probe](hardware-session-probe.md), run inside the same
Hyprland session after capture and before review. Set `MODEL_ID` to this Air's
device-tree ID, `RELEASE_SOURCE_REVISION` to the spec's `source_commit`, and
`PRIVATE_SESSION` to a fresh absolute filename in the private directory.

```sh
baseline_sha256=$(sha256sum < "$PRIVATE_BASELINE")
(
  umask 077
  set -C
  python3 -I -B scripts/hardware/session_probe.py --model-id "$MODEL_ID" \
    --baseline-sha256 "${baseline_sha256%% *}" \
    --source-revision "$RELEASE_SOURCE_REVISION" --execution-context physical \
    > "$PRIVATE_SESSION"
)
```

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

Freeze the [acceptance contract](acceptance.md) before trials. Its JSON must
include a positive integer `sleep_wake_repetitions`. For a dual-model release,
give both reviewers the same original spec bytes and prepare a separate draft
for each model before editing the spec.

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

After reviewing the outputs, append the `evidence` rows from each `draft.json`
to the release spec together. Appending the first draft early invalidates the
second review's spec pin. Keep the original spec bytes and use each draft's
`machine_record` ID in the
[release gate envelope](release/interface.md#stable-gate-envelope-version-1).
Reprepare the draft when any release inputs or policy change. The sanitized
contract projection carries the frozen contract's digest and sleep/wake count.
Retain the full contract and raw records privately for factual review. The
draft leaves hardware validation at `NOT RUN`. Functional, lifecycle, recovery
and benchmark results require separate observations and approval.

## Hand off the physical checks and benchmark preflight

| Unit | Capture and session identity | Release record |
| --- | --- | --- |
| M2 Air 13-inch (2022), `Mac14,2` / `J413AP` | AArch64, 16 KiB, `apple,t8112`, `MODEL_ID=apple,j413` | [`m2-air-13`](validation/m2-air-13.md) |
| M2 Air 15-inch (2023), `Mac14,15` / `J415AP` | AArch64, 16 KiB, `apple,t8112`, `MODEL_ID=apple,j415` | [`m2-air-15`](validation/m2-air-15.md) |

1. The coordinator assigns an operator and independent reviewer for each unit.
   Record the macOS and recovery environment, disk/ESP layout, planned protected
   Asahi versions and exact previous/candidate release hashes. Verify backup
   restore and access to a known-good boot or console. Reserve one system-changing
   job per unit and serialize sleep, audio and package lifecycle checks.
2. Authenticate the held fresh-install handoff offline with the external pins
   and retain the complete predecessor recovery set outside the target before
   starting the macOS installer or changing an existing baseline. Proceed with
   the fresh install once the maintained Asahi installer and image, signed
   repository trust and complete native target transaction are selected and
   reviewed. Record the independent onboarding exercise from clean prerequisites.
   [Fresh handoff](../scripts/install/fresh_handoff/README.md) ·
   [Installation guide](installation.md) · [Contributor guide](contributing.md)
3. On the unchanged Asahi reference for that unit, run the baseline capture
   above before adding the overlay and confirm a successful `pacman -Q`. Record
   the installed protected versions and retain the known-good boot and package
   inputs. On the exact candidate, perform three cold boots and graphical logins,
   20 lid resumes (10 battery and 10 AC)
   with apps checked after every resume, 10 locks/unlocks, and five lifecycle
   cycles each against fresh and existing user configurations. Exercise five
   connections/reconnections for supported display modes. Record every failure
   and keep the original desktop configuration available.
   [Functional and lifecycle contract](acceptance.md#fixed-functional-and-lifecycle-checks)
4. Exercise the actual previous-to-candidate full upgrade, interrupted download
   and transaction, failed session, retained rollback and boot recovery. Save
   the exact commands, before/after package inventories, configuration hashes
   and post-recovery functional observations for each scenario. Use the selected
   Asahi boot and recovery path for that installation's ESP.
   Both models' install and recovery records remain `NOT RUN` until exercised.
   [Exact-machine recovery procedure](release/recovery.md#exact-machine-recovery-exercise) ·
   [Release evidence interface](release/interface.md#exact-machine-interface)

For benchmark preflight, capture the baseline and candidate state with
`--require-m2-air` and check the package inventory in each. Keep the raw
captures private. Use the same machine pseudonym in the draft, the benchmark
plan and the separate `hardware_gate_evidence` with independently reviewed
baseline-functional and recovery PASS results for the exact machine/base.
Calibrate instruments and derive model-specific budgets from the unmodified
reference before [freezing the v2 plan](performance/cli.md#prepare-a-frozen-plan).
See the [instrumentation plan](performance/instrumentation.md).
