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
