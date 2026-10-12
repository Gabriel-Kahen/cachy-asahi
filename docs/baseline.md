# Baseline contract

The chosen initial base is an existing Asahi ALARM installation. Its current website offers Hyprland through desktop installation; this is a discovery reference, not a tested cachy-asahi installation path. See [Asahi ALARM](https://asahi-alarm.org/) and the [distribution integration guidelines](https://asahilinux.org/docs/alt/policy/), reviewed October 11, 2026.

No exact base snapshot or compatible version set has been accepted. Capture the actual target before modifying it:

```sh
python3 scripts/hardware/capture-baseline.py --operator NAME --execution-context physical --require-m2-air --output artifacts/baselines/m2-before.json
```

The collector queries installed package versions, local repository database hashes, kernel, page size, device-tree identity, Hyprland and audio status. It does not install anything, change services, exercise audio, suspend, or validate hardware. Output is created exclusively; choose a new filename for each run. Review logs before sharing them: desktop/audio status may include application names. Failed queries remain explicit in JSON.

Record recovery prerequisites and the full machine/version record from `docs/hardware-validation.md` alongside the JSON. Save actual base repository/package artifacts separately: database hashes do not preserve downloadable versions. Record firmware and boot integration versions from installed packages and supplement omissions manually. Firmware contents and device serial numbers are not collected.

## Protected platform

The overlay must preserve installed Asahi boot integration (m1n1, U-Boot and asahi-scripts), kernel, firmware, Mesa/graphics integration, asahi-audio, PipeWire/WirePlumber configuration and speakersafetyd. Discover exact package names on the target rather than guessing an upstream naming scheme. No PC hardware detector, bootloader replacement, kernel manager, mixer bypass or automatic tuning belongs in the initial overlay.

The [Asahi audio documentation](https://asahilinux.org/docs/sw/audio-userspace/) is a source reference; speaker protection must be validated on the actual machine. The [M2 feature matrix](https://asahilinux.org/docs/platform/feature-support/m2/) separates the two Air models and does not certify this overlay. Record upstream limitations against the tested version set separately from regressions.

## Hardware acceptance plan

Specify runs before testing; do not revise counts to hide failures. Initial acceptance uses 3 cold boots/fresh logins, 20 lid-close suspend/resume cycles (10 on battery, 10 on external power), 10 lock/unlock cycles, and 5 each installation/removal/reinstallation cycles against fresh and existing configurations. Retain every failure and confirm application state survives each resume. Exercise 5 display connection/reconnection cycles only where supported by the chosen platform; unsupported features stay documented limitations.

Speaker protection, headset, microphone, Bluetooth/Wi-Fi, keyboard/trackpad/brightness, hardware rendering, browser/video, service startup after resume and normal/interrupted upgrade plus recovery require operator observations and logs. Tests involving audio and sleep must be serialized on each physical machine. Independent review and sanitized raw evidence are required; the collector cannot supply these observations.

No 13-inch result implies a 15-inch result. Machine records must identify each supported model. Baseline failures must be recorded before the overlay so they can be distinguished from regressions.

The collector maps `apple,j413` to the 13-inch Air and `apple,j415` to the 15-inch Air, as defined by the upstream Linux device trees ([J413](https://github.com/torvalds/linux/blob/master/arch/arm64/boot/dts/apple/t8112-j413.dts), [J415](https://github.com/torvalds/linux/blob/master/arch/arm64/boot/dts/apple/t8112-j415.dts)). Matching identifiers selects a record; it does not attest to physical hardware execution.

## Current resource status

October 11, 2026: local x86_64 development host and Docker amd64 engine verified. No M2 Air or clean native aarch64 builder identified. Local tooling tests can proceed. M1 native repeat builds and M2/M3 hardware acceptance remain blocked by access; no performance measurements exist.
