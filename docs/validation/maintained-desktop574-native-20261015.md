# Maintained 574-package native transaction

October 15, 2026. **PASS for the selected offline package transaction and exact installed inventory on hosted Linux ARM.** This installs existing upstream ARM binaries into a disposable builder image; it does not rebuild 574 packages from source, launch a desktop, install onto Asahi or satisfy M2 hardware acceptance.

[GitHub run 38763655735](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38763655735) executed source [`7784face7c6c2b863df10bbc4a57ac13e95f4135`](https://github.com/Gabriel-Kahen/cachy-asahi/commit/7784face7c6c2b863df10bbc4a57ac13e95f4135), using `ubuntu-24.04-arm`. The job reports host and Docker daemon architecture `aarch64`; runner image is `20261012.149.1`. This run did not independently record a physical CPU, page-size or Apple-machine observation.

## Inputs and actual result

The committed input manifest is `scripts/ci/maintained-desktop574-inputs.json`, SHA-256 `b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9`. It selects 574 unique package/version rows, their pinned archive/signature bytes, the retained rootfs and three public keyring files. The six exact retained package/signature files were seeded through the existing helper before the secret-free acquisition/build step. Seed result: `SIX_EXACT_EXISTING_SEED_FILES_READY`.

Actual report:

```text
status:           PASS_NATIVE_OFFLINE_574_TRANSACTION
acquired:         1153
failures:         []
packages:         574
build_returncode: 0
host_arch:        aarch64
daemon_arch:      aarch64
native_build:     PASS
hardware:         NOT_RUN
```

The 1153 inputs are 574 archives, 574 detached signatures, the rootfs/signature pair and three public keyring files. The entry checks exact sizes and SHA-256 values, including retained seed files. The rootfs bytes reuse prior accepted authentication and are hash-checked here; this job does not perform a new detached-rootfs GPG audit merely because it downloads that signature.

Produced job-local image:

```text
sha256:363a6a5b93a46e2d091c2b1df360fd76623b17713c62e302bf823b5e6eff792e
```

The Dockerfile compares sorted `pacman -Q` output to the selected expected lock. A separate read-only, no-network, capability-dropped container then reads `/builder-packages.lock`, and the entry compares it again. The retained metadata step prints that full inventory. Reading the downloaded actual log ZIP, stripping only GitHub timestamp prefixes and parsing the two JSON reports independently yields exactly 574 unique installed names/versions, equal to all 574 committed rows, with no missing, additional or changed row.

Canonical sorted inventory bytes, with one trailing newline, SHA-256:

```text
cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac
```

Representative installed versions include Hyprland `0.56.2-4`, Aquamarine `0.15.1-1`, Mesa `1:26.2.4-1`, Waybar `0.15.0-3`, Mako `1.11.0-1`, Wofi `1.5.3-1`, PipeWire `1:1.6.9-1`, WirePlumber `0.5.18-1`, UWSM `0.27.0-1`, and generic `linux-aarch64 7.2.10-1`. Presence in this builder is not a tested session or a selected Asahi platform version set.

## Transaction behavior and limits

Docker builds with `--network=none --pull=false --platform=linux/arm64`; all selected files are staged before build. Inside the disposable image it initializes/populates the pinned public ALARM keyring and runs:

```sh
pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz
```

Pacman configuration has `Architecture = aarch64`, `SigLevel = Required`, `LocalFileSigLevel = Required`, and `HookDir = /builder-disabled-hooks`. The 41 selected hook basenames are overridden with `/dev/null` links. No dependency-bypass option is used. Actual logs show dependency resolution, conflict checks, package integrity checks and the complete successful transaction. Scriptlets are disabled and the known ALPM hooks are masked; explicit `ldconfig` follows. This is intentionally a builder transaction, not normal system initialization, service activation, boot readiness or an installation/removal exercise on a target machine.

The job's eight focused hosted-entry tests pass. No current project desktop-package build, compositor process, Wayland client mapping, frame capture, Waybar/Mako session, portal/audio session or UWSM login runs in this workflow. No 574-package source rebuild, package-pair reproducibility, signed repository publication, registry-image publication, Asahi mutation, M2/16K check, acceleration or performance result is established. All roadmap M2/M6/M7 and full-port release gates remain separate.

## Retention and next execution

The coordinator downloaded the actual logs once to `artifacts/development/maintained-desktop574-run38763655735/logs.zip`, 75305 bytes, SHA-256 `ecdde7d6e5e73e122559f5997549bcc6f244b56bb22021693131a383302648c8`. The relevant members are the seed step, reconstruction/native transaction step, and final metadata/inventory step. This review reads those bytes; it does not repeat the native transaction.

The completed hosted runner's local image is gone; its SHA is an execution identity, not a pullable registry reference. The next runtime workflow must recreate the same pinned 574 context and run its configuration/compositor checks later in that same job. Prepared ordinary runtime source is under `artifacts/development/maintained-desktop574-runtime-next-20261015/`; twelve focused data/mock tests and shell syntax checks pass, but that source has not run a native compositor. It preserves the 574 base, adds an explicit separate QEMU tooling extension and exercises a generic 4K-page ARM software guest. Even a successful guest cannot replace actual Asahi/M2 hardware validation.
