# Private native Linux Done graphics counterfactual

This developer diagnostic runs the retained Done0.1.0-2 foreground-success, exit7 and real watched-sleep8 cases through native Fish, notify-send, a private D-Bus/Mako service and a render-only headless Sway display. It creates no host notifications/windows and never opens the user's display, bus, HOME, physical input or DRM primary card. It does not fetch, compile or install anything. It is **not** the ARM/Hyprland managed lane, an ALPM lifecycle, M2 hardware evidence or release authorization.

Supply already-built native tools and the exact retained Done archive. The machine must be Linux x86_64 or aarch64 with an ordinary nonroot user, unprivileged bwrap namespaces and an accessible DRM render node. Native `/usr`, `/etc` fonts/runtime dependencies and read-only `/sys` remain host inputs; this is not a closed reproducible host-library or source-to-binary attestation. Sway must genuinely support headless/GLES rendering and layer-shell, and Mako must be compatible. The proven instance used Sway1.11/wlroots0.19.0 and exact Mako1.11.0 source, with KMS/libinput/session backends disabled. No compositor/backend patches are used.

Architecture is selected from the **actual Linux host**: `x86_64` requires ELF64 little-endian machine62; `aarch64` requires ELF64 little-endian machine183. Every supplied executable and library must match; unsupported or mixed architectures refuse before any actor or work directory. There is no cross-target `--arch` override. The readonly staged tools/libraries are checked again against the actual host inside isolation. Exact `native_arch` name/machine fields are recorded in bindings and results. Existing x86 status/scope strings stay unchanged; ARM results use `AARCH64` and remain explicitly Sway counterfactuals, without M2/Hyprland/ALPM authority.

**aarch64 actual execution: NOT_RUN.** This source adaptation and inert ELF metadata controls do not attest an ARM tool build, working ARM renderer, page-size compatibility or M2 hardware. To use on an aarch64 developer machine, supply that machine's native Sway/Mako/Fish/system executables and native libraries with their exact hashes in the same manifest; do not reuse the x86 binaries from earlier evidence. The unchanged architecture-neutral Done archive and shipped Mako style remain mandatory. Actual source-to-binary correspondence, complete dynamic dependencies and host graphics permissions remain separate prerequisites/evidence.

Create a caller-owned non-public parent directory, then provide an **absolute fresh nonexistent child** with `--work-dir`. Existing output is always refused; original screenshots are never replaced. Use an ordinary single-link JSON file with these exact keys:

```json
{
  "schema_version": 1,
  "tools": { "sway": { "path": "/absolute/native/sway", "sha256": "64 lowercase hex" } },
  "libraries": [],
  "mako_config": { "path": "/absolute/shipped/mako.conf", "sha256": "c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504" },
  "done_archive": { "path": "/absolute/cachy-asahi-fish-done-0.1.0-2-any.pkg.tar.xz", "sha256": "9ce3c7ba89467f04660014c1b12056dce28bd0c4e69b4cab8a9c2c98e1cce54f" },
  "render_node": "/dev/dri/renderD128",
  "source_metadata": { "qualification": "Caller-declared source/package/revision/archive hashes; not independent binary attestation" }
}
```

The abbreviated tools example must be expanded to **exactly**: `sway,swaymsg,mako,makoctl,fish,grim,busctl,dbus_daemon,notify_send,timeout,bwrap,sleep,shell,python`. Each row has only absolute `path` and SHA256. Custom Sway/Mako executables are privately copied; the other tools must be the fixed `/usr/bin` paths in `run.py`: shell is the real `/usr/bin/bash` behind `/usr/bin/sh`, Python the real current interpreter behind `sys.executable`. Symlink paths, caller-input hardlinks, shared input inodes, wrong or mixed native ELF architecture/hash, setuid/setgid and work/input overlap are refused. The fixed Fish multicall binary may have exactly the three actual /usr/bin/fish,fish_indent,fish_key_reader hardlinks: the complete same-inode group/count is verified before and inside isolation; no other hardlink exception. Binaries/config/archive are read and identity/hash checked before any actor; `/usr` tools are rehashed inside isolation before starting Sway.

For private Sway, put its required native shared libraries in `libraries` as ordinary unique-basename path/hash rows. Only flat ordinary native `.so`/versioned `.so` files are accepted and copied to the owned `/work/libs`; no directory tree or symlink aliases are imported. System dynamic dependencies otherwise come from read-only `/usr`. Include exact native source versions/revisions/archive checksums/license/build references in `source_metadata` where known; the output preserves that data as **caller-declared**, never independent authentication or an invented source/build correspondence.

```sh
python3 -I -B scripts/diagnostics/fish-done-native-graphics/run.py \
  --inputs /absolute/inputs.json --inputs-sha256 ACTUAL_JSON_SHA256 \
  --work-dir /absolute/private-parent/fresh-work --validate-only
# Remove --validate-only to execute; no work is created by validation alone.
```

The fixed private bus/runtime/HOME and all actors live inside owned user/PID/mount/network/IPC namespaces. Only the selected render node is shared. The unmodified product payload is unpacked after complete archive/hash/payload closure validation; it is not installed. Runtime helper bytes are pinned and staged read-only. No inherited display, bus, tracing or user config is accepted.

Each case preserves real typed Notify/reply, explicit3000ms timeout,15s delivery,2s pre-expiry observation/notify-send wrapper,3.5s expiry wait, normal caller status and watched-child retirement. Exactly one original PPM is captured per case with grim. An image-derived shipped-border ROI verifies background/border/text presence; it is not the original Hyprland live-layer geometry witness or a presentation timestamp. No retries, replacement images or TTL extension. Pixel failure remains failure; captured originals stay retained. Human review of all3 frames remains necessary for readability. Render-node/GLES selection is not a live GL vendor/model readback or a hardware-performance claim. Upstream Mako1.11.0's server-information version is hardcoded0.0.0; do not infer the source version from it.

`result.json`, raw bounded bus/PTY data, command receipts, bindings, original PPMs and cleanup outcomes remain in the work directory. Main actors and commands own process groups; errors retain failure and kill/reap owned groups. bwrap/PID namespace lifetime contains remaining actors on failure; no host-wide cleanup scan or independent fresh absence attestation is claimed. An outer120s ceiling bounds the whole three-case fixture. Cleanup removes actors/mount namespaces, not retained evidence files. `PASS_*` is only this local counterfactual pending visual review; Root admission is separate.

Inert controls, without graphics/ALPM actors:

```sh
python3 -I -B scripts/diagnostics/fish-done-native-graphics/test_run.py
```
