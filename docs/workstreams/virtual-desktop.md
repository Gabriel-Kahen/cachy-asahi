# Virtual desktop workstream

Implementation prepared October 11, 2026; **18 portable/synthetic tests PASS**.
The new installed native ARM runtime probe has **NOT RUN** in this workstream.
No compositor, display, GPU, audio, portal, bar or notification session was
launched. Owned files: `scripts/integration/desktop.py`,
`scripts/integration/test_desktop.py`, and this report. No original package,
shared manifest, other implementation, Git state or host packages were changed.

## Frozen interface for CI

The lifecycle/CI owner first verifies every original overlay version and payload
against the four native archives, preserves the frozen base inventory and
commits a clean immutable installed image without ephemeral signing material.
This runner independently binds the **desktop** archive/installed payload only;
it does not replace the four-package handoff. CI retains that installed-image
receipt, actual image ID and native Docker daemon/runner provenance.

Run inside a fresh disposable nonroot container from that verified image:

```sh
CACHY_ASAHI_INTEGRATION_CONTAINER=1 \
CACHY_ASAHI_DISPOSABLE_DESKTOP=ACTUAL_FRESH_32_HEX_NONCE \
CACHY_ASAHI_IMAGE_ID=sha256:ACTUAL_VERIFIED_INSTALLED_IMAGE_ID \
python3 /runner/desktop.py \
  --package /inputs/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.zst \
  --package-sha256 ACTUAL_64_HEX_ARCHIVE_SHA256 \
  --runtime-lock /inputs/expected-packages.lock \
  --output /out/desktop
```

Placeholders describe caller inputs, not existing execution results. Required
`--runtime-lock` is the exact preprovisioned base inventory (the existing native
builder has 341 packages). Installed versions must match every locked package;
extra names are limited to the four original overlay packages. Hyprland must be
`0.56.2-4`, Aquamarine `0.15.1-1`, and `Hyprland --version` must identify commit
`efb50993780079460b0cbed1363e2166a2de1d9f`. Archive identity/version, all seven
installed bytes and pacman ownership must match. No fetching, package install,
account setup or daemon activation occurs in this script.

Actual required container flags/mount contract:

- Nonroot ordinary image user; `--read-only`, `--network=none`, `--cap-drop=ALL`,
  `--security-opt=no-new-privileges`; bounded CI memory/CPU/pids limits.
- Explicit read-only `/inputs` and `/runner` mounts; runner path is fixed as
  `/runner/desktop.py`. Archive and lock must be regular contained `/inputs`
  files, at most 1 MiB each (the selected package is text-only).
- Explicit writable fresh `/out` evidence mount; output subdirectory must be
  exactly `/out/desktop` and absent. Read-write `/tmp` must be tmpfs.
- No nested mounts under `/inputs`, `/runner`, `/tmp`, or `/out`, and no host
  home/system directory mounts, Docker socket, display/audio sockets,
  `/dev/dri`, `/dev/snd`, or `/dev/input`. No host X11/Wayland/D-Bus/Pulse/PipeWire
  connection variables. Standard Docker hosts/hostname/resolv mounts are allowed.

Before outputs/processes, the runner checks actual root/input/runner/output/tmp
mount flags/types, root-owned Docker marker, architecture/user, effective/
permitted/bounding capabilities, no-new-privileges and observed loopback-only
interfaces. It refuses known device/socket exposure and system-path mounts.
Namespace IDs, observed security facts, caller nonce and image ID are retained.
These observations plus an environment declaration are not independent proof of
image/native/host lineage: CI must retain Docker inspect/launch provenance and
supply only the reviewed mounts. Fresh process-local home/config/cache/runtime
paths are created under the disposable tmpfs; runtime directory mode is 0700.

Each subprocess has a default 15-second deadline (`--timeout` may be <=60),
original-process-group cleanup and 1 MiB streaming stdout/stderr limit. A noisy
process is killed at that cap rather than filling the disk before refusal.
SIGTERM, including arrival at command completion, fails the command and reaps
the original group. Detached sessions, SIGKILL and uninterruptible OS stalls
remain outside Python cleanup guarantees; CI supplies an outer job/container
timeout. No session or audio/brightness command is used in these checks.

Output `desktop.json` binds archive, runtime lock, installed files and command
logs. Guard refusal creates no output or subprocess; guarded input/command
failures retain FAILED evidence. Existing output paths are refused. Fatal exits
or incomplete evidence never count as a successful result.

## Checks and limits

| Check | Mechanism | Scope of a PASS |
| --- | --- | --- |
| Installed package | Exact archive SHA-256, `.PKGINFO`, seven-member set, installed byte hashes and `pacman -Qoq` | Actual packaged text files/owner match; no lifecycle claim |
| Runtime snapshot | Actual full `pacman -Q` versus frozen base lock plus four original overlay names | Installed base versions match the declared image snapshot |
| Lua syntax | Existing native `luac -p` on the installed file | Lua syntax only |
| Hyprland default/optional template | Existing `Hyprland --verify-config --config` on actual installed file and a private copy with the documented startup callback enabled | Native compositor parser/API compatibility only; callbacks/commands are not run |
| Waybar JSON | Stdlib strict JSON with duplicate/nonfinite rejection | JSON syntax only, not Waybar binary/module/session validation |
| Waybar CSS | Existing GTK3 `CssProvider` via small isolated Python ctypes subprocess; capture parsing-error and GError | Actual native GTK stylesheet parser, without gtk_init/display/application creation |
| Mako config | Original five-option subset matching audited upstream value types | Source-audited static subset only, not Mako binary/runtime parsing |

Frozen inventory contains GTK3 `1:3.24.52-2`, GLib `2.90.1-1`, Lua `5.5.1-1`,
Python `3.14.8-1` and libarchive `3.8.9-1`; they support these checks without a new
package. **Waybar and Mako are absent.** Their application runtime fields remain
NOT RUN, and no dependency is silently added. A full bar/notifier runtime test
would require separately audited/pinned dependency extensions and a viable
isolated compositor; adding packages alone does not supply one.

## Primary pinned source audit

- Hyprland v0.56.2 commit `efb50993780079460b0cbed1363e2166a2de1d9f`:
  [verification/startup branch](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/Compositor.cpp#L270-L342)
  and [main verification exit](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/main.cpp#L284-L294).
  Verification returns before creating the Wayland display/backend. Direct
  verifier invocation is intentional; no launch wrapper/compositor session runs.
- Aquamarine v0.15.1 resolves to `f31c47a1b9d300847d8fc3108ad959448103dfc1`.
  [Headless backend](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/Headless.cpp#L125-L139)
  returns no DRM descriptor; [backend allocator startup](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/Backend.cpp#L162-L179)
  requires a backend with a usable DRM fd to create its primary GBM allocator.
  Headless outputs alone are insufficient: allocator absence fails startup.
- A nested [Wayland backend](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/Wayland.cpp#L96-L164)
  still requires DMA-BUF feedback/DRM access; [GBM allocation](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/allocator/GBM.cpp#L331-L345)
  needs PRIME export. Hyprland's [OpenGL initialization](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/render/OpenGL.cpp#L289-L358)
  is DRM EGL/GBM based; no audited surfaceless software fallback was found.
  [Aquamarine environment reference](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/docs/env.md)
  does not supply a `WLR_RENDERER`/headless software selector. Mesa software flags
  do not create the missing backend allocator.
- Waybar 0.15.0 commit `90b209add8937514d0a987aa842e701bd8f1232e`:
  [JSON parser invocation](https://github.com/Alexays/Waybar/blob/90b209add8937514d0a987aa842e701bd8f1232e/src/config.cpp#L88-L105)
  and [GTK stylesheet provider](https://github.com/Alexays/Waybar/blob/90b209add8937514d0a987aa842e701bd8f1232e/src/client.cpp#L190-L202).
  Strict JSON is a deliberately narrower syntax check; GTK's stylesheet parser
  is the actual library path used by Waybar, but no Waybar process is tested.
- GTK 3.24.52 [provider header](https://github.com/GNOME/gtk/blob/3.24.52/gtk/gtkcssprovider.h)
  and [API documentation](https://docs.gtk.org/gtk3/method.CssProvider.load_from_data.html):
  callback/GError handling captures load errors; no display initialization occurs.
- Mako v1.11.0 commit `91c6b799855762ad1eb8b4498967c270a339be0c`:
  [configuration types](https://github.com/emersion/mako/blob/91c6b799855762ad1eb8b4498967c270a339be0c/config.c#L560-L641)
  and [options documentation](https://github.com/emersion/mako/blob/91c6b799855762ad1eb8b4498967c270a339be0c/doc/mako.5.scd).
  The five selected fields are hex colors/nonnegative int values. No upstream
  source is bundled/relicensed and no full Mako parser equivalence is claimed.

**Software compositor smoke: BLOCKED, not attempted.** Under no-DRM/no-host-socket
isolation, the pinned upstream allocator path has no viable software-only
Hyprland session. Distribution binary patches were not independently inspected;
this is an upstream source conclusion, not an executed failed session. No
Weston/VKMS/new compositor or undocumented environment workaround is added.
GPU acceleration, portals, audio/protection, input/scaling/notch, suspend,
16K/model support and M4/performance acceptance remain NOT RUN.

## Actual checks and handoff

`python -m unittest discover -s scripts/integration -p test_desktop.py -v`:
**18 PASS** on the development host. Tests use temporary text/ownership fixtures,
mock container facts, synthetic successful/failing verifier output, and short
Python subprocesses for timeout, streaming cap and completion-SIGTERM cleanup.
They do not execute Hyprland/GTK/bar/notifier sessions or qualify native runtime.
The synthetic success record still has application/session/hardware/performance
acceptance fields NOT RUN and software compositor not attempted.

Independent read-only source review verified frozen dependencies and GTK ABI
against pinned headers. Its excessive-output and completion-SIGTERM findings
were fixed with focused regressions. A root review request strengthened actual
mount/capability/network refusal before outputs/processes. No other worker files
or frozen package dependencies were changed.

CI owner should mount the final scripts at `/runner`, install the original
archive through the separate lifecycle stage, and run the exact interface above
inside a fresh verified installed image. Native `desktop.json` and raw logs must
be inspected; this prepared implementation does not invent that result. Native
parser/software checks cannot pass M2 hardware or stable release gates.

## Final source freeze

Ready for the CI owner's installed-image invocation. Final SHA-256:

- `scripts/integration/desktop.py`: `ed3a2c65a60fa070832061c69f7bf8ec7a616d34aacdf2e6b7080935c0bdde2f`.
- `scripts/integration/test_desktop.py`: `f960443c7e8bebaf40284905b9e43be5f1af9cf4339c27da96d88fc388972e18`.

Final execution: 18 portable tests PASS, including all eight nested-mount
read-only/read-write rejection fixtures. Independent read-only review rechecked
the exact final runner hash, accepted the valid contract and refused every
nested override. Excessive-output, completion-SIGTERM and nested-mount findings
are resolved for this source. No native/GTK/compositor/device session was run by
the reviewer or worker; actual installed native parser results remain NOT RUN
pending the integration job. No further desktop/package source change is needed
for this handoff absent an actual runtime failure.
