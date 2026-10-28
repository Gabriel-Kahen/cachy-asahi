# Screenshot helper: local headless software capability and actual failures

Positive local pixel capture is BLOCKED by the installed compositor capability gate. No compositor was launched and no PNG was captured. Four real helper failure cases passed safely against a private absent Wayland socket. This is x86_64 software/file behavior evidence only; it is not an ARM archive execution, accelerated Hyprland, Asahi transaction, M2 or hardware capture result.

The exact current helper is `packages/desktop/cachy-asahi-hyprland-settings/cachy-asahi-screenshot`,8523 bytes,mode0755,SHA `5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8`, in the0.1.0-2 source recipe. Source and package metadata were read without installing or changing them. The roadmap/inventory still require native builds, integration and target validation separately.

## Exact capability blocker

The installed binary reports Hyprland0.56.2, clean commit `efb50993780079460b0cbed1363e2166a2de1d9f`, built with Aquamarine0.15.0 and running Aquamarine0.15.1. Its help exposes config/socket flags but no purely headless software launch contract. Matching upstream [Hyprland initialization](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/Compositor.cpp) requests HEADLESS, DRM-if-available and a Wayland fallback. The [Aquamarine0.15.1 allocator path](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/Backend.cpp) obtains its normal allocator from a DRM FD; the NULL exception is not a backend Hyprland selects. Headless outputs alone therefore do not satisfy this task's zero-DRM software requirement.

This is a prelaunch Source capability finding, not a failed startup experiment or proof that no future/patched compositor could work. Reported version/source correspondence is recorded; binary reproducible-build equivalence is not claimed. Guessing old wlroots environment variables for this Aquamarine Hyprland, launching a nested user window, using the current compositor's virtual output or touching a GPU/input/TTY was excluded. Sway, Weston and swaybg are absent from the local tool search. No host package was installed.

## Actual helper executions

`run-offline-failures.py` invokes the actual helper using `/usr/bin/python3 -I -B` and real installed grim/slurp. Every child receives a new explicit environment: owned0700 HOME/runtime/config/cache/state paths and an absolute absent WAYLAND_DISPLAY inside that private runtime. DISPLAY, WAYLAND_SOCKET, user compositor instance and session bus variables are not inherited. The output directories belong only to this review namespace. No GUI inventory, user window/focus/clipboard operation or global configuration mutation is used.

| Actual case | Observed result |
| --- | --- |
| Full capture, absent private socket | Exit1, empty stdout, grim failure diagnostic, no PNG or partial |
| Same full failure repeated | Same refusal; output remains empty |
| Region capture, absent private socket | Exit1, empty stdout, slurp/setup refusal with explicit no-full-screen-fallback diagnostic |
| Existing0755 output directory | Exit1;0755 directory and preexisting0600 sentinel bytes/mode preserved |

All four outcomes, exact argv/environment, directory listings and sentinel hashes are retained in `actual-results.json`. Independent review checks the strict current directories, including absence of any leftover entry in the private runtime/output; it does not merely trust a file-only listing. The helper Source remains unchanged. Its own failure cleanup paths ran; no positive publication/pixel decode was possible, and no pixel success or compositor retirement is claimed. No compositor existed to retire.

## Concrete future CI proposal

`ci-proposal.md` specifies a disposable unprivileged, no-device/no-host-IPC software job using Source-audited Sway1.11 commit `990b23c0e584114c3694447344d6bbf44b2d748f`, wlroots0.19.0 `13a62a23a258d96f902c740310d5c7c59784a4d1` and swaybg1.2.1 `dcb5ebc76adcfef81c1a275ae7ed21a7936cbd7c`. Explicit headless/pixman selection, SHM allocation and private socket behavior are Source-audited, not locally executed. The future image must also include real grim, slurp and Pillow; complete dependency/build closure and an image digest are not yet frozen. A missing Source lookup is recorded rather than silently treated as a complete image.

Finite acceptance uses three real helper captures: repeat a known solid background, then change that compositor background. Independently verify chunk CRCs, Pillow verify plus full decode, dimensions, every expected pixel, unique0600 paths, unchanged prior PNGs and absence of partials. The plan also repeats real offline/region/directory refusals and records owned-process cleanup separately. It supplies no fake grim/slurp result or generated PNG as capture evidence. Positive region selection needs a separately audited virtual-input fixture and is not included.

No canonical Source, manifest, workflow, repository variable, Git ref or CI trial is changed/submitted by this review. Root can review the concrete proposal and freeze its disposable image before a separate software-only CI run. Native ARM package execution and the two M2 Air hardware checks remain independent gates.
