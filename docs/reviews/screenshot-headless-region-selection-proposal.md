# Successful region selection: pinned Source audit

Status: **Sway cursor IPC alone is insufficient in the held zero-device headless setup; successful region selection remains NOT TESTED.** No runner, helper, workflow, package, runtime pin or Source-lock change is proposed by this packet. The actual [full-screen software trial](screenshot-headless-software-run-38634245640.md) remains a separate accepted bounded result; it exercised region failure only.

The [audit packet](../../artifacts/reviews/screenshot-headless-region-selection-proposal-20261014/) reads the exact held Debian source archives for Sway1.10.1-2, wlroots0.18.2-3, slurp1.5.0-1 and swaybg1.2.1-1. Selected source/docs are extracted only after archive size/SHA256 checks against immutable runtime lock `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05`. Debian patch applicability is reviewed in the [seat Source audit](../../artifacts/reviews/screenshot-headless-region-selection-proposal-20261014/seat-source-audit/). No downloaded source, compositor, helper, slurp, Docker, APT or host GUI/input actor was executed. No CI retry, variable, Git/worktree, package or system mutation occurred.

## Exact interface and blocker

Sway's pinned `sway-input.5.scd` documents `seat <seat> cursor set|move <x> <y>` and `seat <seat> cursor press|release <button>`. It marks these commands deprecated in favor of the virtual-pointer Wayland protocol. The implementation accepts live IPC commands, warps/moves the seat cursor and dispatches button events with a null physical-device pointer. Thus the command syntax exists; command availability alone is not a usable slurp input path.

The missing step is a seat pointer capability:

1. A fresh wlroots seat starts without pointer capability. The explicit headless backend creates outputs, not physical input devices.
2. Sway's `seat_update_capabilities` starts with zero flags and adds `WL_SEAT_CAPABILITY_POINTER` only for attached pointer/tablet devices. An empty device list therefore advertises no pointer. Creating a Sway cursor object or issuing the cursor IPC commands does not attach a device or set that capability.
3. Real slurp's `seat_handle_capabilities` obtains a `wl_pointer` and installs its enter/motion/button listeners only when the compositor advertises the pointer capability. With none, slurp has no pointer listener to receive the synthetic IPC events.
4. Forcing an unsupported `wl_seat.get_pointer` request is not a legitimate bypass: wlroots validates whether the capability has ever been advertised. Changing a printed slurp geometry, returning canned output or skipping real selection would also fail the requested test.

The exact supporting files/lines and archive hashes are retained in the Source audit and [independent review](../../artifacts/reviews/screenshot-headless-region-selection-proposal-20261014/peer-review/). This is a source-supported blocker for the held device-free configuration, not an observed failure from a newly launched seat or slurp. The successful prior run did not export an actual seat-capability query; this audit does not invent one.

## Best legitimate existing interface

The pinned Sway/wlroots stack exposes `zwlr_virtual_pointer_manager_v1`. A real virtual-pointer protocol client is the existing software interface intended to create a compositor-local pointer, attach it to a seat and send pointer events. It can be confined to the already private Wayland socket; it does not inherently require `/dev/uinput`, host input devices, physical DRM, clipboard access or a privileged container. The exact create/seat/capability route is source-audited, not runtime-tested here.

The held 196-package inventory contains Wayland libraries, wlroots, Sway and swaybg, but no selected virtual-pointer input client is identified by this audit. Availability of the protocol or a shared library is not proof that a working input client is installed. A tiny client using existing runtime facilities is a possible separately bounded implementation approach, but writing/validating that client and driving a real selection would be new Source work; no such protocol framework or new client is included silently in this packet. A new package or container privilege is not proposed as a shortcut.

## Requirements for a later real-selection follow-up

A future Source proposal must establish a real compositor-local pointer and verify actual seat capability before invoking the existing helper's `region` mode. It must wait for actual slurp overlay readiness/pointer-enter, then send a real press, motion and release; helper liveness, IPC command success or a fixed sleep alone is not readiness evidence. Slurp's pinned code unmaps its overlays and roundtrips before exiting, after which the unchanged helper launches actual grim.

Slurp's drag includes **both endpoints**: width and height are `abs(delta)+1`. A desired crop `(x,y,W,H)` therefore ends at `(x+W−1,y+H−1)` for a forward drag. This matters for nonempty dimensions and edge/boundary checks. No predicted geometry may be substituted for slurp's actual output.

Pixel validation must establish crop origin as well as dimensions. A uniform background plus a smaller PNG cannot distinguish which equally colored region was captured. A later test needs an asymmetric displayed stimulus or contrasting boundaries with independently expected crop pixels, then a real helper capture, full PNG decode and comparison. An explicitly labeled displayed test pattern is permissible stimulus; generating a PNG and treating it as captured output is not.

All existing safeguards remain requirements: exact helper Source and package pins, 196-row installed inventory, private runtime/HOME/output and sockets, no DRM/input/TTY/host socket access, network-disabled read-only non-root trial containment, bounded IPC/process/output/time limits, prior-file preservation, real negative cases, owned process/runtime/container cleanup and held image/cache/context limitations. Successful full-screen captures cannot be relabeled successful region selection. ARM archive, Hyprland, M2, license and performance acceptance remain outside this software audit.

Root can use this packet to choose a separately reviewed virtual-pointer client follow-up. There is no claimed region-capture implementation, actual selection, new Source SHA, plan, CI dispatch or runtime result to adopt from this audit.
