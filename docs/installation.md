# Overlay installation and removal

Development procedure, NOT RUN on an M2 Air. No supported release exists. This guide describes the candidate packages' ownership and the target validation sequence; it becomes a supported guide only after the hardware and upgrade/recovery gates pass.

## Starting system

Use an existing Asahi ALARM installation with its working platform packages and supported desktop/session setup. The [Asahi ALARM website](https://asahi-alarm.org/) documents its base installation path. This overlay does not partition macOS storage or supply an installer. Record the exact model and versions with `docs/baseline.md` before changing the target.

The source implementation proposes four packages:

| Package | Package-owned templates | Activation |
| --- | --- | --- |
| `cachy-asahi-hyprland-settings` | `/usr/share/cachy-asahi/hyprland/` | Explicit setup creates a separate user copy; select it through the validated base session launcher |
| `cachy-asahi-fish-config` | `/usr/share/cachy-asahi/fish/config.fish` | Explicit setup adds a guarded interactive source block |
| `cachy-asahi-zsh-config` | `/usr/share/cachy-asahi/zsh/config.zsh` | Explicit setup adds a guarded interactive source block |
| `cachy-asahi-setup` | `/usr/bin/cachy-asahi-setup` and documentation | Preview/apply configuration activation, deactivation and interrupted-operation recovery |

The coordinator must reconcile the manifest, project license, exact compatibility set and dependency transaction first. A candidate recipe is not an install list. Refer to each package's README/usage document and audit for actual dependencies and behavior. No package changes the user's login shell or enables a system service automatically.

## Candidate validation sequence

1. Retain the original working desktop configuration and recovery artifacts. Record their hashes and package ownership. Establish a reachable recovery console and exercise the recovery method before changing the desktop.
2. Verify the selected artifacts' signatures through the reviewed release trust process; do not use an unverified key copied from the same download channel as the artifacts. Confirm checksums and provenance, two clean native builds, package review and the target's full dependency transaction.
3. Inspect package file ownership/conflicts and proposed package-manager transaction before installation. Reject any transaction that replaces or removes protected Asahi components. Missing desktop dependencies must be resolved through the chosen base's compatible package set, not PC repositories or a kernel/Mesa swap.
4. Install only the explicitly selected local artifacts on the recorded target. Save the package-manager output and before/after inventories. Installation itself must not activate user configuration or change services.
5. Enable one configuration at a time. Use a new user-owned Hyprland file; do not overwrite the existing configuration. Preserve the base session manager, portal and authorization-agent integration. Follow the package-specific procedure and validate configuration before first login.
6. Run the exact-machine hardware checks and predeclared repetition counts. Keep failures attributable to a single change. Record baseline limitations separately from regressions.

These steps intentionally stop short of a generic install command: no accepted artifact set, trust identity, base snapshot or compatible target transaction exists yet. Once those inputs are established, replace this section with commands against the tested release and verify the complete guide independently.

## Configuration ownership

Templates are package-owned; user copies and source lines are user-owned. After installation, run setup as the intended non-root user, choosing only installed components:

```sh
cachy-asahi-setup activate --components fish zsh hyprland
cachy-asahi-setup activate --components fish zsh hyprland --apply
```

The first command previews. The second applies only explicitly selected configuration changes. Existing files and user edits are preserved; conflicts stop the affected operation. Validate the copied Hyprland configuration and the base session launch route separately before login. See [setup tooling](setup-tooling.md) for path restrictions, exit codes, recovery and the conditional launcher instructions.

A package upgrade replaces templates. Fresh shell sessions use the updated templates through their guarded blocks. Repeated explicit Hyprland activation updates its copy only if that copy still matches the recorded owned checksum; edited copies are preserved.

Before removal, return to the prior Hyprland configuration/session, then preview and apply configuration deactivation:

```sh
cachy-asahi-setup remove
cachy-asahi-setup remove --apply
```

This removes only recorded unchanged blocks/copies and retains edited files. Resolve reported conflicts before claiming deactivation is complete. For an interrupted operation, use `cachy-asahi-setup recover` followed by `--apply` under the original path options. Keep the setup package installed until deactivation/recovery is complete. Package-manager removal is a separate step and requires the reviewed target transaction. Removing a package does not stop running processes. Record the user configuration hashes before and after removal/reinstallation; preserve intentional edits.

Remove only overlay packages. Review dependency removals separately; the base's desktop/audio packages may serve other configurations and must not be removed implicitly. Perform fresh-user, existing-configuration, interruption, repeated activation, removal and reinstall checks and save their actual results before declaring M2 complete.

## Troubleshooting and recovery

If the candidate session fails, select the retained base session or a console and restore the prior user configuration. Inspect the session manager and package-manager logs; do not bypass speaker protection, force a bootloader replacement, or discard the working Asahi kernel. See `docs/release/recovery.md` for the recovery design and its unexecuted machine gates.

A retained package or filesystem snapshot is a recovery prerequisite. Acceptance requires actually restoring a usable boot/session after a controlled failure on the reference machine.
