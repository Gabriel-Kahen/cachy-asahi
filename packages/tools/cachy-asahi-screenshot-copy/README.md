# Screenshot to file and clipboard

This opt-in development command adds clipboard sharing to the existing M6
Hyprland screenshot-to-file workflow. Invoke it explicitly in your Wayland session:

```sh
cachy-asahi-screenshot-copy full
cachy-asahi-screenshot-copy region
cachy-asahi-screenshot-copy region --directory "$HOME/Private Screenshots"
```

It calls the installed `cachy-asahi-screenshot` helper with the selected mode and
optional directory. That helper retains its private Pictures/Screenshots default,
region cancellation, bounded selection/capture and file publication behavior.
The wrapper then offers the saved PNG through `wl-copy --type image/png`.
The PNG path goes to stdout; status and errors go to stderr. Missing tools are
detected before capture. Capture failure or cancellation never requests a
clipboard copy or falls back to a full-screen capture.

The saved PNG is always retained. Exit0 means capture succeeded and wl-copy
reported success, not that a receiving application pasted the image. Exit1 means
failure; exit130 means interruption. A clipboard failure/10-second timeout can
leave the clipboard outcome unknown; no restoration of the previous selection
is attempted. The saved file remains available for manual sharing. The wrapper
accepts only the returned ordinary0600 current-user file, without hardlinks,
at most64MiB, with PNG header/IHDR/end markers and unchanged observed metadata.
This is structural checking of trusted capture output, not a full image decoder
or protection from hostile concurrent writers sharing your UID.

As documented by [wl-clipboard2.2.1](https://github.com/bugaevc/wl-clipboard/blob/v2.2.1/data/wl-clipboard.1),
wl-copy normally forks a clipboard provider to keep data available after its
parent exits. That intentional provider and an existing clipboard manager may
retain image data. It uses the compositor's default seat; multi-seat selection
is outside this first workflow. There is no upload, clipboard history manager,
clipboard clearing, background capture, service or automatic key binding.

Installing this package activates nothing. After verifying your installed tools,
you may replace a screenshot command in your own opt-in binding with this command.
Review your custom bindings first. Before removing the package, revert any user
binding that references it. Removal owns only this command, documentation and
licenses; it never deletes screenshots or rewrites user configuration and does
not clear an existing clipboard/provider. The existing screenshot/settings
package and Asahi graphics/audio/boot stack are unchanged.

Python>=3.11, the existing cachy-asahi-hyprland-settings screenshot helper, grim
and wl-clipboard>=2.2.1 are required. Region capture additionally needs slurp.
These are dependency declarations, not verified ARM closure. Tests use private
executable recorders and PNG fixtures, including a real bounded timeout; they
never capture a screen or access the live clipboard. Native ARM builds, ALPM
lifecycle, real compositor capture/paste, both M2 Air models and release admission
remain NOT RUN. No performance claim is made.

```sh
python3 -I -B -Werror::ResourceWarning test_screenshot_copy.py -v
python3 -I -B -Werror::ResourceWarning test_package.py -v
```
