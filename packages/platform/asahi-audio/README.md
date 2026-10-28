# asahi-audio 4.1 development data package

This preserves the selected Asahi audio FIR/profile data, PipeWire configuration
snippets and WirePlumber configuration/Lua script. Runtime dependencies remain
wireplumber>=0.5.2, pipewire>=1.0, bankstown>=1.1.0,
lsp-plugins-lv2>=1.2.15, speakersafetyd and triforce-lv2>=0.2.0. Source aliases are
assembled using GNU make, sed and coreutils; no audio daemon/plugin is executed.
The retained v4.1 README requires these WirePlumber/Triforce minima; the older
community recipe had weaker requirements. Its kernel prerequisite is linux-asahi
6.12.12-1 or later (7.1.6-1 for M3). Kernel package selection remains with the
coordinated target-platform policy rather than an automatic package replacement.
The preserved LSP>=1.2.15 floor is stricter than the source README's >=1.0.20.
There are no systemd units, udev rules, ALPM hooks, executable files or /etc files
in this selected package payload. Its Lua script is installed as mode0644 data;
a later WirePlumber session can load it. These are platform defaults rather than
per-user opt-in templates.

This recipe uses the retained versioned archive and exact source commit recorded
in source-provenance.json; it does not download a mutable main branch. Local
source hashes are fixed. Upstream LICENSE.asahi and the independent packaging
MIT grant/notice are installed under /usr/share/licenses/asahi-audio.

A bounded native builder constructs this data-only candidate with makepkg
--nodeps because several runtime dependencies are deliberately absent from the
unchanged signed341 compiler image. Runtime metadata is retained. This is a
build-only exception, not a dependency-resolution, installation, audio-safety or
hardware result. Native package pairs remain NOT RUN at recipe preparation.
Selected_for_release is false. No package install/remove, service start/enable,
audio playback or host trust/Asahi stack mutation is performed by the build.

Installing these platform paths can change ALSA/PipeWire/WirePlumber behavior.
Future installation/removal/upgrade requires a reviewed compatible Asahi kernel,
firmware, safety daemon/plugins, ownership/conflict checks and recovery/deployment
order. The recipe has no automatic post-install actions; its data would be
package-owned. No generic ARM build, existing profile name or source byte match
certifies speakers, microphones, suspend/reboot, physical16K pages, either M2 Air,
performance, or a safe independently installable replacement stack.
