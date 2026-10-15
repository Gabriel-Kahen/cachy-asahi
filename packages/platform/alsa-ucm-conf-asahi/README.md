# alsa-ucm-conf-asahi 10 development data package

This preserves the selected macaudio and aop_audio ALSA UCM profiles. Runtime
dependency remains alsa-ucm-conf>=1.2.7.2. Source files are installed as mode0644
data under /usr/share/alsa/ucm2/conf.d. No ALSA parser/device is invoked by the
recipe. There are no systemd units, udev rules, ALPM hooks, executable files or
/etc files in this selected payload.

This recipe uses the retained versioned archive and exact source commit recorded
in source-provenance.json; it does not download a mutable main branch. Local
source hashes are fixed. Upstream LICENSE.asahi and the independent packaging
MIT grant/notice are installed under /usr/share/licenses/alsa-ucm-conf-asahi.

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
