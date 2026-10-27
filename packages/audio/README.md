# Audio construction candidates

These fixed recipes are build-only candidates, outside ordinary overlay discovery.
The fixed-three caller in `scripts/ci/asahi-audio-rust/` retains the normal generic
checks and permits only its reviewed speakersafetyd findings. It does not install,
activate or publish the outputs. See
[the actual native result](../../docs/validation/asahi-audio-rust-native-20261015.md).

Selected upstream sources are speakersafetyd2.0.1 at
`63a92658a4daec170c6472e38162374206e593fb`, bankstown1.1.0 at
`e9829c9bccf5ed73768135c0ddd506f5a6690f9e`, and triforce0.3.2 at
`c5e9cacb88e6d2bae476e5c2394ce022793c6d5c`. Original recipe reference is
asahi-alarm/PKGBUILDs `9717359f2feac55830f8d57e50e4746e98ba6e99`.
Exact source archives, the unchanged J504 label patch and checksum-verified
117-crate vendor source are retained alongside the recipes. Cargo locks remain
unchanged; builds use frozen/offline Cargo. The GPL-2.0-or-later Triforce field
corrects the older recipe's incorrect MIT declaration.

Six native builds and three byte pairs passed on a hosted4KiB ARM builder.
Structural16KiB ELF checks do not establish execution on a16KiB kernel.
Compiler source correspondence and complete transitive license/notice/source
closure remain unfinished. Those build trials did not run a daemon or load a
plugin. Current-version installation, service/udev behavior, speaker safety, both M2
Air sizes and coordinated platform updates remain untested. Release selection
remains false; preserve the working Asahi platform stack.

The notice-only candidates speakersafetyd 2.0.1-3, bankstown 1.1.0-4 and
triforce-lv2 0.3.2-3 add the same pinned notice input, copying only 3/3/4 regular
mode 0644 license files. Their upstream sources, Cargo locks, vendor closure,
J504 patch, exact 350-package toolchain and frozen/offline build flags remain
unchanged. [Native run38801968699](../../docs/validation/asahi-audio-rust-notices-native-20261015.md)
passes six builds and three byte-identical pairs, with all ten notices present
and unchanged compiled payload hashes. This result does not execute or install
the plugins/daemon. Run38789573004 and the historical audio593 transaction
remain evidence for2.0.1-2/1.1.0-3/0.3.2-2; the current-version transaction is
separate unfinished validation.

[Offline native run38810834920](../../docs/validation/asahi-rust-lv2-offline-native-20261015.md)
separately loads the current Bankstown and Triforce libraries and passes60 fixed
property cases in120 fresh instances, sixteen controls and scoped normal cleanup.
All36 repeat pairs report zero numerical error and equal sample hashes. The
retained metadata reconciles; samples/private binaries were not exported for
independent replay. Full DSP graphs, PipeWire policy, speakersafetyd, real-time
behavior, acoustics and physical16KiB/M2 execution remain unestablished.

Triforce's proposed package metadata summarizes the GNU GPLv3 combination and
its Apache/MIT/Zlib/Unicode component terms; its upstream GPL-2.0-or-later
source declarations and original license are unchanged. This is a distribution
proposal, not an exhaustive file-level legal verdict. The notice text records
configparser's MIT and wide's Zlib choices and colored's exact MPL source URL.
The later wmidi MIT text association, macro workspace manifest difference,
compiler recipe correspondence and complete release-source delivery remain
open review limits; release selection remains false.
