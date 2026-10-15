# Audio construction candidates

These fixed recipes are build-only candidates, outside ordinary overlay discovery.
The fixed-three caller in `scripts/ci/asahi-audio-rust/` retains the normal generic
checks and permits only its reviewed speakersafetyd findings. It does not install,
activate or publish the outputs. See
[the actual native result](../../docs/validation/asahi-audio-rust-native-20261015.md).

Selected upstream sources are speakersafetyd2.0.1 at
`63a92658a4daec170f6472e38162374206e593fb`, bankstown1.1.0 at
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
closure remain unfinished. No daemon or plugin was run or loaded. Runtime
installation/dependency closure, service/udev behavior, speaker safety, both M2
Air sizes and coordinated platform updates remain untested. Release selection
remains false; preserve the working Asahi platform stack.
