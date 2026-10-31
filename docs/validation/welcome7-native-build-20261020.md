# Welcome7 native build pair, 2026-10-20

Run [39348847325](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39348847325) built Welcome `0.1.0-7` twice from source `4b2074d4376b572c2aaf958dc3dae7b0971a23c4` on the native ARM runner. The finite result is recorded in [the build manifest](../../manifests/welcome7-native-build-result.json).

Both unsigned archives are 39,904 bytes, SHA256 `3dec4a467a712908e5f06a481ca7b3206a232c4cf2fc3cc1d933bf3389e2ee35`. Full archive bytes, installed contents, PKGINFO and BUILDINFO compare equal. The two clean containers ran on one host; independent machines are not established.

Each build ran the original 41 C cases (40 passed; the ordinary build UID cannot exercise the UID0 guard), five CLI tests and 25 pinned source checks. The UID0 guard remains `NOT_EXERCISED_ORDINARY_UID_REQUIRES_UID0`. The package has a native AArch64 ELF, the required interpreter, two 16KiB-aligned load segments and exactly the qualified GTK/Pango/GIO/GObject/GLib/libc/loader dependencies plus the explicitly declared ATK dependency already present in the frozen 574-package builder. Alignment does not establish execution with 16K pages.

Root independently joined all 107 Git source blobs, original run/jobs/artifact metadata, the backend ZIP digest and all 32 original members (31 retained files plus retention index). The unchanged strict reader re-inspected source, package metadata and payload, full build provenance, ELF and test logs, pair equality and source-owned container/builder retirement. Retirement records are not a new live observation. Original acquisition occurred once; passive replays used fresh outputs.

This validates the build pair only. Welcome7 remains unselected. Installed lifecycle, native GUI accessibility, real Boot history, crash diagnosis, recovery, actual 16K execution, Asahi integration, both M2 Air sizes, performance and release trust remain unqualified. Its host GTK accessibility results do not substitute for the pending installed GUI trials. Existing package inventory and release selection are unchanged.
