# Fixed16 release-input migration classification

This metadata-only classification starts from sealed actual04 receipt `dee8591c…` and its unchanged full report `94585c39…`. It joins the exact new-pair report `631a0ed1…`, actual receipt `a3189f4a…` and independent peer `eefdfef6…`. All 27 actual04 leaves, three new-pair actual leaves, the new-pair peer index and its guide reauthenticate. No archive, ELF, codec, signature, native build or installed transaction ran here.

The original comparison retains all 26 old-snapshot direct JBIG/TIFF edges: 21 declarations present against the new providers and five unresolved old SONAMEs. Every edge in [classification.json](../../artifacts/reviews/maintained-reverse-consumer-migration-impact-20261014/classification.json) includes its consumer package, old version, member, unchanged raw edge and migration class.

| Historical consumer package/member | Old required SONAME | Migration class |
| --- | --- | --- |
| jbigkit 2.1-8: `usr/bin/jbgtopbm` | `libjbig.so.2.1` | old replaced package |
| jbigkit 2.1-8: `usr/bin/pbmtojbg` | `libjbig.so.2.1` | old replaced package |
| jbigkit 2.1-8: `usr/bin/jbgtopbm85` | `libjbig85.so.2.1` | old replaced package |
| jbigkit 2.1-8: `usr/bin/pbmtojbg85` | `libjbig85.so.2.1` | old replaced package |
| libtiff 4.7.2-1: `usr/lib/libtiff.so.6.3.0` | `libjbig.so.2.1` | old replaced package |

Under the proposed replacement of **both** old packages, these are historical edges from files whose packages are replaced. They do not prove that the new installation is broken. Actual package file replacement, stale files, conflicts, removal/reinstall and loader behavior are untested. No compatibility alias from 2.1 to 2.2 was created or assumed.

The other 14 snapshots are the unchanged consumers for this comparison: gdk-pixbuf2, glycin, gtk-update-icon-cache, gtk3, hyprcursor, hyprgraphics, hyprland, hyprland-guiutils, hyprtoolkit, lcms2, libcolord, librsvg, swaylock and wofi. They contain **zero unresolved direct pair edges**. lcms2's `usr/bin/tificc` is the sole direct pair consumer among them: `libtiff.so.6` and required `LIBTIFF_4.0` are declared by both provider versions. The remaining 13 have no direct pair declaration, which leaves indirect and outside-provider dependencies open.

The exact new-pair library declarations record:

| Replacement library consumer | Needed SONAME | Replacement provider | Declaration result |
| --- | --- | --- | --- |
| libtiff 4.7.2-2: `usr/lib/libtiff.so.6.3.0` | `libjbig.so.2.2` | jbigkit 2.2-1: `usr/lib/libjbig.so.2.2` | declared SONAME present; no named version requirement |
| libtiff 4.7.2-2: `usr/lib/libtiffxx.so.6.3.0` | `libtiff.so.6` | libtiff 4.7.2-2: `usr/lib/libtiff.so.6.3.0` | declared SONAME and `LIBTIFF_4.0` present |

New jbigkit also declares `libjbig85.so.2.2`. Version matching uses only each definition's primary name, preserving parent aliases separately. The selected new report covers four libraries; new jbigkit executables were not selected and receive no dependency verdict here. These are facts about those exact ALARM inputs. Future private project builds require their own exact artifact/declaration checks.

The release-input conclusion is limited to this fixed scope: unchanged consumers show no unresolved direct JBIG/TIFF declaration against the selected new pair, while all five old unresolved edges remain explicitly labeled as replaced-package history. The 547 outside-provider declarations from actual04, indirect resolution, symbols, runtime, 16K/M2 ABI and complete release/port acceptance remain OPEN.
