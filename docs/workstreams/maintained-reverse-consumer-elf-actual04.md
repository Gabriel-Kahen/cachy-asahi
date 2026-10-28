# Corrected fixed16 passive inspection: actual04

The one authorized fresh attempt completed all 16 authenticated old package archives: 2,459 tar members, 87 regular ELF members and 167,475,200 expanded bytes. The saved [report](../../artifacts/reviews/maintained-reverse-consumer-elf-actual04-20261014/report.json) is 513,358 bytes, SHA256 `94585c39c58aed5f3b9afdc678f65810864a727a017aa8add3ca3223f6b7a67f`. Each codec reached EOF and each archive passed the unchanged compressed/expanded/member/metadata/report limits. No package was skipped.

Selected correction receipt `6da48112…` binds checker `a597a8c5…`, ELF `293dfa06…` and delta `af4a43c5…`. Its author suite passed 98 methods/159 subtests, and independent peer `c4510f7a…` passed 14 methods/54 subtests. Preparation reauthenticated all 62 correction leaves, 15 peer leaves, 50 selected crypto leaves, 49 custody leaves and 32 current raw archive/signature objects. Descriptor `0885ae24…`, new provider report `631a0ed1…`, interpreter/codec hashes, wrapper `fc68811d…` and caps remain unchanged. The initial preparation stopped on an absent optional peer-index mode field before snapshot/admission; the preserved preparation history records the fixture correction and zero decoding attempts at that point.

The ordinary 120-second CLI returned 0 naturally. The wrapper observed 2.092702655 seconds total and 1.972277934 seconds parsing. Report and result publication completed before the original deadline. All 32 held descriptors closed positively, with no cleanup errors or late returns. The dispatch-to-final-poll observation includes transport and the delay between tool calls; no separate parent wall timer was installed. These observations do not establish a hard-wall or universal confinement proof. No archive extraction, foreign ELF execution, installation, explicit dlopen/ldd, network operation or new cryptographic replay occurred.

Hyprland's `usr/bin/hyprland` retains raw linkname `/usr/bin/Hyprland` and the explicit installed-root normalized target `usr/bin/Hyprland`. The target is a parsed regular ELF member in that same archive. There were no hardlink headers in the 16 archives; hardlink binary association remains supported by synthetic controls only.

## Direct JBIG/TIFF declaration comparison

The fixed **old** archive set is compared against old providers parsed from jbigkit 2.1-8/libtiff 4.7.2-1, then against the pinned new jbigkit 2.2-1/libtiff 4.7.2-2 provider report. All 26 direct pair edges declare an old SONAME and required versions present. Against the new pair, 21 have their declared SONAME/versions present and five have an unresolved old JBIG SONAME. No direct edge reports missing strong or weak version declarations; that observation does not prove symbol binding.

| Old package/member | Required SONAME | New-pair declaration result |
| --- | --- | --- |
| jbigkit: `usr/bin/jbgtopbm` | `libjbig.so.2.1` | SONAME unresolved |
| jbigkit: `usr/bin/pbmtojbg` | `libjbig.so.2.1` | SONAME unresolved |
| jbigkit: `usr/bin/jbgtopbm85` | `libjbig85.so.2.1` | SONAME unresolved |
| jbigkit: `usr/bin/pbmtojbg85` | `libjbig85.so.2.1` | SONAME unresolved |
| libtiff: `usr/lib/libtiff.so.6.3.0` | `libjbig.so.2.1` | SONAME unresolved |

These five edges belong to the two old packages being replaced. They are preserved as findings of this old-snapshot comparison; they do not establish five failures after installing a replacement transaction. The other 14 package snapshots have no unresolved direct pair edge: lcms2's `tificc` has one `libtiff.so.6` edge with `LIBTIFF_4.0` present in both old/new providers; the remaining 13 snapshots have no direct pair declaration. This says nothing about indirect dependencies or dependencies outside the pair. The pinned new provider report separately records new libtiff requiring `libjbig.so.2.2` and new jbigkit exporting that SONAME.

The report retains 547 outside-provider declarations as OPEN. [Consumer outcomes](../../artifacts/reviews/maintained-reverse-consumer-elf-actual04-20261014/consumer-outcomes.json) retain all 26 direct edges, the five unresolved members, per-package counts, and exact old/new provider references. [Runtime observations](../../artifacts/reviews/maintained-reverse-consumer-elf-actual04-20261014/result.json) retain codec/reader counters and cleanup/publication times.

## Evidence boundary

Original actual01 `ELF_DYNAMIC_TRAILING`, actual02 `METADATA_AMBIGUOUS` and actual03 `TAR_LINK` failures remain immutable, along with their source and correction seals. This complete passive report advances R1/A05/A12 dependency evidence. Source/license correspondence, outside-provider resolution, symbol binding, loader/runtime behavior, 16K/M2 ABI, native build/install/release and full R1–R5/M5–M9/A01–A15 acceptance remain OPEN. Shared manifests, workflows, Git state and other worker files were not edited by this task.
