# Welcome management native candidate lane

Private source proposal for Welcome 0.1.0-2, existing Doctor 0.1.0-1 and accepted
Orphans 0.1.0-1. This lane is manual, unselected, and fail-closed until Root binds
the final product inputs. Those private policy bindings are now complete; the
canonical manifest freeze and workflow digest markers remain Root-only. No native build, package installation, VM, managed GUI,
physical input, M2 hardware test, performance comparison or release admission has
been performed by preparing this proposal.

The policy binds the 24 final Welcome source files and nine payload paths from
Root's adopted source `96aa3e7a81840b7eba6ba07188481fd89631fb6b`, including recipe
SHA256 `071cada88855ac7e462df8cde264d4ae60263655da4706d9c2c9dc5af7b33f6b`.
Its exact UI strings and 1 MiB product output limit are bound as well. All three
products bind final source/payload/check/dependency inputs at that product source:
Welcome 24/9 files, Doctor 7/4, and Orphans 8/5. Doctor's accepted archive is
`cachy-asahi-doctor-0.1.0-1-any.pkg.tar.xz`, 13708 bytes, SHA256
`06898669fdd6c9e5bdcc9909e6b0e75e958bdbd57520a7082c0e9f5f7fac7482`, from
actual38886781500/source `09717a45388e5b90ca80fd3fef327444101c108f`.
Local retained source/provenance/archive/payload/log joins pass for both original
Doctor and Orphans builds; these are existing evidence, not new builds.
`source-manifest.json` and workflow digest markers remain unbound and block the
workflow proof before secrets. Negative controls retain the policy's independent
refusal of an explicitly unbound input before any native observer or output.

## Proposed execution

The workflow reuses the retained original 574-package producer and its six
retained secret inputs plus fourteen pinned public ARM inputs. It changes no
selected input or historical Welcome/16K lane. The consumer builds fresh native
pairs for all three products through the accepted Welcome builder with standard
makepkg checks, dependency validation, source/archive/payload joins and complete
archive reproducibility. Both fresh Doctor archives must match Root's existing
accepted archive exactly. There is no dependency fetch or failed-package skip.

Welcome's ordinary-user check receipt distinguishes 32 passes and the one exact
root-guard TAP skip from 33 executed checks. A separate source-bound control in
the existing guarded root lifecycle actor compiles the process test and runs
only `/management/root-guard` as actual UID 0. Its original TAP, commands, source
pins and receipt must pass separately. Other skips and TODO cases fail.

The signed lifecycle is 574 → 577 → repeated 577 → 574 → 577 → 574. It preserves
all original 574 package-owned payload and database nodes, two ordinary users'
existing files, and generated private reports. It exercises the actual installed
Welcome status, Doctor publication/no-overwrite, and accepted Orphans assessment,
plan and verification controls. Orphan removal remains unimplemented. TEST
signing occurs outside untrusted actors; only public verification material and
detached signatures enter them. Eight explicitly labelled consumer containers
must be proven absent before the original producer is retired.

## Managed generic 4K GUI

`prepare.py` derives a separate runner from the accepted managed GUI transport
through explicit unique source anchors. It keeps the original real user manager,
UID 23001, private Wayland session, generic 4K kernel, original seven views per
profile, 5-second capture settling, 8-second post-capture hold, service startup
checks, log limits, cleanup requirements and original first-frame capture route.
The GUI profile contains exactly 594 installed packages, including the three
products. Optional tool absence is actual signed-package removal to 592 and
restoration to 594 by a bounded root fixture; no GUI text or report is injected.
The ordinary GUI caller cannot write the actual package database or create its
lock.

Each minimal and overlay profile adds five original first frames:

- Both optional tools absent, with their actual buttons disabled.
- Actual fixed `/usr/bin/cachy-asahi-doctor --json` through Welcome.
- Actual fixed `/usr/bin/cachy-asahi-orphans assess` against default installed metadata.
- Real owned ALPM counterpart lock and the tool's resulting failure presentation.
- An actual Orphans child held through its owned pidfd while Welcome closes;
  the product must retire the helper, supervisor and process group itself.

The root fixture only removes/restores the fixed optional packages, owns its
actual ALPM lock handle, and observes stable process identities. Failure cleanup
cannot earn acceptance. Seventeen real AT-SPI operations per profile, sensitivity
states, default helper arguments, unprivileged UID, supervision chain, report
text, target package facts, metadata preservation and retirement are replayed.
Doctor's actual GTK raw report is retained and parsed independently of the
separate CLI report, because collection timestamps and live observations differ.
Orphans' actual GUI preview is joined to the independent full default assessment
on unchanged metadata. The unchanged original Terminal, Files, guide and system
status exercises remain mandatory.

All 24 original PPM first frames, actual accessibility snapshots and body hashes,
raw reports, events, source and generated runner, build logs, source timings and
cleanup evidence are retained for Root's visual review. No recapture or log/startup
waiver exists. Metadata success leaves pixels pending review. The GUI checks
nonselected database preservation and user configuration; full original 574
payload preservation is checked by the separate signed native lifecycle.

## Root adoption and verification

Adopt the proposed new lane and workflow with the completed exact product/archive
bindings. `candidate_source` identifies the audited product source
commit; the workflow separately proves its own exact execution revision. Run
`freeze.py --source <canonical-root>` only from the adopted canonical lane. It
checks all offline dependencies, freezes the closed source manifest, and fills the
two workflow digest markers. Review the resulting manifest and then dispatch the
manual workflow against its exact published SHA. This proposal does not dispatch.

Hosted controls:

```sh
WELCOME_MANAGEMENT_SOURCE="$PWD" python -B -m unittest discover -s scripts/ci/welcome-management-native -p test_native.py -v
WELCOME_MANAGEMENT_SOURCE="$PWD" python -B -m unittest discover -s scripts/ci/welcome-management-native -p test_gui.py -v
```

These controls use inert fixtures and generated source. A successful host C
compile of `a11y_driver.c` checks local API compatibility only. Native pairs,
installed lifecycle, managed GUI execution, original pixels and M2 hardware
remain separate required evidence. A 16K successor is a separate future lane;
this proposal preserves the running historical Welcome 1/16K work.
