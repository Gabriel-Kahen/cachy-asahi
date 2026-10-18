# cachy-asahi-ksmctl

Development candidate: read-only KSM status/reporting adapted from CachyOS's
explicitly GPL-2.0-or-later `ksmctl`. This implements the diagnostic portion of
the M6 tools matrix. Enable, disable, pause, policy management and measured
platform integration remain unfinished work. No memory, responsiveness, battery
or performance improvement is claimed.

In the source tree, `management-policy.md` records the separate source audit and
fixture-only JSON policy validator. `native-stage.md` proposes two native builds against the
coordinator's accepted refreshed 341-package receipt. The policy validator is
not installed and cannot activate KSM. Native builds, installation/removal and
Apple management validation remain unperformed by this worker.

```sh
cachy-asahi-ksmctl --status
cachy-asahi-ksmctl --report
cachy-asahi-ksmctl --report --json
```

No arguments mean status. `--help` and `--version` do not read kernel state.
Exit 0 means the requested observation was read and validated; it does not mean
KSM is active, useful, or hardware-qualified. Exit 3 means the required KSM
directory/run interface is unavailable. Exit 1 means read/type/format/state/page
geometry validation failed. Argparse returns 2 for unsupported arguments,
including all write/management actions.

| `run` value | Reported observation |
| --- | --- |
| 0 | Scanning stopped; already merged pages may remain. |
| 1 | Scanning enabled; activity and savings are not verified. |
| 2 | Unmerge requested; completion is not verified. |

Optional counter files absent from the current kernel appear as `unavailable`
or JSON null, never fabricated zero. Present but unreadable/malformed files fail
the report. Values must be complete decimal lines with LF, within unsigned
64-bit counter bounds (signed 64-bit for `general_profit`). Symlinks, FIFOs and
other special interface files are refused.

Page-valued counters are converted to MiB with the running process's actual
`os.sysconf('SC_PAGE_SIZE')`, using exact decimal arithmetic. `full_scans` is a
scan count and has no MiB conversion. `general_profit` is a signed byte-valued
kernel estimate, so it is divided by 1,048,576 without multiplying by page size.
Counters are independently sampled, not an atomic snapshot. Cumulative scanned
page volume is not resident memory or measured savings. No 4 KiB/512-PTE geometry
is assumed and the CLI offers no page-size override.

The runtime reads only `/sys/kernel/mm/ksm/`. Python API functions accept a
fixture directory/page size for tests; those are not privileged operations or
CLI configuration options. It opens inputs read-only and creates no user file,
service, configuration, hook, timer or kernel state. Installation owns only the
CLI, documentation, notices/provenance and license under `/usr`; removal deletes
those package-owned files and changes no KSM policy or user configuration.

The upstream source is pinned to CachyOS-PKGBUILDS
`c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`,
`cachyos-ksm-settings/ksmctl`, SHA256
`cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9`.
`upstream-ksmctl` retains the exact original bytes; `adaptation.patch` records
the complete derivative, including removal of every mutation branch. The
original Stelmachenok/CachyOS copyright and GPL notice remain in the CLI and
NOTICE. This is independent work, not an official CachyOS edition.

`source-provenance.json` pins upstream, derived source, full GPL license and
patch bytes. `check-source.py` compares them without executing either CLI or
PKGBUILD. The original shell file is retained for attribution/review and is
never installed or executed. No original four-package input lock is changed.

Build/check commands are defined in PKGBUILD for isolated packaging only:
Python AST parsing, read-only provenance verification and temporary-fixture
tests; package() stages explicitly listed `/usr` files. Do not source PKGBUILD
or invoke a host installer for this candidate. Runtime dependency is Python
3.11+; it calls no external Bash/coreutils program. `arch=any` describes this
script's packaging and is not ARM/M2 execution evidence.

Required management/policy expansion is owned by the platform/performance track:
capture actual CONFIG_KSM/controls and baseline values; assess application
merge eligibility and privilege/security exposure; specify bounded enable/pause/
unmerge semantics; record and restore prior policy/service/config state; test
interruption, concurrent changes, low-memory unmerge/OOM and recovery. Restoring
a control value cannot reconstruct pages already unmerged or recover killed
applications. Measure responsiveness, memory, CPU, energy and thermals against
the documented baseline before enabling or retaining any default. Both exact
Air sizes require their own observations and recovery evidence.
