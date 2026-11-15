# Perl native ARM4K installed lifecycle

Root accepted the bounded installed lifecycle for the native-built
`perl 5.42.3-1.3` candidate on 2026-11-15. This is a disposable native aarch64
container result with 4096-byte pages, not target selection or M2 qualification.

The successful [run43734696338](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/43734696338)
used Source `445b37a9475a4e92804954f4f0e3d0ac84cd9511`, job132874611601 and
Original artifact14170381597 (5,305,784 bytes,
SHA256 `067d92660e6acbb7193b6353167ae79ed06b9666a3829f4233321c11c438225f`).
Its complete faithful decode contained696 files/35,520,378 bytes.

Normal TEST-signed local upgrade from the official `5.42.3-1` package,
same-candidate reinstall, no-op upgrade, and signed original-package rollback
passed. Installed probes exercised arithmetic, base64, threads, and recorded
the actual interpreter, module and shared-libperl paths. Dependency-protected
removal correctly refused without mutation; a full uninstall was not tested.
Rollback restored the normalized package payload and local database, preserved
the user fixture, and left no account residuals. Normal transaction differences
remain explicit: four database timestamp nodes,330 payload-directory timestamp
nodes, changed install dates and an append-only pacman log. The fixture and
owned container were removed after natural retirement.

The initial passive validator stopped at an undeclared `math` import. A separate
successor preloaded that exact trusted stdlib module while retaining the original
read/write/process fence. Its one Root-issued call passed complete Original ZIP,
Source252/inverse, retained-result/export, producer and lifecycle consistency
checks. Canonical same-FD/PIDFD custody, independent nonblocking conflicts and
close-only release passed. The closed first validator attempt was not replayed.

Root decision: `Root-native-installed-component-decision.ACTUAL-r1.json`,6168 bytes,
SHA256 `084794319bf849ed1cc2a2387f502acf8cc82dec3fad11b00e3dc8cfc4096535`,
retained under `artifacts/development/orchestrator-resume-20261114/Root-perl-installed-intake-r2/`.
The result extends the [native build pair](perl5423-native-arm4k-pair-20261115.md)
only within this installed lifecycle. External XS, emulated/native16K, M2,
performance and release acceptance remain open.
