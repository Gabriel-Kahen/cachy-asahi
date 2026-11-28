# Updater 4.4.2-3 native pair and workflow exit correction

[Run 45699777848](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45699777848)
ran build-only at `dbeb777d0176f464858e8f7b6e74d7f188ea4b32` with retained
inputs enabled. Source freeze, read-only SSH intake, acquisition of all 527
pinned objects, and both native compilations passed. The bootstrap and both
builds joined the exact 354-package inventory
`5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee`.
The transport receipt precedes the signature gate. The published artifacts
report success after the native worker's separate signature-audit and bootstrap
path.

Both private `cachy-asahi-update 4.4.2-3` aarch64 archives had SHA-256
`44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`.
The package bytes, installed tree and package metadata matched. Both worker
return codes were zero and both containers were removed with verified absence.
Scoped stage cleanup, handoff retirement, and independent recovery passed.
The guarded data and both terminal frames were decoded and checked against
their published byte counts and SHA-256 values.

The GitHub job concluded failure despite those PASS receipts. The CLI ran
`sys.exit(0)` inside its broad exception handler in both `run` and `cleanup`.
That handler caught the resulting `SystemExit`, printed a second failure
receipt, and exited 1. A local reproduction with inert PASS results confirmed
the duplicate output and exit 1 for each command. The corrected CLI returns
from its guarded operation and exits outside the handler. The workflow compares
the same stage and recovery receipts and can now observe the correct exit codes.

Installed Check remained disabled in this build-only run. Separately opting in
requires the corrected review tip and a fresh native pair in the same job.
Full updates, emulated or native 16 KiB execution, M2 hardware, production
trust, and release acceptance remain open.
