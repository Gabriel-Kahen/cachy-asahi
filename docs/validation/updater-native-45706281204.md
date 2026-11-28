# Updater installed Check retry stopped during preparation

[Run 45706281204](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45706281204)
ran with retained inputs and installed Check enabled at
`ea225d8e9b0aee46ae2b93aca022b5a94b6d0956`. The bounded public evidence
confirmed source freeze, retained SSH intake, 527-object acquisition, the
354-package builder inventory, and two clean AArch64 builds. Their bytes,
installed contents and package metadata agreed, with package SHA-256
`44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`.
This is the same archive digest reported by the preceding build-only trial.

The native stage stopped at `installed-prepare` with child exit 1 after
runtime intake. The installed container never launched. GitHub and the stage
reported failure. Retained-input retirement, scoped process/container/signing
cleanup, private-data removal, independent recovery and public evidence export
passed. All three framed archives and their export-manifest entries matched
the published hashes and byte counts.

The retired preparation output leaves the exact hosted cause unverified. The
pinned root filesystem config specifies `.pkg.tar.xz`. A local stage-path
replay with real pair comparison and archive inspection accepted a synthetic
xz pair and the exact retained runtime inputs. The old capsule selector
rejected a synthetic zstd pair after the native comparator accepted it. The
updated capsule selector accepts both checked formats without recompressing
the package. Regression tests reach the real comparison, metadata, and
capsule-writing paths with both synthetic archive formats. The retry also
publishes a finite preparation subphase and problem category if the child
fails again.

The coordinator can retry against the corrected reviewed source using the
same retained-input and installed Check options. Native installed Check,
a full update, 16 KiB execution, M2 hardware and production release acceptance
remain unqualified.
