# #622 native build acquisition hold

The reviewed candidate is `a7c2a30fb37934cad320d982b7d2ab2413dab2a7`.
Hosted run [45688818426](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45688818426)
passed the native runner probe. The retained Minimal206 r12 ref still resolves
to `1604862d09fb04e471da03df2e2a98a5c05a77bf`, the producer used in
[44263404780](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44263404780).
That run retired its derived and imported images and has zero Actions
artifacts. The repository's current Actions cache listing contains no
Minimal206 inputs.

On November 25, 2026, the primary routes returned HTTP 404 to HEAD for 14
of the 206 locked package bodies. This included all four packages eligible
for the original producer's archive fallback. The rootfs, its signature,
the three keyring inputs, and 192 package bodies returned HTTP 200 to HEAD.
These response codes establish transport availability at probe time.

A decisive public acquisition failure was
`linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz`, 69,887,600 bytes with SHA-256
`ba67012ac8ae1312e32c9e5bbee49428e3c8e9405d3d85312732847a9820964c`.
Full GETs returned HTTP 404 from the California and Florida ALARM mirrors,
the original per-package archive fallback, and the archive's November 15
and 23 snapshots. The original Minimal206 cache was recovered separately. All 417 objects
matched their exact lengths and SHA-256 pins, including the kernel archive.
All 207 detached signature checks passed against the locked ALARM signer.
The runner still needs an authenticated route to the retained objects.

The candidate's `scripts/build/project-libraries/prepare.py` accepted all
four pinned upstream files and produced byte-identical recipe trees in two
fresh scratch directories. Its `baseline.py` verified all three official
codec archive/signature pairs and derived the declared 210-package lock.
The candidate's seven controls and the four acquisition controls pass.

Recheck the missing input from a checkout with the r12 Git object available.

```sh
python3 -I -B scripts/ci/project-libraries-native/preflight.py
python3 -I -B -Werror::ResourceWarning -m unittest discover -s scripts/ci/project-libraries-native -v
```

The recheck uses bounded HTTPS GETs, validates the pinned lock and detached
signature, and deletes its own scratch directory. It exits 1 on HOLD.
`KERNEL_PIN_RECOVERED` requires the exact archive and a matching ALARM
signature. Full 417-input acquisition and authentication must still pass
before a future native build. A successor baseline requires review of its
own signed inputs and exact package inventory.

Hosted dispatch needs a runner-readable source for the recovered inputs or a
reviewed successor baseline. Both native pairs and signed lifecycle checks
remain pending.
Future public CI evidence must be limited to approved metadata and must
exclude package bodies, materialized recipes, and held source.
