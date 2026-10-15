# Installed repository enrollment lifecycle on native ARM, 2026-10-15

[Run 38785474034](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38785474034)
succeeded at Source `b8a68a511f61dad7312a2e7847cdeb49970514d1`. Its retained
records establish the finite **actual setup3 install → setup4 upgrade → installed
preview/enroll → remove/reinstall → explicit disable → final removal** sequence
inside one offline generic ARM container. The final inventory returns to the
exact original **341 packages**. Asahi target installation and both physical M2
Air sizes remain **NOT RUN**.

This follow-on consumes the original native package archives rather than rebuilding
them or deriving a synthetic upgrade:

| Version | Original native Source | Archive bytes | SHA-256 |
| --- | --- | ---: | --- |
| `0.1.0-3` | `465bf53545e1d83053bf3c412e210493961b74ae` | 14496 | `85ab7b964cd628ef21f5df6133aa9d046d32ea35cd6af3de0e5b888341550f0c` |
| `0.1.0-4` | `98fecf28a3cde63a9dd7531501c2187825349310` | 22632 | `c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a` |

Retained summary pins match these exact files in the tested Git Source. Setup4's
separate [native build-pair review](repository-enrollment-native-20261015.md)
documents its byte-identical pair and unchanged packaged helpers.

## Actual installed sequence

The lifecycle result has **46 PASS observations across 22 distinct labels**; the
driver log matches every label in the same order. Repeated labels are preservation
checks at successive stages, not 46 independent tests.

| Stage | Retained result and selected source assertions |
| --- | --- |
| Install setup3 | Exact base plus `cachy-asahi-setup 0.1.0-3`; four installed files have expected bytes, root ownership/modes and package owner. The repository command is absent. |
| Upgrade to setup4 | Ordinary local `pacman -U` selects `0.1.0-4`; six installed files, version/inventory, `-Qkk`, `-Dk` and file owners pass. Per-user setup executable remains unchanged. |
| Before manual enrollment | Both installs leave the original main config unchanged and no managed include. The installed command's default preview also leaves selection/base trust/user fixtures unchanged. |
| Explicit installed enroll | `/usr/bin/cachy-asahi-repository --apply enroll` succeeds with a public-only TEST export and its selected full primary fingerprint. The resulting primary is fully valid. |
| Signature policy | Actual `pacman-conf` output satisfies `PackageRequired`, `DatabaseRequired`, `PackageTrustedOnly`, `DatabaseTrustedOnly` and the selected inert URL; no Optional policy appears. |
| Remove setup4 | Ordinary dependency-aware `pacman -R` restores the base inventory and removes all six package files. Manually enrolled main/include/public-export state and TEST public trust remain. |
| Reinstall setup4 | The same original archive restores the six correct package files. Manually selected config/public trust and unrelated user/base state remain. |
| Explicit installed disable | Removes only the managed include/selection and restores the original main config bytes. Imported TEST public trust/local certification remains. |
| Final removal | Package files disappear, exact341 inventory returns, user/base trust and disabled config remain intact. |

The test fingerprint is
`D9CC2D5D56C879EC862B01B36F868E2186D5821D`; this ephemeral fixture identity is
**not an accepted release signer**. The selected URL is
`https://repository-lifecycle.example.invalid/generations/` followed by 64 `a`
characters and `/release/repo`. It is never fetched and proves no remote snapshot
immutability, freshness or publication.

## Preservation, signatures and environment

Eight preservation checkpoints assert the hashes, modes, UID/GID and mtime of four
UID/GID1001-owned synthetic existing-user files (`.zshrc`, Fish config, history,
editor config) and one unrelated root-owned configuration sentinel. They do not
read or certify a real user's home. Both existing default-keyring public primary
certificates, including exported local signatures, and their existing ownertrust
are unchanged at all eight checkpoints. The added TEST certificate/local
certification is also unchanged after removal, reinstall, disable and final
removal. Comparisons use public exports, not mutable raw GPG database bytes.

The installed CLI uses the container's existing default keyring. Package
transactions use a separate private TEST verification ring and temporary
configuration with **required local signatures**. Both original archives receive
ephemeral TEST signatures inside the container. Scriptlets are disabled and
existing ALPM hooks are masked. There is no real signed-repository download,
package refresh, production trust enrollment or service activation. Pacman's
global trust remains global; this test does not establish repository-exclusive
signer enforcement.

The runner records native `aarch64`, ARM Neoverse-N2 and 4096-byte pages. The
container runs offline with declared read-only source/input mounts, a result
mount, bounded resources, dropped capabilities plus the selected package-operation
capabilities, and no-new-privileges. The builder/final inventory SHA-256 is
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
This fixture does not select the frozen full587 composition. GPG emits the
existing default homedir permissions warning in the driver log; it is nonfatal,
and this work does not change that base keyring's permission policy.

## Retention and cleanup limits

The once-collected
[logs.zip](../../artifacts/development/repository-lifecycle-run38785474034/logs.zip)
is **1773052 bytes**, SHA-256
`e78865323b87282d1da396735161e7c39e48f165e1414fb92d5830a6e3c0d1d8`.
ZIP CRC checks and all three ordinary evidence-frame declared sizes/hashes pass:
summary 2325 bytes, native 773599 bytes, lifecycle 1676 bytes. They contain 17
regular files totaling 7287700 uncompressed bytes. The
[local review](../../artifacts/development/repository-lifecycle-run38785474034/review/local-review.json)
and [retention details](../../artifacts/development/repository-lifecycle-run38785474034/review/retention.json)
are readable derivatives. This review performs no recollection, rebuild, package
action, GPG operation or test replay.

The exported records contain bounded commands, PASS observations and result
fields. Successful command output and raw before/after configuration/certificate
snapshots are not individually exported. The preservation/policy conclusions
join these results to the exact tested source assertions; this review does not
independently reconstruct unexported file/trust operands.

Private fixture cleanup is true: the selected code successfully stops its own
signing, transaction and default-ring GPG daemons and removes the private fixture
tree. The container's TEST public certificate is deliberately retained after
disable until the disposable container is deleted. Host cleanup reports absence
of `repository-installed-be61eb47ee743aac` and removal/absence of image
`sha256:68667f2cfc290d1e1e89ea185fb725c0b136d193bbea7a0261d3c3da334c1154`.
The acquired input cache, Docker daemon and unrelated layers/processes are outside
that scoped cleanup claim.

Earlier run38784332931 stopped at a fixture query using unsupported
`--noscriptlet`; that failed history remains. The successful successor separates
read-only query arguments from transaction options without changing archives,
signature/trust requirements or preservation checks.

This accepts the documented generic installed-package/TEST-enrollment happy path.
It does not establish real Asahi trust/bootstrap transactions, authenticated
production key rotation/revocation, a current published repository, full587
updates, interrupted package-manager/power-loss recovery, macOS installation,
physical 16K pages, either M2 Air, or performance. Inventory/default adoption is
owned by Root and is not changed by this document.
