# Installed handoff candidate — private host-container result

This adapter installs, reinstalls and removes the exact existing handoff package
inside one new pinned, offline x86_64 Docker container. It does not grant native
ARM, Asahi/M2, production trust, boot recovery or release acceptance.

The package, launcher, finite runtime and verifiers remain unchanged. The adapter
reuses the byte-identical `scripts/integration/lifecycle.py` process supervisor,
cleanup machinery and actual environment observations. Its new contract is
explicitly `host-x86_64-disposable-docker`; it neither changes nor spoofs the
existing native-aarch64 lifecycle admission.

## Exact inputs and run

- Image: `sha256:30cfe09952ef8d9bfabd64224185c97021b260d47bb83941fec5bae7bdd16145` (already present; never pulled).
- Package: `cachy-asahi-install-handoff 0.1.0-1`, 184625 bytes,
  `cf34935122855ca6aaa02f4c11987d53530e0e729c03698fa03aa1586ffac59e`.
- Unchanged lifecycle source SHA-256:
  `c3223a1bd4002683071f4442e1f5b9caf439c68c4e231da10039cc9cebcdb52b`.
- Runtime/verifier source: `1c4c455b486fd0b0f1c7ae587130a2c05e7a9560`;
  package delivery: `282364173f497f1052267c3901dda395dd59e03f`.

```sh
python -I -B -Werror::ResourceWarning scripts/integration/install_handoff_candidate/host.py \
  --artifact /absolute/cachy-asahi-install-handoff-0.1.0-1-any.pkg.tar.zst \
  --output /absolute/new-private-evidence-directory
```

`prepare.py` uses the unchanged check-only fixtures to create genuine TEST-signed
candidate/predecessor kits and all 16 recovery archives, and signs the exact
package bytes. Only the fixture's exact Git-context query uses the packaged source
lock. Signature/authentication functions are unchanged. The private signing home
and producer-source temporary tree are removed before container creation. Only
finite data, three runner files and the new evidence directory are mounted.

The container uses network none, private namespaces, no-new-privileges, 2 GiB,
2 CPUs, 128 PIDs and only the existing six lifecycle capabilities (mask `235`).
The host checks actual Docker identity, labels, image, arguments, limits and all
three mounts. The guest checks real mount/device identities and all capability
sets before mutation. This rootless Docker exposes six standard character-device
mounts and protected `/proc` null masks as `devtmpfs`; the new host guard accepts
only their exact standard identities. No capability or ARM-guard bypass is used.

Pacman uses a separate ephemeral TEST public keyring and exact local-only config
with `Required TrustedOnly`. Dependencies remain checked; hooks are masked using
the existing builder convention and scriptlets disabled. The package itself has
no hooks/scriptlets. No host package, trust store, service or boot state changes.

## Actual installed result

The final run reports `PASS_HOST_X86_INSTALLED_LIFECYCLE_ONLY`: **30 checks,
29 supervised commands, three real pacman transactions**. Complete package
inventories pass **139 → 140 → 140 → 139** for baseline/install/reinstall/remove.
A missing detached signature is first refused with the 139-package baseline
unchanged. Both installed payload maps contain all 39 exact root-owned files;
a complete post-remove map records all 39 leaves absent.

Installed, moved, reinstalled and moved-after-removal commands run offline with
producer source/signing keys unavailable. The real product CLI retains the
fixed production ALARM policy and refuses TEST trust. A separate explicit TEST
anchor driver executes the unchanged installed verifiers and freshly checks the
genuine signed kits/recovery data. The TEST driver supplies no production trust.

Complete before/after caller snapshots (six phases), recovery/handoff bytes,
receiver state, moved prefix, standard container pacman config and keyring remain
preserved. Package removal is a real pacman removal, distinct from the earlier
archive/extracted-payload inverse. The host then removes only its owned container
and verifies its absence. Cleanup has an independent 45-second budget, cidfile /
name+label+image+actor+mount identity recovery, and best-effort cleanup receipt
logging so evidence I/O failure cannot prevent removal.

`results.json` pins the final retained reports and records earlier attempts.
Attempts 1–3 refused before guest mutation (Docker capability-name normalization,
standard device mounts, then protected null-mask representation). All owned
containers were removed. Attempts 4–6 retain actual successful installed runs;
5 adds complete snapshots, 6 includes failure-path cleanup hardening. No earlier
refusal or extracted-payload result is reclassified.

## Signed upgrade and rollback on November 19, 2026

An offline x86_64 container passed a TEST-signed install of
`0.1.0-1`, upgrade to `0.1.0-2`, rollback to `0.1.0-1`, and final
removal. The 36 checks and 29 commands included four package transactions,
the unsigned refusal, exact 39-file payloads, and offline verification of
the candidate and recovery handoffs. The rehearsal preserved caller data
and both checkpoints. The inventory counts were 139 → 140 → 140 → 140 → 139,
with identical package names and versions in the first and last inventories.

The initial trial stopped before container creation because its exact
historical image was unavailable. The successful trial used a successor
image built from the pinned Arch base and the two archived packages
verified against its public keyring. Independent image readback matched
the original 139-package lock. Both trials used the same signed fixtures.
The owned container and the local scope retired. The independent terminal
SHA-256 is `5b449218eb784d8f41daeb732e1a5b4069b81af7ef3af0b87301553c06cc0dcb`.

Physical Asahi installation, native ARM and production release acceptance
remain open.

## Exact test counts

Commands use `python -I -B -Werror::ResourceWarning <path> -v`.

| Suite path | Cases | Scope |
| --- | ---: | --- |
| `scripts/install/fresh_handoff/test_handoff.py` | 12 | Prior custody/helper controls; explicitly labeled unsigned predecessor seam |
| `scripts/install/test_first_login.py` | 11 | Prior first-login suite |
| `scripts/release/test_recovery_bundle.py` | 23 | Prior recovery bundle suite |
| `scripts/release/test_offline_kit.py` | 17 | Prior signed offline kit suite |
| `scripts/install/fresh_handoff/test_signed_handoff.py` | 9 | Prior genuine TEST signature suite |
| `scripts/install/fresh_handoff/test_runtime.py` | 5 | Prior finite runtime suite |
| `scripts/integration/install_handoff_candidate/test_contract.py` | 23 | Current synthetic contract/real-fact guard controls |
| `scripts/integration/install_handoff_candidate/test_host.py` | 7 | Current synthetic owned-resource cleanup controls |

The earlier **63** is `12+11+23+17`; **77** adds `9+5`. Neither is the count of
`test_handoff.py`. Those prior suite logs remain historical and were not rerun
for this task. The two current suites pass 23 and 7 cases without skips; their
30 unit cases are separate from the installed journey's 30 runtime checks and
29 commands. No native or M2 result follows from either count.
