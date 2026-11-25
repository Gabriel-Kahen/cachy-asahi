# Configured updater 4.4.2-3 preflight

Run 45715088356 qualified the native package and installed Check. The next
entry is the installed `arch-update` with no arguments. The repository has
measured 16 KiB signed ALPM trials and a native installed Check result.
The exact combination of the qualified installed CLI, a signed generic
update, and Apple-policy refusals in a 16 KiB guest remains open.
[Installed Check evidence](../../../docs/validation/updater-native-45715088356.md)

## Source fixture

`test_full_update.py` verifies the exact patched source tree and runs the
no-argument Bash entry with the real Apple policy evaluator. It reuses the
qualified Check fixture's data-only package identity, updater options and
state snapshot reader, plus the existing synthetic Apple-policy data. The
shim directory supplies inert responses for discovery, elevation, package
commands, news and service checks. The fixture creates only private
temporary files.

```sh
source=/absolute/exact/patched
UPDATER_FULL_UPDATE_PATCHED_SOURCE="$source" python3 -I -B scripts/ci/updater-full-update/test_full_update.py -v
```

The configured path needs separate pinned policy, pre-transaction and
post-transaction observations. Even with AUR and Flatpak disabled, it
requires repository-update, orphan-removal and package-cache-removal
permission before discovery. After confirmation, the repository branch
invokes the selected elevation command with `pacman --color never -Syu`.
The pinned post-transaction observations are consulted after that command.

| Fixture case | Expected exit | Evidence |
| --- | ---: | --- |
| Configured generic success | 0 | One exact upgrade invocation and cleared pending records |
| Unconfigured policy | 21 | No discovery or elevation and preserved pending state |
| Declared transition with a protected audio change | 22 | No discovery or elevation and preserved pending state |
| Undeclared cache operation | 22 | No discovery or elevation and preserved pending state |
| Wrong policy digest | 23 | No discovery or elevation and preserved pending state |
| Simulated pacman failure | 5 | One failed invocation with pending state and previous update date preserved |
| Wrong post-observation digest | 23 | After the successful simulated upgrade invocation |
| Protected service discovered after update | 22 | After the successful simulated upgrade invocation, with no restart |

All eight controls passed against the verified 98-file patched source.
Their results establish shell ordering, argument binding and synthetic
policy decisions. Signed transaction, guest and hardware execution remain
pending for this fixture.

## Reusable signed lifecycle evidence

- Overlay583 exercised signed install, remove, reinstall, signature refusal
  and recovery on an offline AArch64 guest that measured 16,384-byte pages.
  Its Setup7-to-Setup8 path verified the exact one-package upgrade, complete
  inventory and ALPM log. The VM owner and scratch/readback paths are useful
  for the updater successor. The historic staging and boot inputs need a
  current complete selection. [Overlay583 evidence](../../../docs/validation/offline-overlay583-emulated-install-20261117.md) · [VM owner](../../install/overlay583_trial/README.md)
- The signed RTC project lifecycle exercised real dependency checks,
  hooks, scriptlets, systemd and an ordinary PAM user on a measured 16 KiB
  guest. This is an elevation and session reference for a future guest
  trial. [RTC lifecycle evidence](../../../docs/validation/arm16k-rtc-signed-project-lifecycle-20261115.md)
- R132 exercised signed forward and reverse ALPM steps on a copied Asahi
  Minimal filesystem with a generic 16 KiB guest kernel. It recorded and
  restored initramfs changes made by the real hook. Asahi boot remains a
  separate gate. [Maintenance evidence](../../../docs/validation/asahi626-maintenance-emulated-arm16k-20261118.md)
- The native bound updater exercised real signed tiny-root libalpm
  prepare/commit, exact add/remove verification and protected-state
  refusals. It calls libalpm directly. The older Current607 16 KiB result
  exercised copy capacity with zero committed transactions.
  [Bound updater evidence](../../../docs/validation/updater-bound-native-20261015.md) · [16 KiB capacity evidence](../../../docs/validation/updater607-generic16k-capacity-20261028.md)

## Inputs for a signed disposable transaction

1. Obtain the qualified `cachy-asahi-update` 4.4.2-3 AArch64 archive with
   SHA-256 `44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc`.
   Run 45715088356 retired its private bytes. The future guest needs the
   exact archive and a dependency-checked inventory pinned for its own
   base. The existing installed Check lock and immutable runtime intake
   supply the five verified vendor package/signature pairs for
   `archlinux-contrib`, `htmlq`, `pacman-contrib`, `pyalpm` and `xdg-utils`.
   [Runtime input lock](../updater-optional-check/historical/dependencies/inputs.lock.json) · [Immutable intake](../../port/updater-native-stage/runtime_intake.py)
2. Select a measured 16 KiB AArch64 guest, an exact read-only baseline and
   fresh owned scratch. Give the guest an ordinary updater user, a scoped
   elevation path and explicit input for the confirmation prompts. Keep
   networking off and AUR and Flatpak disabled. The news request must stay
   inside the offline guest, and orphan, cache, restart and reboot actions
   should remain unselected or refused.
3. Seed the inert `cachy-asahi-check-fixture` data package at `0.1.0-1`.
   Use a read-only `file://` repository advertising only `0.1.1-1` for
   that package. Authenticate the exact archive and signed database with
   required signature checks and a separately issued disposable TEST
   trust root. Supply independent policy and pre/post observation pins
   for the synthetic protected baseline. The updater's policy digests
   bind those inputs. The selected repository, inventory and real ALPM
   operation require their own binding.
   [Existing synthetic package and repository tooling](../updater-optional-check/historical/real-check/real-check.py) · [Bound ALPM caller](../../update/bound_update.py)
4. Record the selected transaction and ALPM actions, the single package
   version and payload change, database and other package preservation,
   and actual guest cleanup. In separate refusal trials, verify zero
   package changes and preserved local database and payload bytes before
   reporting a precommit refusal. A signed repository can refresh its
   sync database before an archive-signature failure. Record post-update
   policy refusals separately from precommit refusal.

## Target acceptance

The supported Asahi transaction needs an approved package composition and
trust policy, authenticated target inventories, actual package-owned
module observations, and a controller that binds the prepared transaction
to the repository snapshot and commit. Changes to boot, kernel, firmware,
graphics and audio need coordinated handling and recovery evidence.

Physical testing is required on both the 13-inch M2 Air (`apple,j413`)
and the 15-inch M2 Air (`apple,j415`) for actual Asahi boot, update and
recovery, graphics, audio and speaker safety, sleep, and desktop/session
behavior. A measured generic guest can qualify the finite software
transaction. [Acceptance matrix](../../../docs/acceptance.md) · [Baseline capture](../../../docs/baseline.md)
