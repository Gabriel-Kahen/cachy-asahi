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

## Owned guest adapter

`guest.py` is the post-bootstrap workload for a separately admitted QEMU
`virt` guest. It requires measured AArch64/16,384-byte pages, loopback-only
networking, read-only `/updater-input`, and exactly one
`cachy_updater16k=<plan-sha256>` kernel argument issued by the owner. The
plan is a JSON object with kind `cachy-asahi-updater16k-disposable-v1`,
integer `valid_from` and `expires` epochs spanning at most one day, the
single current TEST signer fingerprint, and the exact relative path to
SHA-256 map declared in `guest.FILES`. The owner must verify actual guest
UTC before importing fresh trust. The adapter checks plan validity again.

Prepare the guest with the following selected inputs:

- A fresh updater boot derivative and writable QCOW2 child of the sealed Q3
  scratch. The 17,179,869,184-byte backing image has SHA-256
  `70ca6c345fcf5e5d29d0bb90993d54c17a54164f23b2a6fe839e061b51edca45`.
  The 1,611,661,312-byte Qt boot derivative used to prepare the updater boot
  has SHA-256 `951bdc40ec6d3c4735d688acda30f153a22019862bc255059b874d9c27e0a858`.
  The generic control Image is 9,019,400 bytes with SHA-256
  `36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494`.
  The 6,925-byte `q3.lock` SHA-256 is
  `e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9`.
  Boot authority also needs the exact generic kernel config, pinned guest
  worker, read-only input media, a fresh nonce, and reviewed resource and
  retirement bounds.
- The authenticated 362-package before-lock includes the 356-package Q3
  baseline, including signed sudo `1.9.17.p2-6` and xdg-utils `1.2.1-2`,
  plus four vendor additions, the qualified updater and the old inert
  fixture. Its SHA-256 is
  `7a5779caafed704a109debcf207b040e32565b5102c889809eb33d9bbbe8680b`.
  Place the exact qualified archive and separately
  issued detached TEST signature on media as `updater.pkg` and
  `updater.pkg.sig`. Include the original signed old fixture
  `cachy-asahi-check-fixture-0.1.0-1-any.pkg.tar.gz` and its detached signature
  at the media root. Both detached signatures over the pinned archives must
  verify using the selected current TEST key. Before creating trial scratch,
  the adapter also requires the old installed ALPM record to own exactly
  the inert payload, with no install script. It compares the installed Bash
  entry, library files, and policy executable to the qualified archive
  before calling the CLI.
- A root-owned, public-only `/updater-trust` (0700) containing just the
  selected TEST key for the signed fixture repository. Use ordinary files
  for `fixture.db`, `fixture.db.sig`, the sole package, and its detached
  signature. The package must match the historical two-file inert archive.
  Bind the exact existing hook names, success policy and pre/post
  observations, and the protected refusal policy and observation in the
  read-only plan. UID 1000 must be able to read the policy files and traverse
  the input directory. The qualified helper evaluates these synthetic policy
  inputs. The root-owned configuration forces required signatures and
  checks the sole fixture version, archive digest and URL in the real preview.
- A scoped guest sudo mount and root-owned sudoers file containing exactly
  `guest.SUDOERS`. The disposable work filesystem remains `nosuid`. The
  guest gives setuid execution to the pinned `/usr/bin/sudo` through one
  read-only file bind. UID/GID 1000 invokes real sudo only for the admitted
  update. The worker checks that sudo refuses package removal.

`prepare_q3.py` uses the existing Qt offline boot patcher to create a
separate updater boot partition on a fresh reflink. It reads back the
patched worker and file modes and stages the locked vendor pairs and two
unsigned inert fixture archives. Reuse the [offline owner pattern](../../integration/qt612_base_16k_link_preflight/actor.py)
with one fresh writable QCOW2 child backed directly by the pinned Q3 raw
scratch. The old Qt execution authority covers only the Qt operation.
The updater preparation leaves launch authority unissued.

The pinned Image has PL031 built in. The original Q3 serial shows
`rtc0` initialized the guest system clock to 07:19:46 UTC on November 18,
and the guest ALPM log continued at current UTC. The sibling boot uses
the existing RTC guard to check hctosys, advancing RTC and system time
against the owner's actual QEMU-start UTC before loading fresh TEST trust.
[Q3 evidence](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md) · [RTC guard](../../integration/arm16k_c01_workflow_rtc/rtc-clock.sh)

Complete the media tree with the pinned updater, detached TEST
signatures, fixture-only signed database, a single public primary with a
TEST UID and lifetime of at most one day in `TEST-public.gpg`, policy and
observation files, and a fresh `plan.json`.
The owner seals that tree in a read-only 128 MiB ext4 volume with the
label and UUID in `PLAN.UNISSUED.json`. The image root must have mode
0755 and the policy files must be readable by UID 1000.
Bind the final media, guest worker, RTC and boot nonce, runner limits,
cleanup and the live plan hash in the updater admission.

### Separate signed cases

Prepare `update` and `signature-refusal` with distinct nonces, boot
derivatives and input-media UUIDs. Both use the same pinned Q3 raw backing
and inert fixture archive bytes. A successor can use
`prepare_q3.py --prior-packet` with the exact prior isolated preparation
to share its sealed backing by reference. A run makes one temporary
reflink of that backing and retires it after the owned container and
its QCOW2 child have exited.

The negative repository database has a valid TEST signature. Its
candidate's embedded signature and detached sidecar are the exact
valid signature over the old fixture. The host media sealer checks that
the signature fails against the unchanged new archive. In the guest,
the configured updater must invoke real sudo once and report the
package's ALPM signature rejection. The complete installed database,
inventory, payload and pending records must match the old checkpoint.
A refreshed sync database is allowed in this case.

`q3-media.py` verifies a separately pinned signed request and writes the
sealed ext4 image, media receipt and guest plan copy. Run `q3-owner.py
preflight` on the sealed media to obtain the exact admission binding.
Preflight rehashes the image inputs and emits an unissued receipt
without opening Docker. The owner supplies `valid_from` and `expires`
on that binding and independently pins the resulting admission file.
Provide enough time for the 1,300-second attach ceiling and retirement.
Use a different fresh attempt path for each case.

```sh
python3 -I -B q3-media.py --packet "$PREP" --preparation-sha256 "$PREP_SHA" \
  --signed "$SIGNED_REQUEST" --signed-sha256 "$REQUEST_SHA" --output "$MEDIA"
python3 -I -B q3-owner.py preflight --packet "$PREP" --preparation-sha256 "$PREP_SHA" \
  --media "$MEDIA" --media-manifest-sha256 "$MEDIA_HEADER_SHA" --output "$ATTEMPT"
python3 -I -B q3-owner.py run --packet "$PREP" --preparation-sha256 "$PREP_SHA" \
  --media "$MEDIA" --media-manifest-sha256 "$MEDIA_HEADER_SHA" --output "$ATTEMPT" \
  --admission "$ADMISSION" --admission-sha256 "$ADMISSION_SHA"
python3 -I -B q3-readback.py --plan "$PREP/PLAN.UNISSUED.json" --plan-sha256 "$PREP_SHA" \
  --guest-plan "$MEDIA/plan.json" --guest-plan-sha256 "$GUEST_PLAN_SHA" \
  --media-manifest "$MEDIA/media.json" --media-manifest-sha256 "$MEDIA_HEADER_SHA" --media-sha256 "$MEDIA_SHA" \
  --admission "$ADMISSION" --admission-sha256 "$ADMISSION_SHA" \
  --owner "$ATTEMPT/owner.json" --owner-sha256 "$OWNER_SHA" --serial "$ATTEMPT/serial.log"
```

The fixed rootless runner has no network or host devices. Its root and
all input mounts are read-only. It caps the one writable QCOW2 child
at 1 GiB and serial at 1 MiB. The independent reader checks the actual
QEMU command, RTC, guest and Docker receipts, natural poweroff, and
retirement of the exact container and clone. Retain the attempt
directory as the one-shot claim and evidence.

The adapter runs the unconfigured and protected refusals first. It
compares the local database, complete inventory, inert payload, and
pending records before allowing the positive case. The positive case
requires one sudo upgrade request, one real ALPM upgrade, unchanged
nonfixture database entries, expected payload bytes and an intact local
database. A HOLD retains the observed local database version directories
and case exits for owner readback, including a refusal after an actual
commit.
After a command timeout, the adapter leaves scratch intact and defers
database observation until the owner has stopped the guest.
The adapter removes its private updater state. The owner must preserve the
read-only baseline, dispose of the mutated scratch copy, retire the TEST
trust and independently attest guest and resource retirement.

```sh
python3 -I -B -Werror scripts/ci/updater-full-update/test_guest.py
```

## Exact archive retention

The current authenticated native pair is the reproduction route. It
requires a non-root native Linux AArch64 coordinator with local ARM Docker,
the reviewed 354-package builder lock and the retained signed build input
selection. The guest's 356 lock belongs to consumption. Run 45715088356
retired both original archives, and the workflow only exports guarded
receipts. A separately admitted build should copy one original archive
into fresh private handoff custody after the authenticated comparison and
before stage cleanup. Preserve the original filename and compressed bytes.
Check both archives against the qualified package digest and reviewed
metadata, cap the retained regular file at 64 MiB, and rehash the copy.
Expose the single archive to the guest preparer only after successful
cleanup and recovery. Issue its disposable TEST signature separately
against the unchanged bytes. The existing public evidence path remains
the run's receipt channel. [Native pair adapter](../../../packages/tools/cachy-asahi-update/updater-native.py) · [Stage cleanup](../../port/updater-native-stage/stage.py)

The existing private `Gabriel-Kahen/cachy-asahi-ci-inputs` repository is the
custody destination. Its Actions service is enabled. A private artifact
handoff still needs an independently reviewed workflow and a non-root
native ARM runner with local ARM Docker. The qualified public workflow
can execute only in its public source repository. The existing private
deploy key provides read-only input access. The private workflow can use
an explicitly scoped same-repository input selection and short-lived
artifact storage, subject to admission.

Bind source `96a3848c4c4e7d88a2ac979d27066f99b150315a`, the 354-package
lock SHA-256
`5c72ffef2fadecc631861ef12ab7f48e083694a402d0428a395da64fa592dcee`, and
the same 527 authenticated inputs. The four immutable private carriers
provide 224 of those inputs. The unchanged stage additionally requires
18 GiB free on a shared filesystem or 10 GiB free on each of separate
output and Docker filesystems. Actual runner capacity remains unverified.
GitHub lists 14 GB of storage for the standard private ARM runner.
[Frozen carriers](../../port/updater-native-stage/retained-inputs.json) · [Private runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-runners-for-private-repositories)
