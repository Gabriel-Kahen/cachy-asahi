# Generic QEMU desktop successor admission

The source-only workflow checks the successor at `061ee7b52291815837d8e9f4b542f001aa4730b1`
and the maintained carrier at `a3feeebf5f0f9b1f0bc83ce91d1c9ebabe40b734` in separate
checkouts. The pinned virtual adapter is `c347e4641f5f7d1c8b969a588e598f06d6d22e4ad35d1e6e4c816ee309c51e97`.
The maintained outer caller stays at `66b3575463881a6a7f9b3333b06d15e1339b0e9136e147804615b657bb86f52b`.
The profile records all eleven virtual owner files, the caller and the scoped
fixture sources. The workflow runs the UART and composed-caller fixtures from
the selected successor checkout. The two pinned commits must be reachable from
the repository before hosted source CI can check them out.
[Source pins](../../scripts/ci/virtual-desktop-completion-v2/source.json)

## Authority and exact restaging

The existing maintained workflow pins Code `b489e54b5c526525cc083fba0bdcf89962951d00`,
`installer-preflight-maintained-v1` and packet `a989941b2b7c0a342a002838c1c8bc47cec17d4a3a0f767c82b6a8c9bf96825b`.
Its caller enters the installer consumer before reaching the virtual stage. Its
external plan binds the workflow Source and ref, independently selected Data,
source rows and actor. The issued execution grant also binds the run, attempt,
invocation and actor contract. The Code launcher supports a separate 261-row
`repository-svg-maintained-v1` mode. The extra 1,200-second grant covers the
pending repository phase after the broad consumers return.
[Registered workflow](https://github.com/Gabriel-Kahen/cachy-asahi/blob/a3feeebf5f0f9b1f0bc83ce91d1c9ebabe40b734/.github/workflows/maintained-composed-installer-v1.yml#L71)
· [Mode and caller](https://github.com/Gabriel-Kahen/cachy-asahi/blob/a3feeebf5f0f9b1f0bc83ce91d1c9ebabe40b734/scripts/ci/development/controller.py#L765)

To reproduce the new source packet with both checkouts available, run this
from the admission checkout. The output is a new file outside either input tree.

```sh
python3 -I -B scripts/ci/virtual-desktop-completion-v2/preflight.py \
  --root "$SUCCESSOR" --maintained-root "$CARRIER" --packet-output "$FRESH_PACKET"
```

The freeze selects `repository-svg-maintained-v1`, removes the seven installer
rows and updates nine exact source rows. It retains the original 161 source rows,
127 generated fixture rows and 14 metadata pins. The new packet SHA-256 is
`04394d95ac79a5f0574d4adaf21f0b473ec264618bbce94961d6fc3c1a82e3ff`.
The profile lists the nine rows. The base input and recipe locks on the current
integration branch differ from this carrier, so the exact maintained carrier
is required for this freeze. [Restaging code](../../scripts/ci/virtual-desktop-completion-v2/preflight.py)

For live use, the coordinator needs a new workflow Source/ref from the maintained
carrier with the nine substitutions and that exact packet at the canonical
`scripts/ci/development/packet.lock.json` path. The workflow must select the
repository-SVG mode and packet, then obtain a fresh, separately reviewed Data
commit for its selection and peer receipt and register a matching Root plan.
The launcher creates the per-run grant after verifying these bindings. The
virtual controller still requires the same-job lifecycle PASS, original four
packages in the exact 345-package installed image, and 45 authenticated tooling
objects from the selected lock. The hosted workflow also needs the approved
retained-input delivery for the maintained baseline.
[Launcher selection checks](https://github.com/Gabriel-Kahen/cachy-asahi/blob/b489e54b5c526525cc083fba0bdcf89962951d00/.github/bootstrap/development-launcher.py#L301)

The historical direct route is also reproducible as a separate restage from
product `6e7d18a1c79e27fc6a236777a944ae2389dc259c` and workflow
`8774d35b63a77cff50588ae10c75ba81b06f925f`. Its `virtual_retry.py` caller SHA-256
is `fd902b120e2a399587b61b5dea0552ce4e5a1768ce566f147bab3f91bdc58197`. Restaging
that route requires a fresh product pin, re-frozen integration lock and
approved retained-input delivery. It exercises the guest and private controller.
The maintained route also exercises the successor's composed evidence reader.
[Direct workflow](https://github.com/Gabriel-Kahen/cachy-asahi/blob/8774d35b63a77cff50588ae10c75ba81b06f925f/.github/workflows/native-arm-build.yml#L29)

## Measured timings and configured ceilings

Prior direct jobs took **614–631 seconds** wall time, with **294.289–300.057
seconds** in the guest, under a 90-minute job cap. These measurements cover the
older direct route. The maintained composition's full wall time remains
unmeasured. [Visible-client run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38792647293)
· [Earlier direct run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38784585311)

The virtual stage allows up to 600 seconds for acquisition and 3,420 seconds
for its owner call. That is 67 minutes before short caller preparation and
receipt work, subject to the shared job deadline. The owner allows 3,300
seconds and sets 1,200-second preparation and guest budgets, with at most 15
seconds for QEMU shutdown and UART drain within the guest budget. The launcher
uses an issued 180-minute allowance and a work cutoff of at most 168 minutes
from entry, with a two-minute reserve before the issued deadline. The maintained
carrier workflow caps the job at 190 minutes and its execution step at 185.
The virtual containers cap memory at 6 GiB, CPU at four cores and processes at
256. The guest uses 4 GiB and two vCPUs. It needs an 8 GiB sparse disk and
preparation free space of twice the staged allocation plus 1 GiB. At the
allowed staged ceiling this is just under 13 GiB free, in addition to the
storage already used by the builder and cache.

This preflight supplies source and fixture evidence. Live generic QEMU execution
for the successor and both physical M2 Air records are `NOT RUN`.
