# Updater 4.4.2-3 installed Check trial

The installed trial reuses the immutable
[4.4.2-2 runner](https://github.com/Gabriel-Kahen/cachy-asahi/tree/480053c0866a922138d85af2b9880fb0e10d7b2c/scripts/ci/updater-real-check)
for required-signature installation into the exact native 354-package compiler
image. The new capsule selects the 360-package installed inventory with
4.4.2-3 and adds eight cases to the seven existing signed local repository and
full-update refusal cases. The installed Check uses real pacman, fakeroot,
checkupdates, and the TEST-signed repository. Inert PATH commands supply optional
AUR and Flatpak query responses without contacting optional remotes.

The added cases seed AUR and Flatpak pending state, then inject AUR, Flatpak user
discovery, system discovery after an empty user result, AppStream, mask and
remote failures. The installed Check must return 20 and preserve every prior
state entry by bytes, mode and mtime. Successful empty discovery then clears the
pending files, renders the up-to-date tray state and refreshes the check time.
Exact command traces require both discovery commands and no remote call in this
last case. Parent checks still compare the pacman database, inert package
payload, installed updater payload and exact installed package inventory.

## Source preflight

From the reviewed worktree. The four original blobs are copied byte-for-byte
under `historical/` and verified against their SHA-256 pins during preparation.

```sh
python3 -I -B scripts/ci/updater-optional-check/prepare.py
python3 -I -B -Werror::ResourceWarning scripts/ci/updater-optional-check/test_optional_check.py -v
```

Supply `UPDATER_OPTIONAL_PATCHED_SOURCE` pointing to the canonical private tree
extracted from the pinned sanitized archive with both package patches applied
at zero fuzz to run the Check entry test. It verifies the patched-source ledger and
executes the full source Check entry in a scratch profile, with an inert
checkupdates command in addition to the optional command fixtures.

The current dispatch seal binds the revised recipe checker. The predecessor
seal and package checkpoint remain available at commit
`db7acf84f8e3205b5812c101480d9d3bcafcd544`, with SHA-256s
`e745cd8bfc44df327be5523718b53b33668b3497583fcba995cd31cb41ab34ef` and
`0736114291b4c1f37773867d2d1ac7fbe7362e0f0cecac47b37ad25d55b99341`,
respectively. The revised seal has native build and installed Check status
**NOT RUN**.

## Native execution prerequisite and invocation

The same-job controller can prepare the capsule after both private native builds
pass and before the owned image and package are retired. Its pinned runtime
cache supplies the five archive/signature pairs plus the ALARM keyring. The
historical live runtime acquisition returned HTTP 404 in
[run 40242384425](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40242384425).
The first four exact archive/signature pairs are in
[carrier 405761af](https://github.com/Gabriel-Kahen/cachy-asahi/tree/405761af52cdfa92b97bbf5b0519f32230d9a254).
The fifth, xdg-utils, is in
[carrier 4659076d](https://github.com/Gabriel-Kahen/cachy-asahi/tree/4659076d3a1d3e5cf87c185a3ff383fbc38e734d).

```sh
python3 -I -B scripts/ci/updater-optional-check/prepare.py \
  --native-output "$native" --cache "$cache" --output "$trial/inputs"
```

Preparation emits a JSON receipt naming the native image and package SHA-256.
The controller registers the runtime container and bounds execution against the
job deadline. The historical network-disabled ARM configuration runs
`/usr/bin/python3 -I -B /inputs/inside.py` as UID 0 with a writable disposable
container root and the seven exact capabilities from the tested prior lane:
CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID, SYS_CHROOT, and SETFCAP. The capsule
needs one read-only host bind at `/inputs`. It emits one bounded JSON line to
supervised stdout after signing-state cleanup. Its success requires all fifteen
named cases with their expected exit codes. Verify owned container absence and
private-data cleanup before publishing the admitted scalar receipt fields.

This fixture covers the native Check command in a disposable container. Live
optional backends, a real update transaction, production signing, 16 KiB target
execution, and M2 hardware remain outside its qualification.
