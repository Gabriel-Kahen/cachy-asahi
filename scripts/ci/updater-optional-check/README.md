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

From the reviewed worktree with the historical Git object available:

```sh
python3 -I -B scripts/ci/updater-optional-check/prepare.py
python3 -I -B -Werror::ResourceWarning scripts/ci/updater-optional-check/test_optional_check.py -v
```

Supply `UPDATER_OPTIONAL_PATCHED_SOURCE` pointing to the canonical private tree
extracted from the pinned sanitized archive with both package patches applied
at zero fuzz to run the fourth test. It verifies the patched-source ledger and
executes the full source Check entry in a scratch profile, with an inert
checkupdates command in addition to the optional command fixtures.

## Native execution prerequisite and invocation

The existing `native-arm-updater.yml` has a build-only broker and deletes the
private image and archive after the pair. Installed execution requires a
reviewed same-job integration before that cleanup and an authenticated cache
route for the pinned builder inputs and all five runtime archive/signature
pairs. The historical live runtime acquisition returned HTTP 404 in
[run 40242384425](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40242384425).
The exact four missing package/signature pairs are available from the
[public incoming31 carrier](https://github.com/Gabriel-Kahen/cachy-asahi/tree/405761af52cdfa92b97bbf5b0519f32230d9a254).
The fifth pair, xdg-utils, was already present in the prior retained cache.
The capsule requires the actual five pairs and the pinned ALARM keyring file
regardless of transport. A separate installed workflow dispatch is unavailable.

Within the future reviewed, dedicated native job, after both clean builds pass
and before product/image cleanup, set `native` to the private build output,
`cache` to the populated private archive cache, and `trial` to a fresh owned
0700 directory under `/tmp`. Register and supervise the exact named fixture
container with the owning controller. Supply a clean Docker environment and
give the run and cleanup independent deadlines.

```sh
python3 -I -B scripts/ci/updater-optional-check/prepare.py \
  --native-output "$native" --cache "$cache" --output "$trial/inputs" \
  > "$trial/input-receipt.json"
image=$(python3 -I -B -c 'import json,sys; print(json.load(sys.stdin)["native_image"])' \
  < "$trial/input-receipt.json")
case "$(docker --host unix:///run/docker.sock info --format '{{.Architecture}}')" in
  aarch64|arm64) ;;
  *) exit 1 ;;
esac
test "$(docker --host unix:///run/docker.sock image inspect --format '{{.Os}}/{{.Architecture}}' "$image")" = linux/arm64
nonce=$(python3 -I -B -c 'import secrets; print(secrets.token_hex(16))')
name="cachy-asahi-updater-runtime-$nonce"
mkdir -m 700 "$trial/out"
# The owning controller records "$name" before this launch.
timeout --signal=TERM --kill-after=15s 360s docker --host unix:///run/docker.sock run \
  --rm --name "$name" --pull=never --platform=linux/arm64 --user=0:0 \
  --network=none --ipc=private --cap-drop=ALL --security-opt=no-new-privileges \
  --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SETGID \
  --cap-add=SETUID --cap-add=SYS_CHROOT --cap-add=SETFCAP \
  --pids-limit=256 --memory=2g --cpus=2 --tmpfs=/tmp:rw,nosuid,nodev,exec,size=512m \
  --mount "type=bind,src=$trial/inputs,dst=/inputs,readonly" \
  --mount "type=bind,src=$trial/out,dst=/out" \
  --env "CACHY_ASAHI_UPDATER_RUNTIME=$nonce" --entrypoint=/usr/bin/python3 \
  "$image" -I -B /inputs/inside.py > "$trial/runtime.log" 2>&1
```

The trial requires exit zero, `out/result.json` with runtime and all fifteen
cases passing, signing-state cleanup, and verified absence of owned container
and private data after the runner's ordinary cleanup. Retain only reviewed
scalar/hash evidence. Neither the source preflight nor successful fixture
projection establishes native execution, production signing, live optional
backend operation, full-update behavior, target 16 KiB execution or M2 support.
