# Full composition generic ARM VM caller

Source-only proposal. No container, image, key, VM, mount, device or service was
created during implementation. This route does not change the existing generic
366-package image, 17-method installer transaction fixture, failed native
container P0 result, or Asahi production defaults.

`run.py` consumes the successful producer's retained `private/ready` directory
and its actual manifest digest. The producer remains alive until the VM caller
finishes; its separate cleanup API owns the original574 builder image and
producer signing agents. The VM caller borrows that image by immutable ID and
never removes it. Its output must be a fresh absolute direct child of `/tmp`.

The integrated `ci.py` caller performs this sequence and fetches the exact held
tooling inputs into its private cache. The standalone `run.py` form below
requires an already populated tooling cache. The native CI handoff is sequential:

1. Use `producer.prepare(args)` with the held composition inputs. Preserve its
   returned ready path and exact `manifest.json` SHA256; do not manufacture
   archive pins. The ready tree contains signed587 archives, detached signatures,
   two public keyrings, initial587 lock, actual574 builder lock, and manifest.
2. Invoke the following command on the nonroot native aarch64 runner, substituting
   the actual producer paths and digest. The tooling cache is the existing held
   `scripts/virtual/tooling.lock.json`21-row cache, including its signatures and
   public keyring. There is no fetch fallback.

   ```sh
   python3 -B "$candidate/run.py" --ready "$ready" \
     --manifest-sha256 "$actual_manifest_sha256" --code "$source_checkout" \
     --candidate "$candidate" --tooling-cache "$held_tooling_cache" \
     --output /tmp/cachy-full-installer-owned-trial
   ```

3. Retain the VM `result.json`, bounded preparation receipts, VM receipt and
   bounded UART log. In the CI owner's unconditional `finally`, call
   `producer.cleanup(producer_output)` and require its separate cleanup receipt.
   A VM PASS does not establish producer cleanup.

`candidate` contains `run.py`, `prepare.py`, `guest.py`, `installer.py`, and
`profile.py`. The caller copies these to its private output, then invokes
`profile.build(ready, code, candidate_copy)`. This generates the actual payload
contract and installer profile there, without modifying the source candidate or
the producer ready directory. Source closure comes from returned
`profile['code_files']`; optional `--code-files` must equal that exact set.
The code checkout must match the producer's declared revision, and selected
tracked files must have no difference from HEAD. Profile input checks additionally
bind the held updater configuration's dependency hashes.

The owned Docker route has three finite phases:

* Tooling: writable private overlay, network none, no host device/socket, NNP,
  exact CHOWN/DAC_OVERRIDE/FOWNER/FSETID capabilities. Verify every held21 tooling
  archive's upstream signature and metadata, mask all hooks, disable scriptlets,
  and add only missing versions to the actual574 image. An overlapping different
  version fails. Verify the exact574-plus-tooling union; remove the ephemeral
  tooling TEST trust agents/home before committing a uniquely tagged owned image.
* Preparation: read-only derived root, same metadata capabilities, bounded tmpfs.
  Reuse the generic builder's environment checks, launcher pins, bounded process
  commands, allocated-space checks and fixed kernel identity. Copy `/usr`, `/etc`,
  `/var`, `/boot` as fixture data, retain root aliases and special mode ownership,
  replace the guest's copied pacman secret-key directory with an empty directory,
  and stage root-owned protected installer code/profile/cache. Use `mkfs.ext4 -d`
  on a sparse20GiB regular image; no host mount is used. The guest has its own
  fstab/unit/target only. Xattrs are not preserved; this is a software fixture.
* Runtime: read-only derived container root, UID/GID23001, cap-drop ALL, NNP,
  network none, no KVM/devices/socket. QEMU11.1.2 uses virt-11.1, TCG, CPUmax,
  two CPUs,4GiB guest RAM, no default devices/network/audio/display/monitor,
  held virtio-blk-pci disk and snapshot=on. QEMU temporary COW lives under the
  private disk-backed `/out`, not the bounded runtime tmpfs. Generic4K kernel
  Image SHA256 is `92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a`,
  release `7.2.10-1-aarch64-ARCH`. The cmdline selects only
  `full-installer.target` plus the existing generic VM marker.

Tooling/preparation each have1800s absolute child deadlines; VM has5400s,
and the host actor window has9600s. Preparation accepts at most10GiB staged
allocated data, reserves twice its declared stage bound plus2GiB before copying,
and requires staged allocated bytes plus2GiB before mkfs. Runtime requires12GiB
free for guest COW/target/evidence. The fixed20GiB guest disk and profile's
200000-node/6GiB payload bound remain finite. Capacity failure refuses before
continuing; it does not trim packages or increase limits. Profile generation has
its own held archive/decompression/deadline bounds.

UART accepts at most64MiB total and1MiB per declared event, and exactly ordered
`FULL_INSTALLER nonce JSON` boot/result/exit frames. Partial streaming lines wait;
truncated final frames, duplicate keys/events, wrong nonce/kernel/page size,
failed result and failed guest cleanup refuse PASS. After the exit frame, QEMU must terminate naturally with status0 within90s.
QEMU process ownership stays reserved through the final group signal, then
absence is verified before PASS.
The controller independently rehashes source/cache files and checks the borrowed
producer image identity after the VM. It retires only token-labelled containers,
its derived image and private disk/COW/staging directories. Reports remain.
Cancellation during a Docker daemon image commit reports UNKNOWN cleanup with
the unique image tag retained; it does not claim daemon completion or absence.

Acceptance is a generic4K software installer transaction against the exact587
input fixture with the guest engine's preservation and transaction checks.
It establishes no Asahi installation, target boot/session, partitioning/macOS
journey, M2 hardware,16K compatibility, performance, production key custody, or
native-container P0 success. Actual producer, tooling, mkfs, boot, installer and
cleanup results remain unrun until Root integrates and dispatches the candidate.
