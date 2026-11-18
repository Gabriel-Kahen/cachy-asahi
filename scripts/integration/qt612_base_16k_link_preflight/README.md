# Qtbase QtCore link preflight on emulated AArch64

This preflight reads the closed Q3 configure result and its exact 16 GiB
scratch image. It checks the whole scratch pin on a temporary same-filesystem
reflink and reads selected ext4 files with read-only Debugfs. It verifies that
the guest PKGBUILD equals the existing Qt-family `gui_server` projection,
including the serial autogen and server dependency guard, and checks the
actual CMake cache, Ninja manifest and rules. Ninja runs only its graph and
command-inspection tools.

## Replay the preflight

Pass the canonical paths to the Q3 terminal receipt and original scratch.
Select a writable probe directory on the scratch filesystem and outside the
Q3 attempt and receipts. The original scratch and receipt are opened without
updating access time. The probe directory holds a temporary reflink and
bounded tool outputs. The command emits an unissued JSON plan on stdout.

```sh
lane=scripts/integration/qt612_base_16k_link_preflight
python3 -I -B -Werror "$lane/test_preflight.py"
python3 -I -B -Werror "$lane/preflight.py" \
  --q3-terminal "$q3_terminal" --q3-scratch "$q3_scratch" --probe-dir "$probe_dir"
```

| Q3 Ninja target | Commands | C/C++ compile edges | Shared libraries linked |
| --- | ---: | ---: | --- |
| `lib/libQt6Core.so` | 321 | 303 | QtCore |
| `lib/libQt6Gui.so` | 639 | 597 | QtCore, QtDBus, QtGui |
| `all` | 1,855 | 1,385 | Full configured build graph |

The Core target includes the versioned `libQt6Core.so.6.12.0` link and
the SONAME symlink. The Gui closure includes the Markdown importer and the
exact system md4c library. The retained R4 importer object is a separate
compile result. The Q3 Gui link requires 260 direct object inputs and the
Core and DBus shared libraries. [Q3 configure validation](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md)

## Core checkpoint and resource limits

The plan selects the existing serial CMake build invocation with
`--target lib/libQt6Core.so`. The command belongs inside the exact Q3
356-package root at its original guest path, with UID and GID 1000. The
checkpoint keeps Q3's compiler, flags and generated rules. It uses the
existing owned QEMU continuation boundary for a future issued attempt.
The boot and Q3 backing images are read-only inputs. A fresh attempt owns
the writable QCOW2 overlay, separate result disk, scope, nonce and capacity
checks. Feed the returned file and allocation limits to the existing owned
runtime command observer. Recheck actual output filesystem capacity at entry.

The probe measured 12,484,247,552 free bytes inside the Q3 ext4 scratch.
The Core proposal keeps 4 vCPUs, 4 GiB guest memory, 6 GiB actor memory,
and a 64 MiB result disk. It proposes a 4 GiB overlay cap, 32 MiB for
reports, 2 GiB live host disk reserve, and 2 GiB host memory reserve. It
allows 6,900 seconds for the guest build, 7,200 for QEMU, and 7,500 for
the outer attach. These are stop limits. No completion budget has been
measured for Core. R4 measured 209.20 seconds and 349,966,336 allocated
overlay bytes for its importer run.

A future Core result needs natural command exit, original output custody,
and AArch64 ELF64 shared-library readback for `libQt6Core.so.6.12.0`, with
SONAME `libQt6Core.so.6` and 16 KiB-compatible load geometry. Retain the
elapsed time, peak memory and peak allocated storage with the owned cleanup
evidence. The Qt-family package checker already provides an ELF parser for
these binary checks.

Gui and the full Qtbase build and package stages remain pending. The
`all` graph excludes package staging, the recipe smoke check and XZ
compression, whose runtime and storage remain unmeasured. The existing
Qt-family packaging recipe and native runner gates continue to apply.

## Prepare a local capsule

The capsule preparer reads Q3 and R4's independently closed receipts and
pins the original Q3 kernel, boot disk, and scratch. It exports the
portable runtime files from local Git commit
`ac9ed3ceb1df938473a6a9bfe4dcd941120c923a`. All four importer leaves retain
the exact bytes used by the original private capsule. It reflinks the original
carriers on the same filesystem, injects the QtCore guest into the private
boot copy, reads the injected bytes back, and formats a separate 64 MiB
result template. The original carriers are opened with access-time updates
disabled. The preparer emits a canonical handoff, plan, and unsigned
binding. These commands use filesystem and graph tools.

```sh
python3 -I -B -Werror "$lane/prepare.py" --output "$capsule" \
  --q3-terminal "$q3_terminal" --r4-terminal "$r4_terminal" \
  --docker-client "$docker_client" --docker-client-bytes "$docker_client_bytes" \
  --docker-client-sha256 "$docker_client_sha256" --docker-socket "$docker_socket"
sealed="$capsule/source/$lane"
handoff="$capsule/HANDOFF.UNISSUED.json"
python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" preflight
```

Use independently reviewed bytes and SHA-256 for the canonical executable
path. The canonical Unix socket must belong to the calling ordinary user.
Preparation seals their identities and socket endpoint into the handoff.
The sealed site preflight installs a child-process and socket fence, verifies
the staged inputs and Docker binding, and measures host capacity. Its result
should record `PASS_SEALED_UNISSUED_PREFLIGHT` and
`previous_claim_present: false`. The separate Root selection uses the
exact fields from `binding.UNISSUED.json`, with issuer `Root`, approval,
and a finite entry window. Staging leaves the binding unissued.

## Owned execution and independent readback

The site uses the separately issued Root selection and enforces a single
claim in the exact local user scope. Its offline rootless Docker container
uses the reviewed executable and socket, checks that the daemon actually
reports rootless mode, and requires the pinned local image. It uses 4 CPUs,
6 GiB memory, zero additional swap, and a
read-only root. QEMU uses TCG with read-only boot and scratch backing.
The only mutable data paths belong to this attempt's overlay and result
disk. The actor bounds the operation, monitors allocation and reserve,
and retains original commands and their separate streams with retirement.
An entry uses the exact target and deadline already recorded in the plan
and source.

```sh
systemd-run --user --scope --unit=cachy-asahi-qtbase16k-qtcore-link.scope \
  /usr/bin/python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" run --authority "$root_selection" \
  --authority-sha256 "$authority_sha"
```

After the user scope terminates, select the attempt from
`root-run.claim/attempt.path`. Capture the site observation in a fresh
file and independently pin its whole bytes. By default the independent
reader runs with a process and socket fence. It verifies the original
result ext4 and its exact files, including the build log, both 356-package
snapshots, the real ELF64 AArch64 shared library, its SONAME and 16 KiB
load geometry. It joins the observed symlink chain and bounded metrics.

```sh
python3 -I -B -Werror "$sealed/site.py" --handoff "$handoff" \
  --handoff-sha256 "$handoff_sha" observe --attempt "$attempt" > "$post_scope"
python3 -I -B -Werror "$sealed/readback.py" --output "$attempt/output" \
  --plan "$capsule/PLAN.UNISSUED.json" --plan-sha256 "$plan_sha" \
  --actor-result-sha256 "$actor_result_sha" --handoff-sha256 "$handoff_sha" \
  --authority-sha256 "$authority_sha" --post-scope "$post_scope" \
  --post-scope-sha256 "$post_scope_sha"
```

If a naturally retired attempt ended before it could write an actor report,
omit `--actor-result-sha256` and retain the other pins. The reader requires
the original nonzero attached exit and records the bounded diagnostic file
pins as HOLD.

The runtime may stop at its storage, memory, log, or time limit. The
checkpoint is for the single QtCore link with emulated 16 KiB pages.
QtGui, full Qtbase packaging, installation, and native validation have
separate execution and evidence requirements.

## Offline controls

```sh
bash -n "$lane/guest.sh"
for test in test_preflight.py test_guest.py test_site.py test_readback.py; do
  python3 -I -B -Werror "$lane/$test"
done
python3 -I -B -Werror "$lane/test_capsule.py" --capsule "$capsule" \
  --handoff-sha256 "$handoff_sha"
```
