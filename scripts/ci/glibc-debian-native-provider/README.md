# Debian-source native provider pair

Manual native aarch64 build/test lane for the distinct unselected `2.43.caa2-1`
conventional `/usr` provider. Source authority is the independently Root-bound
Debian chain in `scripts/ci/glibc-debian-provider/authority.json`, not the earlier
GNU source/pair admission. The immutable eight-file carrier is
`05d07fd634cb004eb7feab6e5fa9b175c5687efa:payload/`; seven source/authority files
are 33,814,609 bytes, with a 1201-byte index. Current signature/key/freshness
checks run again on the real clock before any native actor or private secret.
Expired metadata refuses this fixed packet; a refreshed chain needs a new
explicit Root source/authority/packet decision, not a clock waiver.

The integration manifest closes the source/helper/recipe dependencies. Source
must equal workflow and checkout revisions. The canonical Debian adapter pins
17 original helper files, copying 14 byte-for-byte, renaming two, and adapting
only two metadata version constants. Its new entrypoint calls the unchanged
native executor's `execute`, not the original admission-bearing CLI. The old
GNU acceptance/bindings and private16K result are neither copied nor called.
Fresh native execution uses the unchanged frozen574 producer, 14 public cache
files and six existing private cache inputs. Private inputs and whole574 roots
are never included in the public export. No Asahi platform package is selected,
installed, or removed on the host.

Two independent builds must pass fatal upstream tests (no FAIL/XPASS/ERROR),
ABI checks, metadata/dependency/payload ownership checks against all574,
compiler header checks with no bootstrap fallback, eight staged runtime cases,
and normal-interpreter parent/child probes with 13 actual compilation commands.
Both package archives and normal probe binaries must reproduce exactly. Existing
source/authentication, full upstream summaries, ABI/stage/ownership, header,
runtime, normal compiler and package metadata receipts remain required. Existing
runner status names are preserved and qualified by the distinct source receipt
and caa2 package version; no previous native result becomes evidence here.

Native containers retain `--network=none`, readonly root, all capabilities
dropped, no-new-privileges, ordinary caller UID, 12GiB memory, four CPUs, 1024
PIDs, nofile8192 and 512MiB tmpfs. The unchanged executor requires 40GiB measured
free space, gives each build 6300s and smoke900s inside its 15000s runner bound.
Workflow job360min, producer2300s/40min, pair280min, cleanup15min, export3min.
Cancellation handlers and exact ownership/lease/label/image checks retire the
five possible consumer names before the producer; foreign/unknown consumers
preserve the producer. Cleanup uses only the local default Unix Docker daemon.
Consumer ownership tokens and labels have a separate Debian namespace.

`reuse.py` SHA-pins the original owner and preserves its cleanup functions
unchanged. Exactly four counted retention edits accept an explicit emitted
harness, remove the fixed old harness path, permit the Debian archive plus
12MiB Sources index under the existing 96MiB source cap, and qualify the final
success status as Debian. Before export the owner rechecks the exact preparation output manifest pin and
its closed, flat, at-most32 files, preventing an emitted-path change from
expanding the export. All other per-file bounds, required proof checks and
768MiB aggregate cap remain unchanged. Export is a closed list of public source,
new packages, compiler artifacts and bounded evidence/log tails; no rootfs or
broad workspace upload. Evidence retention is three days.

Source-only controls: `python3 -B -m unittest discover -s
scripts/ci/glibc-debian-native-provider -p 'test_*.py' -v`, the candidate's 11
controls, and unchanged maintained574 controls. Synthetic packet/daemon tests
never grant authority or native credit. This proposal has no native result,
installation/lifecycle/recovery, generic16K, M2 hardware, security review,
performance measurement or release admission. Root must integrate and dispatch
its exact source revision and assess the actual resulting receipts separately.
