# Proposed Perl 5.42.3 native adapter

This directory supplies finite proposed Source, producer, entry, and independent
Reader definitions for the held `5.42.3-1.3` candidate. It has not run a compiler,
namespace probe, native producer, entry, Original, operational Reader, or intake.
All publication, Source/ref/run/job/approval/artifact/image selectors remain NULL.
`native_acceptance` remains false, including in future successful DATA receipts.

Only this new directory changes. The candidate, 37-file native packet, generic
builder/entry/bootstrap, shared workflows, and manifests remain held. Runtime
helpers are unchanged copies with exact predecessor hashes in `helper-pins.json`.
The new Python and shell files use SPDX MIT; retained packet notices and licenses
remain intact. Upstream Perl is pinned to
`bc3dab4d4f66de5ea67dda34e5feb5230a54c603`; its 22,610,875-byte tarball hashes to
`16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`.

## Execution-domain gate

Source3937 (`3937d8b9f3210f4e9868bf19f01dfa22de64ddfe`) uses an ordinary image-build
`RUN USER alarm` execution domain, UID 1001. It does not establish namespace
support under this adapter's `PERL_ARM_CAP0_NNP_RO_CONTAINER_V1` domain. There is
no equivalence claim or fallback. `common.admission()` and the independent Reader
require a separate actual `PASS_NAMESPACE_EFFECTS` qualification from an
authenticated qualification Source, with the same run/job/image and canonical
domain hash. Source3937 is refused as that
qualification. Caller assertions alone cannot waive the effect or retirement
checks. No actual namespace qualification has been supplied here.

Root must authenticate and independently review the complete Source before any
import, authenticate canonical admission/qualification operands and their origin,
and own publication/readback, workflow routing, approval, and once-role handling.
Hashes bind bytes; they do not authenticate Root or grant authority. Root must
also qualify the native local Docker daemon and its host-visible DockerRootDir,
and prepare/admit the signed 349-package image and input-signature audit. A local
socket pathname and `docker info` are insufficient proof of daemon isolation or
identity. The image must have no inherited anonymous-volume declarations.

The proposed operation is `perl5423-native-pair-v1`; the frozen packet's proposed
operation is `perl5423-repro-native-pair-v1`. Root must integrate the distinct
operation explicitly. There is no automatic alias or lane exemption. Queue,
concurrency, and resource-class fields are proposals requiring Root integration.

## Adapter seams

* `entry.py` sets `SOURCE_DATE_EPOCH=1785628800`,
  `CACHY_ASAHI_PERL_BUILD=1`, `LC_ALL=C`, `TZ=UTC`, and `MAKEFLAGS=-j2` in the
  actual command environment. It retains the complete `/etc/makepkg.conf` and
  appends the exact `contract.json` suffix selecting `.pkg.tar.zst`, zstd with two
  threads, and `-j2`. Removing that suffix restores every base-config byte. Both
  configs are retained and independently checked across the pair. The explicit
  config argument is a reviewed seam; the frozen packet's old argv is unchanged.
* The ordinary command is `/usr/bin/makepkg --config /work/makepkg.conf
  --cleanbuild --nosign --noconfirm --log`. The frozen recipe runs its full
  `TEST_JOBS=2 make test_harness` check. No check filter or dependency waiver is
  added. The expected `cf_time` is `Sun Aug  2 00:00:00 UTC 2026`.
* `reader.py` checks actual package architecture `aarch64` against membership in
  the reviewed dual-architecture recipe. It parses native ELF machine 183; an
  upstream architecture declaration is not accepted as native build evidence.
* The libcrypt seam records the actual ALPM owner and database, both
  `/usr/lib/libcrypt.so` and `/usr/lib/libcrypt.so.2` symlink chains, and their
  shared canonical target. Native ELF SONAME must be `libcrypt.so.2`. Raw
  `readelf` evidence is joined independently with the ALPM records and ELF bytes;
  the recipe's literal `libcrypt.so` dependency is preserved.

## Finite producer and evidence

`producer.py` proposes two sequential fresh work volumes, each owned by a unique
nonce. Each build uses UID/GID 1001, 2 CPUs, 4 GiB memory, 4 GiB total memory plus
swap (zero added swap), 256 PIDs, no network, read-only root, cap-drop ALL,
no-new-privileges, init, and fixed bounded `/tmp` and `/run` tmpfs mounts. The
actual inspect records and entry-side cgroups/proc status must match. A separate
root initializer has only CHOWN capability and only changes ownership of the
fresh private work volume; it is not a namespace/build qualification actor.

Each full build has at most 2,400 seconds. The pair has 6,000 seconds including
180 seconds reserved for cleanup. All commands use the held `owned_child.py`;
success requires natural direct waitpid retirement and process-group absence.
Timeouts, forced retirement, ownership uncertainty, and cancellation cannot pass.
SIGINT/SIGTERM set a scoped flag observed after the owned-child witness exists;
cleanup defers repeated cancellation and restores previous handlers afterward.

Seven fresh capacity gates cover input snapshot, each volume, each actor, and
each export. The forecast reserves 2 GiB work, 64 MiB input, 512 MiB for each
remaining export, and 1 GiB reserve per actual filesystem device. It requires
120,000 available fixed-pool inodes and 8 GiB initial host MemAvailable. Unknown
or dynamic inode pools refuse and need a separately justified capacity model.
The work forecast is not a disk quota. While builds/exports run, a one-second
watch requires at least 1 GiB free disk per device and 4 GiB host MemAvailable.
Root's image preparation is outside these adapter allocation bounds.

Exports are plain `docker cp ... -` tar DATA. An inherited soft RLIMIT_FSIZE
caps stdout at 256 MiB, respecting any tighter existing limit and restoring the
parent limit. The raw tar and decoded copies account for the 512 MiB forecast,
an explicit change from the held packet's older export forecast. Both parsers
require one safe empty output root, at most 256 headers/64 flat regular files,
64 MiB per file, bounded PAX headers, safe modes, and a complete zero tail. They
refuse aliases, sparse files, escapes, and duplicates. Exports are never executed.

A passing producer transcript has 37 owned operations. It retains raw logs,
inspect results, output tar bytes, limit-restoration receipts, all entry output,
capacity observations, and initial/final resource lists. Build one is exported,
pinned, and retired before build two. Cleanup targets only the four named
containers and two private volumes and proves their final absence. It never
deletes Root's image. Failed runs retain a FAIL receipt and cannot qualify.

## Independent Reader

`reader_entry.py` is the future Root entry; `reader.py` does not import producer
or common implementation. Before artifact access, it requires authenticated
Source and actual matching namespace qualification. It independently joins the
37-operation grammar, lifecycle evidence, inspect records, capacity bounds,
raw export envelopes, exact input maps, full 349 inventory, provider evidence,
metadata, harness logs, staged runtime evidence, and raw package pair.

The actual package API requires Python 3.14 zstd support and bounds compressed
archive bytes at 64 MiB, decoded bytes at 160 MiB, members at 12,000, and each
member at 32 MiB. It compares every payload entry and raw archive bytes, checks
29 aliases, required native extensions and provider notices, and validates
actual aarch64 metadata/ELF. Harness counts must be positive and bounded; host
x86 test counts are not a native oracle. A successful result is
`PASS_NATIVE_PAIR_DATA`, with native acceptance still reserved to Root.

## Proposed Source construction and inverse

`profile.json` pins the 19 runtime leaves. Its SHA-256 is
`97b6e3f633fa6e4d76dc9e46951df893fa85121e107d4730e3522430efafd21d`.
`prepare.py` validates the complete immutable 37-file packet, prefixes it with
`packet/`, adds the pinned runtime leaves, and generates `inverse.json` plus
`source-map.json`. Deleting exactly the inverse's listed additions restores
every held byte/mode and the original tree. No predecessor file is rewritten.
The constructor uses the pinned filesystem-only atomic helper; it has no Git,
network, compiler, namespace, producer, entry, or Reader dispatch.

The retained real packet was rendered **in memory only**: 58 files, 24,157,085
bytes, proposed tree `a4da05070e53c291a81c2304a10de11552802f41`, source-map hash
`c6fc60aff2f57351aa6243abbc219ffd4d02ead39ef7727343022e7e8bc7cc43`.
No filesystem Source output or Source publication was performed. Root can
review the constructor's future DATA-only invocation:

```sh
python3 -I -B scripts/ci/perl5423-native-adapter/prepare.py \
  --packet /ROOT/IMMUTABLE_37_FILE_PACKET \
  --profile-sha256 97b6e3f633fa6e4d76dc9e46951df893fa85121e107d4730e3522430efafd21d \
  --output /ROOT/FRESH_PROPOSED_SOURCE_DATA
```

`definition.json` supplies explicit future producer/Reader argv with Root-owned
operands. The NULL templates are intentionally unrunnable admissions. No workflow
or manifest was edited to route them.

## Validation and limits

On Python 3.12.13 and 3.14.6, 15 Source/producer controls and 18 passive Reader
controls passed with subprocess, network, ctypes, fork, and exec fenced. The
Reader fixtures are synthetic DATA, including modeled AArch64 ELF and gzip tar;
they exercise parsers and refusal paths without a real artifact Reader role.
The composed positive fixture models build-data snapshots, while separate tests
exercise those parsers directly. See `validation.json` for the closure receipt.

Native namespace support, aarch64 builds, installation/removal for 1.3, 16K/M2,
installed ABI, external XS, performance, trust/legal-policy admission, and release
qualification remain unestablished. Earlier x86 host builds and 1.2 lifecycle
checks do not qualify these gates.
