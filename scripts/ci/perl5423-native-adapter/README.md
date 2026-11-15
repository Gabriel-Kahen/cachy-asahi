# Proposed Perl 5.42.3 ordinary container adapter v2

This unpublished revision builds the held `5.42.3-1.3` candidate through ordinary
configured makepkg in a non-root Docker build actor. It removes an unused
requirement that both nested bwrap/unshare effects be SUPPORTED. The actual
container, Source, daemon, signed349, resources, checks, provenance, independent
Reader, and retirement gates remain mandatory. New entry/init process proof is
also mandatory. No compiler, native actor, Source publication, or operational
Reader ran during this revision. All actual selectors remain NULL and native
acceptance remains false.

Only this adapter directory changes. The frozen candidate, 37-file native packet,
generic builder/entry/bootstrap, namespace sources, workflows, and manifests are
held. New code is SPDX MIT; unchanged runtime helpers retain their exact pinned
hashes. Root owns actual authentication, publication/readback, operation routing,
once-role handling, dispatch, and acceptance.

## Why the nested feature is unused

`source-audit.json` records a bounded DATA inspection of the exact source archive
SHA `16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`,
revision `bc3dab4d4f66de5ea67dda34e5feb5230a54c603`: 22,610,875 compressed bytes,
106,076,160 decoded tar bytes, 7,915 members. No extraction or upstream execution
occurred. All 18 held recipe leaves matched their byte/mode pins.

The selected path is Configure, `make -j2`, unfiltered `TEST_JOBS=2 make test_harness`, `check_config.pl`, DESTDIR installation, and the named local
staging helpers. The upstream Makefile/runtests/TAP harness and extension build
sources invoke ordinary local Perl/make commands. No concrete operation requiring
nested user/mount/network namespaces was found in that route. Bare upstream
“unshare” occurrences describe internal shared Perl data.

The candidate's optional standalone `test_staged_commands.py` DOES invoke bwrap.
It is absent from PKGBUILD `source[]` and is never called by the selected
prepare/build/check/package phases. This revision does not invoke or qualify it.
The static audit does not prove native success or external tool/configuration
behavior; actual unfiltered checks must still pass.

## Changed premise, unchanged physical domain

The operation is now `perl5423-native-pair-v2`; contract and admission schemas are
2. `domain.json` remains byte-identical to v1, hash
`6c6bdc29acf59e8ea911167f08d4d66a993777c121b2399211cec030e2a5b804`.
Its `PERL_ARM_CAP0_NNP_RO_CONTAINER_V1` name describes the physical container
policy, which has not changed. The semantic premise is explicitly
`ORDINARY_ROOTLESS_CONTAINER_NO_NESTED_NAMESPACE_PRECONDITION`.

The legacy `--qualification` operand now requires an exact schema-2
`ROOT_NATIVE_CONTAINER_ADMISSION_V2` receipt with status
`ROOT_ADMITTED_CONTAINER_PRECONDITIONS`. Root must authenticate it and its proof
objects. It binds the same fresh Source/run/job/image/domain, Source-readback and
actual native-daemon identity hashes, signed-input audit, and expected349 lock.
It does not predeclare a successful container or package result. Actual
create/inspect and per-build runtime checks establish those later observations.
Old namespace PASS/case schemas cannot satisfy this receipt.

Nested namespace invocation is always `NOT_INVOKED` and qualification always
`NOT_QUALIFIED`. Optional `--nested-namespace-diagnostic PATH` accepts at most
64 KiB of strict JSON object DATA, exactly bound by the receipt's byte/hash
`nested_diagnostic` descriptor. The original bytes are retained under inputs and
checked independently; DENIED, UNKNOWN, and other observations grant no feature
support or build authority. Descriptor/operand mismatches refuse before actors.
Source3937 and its separate run 43679486072 are not Perl qualification; this
revision takes no action on that run. No alternate lane or automatic alias is
introduced.

## Actual runtime and build checks

Each main actor remains UID/GID1001, 2 CPUs, 4 GiB memory, zero added swap,
256 PIDs, init, network-none, read-only root, cap-drop ALL, NNP, exact read-only
inputs, one private writable work volume, and bounded safe 64 MiB `/tmp`/8 MiB
`/run` tmpfs mounts. Root authenticates the actual local daemon and immutable
native image. Images with inherited anonymous volumes refuse. The distinct root
CHOWN initializer changes only ownership of the fresh private volume.

`runtime.py` reads bounded actual proc/cgroup/mount/interface observations before
makepkg. `runtime.json` binds admission, Source map, and domain to the actual
entry and init parent: native aarch64, complete credentials/maps/groups,
capability sets zero, NNP1, exact cgroups, namespace continuity, direct PPID1
lineage and start times, expected executable/argv, observed RO/RW/tmpfs mounts,
loopback-only interfaces, hostname, and page size. The independent Reader
revalidates this DATA before package credit. It imports no producer/runtime code.
These are existing-container observations; no nested namespace is requested.

The actual child environment fixes `SOURCE_DATE_EPOCH=1785628800`,
`CACHY_ASAHI_PERL_BUILD=1`, `LC_ALL=C`, `TZ=UTC`, and `MAKEFLAGS=-j2`. The complete
base makepkg config is retained with an exact invertible suffix for zstd output
and two compression/build threads. The command remains `/usr/bin/makepkg
--config /work/makepkg.conf --cleanbuild --nosign --noconfirm --log`, without
check filters or dependency waivers. Full harness failure remains failure.
`cf_time` must be `Sun Aug  2 00:00:00 UTC 2026`.

Actual package architecture must be aarch64 within the reviewed dual-architecture
recipe; ELF machine must be 183. The actual libcrypt ALPM owner/database, both
link chains, ELF SONAME `libcrypt.so.2`, and raw readelf output must agree.
All 349 packages, providers, notices, 29 aliases, required extensions, staged
runtime, metadata, config provenance, and raw archive/payload equality remain
independently checked.

## Bounds, retirement, and Source delivery

Builds remain sequential, 2,400 seconds each, 6,000 seconds per pair including
180 seconds reserved for cleanup. The unchanged owned-child primitive requires
natural direct waitpid retirement and group absence. Cancellation, forced
cleanup, or ownership uncertainty cannot pass. Scoped signal handling preserves
owned retirement and restores handlers.

Seven capacity gates forecast 2 GiB work, 64 MiB input, 512 MiB per remaining
export, and 1 GiB reserve per device; require 120,000 available fixed-pool inodes
and 8 GiB initial host MemAvailable; and refuse unknown/dynamic inode pools.
An active watch preserves 1 GiB disk/4 GiB host memory reserve. Forecasts are not
disk quotas. Root's admitted image preparation is outside these actor bounds.

Exports remain 256 MiB inherited-soft-FSIZE-bounded tar stdout, with tighter
existing limits respected and restored. Both parsers enforce safe bounded flat
DATA and complete tails. A passing transcript retains 37 owned operations, exact
inspect/log/export evidence, retirement of build one before build two, and final
absence of only the four owned containers/two volumes. Root's image is retained.
Actual package decoding still requires Python 3.14 zstd, 64 MiB compressed/160 MiB
decoded limits, 12,000 members, and 32 MiB per file.

`profile.json` pins runtime definitions, audit, and helpers. `prepare.py` adds
these leaves to the unchanged packet and emits the complete Source map and
additions-only inverse. Root reviews/constructs/publishes the fresh Source; only
an in-memory proposed render was checked here. `definition.json` supplies future
Root argv, with optional diagnostic handling described above. The NULL templates
cannot dispatch a build. `validation.json` records current hashes and controls.

Actor-fenced controls on Python 3.12.13/3.14.6 use synthetic DATA, not native
qualification. Native Perl, native 16K/M2, installed ABI/external XS, performance,
trust/legal-policy admission, and release acceptance remain unestablished.
