# XS v2: preserve the accepted package's read-only runtime modes

Actual XS v1 run43705018149/job132784130584 failed before the XS producer.
The signed349 bootstrap built its image; preparation then exited1 at the mode
guard in `xs/prepare_inputs.py:108`. Source0885f89ab7a4301bbdf9c4b180620fb447d9a41a,
its297 files, original POST/run and all original evidence remain unchanged.

The guard was too restrictive. The first rejected tar member is
`usr/lib/perl5/5.42/core_perl/B.pm`, mode`0444`,31346 bytes, SHA256
`0a8e0afeb5115f039d64d2495675b894000e22fb3e3726c8a85a55ef511108a3`.
The count and byte limits were not exceeded. Bounded read-only inspection of
the exact accepted archive found:

| Archived selected-file mode | Files |
| --- | ---: |
| `0444` | 1587 |
| `0555` | 53 |
| `0644` | 229 |
| `0755` | 1 |

All1870 selected regular files total74426813 bytes. The archive is unchanged:
22071176 bytes, SHA256
`647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`.
It contains3262 payload nodes and54 ELF files. The two read-only modes are
legitimate package inputs, including modules/headers and shared ELF objects;
preparation must not add write bits to them.

## Exact correction

Only the new `native_adapter/hosted_source_v2/` route changes preparation. Its
`runtime-files.json` is the complete archive-derived path/byte/SHA256/mode map:
349767 bytes, SHA256
`7004309f83344b49f0f8ca598d8cefcffbc078450944824849ab9c575f1c0cd2`.
The future preparation actor first verifies this whole pin, exact1870-file
namespace, byte totals and mode distribution. Every selected tar member must
match its exact reviewed descriptor. Missing/extra members, aliases, altered
bytes/hashes/modes or unsafe modes refuse before prefix creation.

The allowed ordinary modes are exactly0444/0555/0644/0755, and the per-path map
further constrains which one each file has. The second DATA pass rechecks all
archive rows, copies bytes, applies the archived mode with `fchmod`, and checks
actual regular single-link ownership, bytes and mode. The frozen preflight then
rehashes the actual closed prefix and exact mode map before planning the four
commands. No archive byte or mode is normalized or rewritten.

Architecture, ownership, no-alias/special-file policy,32 MiB per-file,
5000-file/128 MiB selected budget, bounded single-frame decoder,8192 headers,
256 MiB decoded/64 MiB window/90-second preparation deadline, exact metadata,
toolchain pins and the main actor's read-only prefix bind remain in force.
The original fixture, preflight, runner and native consumer engine are unchanged.

## Separate Source and authority lineage

New outer operation is`perl5423-native-xs-v2`, with dedicated alias
`native-arm-perl5423-xs-v2.yml` and proposed fresh ref
`refs/heads/codex/native-arm-perl5423-xs-v2-20261115`. The dispatcher alias remains
`native-arm-build.yml`, with the existing shared concurrency group, queue:max
and cancel-in-progress:false. Root must issue fresh Source/readback/authority
and perform any actual dispatch; v1 is not replayed or reopened.

V2 delegates the four commands to the byte-identical native consumer engine
whose inner operation is still`perl5423-native-xs-v1`. This is explicit reuse
of the frozen executor, not a claim that its implementation changed. The new
outer Source/run/job/approval and reviewed mode-map pin bind that delegation.
The signed349 bootstrap, finite resource controls and cleanup code are retained.
All new actual Source/ref/run/job/Reader/authority/approval/artifact/image
selectors remain null in emitted declaration data.

The v2 constructor consumes the exact prior297 Source, verifies every file and
mode/map/tree, and derives a new298-file Source. All held272, consumer13,
accepted archive/metadata/Root decision and license bytes/modes are preserved.
Only the new payload, dedicated workflow/provenance/map and additional reviewed
runtime map differ. Constructor publication is fresh disjoint filesystem DATA,
not Git publication or a Source/native/Reader job.

```sh
python3 -I -B scripts/port/perl5423-xs-consumer/native_adapter/hosted_source_v2/prepare.py \
  --previous-xs-source /Root-authenticated/exact297-xs-v1-source \
  --profile-sha256 c633adbfba721687a3158466e42a4e68307f27b64f9b87b94aded9da209bd719 \
  --output /Root-owned/fresh-xs-v2-source
```

Constructed private DATA candidate:
`/tmp/perl5423-xs-v2-source-DATA-20261115-r1/source-tree`.
It has298 files/87360147 bytes; map58527 bytes SHA256
`9255e7853758069a4ed23eb89872a162fdb116b6a86fc7e3c03914a8df9c0c03`,
prospective Git tree`38e123007884b0c237c16479574145f433939e6a`.
The reviewed v2 profile is981 bytes SHA256
`c633adbfba721687a3158466e42a4e68307f27b64f9b87b94aded9da209bd719`.

Seven mode/map/copy DATA controls and three constructor/lineage controls pass
on Python3.12.13 and3.14.6. Read-only first-pass inspection of the actual accepted
archive matches every manifest row; no actual prefix was materialized. Mode
preservation copy tests use explicitly modeled temporary bytes, including
0444 module/header and0555 ELF-like data. Both versions also pass payload AST
and complete actor-fenced v2 Source DATA joins. No preparation main, Perl,
compiler, XS, container, job, network, lease or Root authority role ran here.

## Preserve the failed run's cleanup facts

The new passive `independent_reader/failure_v1/failure-audit.json` records the
original717865-byte artifact14158466920, SHA256
`475ecba33fc5fee2109c94c0d3b82b6eab75863c38226d39f8a4fb478d563ef9`,
all586 decoded files/4679877 bytes, captured raw stream pins and the exact
failure/cleanup observations. It creates no operational Reader verdict.

Operation270's attached prep CLI naturally returned1. Inspection273 shows the
prep stopped with PID0/exit1 and no OOM;274 removed that exact stopped container
with plain `rm`. There was no `stop` command or forced removal. The named prep,
inventory probe, image ID and owned aliases are subsequently absent. The
original generic cleanup error, overallFAIL, empty preparation receipt, null
producer result and Root HOLD remain recorded. Final absence does not turn
that failed preparation into success or erase the generic retirement hold.

The existing independent v1 reader already supports archive-derived0444/0555
maps and correctly refuses a failed top-level run. It is not loosened. A future
v2 Original needs a separately Root-admitted reader binding to its new Source
and outer operation; no current v1 scoped verdict can be transferred to it.
XS, installation, general ABI, native16K/M2, performance and release remain
unqualified until their actual independent evidence and Root decisions exist.
