# Passive independent XS Original reader

This reader is outside the already published297-file XS Source. It changes no
producer, entry, fixture, constructor, workflow or shared manifest. Authoring
checks have not consumed an actual XS Original or produced an operational
Reader verdict. Root reported run43705018149/job132784130584 in progress; the
Original artifact had not been acquired at that handoff.

`scripts/port/perl5423-xs-consumer/native_adapter/independent_reader/reader.py`
accepts a separately whole-pinned external Root binding, the complete published
Source tree, the opaque Original ZIP, its retained artifact metadata and the
exact materialized evidence tree. It makes no network request, starts no child,
uses no daemon or lease, imports no producer/actor/package code, and extracts or
loads no package. Its pinned support modules are passive archive/ELF/DATA
classifiers copied unchanged from the existing native reader. Root's independent
worker admission, execution custody, authentication and acceptance stay external.

## Exact Root operands

Use Python3.14+ for its bounded stdlib zstd decoder. Root supplies these files;
the Reader never acquires them:

| CLI option | Root operand |
| --- | --- |
| `--binding` | Actual external JSON following `binding.TEMPLATE.json` |
| `--binding-sha256` | SHA256 of that entire external file |
| `--source-root` | Complete exact297 Source bytes/modes, without unrelated files; a real `.git` directory may be present |
| `--original-artifact` | Authenticated opaque Original artifact ZIP, at most512 MiB |
| `--artifact-metadata` | Retained GitHub artifact metadata object, not a list wrapper; its whole hash is in the external binding |
| `--evidence` | Exact regular-file materialization of that Original ZIP, with acquisition/worker/Reader sidecars outside this directory |

Root has supplied the following current binding values. These remain external
to the reusable Reader and its null run/job/approval/artifact template:

```json
{
  "source": "0885f89ab7a4301bbdf9c4b180620fb447d9a41a",
  "ref": "refs/heads/codex/native-arm-perl5423-xs-v1-20261115",
  "run": "43705018149",
  "job": "132784130584",
  "approval": "6018831011cca72f36954c4d01133802bcd2da16a61c0f803aaa3054d1850406",
  "source_map_sha256": "674cc3d18e954dd1f3f351b357f746e3b9ab1b7580370666061fcb9deeb15efc",
  "operation": "perl5423-native-xs-v1"
}
```

Wrap those seven fields in the template's `binding` object. After Root's
Original acquisition, fill `artifact.id` (decimal string), `artifact.bytes`
(actual ZIP length), `artifact.sha256` (actual whole ZIP digest), and
`artifact.metadata_sha256` (whole retained metadata object digest). Null or
missing fields refuse; elapsed time is no replacement for an actual operand.
Artifact metadata must join that Source/run/ref, declared byte count and name
`perl5423-native-xs-v1-43705018149-1`. It does not independently authenticate an
artifact: Root must establish origin and custody before this passive role.

The future Root entry point is:

```sh
python3.14 -I -B -Werror::ResourceWarning \
  scripts/port/perl5423-xs-consumer/native_adapter/independent_reader/reader.py \
  --binding /Root-owned/actual-xs-reader-binding.json \
  --binding-sha256 ACTUAL_WHOLE_BINDING_SHA256 \
  --source-root /Root-authenticated/exact297-source-tree \
  --original-artifact /Root-authenticated/Original-xs-artifact.zip \
  --artifact-metadata /Root-authenticated/artifact-metadata.json \
  --evidence /Root-owned/Decoded-Original-xs
```

Keep stdout/result custody outside the evidence directory. Root's existing
owned worker must supervise the actual Reader; the program's240-second DATA
deadline is checked during bounded operations, not an independently interruptible
guarantee for blocked filesystem/kernel calls. No actual invocation is authorized
or implied by this documentation.

## Checks and finite scope

The reader independently hashes all297 Source files/modes and recomputes Git
tree`6a1c29b7aa1655943b54de71a89f3900ff1671c9`; it verifies the exact272 held
subtree/map/tree and identical dedicated workflow aliases. Captured natural Git
HEAD/tree streams join every Source blob and mode to the job/Root binding.

The whole Original ZIP digest and artifact metadata must match the external
Root input. Every unique bounded ordinary ZIP member must match every retained
file, with no omissions or extra files. Paths, aliases, symlinks, executable or
special member modes, encryption, unsupported compression and unsupported
extension metadata refuse. Known bounded ZIP64 sizes and UTC timestamp fields
are inert metadata. Original members are capped at256 MiB,4000 headers/1 GiB
decoded, and the retained tree at3000 files; nothing is extracted by the reader.

The bootstrap audit joins all517 transport inputs,257 recorded GPG verification
results and their exact raw naturally retired command streams, signed349 lock,
native image, Rootful unremapped daemon/socket observations, input preparation,
explicit delegation, CPU/memory/swap/PID/capability/network/read-only policies,
owned resource identifiers and final absence. It checks every ordered bootstrap
and native operation, including the22 native producer CLI operations, raw
inspect records and complete bounded flat DATA export. GPG status observations
are checked; this passive program does not rerun cryptographic verification.

The consumer audit independently parses the exact accepted package archive
(22071176 bytes, SHA256
`647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22`),
using the pinned package/ELF reader with64 MiB compressed/160 MiB decoded,
12000-header/32 MiB member/128 MiB decoder-window/90-second bounds. It derives
the complete ordinary selected runtime/header/Config/libperl map, joins actual
package metadata and every prepared bundle descriptor, and reconstructs the
exact four argv arrays and replacement environment without importing preflight.

Every command must have natural zero exit, direct reap, absent owned group,
correct raw stdout/stderr pins, finite wall limits and successful owned stage
cleanup. Actual runtime/init/cgroup identities, cap0/NNP/seccomp, no network,
private bounded mounts and unchanged process/thread/resource counters must
agree. Makefile, compiler dependency file, generated C/AArch64 object/extension,
actual Config/module/header/libperl/extension paths and hashes must join the
archive map, captured receipts and their raw provenance. Harness and standalone
module closures may differ (Test::More is loaded by the harness); each closure
must remain inside its allowed candidate namespace and agree on candidate facts.

The frozen test source binds the21 assertions to version/API, undef/zero/-7,
empty/NUL/Unicode strings and UTF8 flags, signed IV64 zero/-1/extrema, array
contents/UTF8 flag and actual extension path. The reader requires the exact
roundtrip file and complete21-assertion harness PASS, plus matching runtime and
standalone provenance. When successful TAP/value lines are suppressed by
Test::Harness, this establishes source-bound assertion evidence, not a fabricated
per-value runtime trace. The removed stage and image tool binary bodies are not
exported; their proof is the pinned Source/runtime guard under Root's admitted
image, with those limits reported explicitly rather than claiming direct rehash.

`PASS_SCOPED_XS_ORIGINAL_DATA_CHECKS` is a DATA result only. Every result retains
`Root_authentication=false`, `Root_acceptance=null`, `native_acceptance=false`,
`XS_acceptance=false`, and `qualification=NOT_GRANTED`. It grants no installation
lifecycle, general XS ABI, native16K/M2, performance or release acceptance.
Missing, contradictory, substituted, partial or failed evidence returns refusal.

Authoring controls cover missing external inputs, null binding, JSON/path/archive
tampering, forced/unobserved retirement, bootstrap ordering/signatures/policy,
consumer harness/provenance/runtime boundaries and export integrity. These
synthetic component controls create no operational success receipts and do not
constitute an actual XS Original Reader run.

The standalone Reader's12-file source inventory is pinned by
`independent_reader/profile.json`, SHA256
`434821d642582ce233a33fd7f8e7408370d035ca24b9ce1cad4f98570afcd310`.
That inventory is DATA for Root's separate Reader admission and creates no
authority. Six transport/binding, four bootstrap and eleven consumer controls
pass on Python3.12.13 and3.14.6; actual runtime requires3.14+. A separate
actor-fenced Source-only component check verified all297/held272 bytes, modes
and Git trees without consuming the running job's evidence.
