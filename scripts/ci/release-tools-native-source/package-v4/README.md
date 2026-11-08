# Opt-in release-tools 0.4 finite package factory

This is a DATA proposal for the existing `release-alpm-upgrade-v1` journey,
using original 0.1.0-1 as predecessor and merged 0.4.0-1 as target. It does not
modify the 0.1–0.3 recipes, historical Source201 variants or their readers.
It is not a native result, admission, installation or release approval.

The parent is exact Source `686958cf7a3248fc0ef33ad4b61ffd22a325c4e5`,
tree `bcf78785cd46a2acc75c772f9f6ba21f7bd831b0`: 201 leaves with a
200-row source map. Exactly seven emitted leaves change; 194 remain byte/mode
held: the source bundle, release contract, two release producers, projection,
matching reader and regenerated source map. The projection changes only its
three producer hash literals. All non-target producer/reader predicate functions
are held by recorded parent AST pins and focused DATA controls.

The 51-member canonical USTAR bundle is 942,080 bytes, below the inherited
1 MiB limit. It retains all 18 original v1 recipe leaves and adds the exact
33-leaf v4 recipe from source head `c393c38043bd34f2380ceab55434a59c2d3183d1`,
genuinely merged by PR400 as `0dc457ae4a785bfa273890d84114d52f0cf87c17`
(tree `c40548c13d014c15716d04a6dfca5fefcd5a779d`). The new contract binds
31 source checksums, 17 retained runtime files with exact MIT origins, 23
installed files/modes, the transport's seven dependencies and all nine launcher
runtime pins. The original Topmem recipe fixture remains unchanged. A v3→v4
bundle would exceed the existing cap and is outside this variant.

The target keeps protocol prefix `v2`; that name identifies the upgrade leg,
not package version 0.2. The future actor requires actual 19-control `check()`
output, signed package installation under the existing TEST-only policy,
all eight business commands through both `/usr` and a moved prefix, signed
withdrawal copy/pack/unpack and real synthetic-stable CLI refusals. New external
fixture/signing/verification commands use the existing owned run journal;
its 160-command bound is unchanged. The matching reader requires those exact
argv, outputs, signatures, archive and producer pins. Host package controls and
file inverses do not establish any native upgrade result.

The fixed 349-package base already contains the added explicit libarchive
3.8.9-1 dependency. Its inventory, input locks/signatures, process retirement,
PID1, resource limits, ownership, transport and native acceptance predicates
remain unchanged. Prior failures remain failures; no result is migrated.

`prepare.py` exposes a pure metadata plan and an explicit future Root-only
constructor. The latter authenticates the externally supplied profile SHA,
complete parent namespace/bodies/modes/OIDs, all six payloads and exact new map,
then writes a fresh private Source directory. Import never constructs or runs
anything. Tests and the dedicated workflow use only metadata/AST/bundle DATA;
they never call the constructor or execute the reader, native or image actors.
Root alone constructs/publishes an actual Source, admits/dispatches native work
and runs its matching reader. Main and canonical inventory remain coordinator
owned.

Reviewed profile: `profile.json`, SHA-256
`32a7b49878d1dfe244914b73ff8a4ec2f42153582d664b72b5630ad7d1d3101a`.
Proposed metadata tree: `c42c5613b09040d0f14dddc851452ec61c213909`;
map SHA-256 `bfee786c2dbcbad2e5dae8d5294784ad34c386b382700083e2ae8fb84e499c8f`.
These are calculated DATA, not an emitted or committed Source.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/release-tools-native-source/package-v4/test_prepare.py \
  --profile-sha256 32a7b49878d1dfe244914b73ff8a4ec2f42153582d664b72b5630ad7d1d3101a -v
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/release-tools-native-source/package-v4/test_reader_data.py -v
```

Future Root constructor command, after separate Root qualification:

```sh
python3 -I -B scripts/ci/release-tools-native-source/package-v4/prepare.py \
  --parent-source /absolute/Root-owned/exact686-parent \
  --output /absolute/Root-owned/private-parent/absent-v4-Source \
  --profile-sha256 32a7b49878d1dfe244914b73ff8a4ec2f42153582d664b72b5630ad7d1d3101a
```

That constructor command has not been invoked by this task.

Actual Source construction/publication, native ARM, ALPM, target installation,
16K, physical M2, performance and release acceptance remain NOT RUN or NOT
ADMITTED for this variant. The existing 19 host package controls are separate
evidence and confer no ARM acceptance.
