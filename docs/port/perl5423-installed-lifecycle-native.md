# Hosted installed Perl lifecycle Source constructor

This is a Source/DATA adapter, not an installed or hardware-tested result. It
pins lifecycle core `7bf0da67717ea24f0b1782f8505967c48b64b0b0`, including normal
`pacman -R perl` dependency refusal before upgrade, and the frozen signed349
bootstrap Source map
`4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96`.
Only the new `scripts/ci/perl5423-installed-lifecycle-native/` subtree and this
document belong to this change. Shared workflows and manifests are untouched.

The proposed operation is `perl5423-installed-lifecycle-native-v1`. Its generated
workflow has identical dedicated and `native-arm-build.yml` aliases, first manual
attempt only, and shares the existing `native-arm-build` concurrency lane. Root
must separately admit a new exact published Source/ref/map and resource policy.
The templates are deliberately unadmitted; constructors cannot turn their null
fields into Root authority.

## Inputs and current stopping point

`available-inputs.DATA.json` records the nine concrete public input paths, sizes,
SHA256 values and observed modes, plus the accepted candidate, external TEST
signing record, baseline archive review and Root baseline review. These files
were read and hashed as DATA. No package archive was parsed in that inventory,
and its status grants no admission. The candidate is the accepted native ARM4K
build from Source `25dc3e65bdb6137c87a9409067fe9b2cf6e9763f`, run
`43692477455`; candidate bytes are unchanged. Root supplied the TEST signature
and public-only combined trust bundle. This worker created no signer or secret
key and performed no cryptographic verification.

Before sealing, Root supplies a complete record matching
`prerequisites.TEMPLATE.json`, with its independently provided SHA256. It must
join all nine actual input descriptors, the accepted-build decision, the exact
archive-derived `baseline-review.json`, external public-trust review, and the
following image/policy expectations:

- Exact `/etc/pacman.conf` mode, size and hash.
- Complete path/type/mode/hash or link-target snapshots for
  `/builder-disabled-hooks`, `/etc/pacman.d/hooks` and
  `/usr/share/libalpm/hooks`, including explicitly absent roots.
- Explicit review of the lifecycle transaction's `/work/pacman.conf`, which has
  **no HookDir directive** and uses ALPM's default hook directories. Bootstrap
  `/etc/pacman.conf` uses `/builder-disabled-hooks`; preserving its bytes does
  not establish equivalent effective transaction hook policy.
- Explicit review of the separate Root writable native ARM4K ALPM domain and
  external TEST/public trust provenance. No nonroot read-only XS/LLVM domain
  qualification is reused.

The existing Root baseline input review covers the exact old signed archive and
ordinary frozen349 rollback input. It does not supply the complete fresh-image
snapshot or this operation's whole prerequisite/admission record. Until those
are present, the constructor refuses before loading the held archive parser or
publishing a Source tree. No actual Source packet, Source/ref/map approval,
native dispatch, image qualification, installation, or operational Reader result
has been produced by this change.

## DATA construction

With the complete external Root record in place, run from an ordinary private
directory, using absolute, disjoint paths:

```sh
python3 -I -B scripts/ci/perl5423-installed-lifecycle-native/prepare.py \
  --frozen-source ROOT_FROZEN272_SOURCE_TREE \
  --lifecycle-source ROOT_PINNED_CORE_DIRECTORY \
  --input-review ROOT_COMPLETE_PREREQUISITES_JSON \
  --input-review-sha256 ROOT_PREREQUISITES_SHA256 \
  --output FRESH_SOURCE_TREE
```

`--lifecycle-source` points at the core's
`scripts/port/perl5423-installed-lifecycle` directory. The constructor checks the
complete frozen Source closure and every held core byte/mode, runs only the
core's pure DATA preparer, and rejoins its generated baseline review to Root's
already pinned archive review. Core-generated files become protected DATA;
`source-map.json` is explicitly sealed `0444` independent of caller umask.
An opaque deterministic tar preserves those exact `0444` modes inside ordinary
Git `0644` Source. No fabricated mode conversion through Git is used.

The output contains original200 bootstrap leaves, pinned lifecycle code, the
public capsule, Source-pinned input review, two identical workflow aliases, a
complete byte/mode map, and an inverse that removes the exact additions and
restores original200. Actual Source/ref/run/job/approval/image/container/Reader
selectors remain null. Bounds are 320 Source files/96 MiB, capsule 64 members/
48 MiB, and constructor address space 512 MiB. Publication is fresh, atomic DATA
publication; package installation/removal is outside the constructor.

## Proposed native role

After independent Root publication/readback/admission, the workflow verifies the
complete Source before existing secrets, reuses frozen retained/public input
transport, materializes only the Source-pinned capsule, and seeds the exact
already retained old Perl archive/signature into the existing cache. It contains
no new package/source downloader or fallback URL.

The fresh signed349 bootstrap is followed by a distinct Root UID0, cap0,
read-only, network-none metadata container (one CPU, 256 MiB, no swap, 32 PIDs).
It records the actual ARM4K runtime, lock, config, complete hook maps and fresh
baseline public-file facts. Root's complete expected metadata must match before
the writable lifecycle actor starts. Fresh bootstrap trust-file bytes are
observed rather than predicted, because bootstrap's local public key generation
is not deterministic. The metadata probe issues no writable-domain admission.

The held lifecycle producer uses Root UID0 with a writable disposable container
root and only the core's reviewed capabilities, network none, two CPUs, 2 GiB,
no swap and 128 PIDs. Its only host bind is read-only `/inputs`; work/run/tmp are
bounded tmpfs. It checks dependency-protected removal refusal, trusted upgrade,
repeat/needed behavior, exact rollback, interpreter/module semantics, inventories,
raw database and protected state. Signing credentials are excluded.

The proposed total native envelope is 5,700 seconds: active 5,460 seconds
(bootstrap 4,500, lifecycle producer 660, metadata 120, coordinator reserve 180)
plus cleanup 240. The step is 96 minutes; the whole job is 120 minutes. Root
still reviews this proposal. Failed or uncertain owned-resource cleanup remains
failure; no daemon restart, broad prune, or cleanup of unrelated objects exists.

The native job retains original evidence and stops pending separate Root review.
It never invokes `hosted/reader.py`. That later DATA wrapper requires an
externally authenticated exact Source/ref/run/job/approval/image binding and
original producer-report hash, checks the frozen257 signature observations and
their original raw owned-command channels, bootstrap image/Source joins, image
metadata, and delegates lifecycle DATA checks to the pinned core Reader. Its
result is consistency evidence, not release or M2 acceptance.

## Validation and remaining holds

Run the fenced DATA controls with:

```sh
python3 -I -B -m unittest discover \
  -s scripts/ci/perl5423-installed-lifecycle-native -p 'test_*.py' -v
```

Controls use temporary text/JSON and synthetic capsule fixtures. They exercise
refusal ordering, protected modes/private umask, exact pins, complete maps and
inverse, bounded metadata domains, complete hook expectations, public trust
observation and malformed capsule rejection. They do not execute package bytes,
GPG, Docker, ALPM, Perl, a native actor or the operational Reader. See
`validation.json` for actual counts and limitations.

All existing original4/source108/native16K/M2/performance/current-distribution
trust/release holds remain. No hardware or performance claim follows from this
Source adapter or its DATA controls.
