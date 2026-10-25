# Exact Core47 → Core49 source factory

This pure factory takes the complete ordinary public47 source tree at
`3a5b0a33f469e4de4f3f85a87bc53815556e1430` and reproduces every byte of public49
`fce485162569f090fbedd5fc2e3faaf78d05d7d8`. Supply exported ordinary trees, not Git
administration or development-author directories. No development paths, actual
archives, API credentials, native actors or installed state are used.

```bash
python3 -I -B -Werror scripts/ci/core7-mime-cache-source/prepare.py \
  --source /absolute/exported-public47 --output /absolute/fresh-output \
  --context known
```

`--context null` emits the same49 source bytes with NULL source/ref receipt
identity. Both receipts have actual=NULL and native_acceptance=false. Output must
be fresh, absolute, normalized and disjoint from the supplied input and factory.
Destinations named as native actual roots are also refused.
All source/profile/payload content, stable descriptor identities and complete
namespace membership are checked early and again before writes. Read atime is
excluded from identity. Source aliases, hardlinks, special files, unknown/empty
directories and late mutation/replacement refuse. The factory starts no actor.

The finite transformation preserves39 files, changes8 and adds2 readable
operands. Complete before/after maps, one-count seams and the whole47 inverse are
sealed by the entry point's profile pin. The original ordinary ALPM command,
default90/candidate180/graph1200 and all other security/clock/runtime bodies are
held, including the existing three generated-cache commands. One obsolete test
assertion now checks the actual normal command and held180/default90 contracts.

The unchanged published MIME helper/profile permit only the exact six original
XML inputs, signed-source generator/hook and1,084 explicitly listed added nodes
with complete hash/mode/uid/gid. Unknown nodes or input/mechanism changes refuse;
there is no prefix-wide permission. Its original source ancestry guards remain
part of emitted source entry qualification. The factory does not reissue archive
signature verification or native acceptance; the original native crypto,
whole-root, hook, PID1, boot and retirement gates remain required.

Portable checks use only supplied pinned public47/public49 trees:

```bash
CORE_MIME_INPUT=/absolute/public47 CORE_MIME_EXPECTED=/absolute/public49 \
  python3 -I -B -Werror scripts/ci/core7-mime-cache-source/test_source.py
```

Tests exercise real known/NULL CLI reproduction, complete emitted source entry,
all seven current initramfs tests, whole inverse/held-body checks, real late
same-byte inode replacement/profile drift, FD/read-atime behavior, prewrite
refusals and the exact MIME-node/hook policies. The dedicated read-only Python
3.12/3.14 workflow exports only two pinned public source fixtures. It acquires no
native evidence. M2, hardware, installed/boot behavior and performance remain
separate, unqualified by this factory.
