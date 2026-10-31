# Native ARM4K updater source factories

This source-only factory reproduces two separately published ten-file wrappers over the complete immutable489-file updater implementation `b21a5864d5a4610b9181a1c270ac8821d8448a17`:

| Explicit profile | Exact source | Scope |
| --- | --- | --- |
| `normal` | `94297073ac36f257edd118aceba3e375a7148550` | Full copied-root native ARM4K normal update |
| `recovery` | `c75911fe09fb5ceba1e54a6456d5b9c4721960b6` | Separate precommit-exit86 and postcommit-exit87 cases |

Pass an ordinary complete b21 checkout and a fresh disjoint output directory:

```sh
python3 -I -B scripts/ci/updater604-native4k-source/prepare.py \
  --held /absolute/b21-source --profile normal --output /absolute/fresh/source
```

The profile is required. Generation reads and authenticates the whole pinned input and every used readable payload before creating output. It reproduces both workflow aliases, source manifest, NULL actual fields, original runtime and complete input/trust/retirement policies byte for byte. It executes no actor, package operation, Git/API call, reader replay or GPG operation; private caches and filesystem roots are not expanded into output.

The original full owner, fresh observation/copy/hash/capability/link/security checks,604 inventory, signatures, checkpoint decisions and ordered cleanup remain source-held. Both wrappers require actual aarch64 Linux4096-byte pages and disposable Docker custody. Their native workflow retains all55 steps and original enclosing clocks. Failure driver2400 belongs to the original interruption cases; normal driver1860 is unchanged. Stage/copy1200, verification600, enclosing3900, lifetime cleanup60, wrapper15600 and job21000 remain unchanged. Nested allowances are nonreserved and do not promise completion within the enclosing clock.

Hosted read-only CI checks exact output against both pinned public sources on Python 3.12 and 3.14, with drift, missing, extra, alias and refusal controls. It runs all 11 normal and 10 recovery controls from the actual emitted sources, including the original three prerequisite decision parser. Those accepted decisions authorize inputs only. Source generation performs no actual qualification or acquisition. Existing source factories and defaults are unchanged.

Root separately accepted the finite normal4K case in run `39759891349` on exact source `94297073ac36f257edd118aceba3e375a7148550`: 125,358 copied nodes, 604 packages, 603 protected packages, one committed transaction and complete owned-copy disposal. This is disposable native ARM4K container evidence. The original recovery runs39768760117 and39768777427 failed artifact upload because the workflow selected the normal output path. The corrected recovery source changes only both upload operands and its manifest; all runtime bodies and clocks are held. New recovery results remain pending. The factory grants no acceptance, and this result establishes no 16K fit, boot recovery, Apple/M2 support or release admission.

The portable retention-path regression executes each emitted normal/recovery alias’s actual retention shell and whole fixed-role retainer with explicitly inert authentication DATA. It checks the real eleven-member ZIP, CRCs, missing-role list and exact upload path; restoring the old wrong operand must refuse. This source-only control grants no recovery acceptance.
