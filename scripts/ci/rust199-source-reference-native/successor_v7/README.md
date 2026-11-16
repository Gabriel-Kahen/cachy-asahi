# Rust notice preservation Source DATA proposal

This notice-only successor proposal adds deterministic preservation code and exact
factual notice DATA to frozen Source314. It executes no actor, Reader, build,
Cargo, container, network, installation, signature, publication or Root admission.
Old physical Source314/v6 and all 108 historical holds remain untouched.

The Root-supplied seal is
`d66d49a2734e79c6f9d1f5a57fda98ab519d39016483da0f4f88a0f626576fd9`.
`catalogue.py` authenticates all 15 sealed audit files and deterministically derives
the maintained preservation catalogue. The source catalogue's DRAFT name and NULL
legal/Root acceptance fields remain factual; they do not block this explicitly
requested preservation implementation and do not become legal acceptance.

The catalogue selects 425 complete source files, 6227097 bytes, containing all
433 actual keyword contexts in the sealed audit. References, examples and author
roles remain labelled as contexts and roles. Complete files are preserved so
notice bodies extend beyond the selected context span without being cut off.
The 21 exact retained grant bodies, 67508 bytes, retain their original evidence
pins, paths, component associations and existing scope/binding limitations. They
are distinguished from files authenticated directly by the Rust source archive.
No owner, year, universal grant, native consumption or legal clearance is inferred.

The helper authenticates the complete 265258564-byte Rust source archive before
reading selected regular members without filesystem extraction. It verifies each
whole-file hash and each exact context, then writes deterministic files beneath
`share/licenses/rust199-source-reference/source-notices/`. Identical bodies share
one digest-named file; index.json retains every source path and whole-file pin,
and separate original evidence provenance for grants. The exact catalogue is
also retained. There are 386 unique source files and 406 total unique bodies,
5802472 output body bytes, after deduplication.

`payload/packages/port/rust199-source-reference/reference.py` changes only the
package notice hook. After existing Rust and compiler-rt/libunwind grants are
copied, it verifies the helper and catalogue and invokes preservation against
`verified-materials/rustc-1.99.0-src.tar.xz`. Existing grants remain present.
Source314's compiler flags, actors, resources, qualification, contracts and
admission semantics remain byte-for-byte unchanged by this constructor.

Operational integration is still pending with the coordinator: actor/entry.py
enforces the original dd6871d5 nine-file candidate and contract, while phase.py
and qualify.py independently pin the old reference.py. The new proposal therefore
honestly carries `operational: false` and
`COORDINATOR_SUCCESSOR_CANDIDATE_BINDING_REQUIRED`. It must not be dispatched as
an operational successor. The coordinator owns any separately reviewed successor
candidate binding; this worker did not weaken those guards or invent a candidate
Git commit. Root's eventual integration will have a different Source identity.

Run the portable controls:

```
python3 -I -B packages/port/rust199-source-reference/test_notice_preservation.py
python3 -I -B scripts/ci/rust199-source-reference-native/successor_v7/test_source.py
```

The constructor requires the exact frozen parent and an externally pinned profile:

```
python3 -I -B scripts/ci/rust199-source-reference-native/successor_v7/prepare.py \
  --parent /absolute/immutable/Source314 \
  --output /absolute/fresh/disjoint/proposal \
  --profile-sha256 SHA256_OF_CONSTRUCTOR_PROFILE
```

It changes only the three payload leaves, adds the truthful pending marker,
regenerates the map, and verifies a complete inverse to Source314. Its output is
Source DATA, with all future actual selectors NULL. See prospective.DATA.json for
actual passive validation and exact prospective identity. Native, actual ALPM
packaging, generated COPYRIGHT.html, final package notice comparison, and M2
checks remain NOT RUN. The sealed source audit establishes a copy/scrape-input
gap; this proposal makes no claim of an actual emitted-output omission.

Base: public Main 9fe143d2357c633748080de3a54ec2c0f2ccef6a. Canonical v6 code:
d9f66d8bb10c9af91a7169cfa5f6b6fcb453910b. The allowed v6 prerequisite
25471c5ab5c1fd0b74cc8f2816f5a79d5343c083 was cherry-picked separately. Root
reports PR469 merged at 50ee5db18fba88bba19e7b2ac475dcdbd9fe4368; this isolated
branch remains on the explicitly assigned base. Integrate the notice commits
only; do not reapply the already integrated v6 prerequisite.
