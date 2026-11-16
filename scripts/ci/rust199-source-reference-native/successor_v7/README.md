# Proposed Rust notice preservation delta

This is package-hook DATA and portable utility code, not a runnable v7 Source
constructor. The original physical Source314/v6 and all 108 historical holds
remain unchanged. No build, Cargo invocation, container, network operation,
installation, hardware test, signature, publication, or Root admission occurred.

The helper authenticates the complete Rust source archive before reading 281
regular source files selected by the exact factual `notice-catalogue.DRAFT.json`
from the all108 audit. It preserves complete files instead of possibly truncated
keyword contexts. The catalogue retains the 283 context spans, component metadata,
original draft pin, source paths and whole-file pins. Its review/acceptance fields
remain NULL. These are authentic contexts, including references/examples; they
are not a claim that every context is a grant or a package-wide applicable notice.
Manifest authors remain labelled as authors, with no inferred owners or years.

`payload/packages/port/rust199-source-reference/reference.py` differs from v6
only in package(): after existing grants are copied, it verifies the new helper
and invokes it against `verified-materials/rustc-1.99.0-src.tar.xz`. The helper
writes `share/licenses/rust199-source-reference/source-notices/`, deduplicates
identical complete bodies, and retains each path in `index.json`. Existing grants
are retained. Whole-file source bytes are kept without normalization.

Two prerequisites block an operational constructor:

1. The audit catalogue is still explicitly DRAFT, with Root_review and accepted
   NULL. A reviewed selection must be supplied or this exact factual selection
   reviewed; this worker did not manufacture review or legal acceptance.
2. Source314's actor/entry.py enforces the original dd6871d5 nine-file candidate
   and original contract. actor/phase.py and actor/qualify.py independently pin
   reference.py to e707e4642cf5fcd59d57d49aa4e38c73e595213f7c728a645587e42c1db3f1cb.
   Changing reference.py and adding helper/catalogue requires an explicit successor
   candidate binding. Actors, contract, qualification, admission and resources
   were outside the permitted notice-only semantic delta and were not weakened
   or relabelled. An overlay alone would be refused by the unchanged actors.

`prospective.DATA.json` records the exact *incomplete, non-operational* proposed
Source identity for the three payload leaves plus a truthful pending marker.
It is not a publishable or admitted successor. A reviewed selection or binding
change will necessarily yield a new identity. No physical Source was generated.

Validation: `python3 -I -B
packages/port/rust199-source-reference/test_notice_preservation.py` passes nine
controls. A passive read of the whole pinned 265258564-byte archive verified all
281 selected files, 4902587 bytes and 245 unique bodies against the catalogue,
including each context. The tests use fixture DATA for refusal and staging
controls. Native build, actual ALPM packaging and hardware checks: NOT RUN.

Base: public Main 9fe143d2357c633748080de3a54ec2c0f2ccef6a. Canonical v6
code: d9f66d8bb10c9af91a7169cfa5f6b6fcb453910b. The allowed v6 prerequisite
25471c5ab5c1fd0b74cc8f2816f5a79d5343c083 was cherry-picked separately; integrate
only the new notice-preservation commit from this branch.
