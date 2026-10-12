# Held KERNEL-C01 independent review

October 12, 2026. **The retained source experiment is independently verified;
the future native build gate has the two findings below and is not signed off
for execution by this review.** Read the revised roadmap, inventories, platform
correspondence and protected tuple first. Ownership here is this document only;
held source, archives, locks, platform files and ARM-C01 files were not edited.

Checks used local temporary fixtures and read-only retained source. No kernel
compilation, Docker, native kernel, install/boot/module/service or host package
operation occurred. Source application and synthetic checks cannot pass native
kernel, M2/16K runtime, recovery, graphics/audio/power or performance acceptance.

## KERNEL-PRE-1: builder hash is not bound to parsed metadata

`verify_build.preflight()` calls `harness.read_json(builder)` before hashing the
path. A change between those reads can make it use one receipt's metadata while
accepting another receipt's pinned digest. An independent temporary swap schedule
parsed a REVIEWED_NATIVE_KERNEL_BUILDER/quota-true object, then replaced that path
with the different pinned UNREVIEWED/quota-false bytes before the hash check.
The actual preflight returned NATIVE_BUILD_INPUTS_VERIFIED, with UNREVIEWED on
disk. Native/tool/source gates were mocked to isolate this metadata binding;
no builder command or native program ran.

Hash and parse the same immutable captured bytes before consuming status, image,
package/tool or enforced-quota fields. This is a future-gate finding, not drift
in the retained full source trees. It was reported to the coordinator; held
files remain unchanged.

## KERNEL-OUT-1: output verification is only a partial-header check

The actual synthetic fixture demonstrates that `verify_outputs()` returns
BUILD_OUTPUT_STRUCTURE_VERIFIED for two eight-byte DTBs containing only magic
and total length, ELF type/version zero, arbitrary nonempty Module.symvers and
no `.ko` files. This is consistent with its implementation but insufficient to
establish complete valid Image/modules/Apple DTB output.

The present checks cover Image magic/page-size flag, ELF class/endianness/machine,
bounded program-header layout and PT_LOAD alignment/congruence/file ranges,
DTB magic/declared file size under the two expected filenames, nonempty symbol
file and hashes. They do not validate a full FDT header/tree, model/compatible
properties, executable ELF type/version, expected modules or module architecture.
Strengthen that future acceptance gate or explicitly narrow its receipt/docs
before treating it as complete native build-output verification. All synthetic
results still correctly say hardware NOT RUN and performance NOT MEASURED.

The native wrapper otherwise requires nonroot native aarch64, a reviewed
immutable builder/package/tool receipt, nine resolved executable hashes,
declared enforced output quota and separate 24GiB headroom. It clears the Make
environment, uses explicit compiler paths, fixes timestamp/suffix for both
variants, bounds jobs/address space/time, checks every config setting and has
no install/modules_install/boot/service target. These source checks and an
attested quota prerequisite are not actual builder/quota execution evidence.

## Retained provenance and full source independently checked

Asahi source is pinned to `94fb23346d522edf53722357c426a3e58030beea`,
`asahi-7.1.13-3`, retained source SHA-256
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`.
The actual embedded config is
`ae1d4ce855bd435b62c8fb213cbcf2d4eefd47b62274792c4a6bf299848b3876`;
the supplied historical config differs only in the recorded pahole131/132
setting. Historical correspondence does not claim regenerated config,
reproduced kernel binary, authenticated complete platform or hardware acceptance.

The sole selected [Cachy patch](https://github.com/CachyOS/linux/commit/0d61333f6e03e8fa4620e33e1bac4c644a9412c6)
matches the complete eight-added-line hunk in the
[primary Linux commit](https://github.com/torvalds/linux/commit/447cfed6d700bfbd5a7120f8ea5821a0e1191667).
Independent retained-byte comparison confirms identical hunk bytes; git index
metadata differs, so the entire patch files are not claimed identical.
The hunk lets a BIO cache miss try the existing slab allocation before mempool
fallback. No new config, Apple driver or page/DMA geometry change is included.
Source reasoning alone does not prove allocation/runtime/performance results.

Independently rehashed the actual compressed source, config and 2,249-byte patch,
then reran the held full-tree verifier against both retained trees. The archive
contains 100,117 members and 1,589,202,874 declared bytes. Each tree verifies
93,861 regular files; baseline has no changed file and candidate has exactly
`block/bio.c`. Every one of the 99 links in each actual tree also resolves
strictly to an existing path inside that tree. All four license/notice hashes
remain unchanged. Dry-run/application logs hash-match their retained receipts,
return zero, and contain only the expected file operation: no fuzz, offsets or
rejects. This review did not reapply the patch to the retained trees.

BIO hashes are
`ee6bf72d442a263fc8c86db6048c4476775a860971ba42e1c7cba1e1d693dd27`
before and
`be44b4dcbf65d05c43447f5a37a20a322ed2bf9e06a0f41d9a496bc8ab274dd4`
after. GPL-2.0 SPDX and Jens Axboe copyright remain in the file; original patch
authorship/signoff/review are retained. COPYING and the three accompanying
license/rules texts are unchanged. This is selected-file notice verification,
not full kernel/firmware redistribution-license closure or publication approval.

Current plan lock
`d26f691006a24f76db11f2f353e0ec10d93425ce2b6f8970a446b7bd34c98617`
and historical application lock
`611da0b6104baa3a2c444ce7637b0296a6fe97c88a098f0980a9faf1a0e1751d`
have identical source/archive/config/patch/file/license fields; only build_plan
differs. Old application receipts remain unchanged. The existing independent
review hash matches
`aa23a7b0cd9a3d6dc75564fffbbea8b9a0e960a3f854a9ec53c1676690735fe3`.
Its prior source PASS is evidence; it does not close the new future-gate findings.

## Boundaries, protected inputs and actual tests

The source harness restricts new canonical outputs to its owned ignored directory,
rejects archive traversal/duplicates/special files/hardlinks and escaping links,
pins a bounded private compressed snapshot, reapplies member/count/declared-byte
budgets during extraction, and compares full member hashes/link spellings.
Application invokes only fixed-path GNU patch under a cleared environment,
requires the exact target/header set, zero fuzz/rejects and final member hashes.
Failure receipts and the earlier failed extraction evidence are retained.

A temporary cyclic-link fixture passes the generic archive/full-tree containment
check because ordinary resolve is non-strict. That checker does not generally
prove link target existence or acyclicity. This is an explicit scope limit; the
separate strict check above proves all 99 links in the exact retained archive
trees are existing and contained. Content/link comparisons do not claim full
UID/GID/mode reproduction of a tar archive through its safe extraction filter.

Independent portable suite: **27 PASS**, including source-path/patch/duplicate/
storage/input-swap/link/failure and synthetic config/Image/ELF tests. Shell syntax
passes. These tests invoke GNU patch only on temporary synthetic slices and do
not compile or execute upstream kernel code. Independent counterexamples above
are additional probes, not new native results. Overlapping earlier review test
counts are not summed as unique tests.

All six ARM-C01 source hashes/modes and exporter binding still match its held
stage lock, whose file SHA is
`98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5`.
Protected platform proposal hash remains
`2fbfe509dd851c201db9bb836078bf14c571e3a4c5336b29fc2fd102732f30c9`;
kernel correspondence remains
`5aa4a7efcd821cd497655072f9e04c71ed01480b2860a2bb7d8c72b610fb49d5`.
The proposal's transaction/image/owner-trust/installation/hardware acceptance
flags remain false, with system_mutation false. No accepted platform tuple or
ARM-C01 evidence was repurposed as kernel performance evidence.

| Held reviewed source | SHA-256 |
| --- | --- |
| `harness.py` | `f2d6fc62d28b0c189469ca7cf8293f10c574ecd0459c33c013bf1a271b8a5ebf` |
| `verify_build.py` | `ae75f2777fd1f60ba59b62dd6bab6e8a8fa11ee8cdea2fcef73f82e00e8191ea` |
| `native-build.sh` | `0dff90399813b3ea5016c3bc4a6bfd79017355571cc1e8e7b90d036d4b15cb23` |
| `test_harness.py` | `9bd5e141e5138107b2d9ab434d9230dd8685ff2fb6702b5b4dc496f068629c15` |
| `test_verify_build.py` | `16b8e760ab25406706fc28eaaa3c4fe121ed24b101e65ba322602db8aa17a4b4` |
| `audit.json` | `15cfa7700e79d86cfacb71c67606af62b05bce0958bbecc3d52f59211fd029bc` |

Source application is verified on the exact retained inputs. Builder freezing,
KERNEL-PRE-1 and KERNEL-OUT-1 closure, native allocation regression/full builds
and subsequent exact-M2 physical recovery/runtime/measurements remain unfinished.
