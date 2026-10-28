# KSM source deadline: unbuffered followup review

October 12, 2026. **PASS for the source correction; coordinator registration
remains separate.** The prior blocked review and its buffered-close reproducer
are preserved unchanged. This followup writes only this document and
`artifacts/reviews/ksm-source-deadline-root-peer-20261012/unbuffered-followup/**`.
The roadmap and package inventory were read. No runtime source, shared map,
workflow or project Git state was changed; no native actor or daemon ran.

The externally pinned checkpoint is
`1c33b467a51e34ca5195832c5f9eadf6af998609a888fdce8829084ae2cfb856`.
All checkpoint artifact rows and owned source/document hashes, sizes and modes
match. The executor is
`5dda4fed77274aacc523a30aa5c97033ca9defdc8928faedcb495b80655f228c`;
its test source is
`84d7d6756ab63aca4f2995cac08c633d24670a48be32622dcf6d9e231e681524`.
The prospective map
`0623a4d68b736c85128b55686347921ab50fc45c9105785c54f8b74206177435`
binds 152 files /2,257,813 bytes. An independent fresh copy authenticated every
mapped byte and mode before importing test code. Adopted map `65a7ab50…` remains
unchanged; this copy is review evidence, not a new registry grant.

Only `source_tree` differs among executor function ASTs versus the preceding
held executor `a0b93c59…`. The six protected functions (`owned_cleanup`,
`baseline_observe`, `invalidate_public`, `context_digest`, `save_status`,
`owned_output`) are unchanged, as are acceptance, broker and test-broker bytes.
The existing absolute caller cutoff is propagated without renewal.

## Causal result

The independent probe replays old and new source in separate authenticated
copies, using a real tiny file and injected monotonic clock 179→181 with cutoff180.
The old buffered write leaves disk size0 until context close, then writes24 bytes
at181 after `acceptance aggregate deadline exceeded`. The corrected function
performs its actual raw write at179, observes24 bytes already present, refuses
when the clock reaches181, and closes only the descriptor. Close adds **zero
source bytes**. This fixes the reported queued-write edge; it does not assert
that a kernel write already started before the cutoff can be interrupted.

The corrected function bounds each `os.write` chunk to65,536 bytes and handles
short writes by their actual positive integer count. It checks the same caller
cutoff before and after writes and fsync; every refusal closes the descriptor.

## Focused verification

**Fourteen tests pass, zero failures/errors/skips**, executed under
`python -I -B -S -Werror::ResourceWarning`. Eleven held focused tests cover the
caller deadline, Git output/deadline bounds, late source capture/copy/launcher
completion, prewrite/postwrite cutoff and real short-write/chunk behavior. Three
additional independent tests cover:

- Zero, negative, boolean, noninteger, absent and oversized returned write counts:
  refusal on the first call, no fsync, no source bytes and a closed descriptor.
- A real three-byte short write crossing the cutoff: only that initial prefix
  reaches disk; no second write or fsync occurs; the descriptor closes.
- Fsync failure after a real write: refusal and descriptor closure.

Injected clocks/counts and host/backend predicates are local controls. No native
KSM, Docker, package install or daemon/backend operation was executed. Fresh
source bytes remain stable, no PYC/cache directories were created, temporary
fixtures were removed, and the prior blocked review hashes remain unchanged.
The full suite was not rerun because these focused checks exposed no additional
concern. The author's broader results remain separately attributed.

The [followup receipt](../../artifacts/reviews/ksm-source-deadline-root-peer-20261012/unbuffered-followup/review.json)
binds independent scripts, logs, source pins and both causal records. Reproduce
in a new empty followup output directory before reusing its exclusive-create
harness. Native lifecycle, hardware/M2/16K, installation and performance
acceptance remain **NOT RUN**.
