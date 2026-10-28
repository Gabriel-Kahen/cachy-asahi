# Reader2 installed-payload image adapter: independent source review

**BLOCKED for broader actor admission.** All 47 held models pass. The new
metadata-first opener, inode-only commands, typed parsers, streaming limits,
source/input hashes and final result withholding are supported by source/model
checks. Independent finite controls nevertheless expose incomplete child/pipe
cleanup on a second cancellation or close failure, and the production entry
point does not carry prior archive-decoded work into its fresh resource ledger.
No actual image/debugfs execution or installed/trust acceptance bypass occurred.

## Exact held scope

Checkpoint `907a91ee837f173281e206ad9920907c77035f5c594e5958c233640690fa2b77`
binds reader source 19,640 bytes/SHA
`1e56dc9fed2a6de1c83850f8f5bf4213265becd22075d2941ec6f25e18aed086`,
tests 22,705 bytes/SHA
`44ab3d262369116d83212ab0ded403db42e87bce85f4968b405e089f50ff4499`,
and historical S01 core SHA
`0644277166c752094eca97dc75fe6406da5dd0154fad9c82b8b4ea1cf748d6df`.
Fresh captures come from the checkpoint's `source-final` packet. Legitimate
primary core corrections/rebinding while this review runs are not defects or
proof that a historical hold changed. The historical dependency is unadopted
under the four findings in the preserved S01 root review; its correction and
explicit new-pin recheck remain separate work.

The exact guide SHA is
`32e1e1cb2f12c8211600a6b373f2782aa615d5e709d7a95e64a173f622670b79`.
Fifteen owned-artifact/guide/tool-contract references (182,229 bytes) were
rehash-checked. The original `907` and `aec` packets and the `a9fd` S01 peer
receipt remain historical evidence. No source, shared map/manifest/workflow,
Zsh hold or Git state was edited.

## Supported source/model behavior

Default `execution_selected=False` refuses before core/input I/O. Exact held
core bytes are read, SHA/mode/type/identity checked and compiled without
import/PYC fallback. The new O_PATH opener validates an ordinary single-link
leaf before any readable descriptor acquisition; controlled FIFO/symlink/
character-device and stale-reference models refuse before content access.
The derived readable inode, named leaf and ancestors are bound through final
checks and disposal. This improves the new adapter's opener without silently
rewriting the historical core.

Only positive decimal inode commands `ls -p <N>`, `stat <N>` and `cat <N>` are
formed. Names are parsed as bounded data and never enter commands. Dot/parent
relationships, modes/types/uid/gid/size/link count, raw stat hashes, duplicate
records, depth/cycles and content size are checked. Special inode types do not
receive a cat request. Ambiguous fast-link framing and unobserved long-link
bytes refuse. Actual pinned debugfs output compatibility remains NOT RUN.

`ls/stat` retain 8 MiB stdout and 64 KiB stderr with a closed banner check.
`cat` hashes exact observed size through 1 MiB chunks, up to 512 MiB per file;
ordinary content is not retained, and link data is bounded to 4,096 bytes.
Within a Tool instance, all stdout and `budget.decoded` share an 8 GiB cap.
Each call is clipped to 20 seconds and the caller's finite 20-minute absolute
cutoff, reserving two seconds inside the call for teardown. Final tool/image
rehashes and descriptor disposal precede the returned result; late cutoff and
finalizer failures withhold it. These controls do not establish full-data
resource feasibility or real process-group absence.

The fresh 47-model suite passes with no skips under 60-second wall, 30-second
CPU, 512 MiB address-space and 4 MiB output/file limits. Subprocess factories,
image data and finalization are mocked. Thirteen independent process/cap/
reference/finalization controls and the separate source-audit causal models
and 75 source/AST checks are retained in the owned peer namespace. Harmless tiny ordinary/FIFO/symlink
and signal-mask fixtures are distinguished from real program/image actors.

## Required corrections

### [P1] Complete teardown despite cancellation or a pipe-close exception

`checked_process()` restores the caller signal mask after registering the
spawned process, but its cleanup at lines 179–191 is unmasked. A second modeled
cancellation at `killpg` leaves the fake child unreaped: `wait` is never called,
although both fake pipes close. The ordinary no-result boundary survives.

Two additional finite controls first trigger `stdout-bound`, mock successful
termination/reaping, then make stdout.close raise KeyboardInterrupt or OSError.
Stderr.close is not attempted and stderr remains open. The propagated cleanup
exception replaces the original raised failure; the latter survives only as
exception context. No real process, signal, pipe, device or byte side effect
was exercised by these fault controls.

Retain tracked ownership through teardown, protect the finite disposal window
against another cancellation, and attempt every owned pipe close even when one
fails. Preserve the initiating failure/cancellation while reporting cleanup
failure separately as appropriate. Keep the existing caller cutoff/reserve;
do not introduce a new general fault framework or claim cleanup PASS merely
because the primary child returned.

### [P1] Bind prior decoded work to the selected combined ledger

Tool constructs a new `core.Budget(deadline)` at line 198. It retains the
absolute cutoff but initializes decoded/node counters to zero.
`run_selected(source, contract_ref, image_ref, expected, ownership, deadline)`
accepts already observed archive facts and has no prior Budget or work-counter
parameter. In a fully mocked constructor model, a prior ledger has decoded
8 GiB minus one byte; the selected Tool nevertheless starts at decoded zero.
The model stops before input or actor execution. No executed total-cap bypass
was measured.

The guide's claim that prior archive-decoded work and image output share the
same 8 GiB is conditional on a caller using the Tool ledger for that earlier
work or explicitly transferring authenticated counters. The advertised entry
point does not implement or prove that transfer. Before actual actor admission,
bind the prior work to the same selected ledger/cutoff, or provide the explicit
root-reviewed caller integration that does so. Preserve the selected combined
cap and do not silently describe a fresh per-phase allowance as shared work.

## Data, installed-tool pins and remaining acceptance

All 26 retained regular-file rows larger than 8 MiB and all 116 old filename-
grammar cases exactly correlate to ownership supplement SHA
`8ad2e76c22940ee27d3dac99c2da93961be9b3b1dd753e6335eddd1f1b1f794c`.
The declared maximum is 63,571,696 bytes, below the selected 512 MiB/file cap.
Inode-only source syntax can represent the permitted names without command
interpolation; actual image records and long-link behavior remain unexecuted.
This review did not reread raw 624 archive headers.

The fixed installed-tool contract SHA
`6f0900f9a691944fe4a804407a3dd6e72ad8fb6380662162a74325b3d2384bf8`
binds debugfs, its interpreter and recursive libraries. Nine unique ordinary
installed endpoints were independently rehashed, with SONAME/interpreter
links and recorded modes checked. The captured manual and byte format strings
are data evidence. No executable ran; these byte pins establish neither a
source redistribution grant nor actual loader/output compatibility. The
historical contract's approved-false/path-grammar proposal is separate from
the checkpoint's newer inode-only source policy and explicit future selection.

Metadata verification read 4,271,558 bytes and ran no image/archive actor.
Full-261 correspondence, source redistribution, image issuer/independent
key-owner trust, installation, hardware, 16K, recovery and performance remain
unaccepted. Exact tuple coverage stays at most 259/261 with 26 signer-fact
join gaps. These models close neither that inventory nor the protected
platform's existing dependency/ELF/firmware blockers.

The final peer receipt indexes this guide, held sources, actual tiny fixtures,
fully mocked faults and data/installed-tool hash checks under
`artifacts/reviews/platform-installed-payload-image-reader-root-peer-20261012/`.
The next core-correction review can close the historical dependency findings;
it cannot by itself close the reader cleanup or combined-ledger issues.
