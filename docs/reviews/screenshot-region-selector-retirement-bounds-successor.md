# Region-selector trace bounds successor

This is a Source-only successor to receipt
`1f197501ecaf3dfe686e89581cc2ed1d25b8123b53630a50bcfbdaf783cd3cfa`.
The independent review was sealed BLOCKED as
`a81de2d7edf3fe0b945e99c7cd88583bd5f881cb0864ec92a117276c303c46f3`
before this authorship. Both packets remain immutable. This successor addresses
its four concrete trace countermodels; it has not been adopted or run.

The copy list proposes exactly three replacements against authenticated Source
`020460cdf7165e5deb384f151c77500f38ec9532`, with no additions:

| Role | Proposed SHA-256 | Bytes |
| --- | --- | ---: |
| region_trace.py | f7e50d30a749fca1af52e9e21e0a05a6d5b1173fbba0066092b9a2b8254971c8 | 5776 |
| region_trial.py | 17761e6f50bb3c497f50e72d27a4f3b1e20e30d6df28c9aaf9eeebb938c92749 | 16059 |
| source.lock.json | e71c5fb89be1242bce3b1cbfa8b244b80717512e11c69f42120ff8e3ac7360a3 | 3820 |

Compared with the parent proposal, four exact trace edits require matched call
object IDs and selected layer/surface IDs to be positive uint32 values, and
reject repeated destruction of the selected layer or surface. Reversing those
four edits restores the parent trace byte for byte. The trial is byte-held from
the parent; only the trace descriptor changes in the parent's Source lock.
The inverse lock substitution restores its exact bytes. The closure remains
19 Source roles, including 18 lock leaves and the separately bound lock itself;
the runtime lock still binds 196 packages.

The retained order is selector exit/wait and reaping, complete drag, exact
overlay destruction, display sync and matching callback done, exact eleven-byte
geometry `31,47 73x59`, pointer destruction and capability zero, then custody
forwarding and fresh helper capture. The actual client trace dispatches
display-queue delete_id(20) before default-queue callback20.done(27); this valid
ordering remains accepted. Deletion alone does not acknowledge completion.

Bounded controls compare old acceptance with new refusal for both duplicate
destroys and oversized selected IDs. They also exercise duplicates at later
retirement positions, foreign objects, uint32 endpoints, missing/mismatched
callbacks, invalid order, incomplete drag and failed pointer retirement. The
retained actual trace and capability-zero-before-forwarding controls pass.
Controls extract pure methods through AST and use inert effects; they do not
import or run the operational Source modules.

The helper, strict every-pixel PNG/origin validator, pointer implementation,
workflow, Containerfile, protocols, legal inputs, clocks, custody and cleanup
remain held. The trial's post-close with_virtual_pointer diagnostic still reads
zero; that separate limitation is outside this trace correction. No new sleep,
retry, pixel tolerance or cursor-policy change is proposed.

Actual run 38650296183 retains 4303 matching pixels and four differing corner
pixels: FAIL. Selector/pointer retirement is a cause hypothesis, not a proven
explanation. This successor's native region/cancellation/refusal trial is NOT
RUN. ARM, Hyprland, Asahi, M2, 16K, installation, performance and release
acceptance remain untested. Root must perform a fresh independent Source
review and admission before any separately authorized trial. No canonical
Source, Git, API, CI variable or workflow dispatch mutation occurred here.
