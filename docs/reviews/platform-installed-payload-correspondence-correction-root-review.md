# S01 four-source correction and reader rebind: independent review

**The four original S01 causes are corrected; adoption remains BLOCKED on a new
helper-disposal finding and the separate reader findings.** Fresh 38 core and
47 reader methods pass with no skips. Independent old-red/new-green controls
verify the ordinary-input, hardlink-cutoff and symbolic-namespace corrections.
The reader changes exactly one CORE_SHA literal and its tests are unchanged.
No actual image/debugfs/GPG/archive extraction/device/native actor ran, and no
installed/trust acceptance flag became true.

## Exact correction scope

Checkpoint SHA
`1963df90e99d64daf8040438b737209974ea9a7a9d6674c1f1a61d1ca6c9e351`
binds:

| Held file | SHA256 |
| --- | --- |
| Core | `d73e004c1d00986e423c6429dca1dc884e55b98c9d6edba2ed663242ea415f97` |
| Core tests | `8bf7de6ad2fc76b90d2959c2dd8fe3c63cd821b9b7ce378dc9be45aa767e605e` |
| Reader rebind | `cc683c756aa433539e4dfe35da172b24a3a42220059ca7b6ac58ba99caf1af93` |
| Reader tests | `44ab3d262369116d83212ab0ded403db42e87bce85f4968b405e089f50ff4499` |

Fresh copies come from this immutable source packet. Historical core064,
checkpointaec, reader907, Python3350 observation, guide599/32e1 and the a9fd
root review remain separate unchanged evidence. A legitimate primary core
change is expected; this review never treats failure to equal historical064
as a defect. The correction guide is SHA
`9ff3c4d46b73dba1ce0a8b62e98e79269c3b617232abb419a7167717e0d12ac6`.

Independent AST checks confirm only `opened`, `tree_nodes`, `resolve_link`
and `compare` changed in the core, with one new `readable_at` helper. Other
function and nonfunction ASTs, actor/admission flags and resource constants
remain unchanged. Twenty-eight original test methods are AST-identical; the
remaining original test changes the archive-symlink assertion from OSError
to the earlier ordinary-node ValueError, as documented. Nine new methods
bring core coverage to38. The reader is byte-identical after normalizing its
single CORE_SHA064→d73 replacement; all47 reader tests are byte-identical.

## Original counterexamples and closure

- **S01-O1 closes:** reference/tree reads now obtain a no-follow metadata-only
  O_PATH inode, validate ordinary type and expected identity before obtaining
  the readable descriptor through its own held FD. Mocked character/FIFO/
  symlink and regular-to-special replacement controls no longer reach the
  read-capable open before refusal. Named/ancestor/final checks remain.
- **S01-D1 closes:** hardlink chains, inode-group names, metadata work and owner
  projection check the same caller cutoff. The original virtual-clock expiry
  inside a64-hardlink group now refuses instead of completing unchecked inner
  work. No cutoff reset or actual elapsed-time overshoot test was introduced.
- **S01-L1 closes:** exact root targets `/` and `..` from `usr/link` resolve to
  the implicit captured root. Missing intermediate nodes, nondirectory
  traversal and top-level escape still fail; no host root is followed.
- **S01-L2 closes:** cycle detection uses the remaining resolution state;
  finite `x/../x` with `x→d` now resolves to captured directory `d`. True
  self-loops/cycles still fail and the finite hop limit remains. Hop exhaustion
  is distinct from a proven cycle. Link traversal uses the caller cutoff.

The fresh85 methods pass, and31 independent bounded symbolic/hardlink
characterizations pass. Original three namespace inputs match the historical
c300 model packet exactly before replay against the corrected source.
The source lane separately checks the original mocked reader and cutoff
counterexamples. All result authority flags remain false. Tiny owned-tree/
XZ/TAR/FIFO/signal fixtures and pure/fake-descriptor models are the entire
execution scope; no real image or executable backend ran.

## [P2] New O_PATH binding can survive cancellation during disposal

At corrected core lines87–88, `readable_at` closes the readable descriptor
and then its O_PATH binding sequentially. The second close is not protected
by a nested finally or an equivalent disposal scope. In the single requested
fully mocked schedule, closing the readable FD102 completes and raises
KeyboardInterrupt; binding FD101 is never closed or attempted. No real
descriptor, driver/content read or returned PASS was demonstrated.

Guarantee disposal of the binding even if the readable close raises during
cancellation, preserving the initiating cancellation and all inode/ancestor
checks. Retest this exact two-descriptor schedule; a general fault framework
or broad cleanup rewrite is not required by this finding. The original O1
pre-read cause is fixed, but its new descriptor-owning helper needs this
additional disposal correction before broader reader adoption.

## Reader findings and data acceptance stay separate

The independently sealed reader907 review receipt
`6a9b615d1922e1859fe6124ae4d1a3e35ed898c84970741d1423fa133f65c11d`
remains BLOCKED on R2-C1 (interrupted/incomplete child/pipe teardown) and R2-B1
(prior archive-decoded work is not bound into the production entry point's
fresh combined ledger). A CORE_SHA literal rebind does not fix either source
path. Forty-seven passing reader models do not establish actual execution
admission or cleanup/resource feasibility.

Metadata/static scope checks authenticate every correction reference, the
four source holds and exact historical packets. The44-file old S01 peer hold
was independently rehashed; the Zsh0b8 handoff pin is unchanged. The prior
Python3198-body/3201-header observation stays raw one-archive evidence.
Exact tuple coverage remains at most259/261 with26 signer-fact join gaps.
Installed payload, image issuer/independent owner trust, source redistribution,
installation, hardware,16K and performance remain unaccepted. No graph/ELF/
firmware decision or shared source map/manifest/workflow/Git change occurred.

The receipt and evidence are confined to
`artifacts/reviews/platform-installed-payload-correspondence-correction-root-peer-20261012/`.
Close the new binding-disposal issue and reader R2-C1/R2-B1 separately; retain
all historical source/model facts without reclassifying them as installed
or physical-system acceptance.
