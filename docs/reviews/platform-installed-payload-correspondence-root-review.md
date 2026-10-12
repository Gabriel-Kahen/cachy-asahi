# S01 installed-payload correspondence: independent source review

**BLOCKED on four source findings.** The held 29-test suite passes, and the
retained metadata/authorized Python observation authenticate to the supplied
pins. Independent controls nevertheless reproduce two reader/work-limit defects
and two symbolic-namespace false-rejection cases. The baseline gate remains
closed, all installed/trust/installation/hardware flags remain false, and no
actual 261-package acceptance bypass was demonstrated.

## Exact review scope and evidence

The reviewed checkpoint is `aec43e737dfdc76b26115691be4a5aa5e02e7e7141ef91cf0b45924789f8e285`.
Fresh ordinary 0644 copies bind source
`0644277166c752094eca97dc75fe6406da5dd0154fad9c82b8b4ea1cf748d6df`
(26,396 bytes), tests
`1660a673834d197525c43935d0c67d91f18332fa57b8517411330c4d8f4badca`
(19,035 bytes), and guide
`599079a3e1f0b9f9d7bcd8aa0ff613e25c5d09892bc5114d3871d8dfd56608d4`.
Twenty-eight checkpoint artifact/guide references were independently rehashed
(1,712,741 bytes), without executing the historical observation/proposal helpers.
No PYC was loaded.

The fresh 29 tiny owned-tree/inert-XZ/TAR tests pass under 60-second wall,
30-second CPU, 512 MiB address-space and 4 MiB output/file limits. Sixty-one
independent model characterizations and 45 source/AST/causal controls were
completed. Two additional root controls use entirely mocked character-device
descriptors. These model fixtures do not open real special references or read
real image/archive/device payloads. Existing tiny FIFO fixture nodes are only
observed in their private test trees. No image/debugfs/GPG/package extraction,
installation, network, mount/namespace, native or device actor ran.

The separate actual-image reader being developed by another owner is outside
this review. No primary source, shared map/manifest/lock/workflow, Zsh source
hold or Git state was edited.

## Findings requiring correction

### [P1] Validate leaf type before a read-capable open

At `installed_payload_correspondence.py:82–83`, `opened()` requests an
`O_RDONLY|O_NOFOLLOW|O_NONBLOCK` leaf descriptor before checking that it is an
ordinary file. At `:200–202`, the tree reader observes a regular file, then
requests the same read-capable open before checking the opened identity.
A replacement special node can therefore reach the open operation before
refusal. `O_NOFOLLOW` controls symbolic links; `O_NONBLOCK` does not make that
operation metadata-only.

Two fully mocked character-device controls and independent FIFO controls
record that open request before `ordinary-node`/`tree-open-drift` refusal.
All fake descriptors close, and no payload content read or real device effect
was demonstrated. This is an open-before-validation defect, not an observed
installed-payload/trust bypass.

Use a metadata-only held leaf reference to validate type/identity before the
read-capable open, bind the derived descriptor to that held regular inode,
and preserve named-node/ancestor/final checks and disposal. Unsupported
platform semantics must refuse explicitly. Extend the race controls without
opening an actual device or FIFO content stream.

### [P1] Check the caller cutoff inside hardlink work

The hardlink-chain and inode-group inner loops, particularly `:314–318`, omit
`budget.check()`. Their nested traversal can be quadratic in the number of
hardlinks while the next cutoff check is deferred. A pure 64-node model with
one shared inode moves a virtual clock past deadline during the inner work;
`compare()` still returns `PASS-inert-tree-correspondence` after that modeled
expiry. The immediate postcomparison check in `run()` refuses, preserving its
acceptance boundary. No actual long-running image operation or elapsed-time
overshoot was executed or measured.

Check the same caller budget during each chain step and inode-group name
iteration, retaining the postcomparison check. Test interruption at those
specific points rather than weakening bounds or changing acceptance flags.

### [P2] Resolve the implicit captured root

`resolve_link()` treats absolute targets as image-root-relative but only
accepts keys in the body-node dictionary. That dictionary omits the implicit
root. Exact matching expected/observed links `usr/link → /` and
`usr/link → ..` consequently produce the sole `LINK_MISSING` failure despite
resolving inside the captured namespace. Top-level `..` still correctly
produces `LINK_ESCAPE` under this helper's confinement policy.

Represent the known captured root in resolution without admitting a host
path or weakening escape checks. Add exact-root and relative-parent-to-root
controls with all acceptance flags retained false.

### [P2] A repeated symlink is not necessarily a cycle

With captured directory `d`, link `x → d`, and matching alias target
`x/../x`, traversal is finite and resolves to `d`. The current seen-key rule
instead produces the sole `LINK_CYCLE` failure when the same `x` is revisited
after consuming part of the path. A true `x → x` self-loop remains a cycle.

Detect repeated resolution state rather than every repeated symlink name,
while retaining a finite hop/work cutoff. Preserve genuine cycles, missing
nodes, nondirectory traversal and namespace-escape refusal.

## Authenticated retained data and preserved limits

The exact authorized old-Python observation is 793,227 bytes, SHA
`3350c5d455af66f678c19ad114b8a7c8f6ec7122f9e82b82148e36b61d0ff0fc`.
Root selection is SHA
`b7d869c4dc4bf7ef78e6cf6e5ebd2e162a80daf8a821ec928662eba576327d4f`.
Independent data checks recompute 3,198 body nodes / 3,201 observed logical
headers: 3,058 files, 127 directories and 13 symlinks. Every recorded raw
Python archive UID/GID is 0:0, and its 3,198 paths match retained `%FILES%`
metadata exactly. This is the prior one-archive inert observation; no new raw
Python archive/header read or GPG operation ran here.

The full old Python 3.14.7-1/aarch64 archive/signature/receipt/inspection and
public-certificate reference joins, including retained VALIDSIG primary
`68B3537F39A313B3E574D06777193F152BDBE6A6`, match the selected historical facts.
This does not supply independent owner trust, source redistribution acceptance,
image issuer authentication or installed-byte correspondence.

Current 261-package inventory SHA
`5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941`
and ownership SHA
`f12aba8413c5d8a5de9419f4321381cde0b1ca50a4d9e1c4f40421768952e994`
bind the retained image SHA
`76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db`.
All 261 ownership rows and 63,721 unique declared paths independently validate;
six genuinely empty metapackage lists remain. The image digest is retained
capture authority: this review performs no fresh image rehash or image read.
At most 259/261 exact tuples are available after the selected Python supplement;
old NetworkManager 1.58.1-1 and Perl 5.42.2-2 remain required. The retained
matched-258 proposal has 232 candidate signature-fact rows and 26 unresolved
joins. Missing normalized facts do not establish absent/unsigned archives or
232 freshly verified signers.

The metadata lane stayed below 8 MiB per file and 32 MiB cumulative reads.
It retained a reviewer-only initial auth-schema KeyError and then corrected
its existing-input-lock join branch without modifying any primary artifact.
The model lane likewise retains its initial mistaken expectation that the
host Python JSON parser must reject a deeply nested array; the corrected
characterization verifies that `run()` refuses the unsupported shape before
input reads. Neither harness correction conceals a source failure.

The final review packet is confined to
`artifacts/reviews/platform-installed-payload-correspondence-root-peer-20261012/`.
Its receipt binds the exact sources, controls, metadata joins and this document.
Actual installed trust, full-261 correspondence, image actor admission,
installation/recovery, ABI/hooks, 16K, M2 and performance acceptance remain
unestablished. The four source corrections and a separate reviewed image-reader
contract are prerequisites to broader reader admission.
