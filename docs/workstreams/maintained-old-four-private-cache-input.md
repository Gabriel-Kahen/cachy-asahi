# Exact old-four private cache transport proposal

This proposal keeps Source09's original 501 input descriptors and 341 inventory
records. It restores transport access to exactly four retained objects without
changing a version, URL, size, hash, signature tuple, repository observation,
Vim pair or source epoch. It is separate from the immutable new-pair migration
proposal `dc00a469e192e8fb829b3cd738b87b690c29f494d021fb312a72c1bb918bb4f6`.
Neither proposal is adopted here.

The packet is
`artifacts/reviews/maintained-old-four-private-cache-input-proposal-20261014/`.
Its exact base is Source09 `7fde499b5dcbe216c8e17eb07abe236978300f1c` at maintained
Data HEAD `a8222e2256f1dba944ab7fc7911ba83e02442ed8`. The managed checkout is
`/home/gabe/.codex/worktrees/maintained-composed/cachy-asahi`. The older Documents
checkout has different Vim rows and is not this base. An initial custody-audit
label confused those paths; its immutable receipt is accompanied by
`custody-current-base-correction/`, which verifies the actual maintained input
lock `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f`.
No maintained-source drift was demonstrated.

Eight local copies, from the baseline cache and reverse-consumer custody,
match the four exact old objects, all mode0600. They total 404,428 decoded bytes:

| Object | Bytes | SHA256 | Fixed chunks | Encoded characters |
| --- | ---: | --- | ---: | ---: |
| jbigkit-2.1-8-aarch64.pkg.tar.xz | 48,816 | `ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db` | 2 | 65,088 |
| jbigkit-2.1-8-aarch64.pkg.tar.xz.sig | 566 | `f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f` | 1 | 756 |
| libtiff-4.7.2-1-aarch64.pkg.tar.xz | 354,480 | `02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd` | 15 | 472,640 |
| libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig | 566 | `8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa` | 1 | 756 |

`private-transport-contract.json` specifies all 19 secret/environment names and
their order. Each value is an opaque canonical ASCII base64 slice of at most
32,768 characters. Total encoded characters are exactly 539,240. GitHub's
[secret size limit is 48 KB](https://docs.github.com/en/actions/reference/security/secrets);
the fixed slices fit individually. Public schema markers are
`CACHY_OLD_FOUR_SCHEMA=1` and `CACHY_OLD_FOUR_SOURCE_EPOCH=1791748800`.
Root alone renders and provisions the exact names and chunks from validated
immutable bodies. This packet contains no raw package body, actual encoded
chunk, secret value or secret/admin mutation.

The helper is inserted into the existing authenticated controller. Its only
call follows creation of the private output/cache directories under the
original authenticated deadline J and active alarm, before Development and
run_composed. Root-admitted handoff/authority dependencies have already loaded;
original native modules, acquisition workers, package recipes, Docker and
publication have not started. No renewed deadline or timeout is issued.

The helper captures and removes every `CACHY_OLD_FOUR_` environment entry,
including unknown names that trigger refusal. All 19 empty/absent values retain
the existing HTTPS path. Any supplied value requires the complete fixed schema,
exact chunk count/order/length, original input lock and epoch. Strict base64
decoding plus canonical re-encoding refuses padding, whitespace and trailing
data ambiguity. All four exact decoded sizes and SHA256 values are checked
before any file is created. Errors never include chunk contents.

The cache directory must be the owned mode0700 directory. Relative file opens
use a held directory descriptor, O_NOFOLLOW/O_EXCL/O_CLOEXEC and mode0600. Each
old object gets one fresh, single-link owned regular file. Writes and return
are checked against original J; descriptor identity and final size are checked.
On failure only verified owned creations are eligible for removal. An initial
fstat failure closes its descriptor and reports unbound-creation uncertainty
without unlinking an unverified path. Cleanup/close failures preserve the first
cause and record uncertainty. No existing or replaced file is overwritten.

The original `native_arm.fetch`, four-thread acquisition, per-input receipts,
all 501 pinned-byte checks, GPG/signature authentication, metadata, build,
integration, recovery, owned launch and cancellation bodies are unchanged.
Those workers consume the preseeded files through their existing cache-first
validation. Secret chunks have left the controller environment before these
lower-trust children; chunks are never passed to recipe/Docker environments,
printed, exported or archived by the helper. Cache paths remain disjoint from
source and output. Private dependency custody does not establish public
release/source/license redistribution admission.

The exact copy delta has only three files and two hash edges:

- controller SHA256 `bbe279edb9743f98e8feed8365859abc221b2665924658e600775c902e18299e`;
- packet SHA256 `9d5a7dc25fd44e127c457c72addb28272b1eb1f5391c4c5b8d5b0a226a3be048`;
- workflow SHA256 `0fed9bcc5f7492ee781d180d6202aea5fde8b8c6192d63d9b0253bd7dcc8dbeb`.

The workflow maps secrets only into the invoking step. Packet Source266 and
metadata14, original Source159, fixtures125, all protected Source09 signal
bodies/maps and the other 268 selected Source files remain unchanged. No new
module or package input is added to the packet. The three physical proposed
files and all 271 Source rows are supplied for review; no future-plan-only
placeholder substitutes for those bytes.

Root's old-signature receipt
`195349617c92c9b1b296d86caa2fb6c0f293ba0a5b7fbdc4aae7073f0be7fb5f`
records trusted-host natural completion for exactly the old two signatures:
jbigkit digest8 and libtiff digest10, both accepted full primary68B. Its
independent retained peer was pending when referenced here. The new-pair's
digest10-only verifier is not applied to old jbigkit. This transport helper
does no cryptography or archive/package execution, and future CI retains its
existing signature checks. Local byte custody does not prove current HTTP
availability or whole-501 admission.

The independent peer checks actual maintained files and Source7fde Git,
three-copy binding, preserved Source09 bodies, exact workflow mapping and
finite synthetic in-memory failure controls. Its fake environment/filesystem
tests are modeled evidence; no actual private chunks or native pipeline are
run. The final receipt binds those controls, custody and its path correction,
Source audit, full proposed files and this guide. `seal.py --check` rechecks
the preadoption old joins read-only; after adoption those old joins necessarily
change. Root must rejoin the actual base immediately before copying.

Root owns private provisioning/custody, CLI selection, registration and
dispatch. No secret is provisioned or worker/actor grant issued here. Historical
497 successful acquisitions and four HTTP404 failures remain unchanged; no
old result is backfilled. Future cache acquisition, all signatures, build,
integration, installation, hardware, performance and public release acceptance
need actual records. Source/license and ABI admission remain separate. This
preparation maps to R1/A05/A12; all R1–R5/M5–M9/A01–A15 remain required.
