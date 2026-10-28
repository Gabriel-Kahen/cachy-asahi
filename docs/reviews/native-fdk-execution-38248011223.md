# Corrected FDK native trial 38248011223

Actual hosted ARM execution completed **FAIL** at 12:22:25 UTC on 2026-10-12.
The accepted source commit was `85e4af5df4f3ff3b10568087c0e4e99e9523ebeb`,
job packet `309fcd6fbec8b7e96c83ea049804ae3134e7190d2145e81afc66d28563097f44`,
and stage lock `b83ddb865d7651c748258ac570e64fb824caf5bced8b1f415694dff7f5c187f5`.
Workflow `1b816792b936c802d07e0e074eebce0b9e5b439c6c1a5984a1a23df1a91330ed`
was unchanged. Committed-source and native prerequisite preflight passed.

The source correction removed the unsupported `docker start --sig-proxy=false`
argument. This trial progressed beyond the preceding inventory-probe refusal;
its finite error is now `producer-after-original-compare-failed`. That code
identifies the last retained producer diagnostic and subsequent failure. It
does not recover the private comparison, original result, or cleanup receipts,
or prove that the comparator itself returned failure. Exact cause remains open.

All 501 acquisition objects are recorded PASS. Original native build acceptance
is incomplete; FDK compilation, installation, hardware validation, and binary
publication are NOT RUN. Outer cancellation is false. The job reports owned
image absence true; this does not independently establish every private
producer resource or build-cache cleanup condition.

Public encoding passed. Strict decoding recovered one 85,516-byte bundle,
SHA256 `0a10aef3d6aa30bb647033e9ab304963faa472cb815a859df2ea33b0da7b15be`,
containing seven regular files. The exact workflow public validator accepted
their closed schemas, original input/recipe pins, export manifest, source/job
bindings, and finite failure code. The actual records and root hash inventory
are retained under `artifacts/ci/38248011223/`; the root receipt is
`root-public-verification.json`. This is acceptance of failure evidence, not
acceptance of native packages or signatures missing from that evidence.

Next work: independently inspect the producer's post-comparison and cleanup
boundaries, reproduce any concrete defect, and add only the bounded diagnostic
classification necessary for another finite trial. Preserve the failed trial
and the strict native acceptance requirements.
