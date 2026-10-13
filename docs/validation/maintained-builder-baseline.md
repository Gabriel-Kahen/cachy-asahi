# Maintained builder baseline: actual input audit

The explicit successor baseline passes its first actual input audit. On October
13,2026, the unchanged native builder's audit mode accepted501 pinned local
transport objects, verified249 signatures under the selected full key
fingerprint, and checked248 package metadata records plus the rootfs inventory.
The process exited0 on an x86 host. Independent retained-evidence review passes.
The [structured execution summary](maintained-builder-baseline-audit.json)
records exact input, recipe, producer and evidence hashes.

The successor input lock is
`beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f`.
Its two Vim package rows explicitly select9.2.1178-1; the other246 package rows,
rootfs, signing key and source epoch retain their prior pins. The four changed
transport objects are the two archives and their signatures. This is a separately
versioned baseline, rather than a replacement claim for the frozen input lock.
The old FDK/updater runs still failed on four unavailable9.2.1164-2 objects.

Root copied and verified501 exact local inputs totaling1,531,622,678 bytes,
then ran the captured79-source audit route. Native producer source remains
`a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`,
and the four recipes remain
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.
The selected direct audit guard bounds1200 seconds, uses isolated raw-source
loading and private temporary/keyring paths, and permits only fixed GPG command
shapes. This execution starts no Docker, integration or package build. The
standalone successor wrapper was bypassed while its first-exception publication
finding was being corrected; the separately reviewed correction closes that
source finding without rewriting this actual run.

All249 retained verification records have integer exit0 and one full pinned
VALIDSIG. Acquisition's historical signature field describes its transport-only
phase; the separate verification records supply the actual cryptographic result.
The command allowlist contains250 shapes; an aggregate invocation counter was
not exported. The pinned primary fingerprint is
`68B3537F39A313B3E574D06777193F152BDBE6A6`. Validity under that key establishes
this selected-key check. Public key ownership, source correspondence and
redistribution terms have separate unresolved gates.

The private GPG homedir received a scoped agent-stop command, which exited0;
its later receipt records no homedir sockets and unchanged97 retained artifact
hashes. Process-tree absence remains unattested. The cache is retained privately.
The independent peer authenticates the retained evidence and uses five pure
negative controls; it reruns no GPG/archive/image actors or current cache hashes.
See the [independent review](../reviews/maintained-baseline-audit-actual01-root-review.md).

The next required step is guarded clean native ARM build pairs using this explicit
baseline, with owned Docker/process cleanup and retained provenance. Installed
Asahi compatibility, complete payload/trust/ABI,16K runtime, both M2 Air sizes,
performance and R1–R5/M5–M9 release acceptance remain open.
