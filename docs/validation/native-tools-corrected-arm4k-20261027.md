# Corrected maintenance and diagnostics: native ARM4K components

On October 27, 2026, Root accepted **cachy-asahi-maintenance 0.1.0-2** and
**cachy-asahi-session-diagnostics 0.1.0-3** for finite generic native ARM build-pair
and disposable installed CLI evidence with **4096-byte pages**. Acceptance is
limited to these exact sources and runs; neither package is selected for release.

| Identity | Maintenance | Session diagnostics |
| --- | --- | --- |
| Native source | `50c6280fa3b2871bb663c0910d95e35f2a488b01` | `e20eb9a2095f3e9a2dd0073ce68f9208bec0d87d` |
| Ref | `codex/maintenance-corrected-fixture-native-v3` | `codex/session-diagnostics-corrected-socket-native-v3` |
| Run, attempt | [40519287429](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40519287429), 1 | [40519714137](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40519714137), 1 |
| Job | `122241646071` | `122243177376` |
| Original evidence artifact ID | `12741965544` | `12741267389` |
| Complete source context | 59 files | 54 files |
| Each native build archive | `cachy-asahi-maintenance-0.1.0-2-any.pkg.tar.xz` | `cachy-asahi-session-diagnostics-0.1.0-3-any.pkg.tar.xz` |
| Each archive size | 53,104 bytes | 20,924 bytes |
| Each archive SHA256 | `028340024c32ff02109679d6a5dfc56122c769830b94014a5373199c26e195d1` | `8e69184b33395d80ba921385d0ed071cc35178ae64f18549a9bf34e5c185c70d` |

For each package, two distinct recorded clean build containers produced identical
archive bytes, payload, PKGINFO and complete 574-package BUILDINFO. These are
within-run pairs; independent-machine reproduction is not attested. The archive
sizes/hashes above identify the built packages, not their containing evidence ZIPs.

Each installed component records five ALPM transitions, two ordinary fixture
profiles and restoration of the original 574-package inventory. Maintenance joins
the complete 16-file installed payload and nine private modules, signed TEST
health fixtures, preserved inputs/configuration and held planning behavior.
Diagnostics joins its seven-file payload and headless/explicit CLI controls;
unknown results and injected absent-tool controls do not establish live target
services. Both records include TEST package signature, preservation and retirement
of four consumers before producer cleanup.

## Acceptance receipts and limits

The [maintenance Root qualification](../../artifacts/development/maintenance-corrected-fixture-native-actual-20261027/Root-native-component-qualification.json)
and [diagnostics Root qualification](../../artifacts/development/session-diagnostics-corrected-socket-native-actual-20261027/Root-native-component-qualification.json)
are the finite acceptance authority. Root joined original terminal metadata,
original logs and evidence ZIPs acquired once, with genuine HTTP/API and artifact
size/digest receipts. Root acceptance is separate from passive projection status;
source qualification alone grants no runtime credit.

The maintenance [strict result](../../artifacts/development/maintenance59-Root-strict-run40519287429-attempt1/strict.stdout)
is 100,182 bytes, SHA256
`81a7f54b33b00944860e4c71c2c96c67c4f20994f46617a093920504940dfa86`.
The diagnostics [strict result](../../artifacts/development/diagnostics54-Root-strict-run40519714137-attempt1/result.json)
is 30,371 bytes, SHA256
`c746d0d12f0fc78ebff4559c2a73c949d7a9b92f0335792e6badb46ddf5877ab`.

Signatures, ALPM preservation and actor absence are source-bound receipt/log
joins. No independent historical cryptographic authentication, private inode,
configuration or process-state replay, or live daemon/service recheck is claimed.
Maintenance's package signature time is joined to the selected job and verified
before staged observations. TEST health keeps ARM security **UNKNOWN** and
maintenance acceptance **NOT_ESTABLISHED**; it does not establish production trust.

Generic 16K and both physical M2 Air sizes remain **NOT RUN** for these components.
Performance is **NOT MEASURED**, security **UNKNOWN**, and release **NOT ADMITTED**.
The selected integrated Asahi composition, live target services, real user
profiles, maintained-system acceptance and target recovery remain separate gates.

## Historical failures remain failures

Maintenance [run 40499578636](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40499578636),
source `3d68ac1f5f29ebbe17fad6e9d20d6c39706cf22d`, failed release1's first
check setup when recursive fixture copying encountered makepkg's live logpipe
FIFO; zero package tests ran. Diagnostics
[run 40499774542](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40499774542),
source `44c025a31c640fd96dda2b1efa2aa06c27c15d41`, failed release2's first
check after 34 of 35 probe controls, at the socket fixture's positive assertion.
Neither failed run reached build2 or installed lifecycle. The later corrected
runs do not change those outcomes.

The [host correction note](native-tool-package-fixture-fixes-host-20261027.md)
retains the causes, bounded source changes and pre-run **NOT RUN** state. Frozen
package/source provenance and old readers likewise retain their historical
labels; this external record supplies the later exact-source component results.
