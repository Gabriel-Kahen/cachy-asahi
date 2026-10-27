# DNS, Sysctl and Topmem source delivery (2026-10-27)

Source-only extension after the management-tools source-delivery packet. It
requires that packet's 22,974-byte exporter, SHA256
`effec5cc5e54c27e16533e447b04b72476f06513bad4c8cd699621ca986d9174`.
The older 21,108-byte PR285 exporter is not this delta's integration baseline.

Adds three exact `0.1.0-1`, `arch=any`, MIT package profiles. Exact PKGBUILD and
SRCINFO hashes admit only the inspected recipes; every local source is retained,
including tests/checkers that are not installed. All three use the full MIT grant
SHA256 `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7`
and their actual NOTICE. Observed source revision is
`89a423cb56f6500b4b81df47e63f0cfdb823b60b`; it labels inputs and is not authority.

| Package | Recipe inputs | Bundle files including recipe/SRCINFO | Payload files | Bundle bytes | source.tar SHA256 |
| --- | ---: | ---: | ---: | ---: | --- |
| cachy-asahi-dns | 7 | 9 | 5 | 51200 | `8b743cbd6b8c23840f711d1f2a190371091f9245635e24037c915cfc5c2a33ca` |
| cachy-asahi-sysctl | 6 | 8 | 5 | 51200 | `2838fbf84431186b82d1d49afb04c1f9310667e77993502d5c079aa21041fa08` |
| cachy-asahi-topmem | 5 | 7 | 4 | 30720 | `a50c138be7aca307ba51b9e3f6b525781a8ee2acd6974a2806b5202afd82f810` |

Every payload file is a direct source-byte copy. DNS/Sysctl install CLI 0755,
README/provenance 0644 and NOTICE/LICENSE 0644; Topmem installs CLI 0755,
README 0644 and NOTICE/LICENSE 0644. DNS's two small package loops are expanded in
independent test assertions. No generated source, compiled file, hook, service or
resource needs a new representation. The common payload function is unchanged.

DNS provenance binds its exact CLI and declares NetworkManager/nmcli as a
separate unbundled dependency. Sysctl provenance binds its CLI and LICENSE.
Topmem has no provenance JSON; its explicit required-source list matches the
actual recipe. Runtime dependencies remain Python >=3.11 for all three, plus
NetworkManager >=1.44 for DNS. This finite original-source bundle does not claim
transitive system-dependency source delivery or legal/release acceptance.

## Host evidence

Packet: `artifacts/development/dns-sysctl-topmem-source-delivery-development-20261027/`.
The first packet is preserved unchanged. The new exporter depends on it explicitly
and changes only its description and three profile records. All eleven earlier
profile records, complete manifests, canonical bundle bytes and payload maps
compare equal against that frozen baseline; `evidence/receipt.json` retains each
baseline version's bundle hash.

**PASS 92/92 on Python 3.14.7**, with no skipped tests: 10 new tests reusing the
first packet's generic source/archive controls; its 10 previous management tests;
15 original-recipe, 9 expanded-recipe and 31 transport tests; 13 unchanged Topmem
synthetic-proc tests; three original DNS parser/allowlist controls; one original
Sysctl provenance control. New negative controls include every one of 24
source/recipe/SRCINFO inputs, nine unsafe nodes, every one of 14 payload files
with byte/mode/missing mutations, extra payload, and 36 archive metadata mutations.
Archive fixtures are synthetic data, not native build outputs.

Bundles made directly from the three actual checked-out trees equal the pinned
source-only snapshots. Each verifies, relocates/unpacks and repacks byte-identically.
Static recipe checks and Python compilation pass. Each package also has a complete
private data stage with exact path/hash/mode mapping; package() is never executed.
DNS's unchanged checker independently accepts the relocated sources and exact
five-file data stage. CLI argument help executes in-process for DNS/Sysctl;
Sysctl's source/license-provenance check and Topmem's synthetic proc/CLI checks
execute from the relocated sources. No host process inventory is read.

The runner creates no children and has no wait/signaling workflow. Python audit
refusals cover subprocess/fork/exec, signals, socket operations, later ctypes
library loads, and explicit live `/proc` or `/sys` access. These are Python-level
controls, not a kernel sandbox. Source entrypoints and unittest classes execute
in the runner process, with captured output and per-log hashes retained.

```sh
python -I -B -Werror::ResourceWarning artifacts/development/dns-sysctl-topmem-source-delivery-development-20261027/qualify.py --checkout "$PWD" --output "$PWD/dns-sysctl-topmem-source-recheck"
```

Output must be absent. The runner verifies its pinned input map, stages the
proposals in a temporary private checkout, compares all eleven prior versions,
and reads the actual three recipes from the explicit checkout argument. New
proposals and harness hashes are bound in the receipt. Source drift refuses.

## Limits

No PKGBUILD sourcing or recipe hooks, native/build actor, GPG, ALPM, installation,
removal, NetworkManager/nmcli, live DNS/sysctl, process signals, network/API,
settings or download actor executes in qualification. No Git mutation occurs;
a read-only `git rev-parse HEAD` query was used during input inspection. Full DNS offline/workflow and Sysctl
mutation/SIGKILL tests are not run in this task. Two old original regression
methods and one expanded method that execute hooks or launch children remain
explicitly omitted. Topmem tests use only synthetic proc directories.

Actual bundles are not bound to binary archives; no release index is emitted.
Native ARM, 16K, installed behavior, M2 hardware, performance and maintained-release
acceptance remain NOT_RUN / NOT_ADMITTED. No blocker was found for these three
finite local-source profiles. Wider source-dependency coverage is separate.
