# Finite Core7 disposable native lifecycle

Root accepted native ARM run [39723885884](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39723885884),
attempt1, source `1a76a09d9cb8210cc2b76eda0c63a08bcd89d4ec`, ref
`codex/core7-baseline-scriptlet-v1`. Once-only original collection and the complete
814-file strict reader both exited0. Root issued a separate component acceptance;
the passive reader's retained `Root_acceptance: REQUIRED` field remains unchanged.
The original800 source and814 reader before/after pins remained exact.

The result covers seven Core products: pacman, systemd, systemd-libs,
systemd-resolvconf, systemd-sysvcompat, systemd-tests and systemd-ukify. These are
the exact independently accepted [fixed-BTF build pairs](core-fixed-btf-native-20261021.md)
from run39589633375. That build acceptance is a separate prerequisite, not a
second package build performed by this lifecycle run.

## Exercised behavior

Two owned disposable cases, pristine and modified, each exercised install,
repeat install, reinstall, rollback and repeat rollback. Both reached589 installed
packages and restored574. The complete result includes22 fresh full graphs and
127 recorded lifecycle commands. The lifecycle recorded1657.411 seconds within
its unchanged3600-second bound; this is an execution duration, not a performance
comparison or a claim about a physical Mac.

The original fixture disables automatic hooks. Before each case's first baseline
capture, the exact signed ORIGINAL systemd scriptlet initializes the previously
uninitialized baseline accounts. Existing records are preserved and repeated
initialization proves account idempotence. Subsequent account changes remain
forbidden. Explicit original/candidate scriptlet execution is checked separately;
this does not qualify automatic ALPM hook dispatch.

Cache transitions retain full raw bytes and typed live-library/key/hash checks,
plus original-helper idempotence. Payload, raw package database, configuration,
capability, mount and other complete graph preservation predicates remain
required. No account/cache exclusion or BPF disable was introduced to pass.
Foreground CLI/ukify/unit observations and ordered cleanup remain part of the
source-bound protocol; they do not establish a booted systemd service manager.

## Evidence and limits

The authoritative local decision is
`artifacts/development/core7-baseline-scriptlet-native-actual-20261022/Root-component-acceptance.json`.
The separately retained `Root-result.json`, original run/jobs/artifact metadata,
once-collected `originals/artifact.zip` and full source/reader bindings remain
beside it. Artifact ZIP:169,694,185 bytes, SHA256
`478c33985130ec95ba7c85f8b05fec6c6fa6c64568747416cb68f05da17e4a35`.
The accepted result hash is
`67808fbceb325367030223982461564f7861547a2fe8376ac9c70dc414fad2ce`.

Private full-root graph checks are source-enforced; complete private maps were
not exported for independent whole-map reconstruction. Retirement is recorded
by the source and was not independently reobserved live after collection.
Automatic hooks and live PID1 remain **NOT QUALIFIED**. Asahi platform integration,
both physical M2 Air models, boot/recovery, performance and release admission
remain **NOT RUN or NOT ADMITTED**, as applicable. The old261 target provenance
is unchanged and unaccepted. This finite result does not qualify the complete
supported composition or change source-only factory admission/default contracts.
