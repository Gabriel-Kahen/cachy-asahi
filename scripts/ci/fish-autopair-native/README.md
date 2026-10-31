# Native Fish autopair candidate

Separate manual native build/lifecycle lane for the final15-file
`cachy-asahi-fish-autopair` source package. It changes neither the frozen
three-tool lane nor the selected core inventory. Its own concurrency group
is `native-arm-fish-autopair-candidate`, with cancellation disabled.

`prepare.py` reads the exact pinned tools-native run/job source and makes
only fixed, count-checked Fish adaptations: one product, four consumers,
Fish-specific statuses/label/token/entry marker, no highlighting fixture
mount, a 1350-second consumer bound, a 96 MiB evidence bound and local harness
paths. The inherited scripts are never edited. `run.py` and `job.py` are
small entry wrappers; generated source hashes are recorded in source proof.
The complete transformed code is available in the development handoff for
review. Unknown source bytes or changed anchors fail before execution.

The package contract fixes upstream revision
`4d1752ff5b39819ab58d7337c69220342e9de0e2`, all15 recipe inputs, unchanged
five helper hashes, complete upstream MIT license and project license,
Fish>=4.9.3, Python build dependency, any architecture and all11 installed
regular files. No automatic Fish conf.d or user startup path is packaged.

The existing owned574 producer supplies Fish4.9.3-1 and Python. The consumer
verifies the actual native daemon/image and complete574 inventory, checks
all dependencies with pacman -T, then calls the accepted Welcome clean
build helper twice in distinct offline read-only containers. No dependency
fetch, Rust, kernel or desktop build is added. Both archives must have
identical complete bytes, BUILDINFO, PKGINFO and installed contents; every
payload hash/mode/owner is joined to the exact source. No ELF is allowed.

The fourth consumer is a disposable root container performing actual ALPM
install, same-version reinstall, remove, reinstall-after-removal and final
remove. Inventories must be574->575->575->574->575->574. Each installed
phase checks all eleven package-owned files and runs the product's actual
fixture driver as an ordinary user, against the installed module directory,
for both fresh and existing user homes. Every complete suite requires
all14 named cases, all57 ordered editing snapshots and every normal exit0.
This repeats after each installed transition; one isolated suite passing
cannot replace later reinstall checks.

Receipts bind actual aarch64 execution, Fish version/binary hash, installed
wrapper hash, raw receipt digest and actual page size. The driver checks
default/vi/hybrid editing, custom and preset keys, prefix/generic/tab
bindings, namespace precedence, noninteractive no-op, repeated source and
source-caller continuation. It never executes the edited command buffer.

The lifecycle reuses accepted Welcome user-preservation semantics. Existing
Fish config, conf.d preference, universal variables, history and a symlink
retain content, mode, owner and recorded timestamps. System `/etc/fish`
and generated user receipts must also remain unchanged. Fixture caches,
PTY snapshots and logs are created outside those protected user homes.
After each removal, the eleven addon files must be absent, the original574
inventory must be restored, and guarded manual sourcing must stay usable.

The existing ordered cleanup is adapted only for four labeled consumers:
probe, buildA, buildB and lifecycle. Persisted names and exclusive lease,
actual ID/image/label checks, unknown/foreign refusal, confirmed-ID removal
and absence verification remain required before original producer cleanup.
No active cancellation pass is claimed when ownership remains unknown.

One closed 96 MiB artifact retains the two exact package archives, all source
and license files, harness, native metadata/build logs, full installed
receipts, inventories and ordered cleanup. Private HOME/caches/layers are
excluded. The upload includes hidden files only within that closed public
directory; export enumerates frozen harness and exact recipe inputs, including
.SRCINFO. Missing evidence, failed packages, byte mismatch, log overflow or
cleanup failure keep the candidate unaccepted.

The handoff includes a source-only frozen binding. After adoption, replay the
controls. For a deliberate re-freeze, restore the two workflow markers
`@JOB_SHA256@` and `@MANIFEST_SHA256@`, then run:

```sh
python3 -B scripts/ci/fish-autopair-native/freeze.py --source "$PWD"
python3 -B -m unittest discover -s scripts/ci/fish-autopair-native -p test_native.py
```

The freeze binds final canonical source/helper bytes and renders the manual
workflow checksum markers. The dispatch source must equal its workflow
revision before the existing secret seed route. No future commit is assumed.
The development handoff's source controls and generated-code checks are
separate from actual native build/installation,16K execution, M2 hardware,
performance, signatures or release admission. Those remain NOT_RUN until
their respective actual evidence exists.


Actual38915141096 builds both candidate packages with all14 native makepkg PTY
cases passing, but its full lifecycle remains FAIL: the first removal's absent
probe invoked Fish against the protected fresh HOME's .config. Despite
--no-config, Fish initialized fish/{completions,conf.d,functions,config.fish},
and the strict preservation check correctly refused the added files/timestamp.
The correction is harness-only: removal probes retain their actual HOME and
all other environment fields, but direct XDG_CONFIG_HOME to a fixture-owned
0700 fish-config directory in the declared external session output tree, owned
by the ordinary test account before launching it. The installed14-case suites,
all five ALPM transitions, strict full-home/system/receipt/outside snapshots and
ordered cleanup remain unchanged. No snapshot reseeding, new ignore entry,
package/runtime change or product version bump is introduced. Both removal
probes still execute real Fish and assert guarded source usability and module
absence. Source/data-only controls reproduce the old write shape, prove new
containment for fresh/existing homes and show real protected mutation remains
fatal. Corrected native lifecycle execution is NOT_RUN until the next actual.
