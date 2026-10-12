# Virtual integration independent review

October 11, 2026 local time. This is an interim source/bounded-fixture review
while five component implementations and CI orchestration are being finished.
Only this document is owned by the reviewer. No Docker job, pacman transaction,
host account/trust mutation, real-home setup, workflow dispatch, source/manifest
or Git change was performed by this review.

Read the roadmap and current package inventory first. The four original
development packages have accepted native build/rebuild evidence; release
selection is still false and target installation/hardware results are NOT RUN.
Virtual integration cannot change those physical/release requirements by itself.

## Reproduced issue and correction

### V1 — Repository success originally lacked expected installed-state checks

The first observed `repository.py::transaction()` recorded PASS after any
zero-exit pacman call. Only negative cases compared before/after snapshots.
The surrounding code checked the separate synthetic fixture's content and
original-package file presence, rather than each original archive's exact
version and payload after install, upgrade and rollback.

Bounded reproduction mocked package commands and snapshots without executing
pacman. Identical before/after state still produced:

```text
trusted-original-upgrade: PASS
```

Sent this assertion gap immediately to the coordinator. The owner subsequently
added required expected state for success, complete base/overlay versions,
package ownership, archive-derived payload hashes, absence of obsolete payload,
and expected synthetic fixture bytes.

Independently reran targeted negative fixtures against the corrected source:

```text
No expected success state:
  successful transaction requires all four expected original versions/payloads
  snapshots/commands executed before refusal: 0 / 0
Wrong original versions:
  installed package versions differ from complete reviewed transaction
Wrong original payload bytes:
  installed payload differs from reviewed archive
```

**Resolved for these reproduced cases.** This checks assertion behavior, not
actual installation or rollback execution. Final frozen source and native
transaction receipts still require integration review.

## Producer/consumer interface findings

### V2 — Raw repository exports require deliberate evidence adaptation

The repository source exports repository trees with managed symlinks (active
selection and pacman database aliases). Existing `log_evidence.bundle()` rejects
symlinks. Reproduced its refusal with a temporary tree matching that export:

```text
symlink evidence forbidden
```

The new `integration_export.py` intentionally exports only bounded public
JSON/log/text receipts and also rejects symlinks and archives. It is not a
direct raw-component export path. The orchestrator must construct deliberately
public regular-file receipts and retain allowed repository aliases as checked
records, rather than feeding the raw tree to a bundler or weakening generic
symlink checks. This is a confirmed interface incompatibility with direct raw
export. The later alias normalization is independently validated below; the
separate public-status filename adaptation remains open as V4.

The exporter also conservatively rejects GPG/private-labelled paths and
credential/private-key patterns. Raw command records containing key-generation
`--passphrase` flags will be rejected even for an empty TEST passphrase. Such
records must be replaced by deliberately public identity/signature/cleanup
receipts before export; private directories must never be copied for later
filtering. The filter explicitly does not promise arbitrary credential detection.

### Different component container contracts must remain explicit

- Lifecycle uses a writable disposable overlay root for real container-only
  pacman/account operations. It binds a nonce, immutable image identity,
  all-four baseline/upgrade package/version/signature/payload maps and fixed
  read-only `/inputs` and `/runner` plus `/out/lifecycle`.
- Repository uses a read-only container root and copies its generic base into
  writable `/scratch` tmpfs; private TEST key storage is separate `/test-home`
  tmpfs. Its private root/database/cache/config/keyring are explicit.
- Desktop and onboarding use ordinary users, a read-only installed image,
  capability drop/no-new-privileges, loopback-only network, read-only inputs and
  owned temporary home/workspace storage. They need an image handoff bound to
  intended installed archive versions and payloads, not inventory alone.

These are compatible separate stages, not interchangeable flags or schemas.
The coordinator was advised to freeze adapters and sanitize any derived-image
handoff before orchestration acceptance.

## Source boundary observations

Reviewed current `lifecycle.py`, `fixtures.py`, `desktop.py`, `repository.py`,
`onboarding.py`, TEST signing, and public evidence exporter source as it appeared.

- Lifecycle and repository refuse ordinary host calls before package/key/account
  mutation, using actual container/mount/runtime/network observations and fixed
  paths. Lifecycle rechecks actual environment before command execution; stale
  supplied probe data alone cannot arm the host package command path.
- Desktop's initial weaker guard was strengthened during review to validate
  actual nonce/image identity, effective/permitted/bounding capability drop,
  no-new-privileges, loopback, fixed read-only runner/inputs/overlay, owned temp
  storage and forbidden host/system mounts. It only launches parser/version
  checks; its no-DRM compositor-session limit is explicitly BLOCKED.
- Onboarding now checks complete installed inventory plus expected baseline
  file hashes/types/modes/ownership. Its PTY/shell/editor/compiler journey is
  explicitly software-only; graphical usability and full target onboarding
  remain NOT RUN.
- Fixture generation hashes and captures frozen original bytes without sourcing
  recipes, retains original MIT material, emits reviewable diffs and greater
  versions with changed installed payload, and labels all derivatives
  DEVELOPMENT ONLY with release selection false and execution gates NOT RUN.
- TEST signing uses one-day TEST identities with private key generation inside
  unmounted container tmpfs, exact archive pins and static inspection, explicit
  signer/source bindings and public-only export validation. Host verification
  uses an isolated temporary public-only keyring, not the host default keyring.
- Repository TEST keys/revocation material stay outside output; source includes
  cleanup on failure and public identity/signature records. Actual ephemeral
  cleanup and publication safety still require the final native execution and
  deliberate public-export path; source is not evidence that those ran.
- Hardware/graphics/physical recovery/performance/stable-promotion fields remain
  NOT RUN or explicitly scoped separately; no source path observed manufactures
  an M2 physical PASS from generic container success.

## Actual bounded checks and unfinished review

Reviewed test fixture paths/mocks before local execution. Package/account/key
commands were mocked; actual shell/editor/compiler checks used temporary homes
and copied known source only.

- Initial aggregate: 54 tests, one 20-second temporary-PTY onboarding failure at
  `zsh-after-remove`. Immediate independent whole 13-step journey rerun passed;
  the standalone nine-test onboarding version also passed. Source was actively
  changing; the first failure was retained, not relabeled a pass or diagnosed as
  a confirmed implementation defect.
- A later aggregate at 77 tests had one onboarding mocked-container/result-file
  fixture failure while that worker added suite integration. It is not an
  accepted aggregate pass and is not treated as missing in-progress work being
  a completed implementation bug.
- Independently ran 24 TEST-signer boundary tests: passed.
- Independently ran 12 public-export tests: passed.

No full end-to-end virtual integration execution or final frozen orchestration
review has occurred in this review checkpoint. Re-run the stable aggregate and
review the final signing/container/image/export adapters before dispatch. Then
independently inspect actual package transactions, changed-version/payload
upgrade and rollback, trust rejection/rotation/revocation, installed-helper
recovery, software journey, private-state cleanup and public receipts.

Even a complete virtual pass cannot close exact-M2 hardware, target Asahi
dependency selection, full physical onboarding, public production repository
trust/custody, boot recovery, power/performance or ongoing-maintenance gates.

## Controller adapter checkpoint

Read the revised `goal.md`, roadmap, outline and acceptance contract after the
coordinator integrated the expanded R1–R5 requirements. This batch remains the
initial four-package integration foundation. It does not establish maintained
Cachy-derived package coverage, Apple platform management, final-system tuning,
complete-port installation or a subsequent maintained port release.

### V3 — Installed handoff loses the contracted child environment

`installed_handoff.py::Handoff.command()` initially supplied a minimal child
environment with PATH, HOME, LC_ALL and PYTHONDONTWRITEBYTECODE only. Its actual
lifecycle child reads `CACHY_ASAHI_DISPOSABLE_LIFECYCLE` and
`CACHY_ASAHI_IMAGE_ID` from the environment before executing. Those two values
were therefore absent even though the outer handoff guard accepted its contract.

Independently captured the subprocess environment with a mocked command: both
identity fields were absent. The lifecycle's actual guard requires them, so an
actual handoff would fail before its package transactions. Reported immediately
to the coordinator. The existing mocked lifecycle child could create a PASS
receipt without exercising this producer/consumer boundary. Explicit forwarding
of the already-validated contract identity and a child-guard regression are
required; forwarding arbitrary inherited environment is unnecessary.

The owner corrected this at handoff SHA-256
`1f5ee982b3ef2ab3f2b120b4373fa5f1365960452e4e2aa1f02637d692ebfc30`.
Independently reran the command-environment reproduction with conflicting
inherited nonce/image values and an unrelated private-labelled sentinel. The
exact contract values were forwarded, the unrelated sentinel was absent, and
the actual lifecycle guard accepted the synthetic child's contracted identity.
All **24 current handoff tests passed without skips**. **V3 resolved for this
boundary**; actual lifecycle transactions remain unexecuted by this reviewer.

### V4 — Public repository signature-status filenames are rejected

The real repository producer emits names such as
`NNN-gpg-untrusted-A-status.txt`, with matching names for tampered/revoked
signature checks. The controller's selector treats `gpg` in any filename as a
sensitive path and supplies an empty placeholder to the public exporter. The
exporter then rejects that path, causing the repository stage to fail even if
every real transaction and trust check succeeded.

Bounded reproduction invoked the actual repository `command()` with a mocked
subprocess returning a public NO_PUBKEY status, then invoked the actual
controller selector/exporter against the resulting temporary evidence:

```text
ValueError: public evidence exporter rejected component output
000-gpg-untrusted-A-status.txt: sensitive-path; subtree not exported
```

Reported immediately. Deliberate public status-log naming or an exact public
adapter is required; arbitrary GPG/private-path filtering should stay strict.

The controller now projects six exact producer labels to neutral public names,
binding each original log name, index and SHA-256 to the producer result. Reran
the actual producer-command/export reproduction for all six labels: all six
public projections exported successfully. Changing an original log failed its
hash binding, and adding an unmapped GPG-labelled path still failed export.
All **21 current controller tests passed without skips**. **V4 resolved for
these boundary cases**; private-path filtering was preserved.

### Reviewed boundary behavior and verification limits

- The controller's source freeze captures hashes and modes, excludes unused
  `scripts/virtual` and `scripts/client`, rejects links/private paths, re-derives
  exact fixture files before native mutation and rechecks its copied snapshot.
- Containers use immutable local ARM image IDs, explicit mount destinations,
  loopback-only networking, dropped capabilities and no-new-privileges. Only the
  lifecycle handoff has a writable root; other root-required tests use private
  writable tmpfs against a read-only root.
- Image commit requires the bound READY receipt, exact installed inventory and
  original payload checks, private-state cleanup assertions, and an exited
  successful container with the expected base image. The derived image is
  inspected as ARM64 and passed to the software-only consumers by immutable ID.
- Original and generated upgrade archives are inspected without extraction,
  hashed against native provenance, bound to fixture versions and changed
  expected payload, and compared across clean builds. Public binary export is
  limited to the four inspected MIT development fixture archives with hashes;
  arbitrary component binary/private state is excluded explicitly.
- Repository alias export now resolves in-scope aliases, copies file aliases as
  regular files, records directory aliases and signs the alias receipt. Source
  inspection and a bounded actual-export reproduction confirm removal of the
  earlier direct-symlink export incompatibility: directory `active` and database
  file aliases became explicit records/regular copies, zero symlinks remained,
  and `log_evidence.bundle()` produced a regular bundle. Signing was mocked;
  **V2 resolved for this producer/consumer boundary**.
- Source-suite acceptance requires successful unittest summaries, nonzero
  discovered tests, zero skips and every planned suite/check passing. Aggregate
  test count alone cannot turn missing/skipped checks into acceptance.

Independently ran the current CI adapter test suite: **143 tests passed, no
skips**, using only its mocked commands and temporary filesystem fixtures.
Passed that actual verbose test log through the controller public exporter as
well. This is a local source checkpoint, not a frozen end-to-end native
integration result. Actual transaction/key cleanup/committed-image behavior
awaits native execution.

The current public adapter retains TEST signature status and archive/certificate
hash receipts, but excludes the actual public `.asc` certificates and detached
`.sig` files. That limits offline independent signature re-verification from
the exported bundles. Advised the coordinator to retain deliberately validated,
bounded public signing material or report this evidence limit explicitly.
No private signing-state export is needed.

## Cross-check of the second controller review

Read `docs/reviews/virtual-controller-review.md` and independently rechecked
its C1–C5 against the currently changing sources. Pure guard probes reproduced
acceptance of synthetic writable ext4 `/dev/dri`, `/dev/snd` and
`/sys/private-home` mounts by the signer, and replaced `/sys`, `/proc` and `/dev`
mounts by source suites. A mocked successful container command plus failed
removal status 1 still returned normally. No host mount/container operation was
performed. These confirm **C1/C2 remain open at this checkpoint**.

Source inspection also confirms no ordinary SIGTERM cancellation handlers,
handoff certification of mounted `/tmp` instead of the underlying committed
image view, and success-only copying of detailed fixture builder diagnostics.
The bootstrap still copies `/tmp/disabled-hooks.txt` without removing it.
**C3–C5 remain source-audited open issues here**, with correction work assigned;
these were not live cancellation/image-commit reproductions by this reviewer.

Checkpoint hashes (not a final source freeze):

| Source | SHA-256 |
| --- | --- |
| CI controller | `466e5d634dd1f2eb02230523d1eed5d3593733d89b01e10765a10082021fe1cd` |
| Installed handoff | `1f5ee982b3ef2ab3f2b120b4373fa5f1365960452e4e2aa1f02637d692ebfc30` |
| Source suites | `8b5734d1c6ddba6b492876dae0baa80db6b6b8348dce4b32ac3b96fb071e028f` |
| TEST signer | `938f9c6d6659e2f042d851add7e6396a1fdf712f31c13313a1ab1925fe562609` |
| Native runner | `566a537220e4734775cb88467b65d87d827b1b07bb286135070d74f8c3f8a57a` |

Resolve the reproduced/source-audited controller findings and public signing
retention limit before frozen-source acceptance. This report does not authorize
or establish native virtual execution, physical acceptance or complete R1–R5.

## Subsequent image configuration review

### V5 — Derived image configuration is neither restored nor checked

The accepted bootstrap sets `USER alarm` and `WORKDIR /tmp`. Lifecycle overrides
the user to root, entrypoint to Python, command to the mounted handoff runner,
and environment to include its disposable nonce and original image ID. At this
checkpoint the controller commits that container without configuration changes
and checks only the resulting ID and architecture. Docker commit preserves
container settings in the new image; its documentation illustrates retained
environment configuration and explicit changes to USER/ENTRYPOINT/CMD/ENV.
[Primary Docker commit documentation](https://docs.docker.com/reference/cli/docker/container/commit/).

A bounded adapter reproduction supplied a successful stopped-container record
and mocked the earlier READY verification, then returned a derived ARM image
with root USER, Python entrypoint, missing-mounted-runner command and disposable
test identity environment. The actual current controller accepted that image:

```text
derived root/test-identity config accepted: True
commit argv: docker commit --pause=true cachy-asahi-handoff-<fresh-nonce>
```

This isolates the image-configuration check; it does not reproduce or bypass
the installed-package READY checks or perform a Docker commit. The software
consumers explicitly override user/entrypoint and image environment, so this
does not establish an observed onboarding failure. It establishes unsupported
restoration/identity-cleanup claims and broken reusable default runner settings.
Reported immediately: restore the accepted base runtime configuration, exclude
disposable environment identities, and inspect/hash the derived configuration
before acceptance. Private image layer/custody limitations remain separate.

The C4 mounted-`/tmp` certification issue is being corrected: current lifecycle
launch no longer mounts `/tmp` tmpfs over the image. Full independent correction
review awaits the completed controller/handoff sources; removing that mount
alone is not recorded as accepted image cleanup.

Read the new `docs/port/arm-experiments.md` for R1–R5 goal fidelity. It defines a
finite isolated native compression/LTO correctness trial, explicit hosted/M2 and
4K/16K boundaries, later PGO input/profile bindings and required final-system
measurements. It labels C01–C04 NOT RUN and cannot select a release package or
complete R2/A07/A14 by design/source inspection. No material goal-fidelity defect
was found in that document; its runner/tarball/execution remain future evidence.

## Correction recheck checkpoint

The CI/controller sources changed materially after the preceding review.
Independently reran the original behavioral boundaries against the current
implementations; these remain source/synthetic checks without host Docker,
package/account/trust mutation or real signing-key operations.

| Finding | Independent current outcome |
| --- | --- |
| C1 original mount probes | All six writable-ext4 signer/source-suite cases now reject; exact standard mount/device/capability observations are required. New derived/repository guard work remains separately assigned. |
| C2 ignored container removal | Successful execution followed by failed cleanup now raises `owned container cleanup not verified`; removal has bounded retries and a daemon-confirmed absence receipt. |
| C3 ordinary cancellation | Mocked cancellation now attempts named-container removal and retains its cleanup receipt. Source contains controller/signer/handoff/source-suite signal handling and bounded child groups. No actual native cancellation job was executed here. |
| C4 hidden image `/tmp` | Handoff rejects a mounted `/tmp` view; lifecycle leaves that path unmounted. Fresh read-only derived-image fixtures reject underlying `disabled-hooks.txt`, private keyring state and payload drift. Actual committed-layer inspection remains an execution gate. |
| C5 failed fixture diagnostics | The exact regression for build output created before failure passes; current finally path copies bounded regular provenance/validation/build logs even after failed build invocation. |
| V5 committed runtime config | Actual current lifecycle adapter with mocked earlier READY/commands accepts restored base config and rejects root USER, Python entrypoint and retained test nonce. Commit resets USER/WORKDIR/ENTRYPOINT/CMD and verifies the normalized derived config against the inspected base. |

**Original C1–C5 and V5 cases are resolved at this source checkpoint**, with C3
limited to controlled mocks/source inspection and C4 limited to temporary
filesystem/fresh-verifier fixtures. This does not accept all later guard changes
or actual end-to-end container execution.

Verified lifecycle's command carries the six reviewed capabilities including
CAP_KILL for demoted-child cleanup; repository/derived verification retain the
five-capability default. Lifecycle nonce/image identity now enter `/usr/bin/env`
process arguments after the image, not Docker `--env`, preventing their insertion
into committed Config.Env. Config equality and explicit identity absence are
checked before the derived image is supplied to consumers.

The public-signature retention limitation is corrected. Independently exercised
the actual explicit signing exporter with synthetic public packet framing:
one certificate plus all eight detached signatures were copied, all nine
manifest hashes matched, and a changed/private-labelled certificate failed its
verified receipt binding. This exercises retention/packet boundaries only, not
real OpenPGP cryptography. Actual signer code performs independent public-only
verification before supplying those successful receipts. The repository adapter
also retains only explicitly allowed receipt-bound public test repository
archives/metadata/certificates/signatures, including designated negative cases.
Generic private/binary filtering remains strict.

Independently ran the changing current CI test suite: **202 passed without skips**.
This is a checkpoint count, not a final frozen aggregate or native suite result.
The reviewed scan excludes independently active `scripts/client`,
`scripts/virtual`, `scripts/experiments` and `packages/tools`; these later batches
cannot be reported as covered by the first integration execution.

### V6 — Lifecycle refuses standard Docker runtime mask paths

Current lifecycle mount validation still omits standard mask destinations:
`/proc/interrupts`, `/proc/timer_stats`, `/sys/firmware` and
`/sys/devices/virtual/powercap`. Adding each conventional readonly tmpfs mask
to an otherwise valid native lifecycle probe independently produces:

```text
unexpected external mount refused
```

The other runner guards recognize these exact masks. This can prevent handoff
from starting on the normal hosted Docker runtime; it is unrelated to CAP_KILL,
which is now supplied correctly. Reported immediately to the coordinator for
an exact path/filesystem/flags/null-mask correction, without accepting arbitrary
children. Still reproduced against lifecycle SHA-256
`393287c9f836700925a2b4a6f3b16c0bca53fb410593fbfc70e4b40226eaa8d4`.
**V6 remains open.** Final source freeze and native execution acceptance remain
pending this correction and the other independently assigned guard fixes.

Read the newly present desktop/application and tools/functionality port audits
for their declared R1–R5 scope. Their proposed root/provider graph, tool
adaptation/replacement queue and compiled candidate are explicitly incomplete;
they preserve Apple platform, exact-model, full workflow and maintenance gates.
Temporary metadata/architecture/source audit is distinguished from an installable
dependency transaction, retained authenticated inputs and ARM build results.
These docs do not waive the expanded goal. Audit proposals do not select release
packages; implementation and source/license/target evidence remain separate work.

## V6 correction and remaining lifecycle mount checks

At lifecycle SHA-256
`f2b50246f4bc372ddd5deff0244e554a90d8e6aad44bc5861de62e5427fb37bd`,
independently supplied all seven legitimate null masks with character device
1:3 and all five readonly directory masks. The actual guard accepted the whole
standard set. Null device 1:5 and writable firmware-directory masks rejected.
All **36 lifecycle tests passed without skips**. **V6's standard-runtime launch
refusal is resolved** for these actual node-observation fixtures.

A residual independent-refusal gap remains in the same lifecycle source:

```text
/sys filesystem sysfs, mode rw: ACCEPTED
/sys filesystem cgroup2, mode ro: ACCEPTED
/dev filesystem mqueue, mode rw: ACCEPTED
```

The system/device branches accept interchangeable filesystem sets at different
destinations and do not enforce `/sys` read-only/security flags. Reported to the
coordinator for path-specific filesystem/mode/security validation. Current
launch commands construct safe default runtime mounts; this is a reproduced
guard-contract gap, not an observed hosted device/mount exposure or the earlier
V6 launch failure. **This residual lifecycle guard case remains open before
final source review.**

Current repository SHA-256
`22a473a80ddf5df47d45d9190ab400eb822fde1f4d89393a6263dde4e3c2b3ef`
now has strict exact mount destinations/filesystem/root/security flags, nested
mount refusal, five capability observations, NNP and device/socket checks.
Independently ran its **34 tests: passed without skips**. This does not establish
real native repository transactions.

Current derived verifier SHA-256
`8a97dfee2b01b96aa5e0209613c8ae4bad93b71568d7b232b4c2d60897d6b0dc`
checks all five capability sets. Independently injected an unsafe bit into each
set while mocking the native/container observations: every case rejected before
read-side queries. Its remaining destination/filesystem review is separately
assigned; no complete frozen-source acceptance is inferred from these checks.

## Initial frozen-source verification

Independently verified `scripts/ci/integration.lock.json` SHA-256
`5006b37d4c214b77e5b9cd17edce718433ab618a5bbc8773571e379a99779c2a`.
Ran its actual preflight: the full source scan matched all **153** file hashes
and modes, fixture generation reproduced all **125** frozen file hashes/modes,
and a temporary copied source snapshot independently passed its full scan.
The lock binds original recipe SHA-256
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`,
recipe origin `ebd5812640b0b69f5c09a47752b739e37e338754` and epoch
`1791748800`. Development-only true, release selection false and hardware NOT
RUN are intact. Setup source remains the accepted `a6251142…` bytes.

The frozen sources include the controller, signer, public exporter, installed
handoff, fresh derived verifier, native source suites and all five initial
integration runners/tests. No file from `scripts/client`, `scripts/virtual`,
`scripts/experiments`, `scripts/port` or `packages/tools` enters this lock;
independently active follow-up work is neither imported nor claimed tested by
this first batch.

Final lifecycle SHA-256
`e408a540765ede2350a57abd311e8814d516ab379351fe28751a20250a3a8461`
now accepts legitimate observed Docker masks and rejects every previously
accepted residual: writable `/sys`, cgroup2 at `/sys`, mqueue at `/dev`, missing
`noexec` at `/sys` and tmpfs at `/dev/pts`. Independently ran the affected
**37 lifecycle tests: passed without skips**. **V6 and its residual lifecycle
mount-role cases are resolved at the frozen checkpoint.**

No deterministic producer/consumer launch blocker was found in this checkpoint.
Config restoration/process-only identity, per-stage five/six capabilities,
public certificate/eight-signature retention, independent fresh committed-image
inventory/payload/underlying-private-view checks, bounded cleanup receipts and
failure diagnostics retain the corrections reviewed above. Native execution is
still required to establish that those operations actually succeed together.

A previously assigned derived-verifier hardening case remains: at frozen
`verify_derived.py` SHA-256
`8a97dfee2b01b96aa5e0209613c8ae4bad93b71568d7b232b4c2d60897d6b0dc`,
its `validate_mounts()` accepts `/inputs` with filesystem `proc`, mode `ro`.
The ordinary input/runner/output/runtime-file destinations do not validate their
filesystem type. Reproduced this pure mount-table case and notified the
coordinator. Controller-created mounts have the intended bind filesystems, so
this does not prove actual host exposure or a native launch failure. It prevents
claiming that every independently assigned refusal-contract issue is closed.
Resolve it or retain this precise source limitation before full V02/V09 source
closure. Actual native stage results and M2/R1–R5 acceptance remain unestablished
by this frozen-source check.

## Final bounded source readiness

The coordinator corrected the last ordinary-filesystem refusal gap. Derived
verifier SHA-256 is now
`b2375e6efe69307bb6510b4e5b3398b16ff3ea7828c77a10e9c0ab691a84b7c4`.
Independently reran the original `/inputs` proc case, wrong filesystem types at
`/runner` and `/out`, and wrong proc/sysfs/devpts types for each Docker metadata
file. Every case rejected. Conflicting simultaneous `ro`/`rw` at root, inputs,
runner, output and metadata also rejected. Legitimate data filesystem mounts
passed. All **six affected verifier tests passed without skips**.

Independently verified the corrected final lock SHA-256
`d01fbf28be171f838e6bd92d6a89127875d5b1d701c0881f1c8f2826e2840670`.
Actual preflight again matched all **153** source files/modes, re-derived all
**125** fixture files/modes, and accepted an independently copied temporary
snapshot. Original recipe/origin/epoch, excluded later workstreams and accepted
helper bytes retain the preceding bindings.

**The reviewed initial source batch is ready for controlled native execution.**
All material reproduced findings in this review have corrections independently
validated for their bounded cases. No remaining deterministic initial-batch
launch blocker or reported guard-refusal gap was found. This is source readiness,
not a V01–V09 native execution PASS: actual signed transactions, upgrades,
rollback, installed-image checks, software journey, native source suites,
cleanup and public evidence still require their real frozen-run records and
independent execution review. Physical/M2, release/production trust, complete
R1–R5 and later excluded software batches remain separate unfinished gates.
