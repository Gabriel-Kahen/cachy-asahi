# Virtual controller metadata correction review

Independent focused source review on 2026-10-12. Read the virtual guest workstream and previous controller/commit metadata reviews, then checked current source, retained probe receipts, pinned primary daemon source and bounded portable fixtures. Only this review document was written. No Docker, Git mutation, installation, native ARM program, guest, compositor or hardware operation was performed.

**Outcome: source-ready for a separately frozen controlled native workflow; no new actionable source blocker reproduced.** This does not establish an accepted installed image or native guest execution.

## Exact source snapshot

| File | SHA-256 |
| --- | --- |
| `scripts/virtual/controller.py` | `63a5dd2185bd263bb8b7699bf7ac3bec1c5746329259c386dc9d93090e73dd64` |
| `scripts/virtual/test_controller.py` | `d77091fd5cf6200a7ee5f79d6b09f3a66afe183effe5113cc0abfdecc38c8f43` |

Independently verified all five CORE entries against current file bytes. Common `6479ee7245be45617deb58dfe5c4e2ca8aa13493a500c6a61feb69008942c381`, guest/preparation/run/C-probe and auditor `f2005ea8366f64cd81aa7fb7dbae9e60c835da77164adba4d8e434af262fda13` retain the accepted earlier review pins. Tooling lock `7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25` and audit `3a7c30ba244a874625da994f896ae080a2b60f092b04f5f2d6caa70239e4f41d` also match current bytes. This correction does not change the authenticated 19-package extension.

## Normalization and commit semantics

`config()` additionally maps precisely `Entrypoint == ['']` to an empty list and `Labels is None` to an empty map. The equality comparison still retains nonempty entrypoints, commands, label entries and exact Env content/order. In particular, `['', '/bin/sh']` and `Cmd == ['']` remain unequal to an empty command configuration; a retained TEST nonce in Env also remains unequal.

`commit_args()` emits `ENTRYPOINT [""]` only for a semantically empty accepted base entrypoint (`None`, `[]`, or the exact sentinel), while preserving the accepted base Cmd. The [Moby v28.0.4 commit merge implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go) inherits a runtime Cmd when both requested command arrays are empty; the nonempty sentinel prevents that branch. Its [container creation implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go) resets exactly that sentinel. Thus the correction avoids inheriting the tooling runner's command while retaining empty-entrypoint behavior. Every virtual child additionally supplies an explicit `/usr/bin/env` entrypoint and executable.

The controller passes test identity through command arguments rather than changing Docker image Env. After commit it compares the complete projected Config with the accepted baseline and still rejects changed commands, Env, labels, user and other projected fields. This normalization does not permit arbitrary metadata drift.

## Preserved acceptance and cleanup gates

The host contract still requires the complete authenticated 341-package base plus all four original packages, accepted lifecycle PASS/ready state, exact source/image/lock/receipt/payload bindings, sanitized READY receipt, matching committed Config and fresh baseline verification. Counts or synthetic accepted-stage fixtures do not establish the actual prerequisite 345-package installed image.

The derived tooling image must still contain the exact 364-package inventory and original payload/ownership maps. It is freshly checked through a separate read-only container after commit, with private state absent. Existing source/device/network/capability/mount/resource guards remain in place.

A unique private recovery tag is checked absent before ownership is registered and commit begins. A returned ID is registered before Config inspection; it must differ from the baseline and preexisting images. An uncertain commit outcome remains FAIL even if tag absence is observed. Cleanup independently checks owned container/tag/image absence and does not prune or remove the accepted baseline by inference from global image-list differences. Cancellation and failed cleanup cannot produce a successful final receipt.

## Independent checks and evidence limits

`python3 -B -m unittest discover -s scripts/virtual -p 'test_*.py' -v`: **31 PASS, zero skips**, comprising 14 core and 17 controller tests. These include generated CLI changes passed through the pinned daemon command-merge branch, exact sentinel/null-label comparison, nonempty metadata rejection, uncertain/remaining-image cleanup refusal and the actual mocked main path with sentinel-bearing image metadata. Docker/native actions in controller fixtures are mocked; real bounded child-process tests do not constitute ARM execution.

Additional temporary fixtures changed accepted receipt contents and refreshed their input hashes, so rejection did not merely result from stale checksums. Failed/not-ready lifecycle state, installed count 344, failed fresh baseline verification and retained TEST identity were all refused. Calling the actual `installed()` function with a mocked query rejected missing, extra and version-drift inventories before any further operation. Additional equality cases rejected nonempty commands/labels and Env order/content drift.

Read, without rerunning, `/tmp/cachy-config-probe-receipt-4qbp04gs/result.json`. It records successful sentinel/reset/empty-label checks, no process started and owned-object cleanup on local x86 Docker `29.8.0`. Its execution label says API1.51 while its `api_version` field says `1.56`; that earlier attribution ambiguity remains a documentation/evidence limit. The compact public `artifacts/reviews/docker-config-metadata-probe.json` records only scope and cleanup. These receipts support the reported metadata-only behavior; they are not Docker28 native ARM, package transaction, guest or frame acceptance.

A future execution must use a newly frozen contract with the reviewed controller hash and the actual accepted 345-package prerequisite image and receipts. Automated capture still stops at `CAPTURED_REQUIRES_VISUAL_REVIEW`; matching hashed frames require separate review. Native guest, acceleration, 16K-page behavior, physical M2, performance and complete R1–R5 acceptance remain separate evidence gates.
