# Successor E: five exact package grant/project-notice closures

This batch closes **five scoped package grant/notice evidence gaps**, reducing
**96 unresolved cases to 91**. The 8–12-case aim was not reached: other primary
sources supplied weaker evidence, which receives zero closure credit. Prior
reports are unchanged. All-file/full-projection, legal, activation, native/M2
and release acceptance remain held, including for these five scoped closures.

| Exact package | Recorded commit | Actual named notice |
| --- | --- | --- |
| jni 0.22.4 | `5ae9458a4ec44c5318f37ddc7569c1d4ae8a69e7` | Copyright (c) 2016 Prevoty, Inc. and jni-rs contributors |
| jni-macros 0.22.4 | `33045a124105c939d1e2cbdcb5a39e5d868ffa03` | Copyright (c) 2016 Prevoty, Inc. and jni-rs contributors |
| jni-sys-macros 0.4.1 | `64d77b7a5f119d7b55b4e2c169a4668067ff59e6` | Copyright (c) 2015 The rust-jni-sys Developers |
| defmt-parser 1.0.0 | `4a8cdb44891ed57b8ff5a023b6bec7137c48708f` | Copyright (c) Ferrous Systems |
| wasite 1.0.2 | `3f7d6ad926848cd52c8d2142fdb2f43ab01ae8ec` | Copyright © 2022-2026 The Wasite Contributors. |

Each complete original manifest/VCS capture matches its literal version,
recorded path/revision and primary Git blob. Root licenses and small directory
shards are pinned independently at each commit. The two JNI grants have equal
bytes but distinct per-commit HTTP/tree receipts; no common scope or attribution
is inferred from that equality. JNI's inherited MIT alternative is resolved
from its exact containing workspace, including its `crates/*` member pattern
and exclusion check. The other four declare MIT as a literal alternative.

All five complete selected MIT grants retain the mandatory copyright and
permission inclusion condition, warranty disclaimer and liability exclusion.
`report.json` carries exact source URLs, revisions, SHA-256/Git blob joins,
license scope and notices. Author lists, templates and different revisions do
not supply attribution.

Wasite's actual root grant is `LICENSE_MIT.txt`. Its notice is separately in
its root package README under `## License`, explicitly applying the available
license alternatives to the project. That complete README matches both the
primary Git blob and authenticated private vendor capture, and the original
manifest declares it as the package README. Its stale remote `v1/LICENSE_MIT`
link was **not followed or substituted for the actual pinned grant**. This
is a project/package-root notice, not a source-file copyright promoted to
package scope.

The defmt parser appears only in the recorded Cargo-tools lock. The other four
are outside both recorded root/Cargo-tools locks. Their source evidence does
not establish actual compiler/runtime or Linux target activation. All five
retain `actual_target_activation = NOT_PROVED`.

The finite unsuccessful group stays unresolved:

- Wasmtime/Cranelift's seven cases: actual root Apache/LLVM grant retained;
  appendix placeholder supplies no named notice. No version/manifest holds
  were relaxed to manufacture seven closures.
- mdbook-i18n-helpers: Apache appendix placeholder is not attribution.
- winsplit, pulldown-cmark-to-cmark and ungrammar: no complete root grant was
  established from the acquired root metadata; no all-file absence claim.
- xflags, xflags-macros and xshell-macros: root MIT Git IDs match previously
  retained bodies without named owners; no new named notice established.
- syn-test-suite: recorded revision request returned HTTP 404. No alternate
  repository or commit was guessed.

`report.json` preserves all 91 remaining components, including original
partial attribution cases, explicit dirty/version holds, the object mismatch,
framework licensing uncertainty and platform/feature constraints.

Acquisition is closed at **29 actual HTTP requests / 76,018 response-body
bytes / 204.454 seconds**, below **50 requests / 2 MiB / 15 minutes**. The
per-body cap is 128 KiB; network timeout is 20 seconds with a 60-second transfer
check. Actual receipt 13 is HTTP 404; receipt 16 is the official HTTP 301 before
the ungrammar repository-ID response. Both count. No retries occurred. TLS
verification was enabled. Incomplete/error bodies cannot satisfy positive
joins; each request's status, bytes and completion flag are retained.

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-e/reevaluate.py \
  --candidate-packet /tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json \
  --output /tmp/new-notice-successor-e.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/archive-inventory/checksum-successor/license-followup/compiler-notices/successor-e/test_reevaluate.py -v
```

All **nine controls passed**, including real offline replay, complete grants,
distinct revision scope, exact inherited license, different JNI notices,
separate project-notice/vendor correspondence, repository/shard identity,
strict request/body/time/error budgets and closed acquisition. Real replay
skips if its deliberately private packet is unavailable. Replay uses zero
requests and a 256 MiB/30-second process bound; output is new below `/tmp`.
The private packet is not published. Primary files stay inert DATA. No archive
reads/downloads, checkout, builds, package activation, source/native actors,
leases, trust, daemons, shared manifests or workflows were changed. Only this
new successor subtree is changed; Root owns integration and publication.
