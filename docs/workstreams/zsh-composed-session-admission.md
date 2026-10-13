# Explicit composed Zsh Session admission

This is a private functional integration proposal under `artifacts/reviews/zsh-composed-session-admission-20261013/`. Primary code, shared source maps, manifests, workflows, Git and actual dispatch are unchanged. The proposal starts from the published controller `2bba69dd425cb9a8dd0f246e293c3091487f1367504860f7cad8a345e5d0cd61` and handoff `b7b665bc8473c010321c88b00cd35350c03677ffadac02fd2a5ab4c16dc0ecce`. It uses the published Zsh addon and Session adapter without editing their implementations.

## Explicit selection and callback

The new composition is `repository-svg-zsh`. The existing `repository-svg` and `installer-preflight` modes remain separately selected. The private packet/controller changes live in [`proposal-source`](../../artifacts/reviews/zsh-composed-session-admission-20261013/proposal-source/); the original 269-file union remains exact in `captured-source`.

| Mode | Selected source paths | Existing consumer callback | Scope |
| --- | ---: | --- | --- |
| `repository-svg` | 258 | `Development.consume` | Existing KSM → ARM → client → virtual, then repository handoff |
| `installer-preflight` | 265 | `Development.consume` | Existing installer-only branch |
| `repository-svg-zsh` | 263 | `Development.consume_zsh` | Zsh → unchanged KSM → ARM → client → virtual, then repository handoff |

The new union adds exactly these five paths to the 258-path base:

```text
scripts/ci/development/zsh_addon.py
scripts/ci/development/test_zsh_addon.py
scripts/ci/development/zsh_session.py
scripts/ci/development/test_zsh_session.py
manifests/reviewed/zsh-native-addon.json
```

The complete private proposal tree has 270 paths because it also retains the seven installer-only paths for compatibility review. That tree is not a 270-path runtime grant. Each selected packet must use its exact 258/265/263 union.

The Zsh mode requires the existing twelve composed metadata pins plus the exact new manifest pin. Both old modes retain their twelve-pin sets and reject the Zsh pin. Packet, grant, Session composition and callback selection must agree; a Zsh packet cannot run under either old mode, and a cross-mode callback grant refuses before Session allocation. Grant17 and runtime3 remain unchanged. Root still derives committed custody and the selected complete source packet.

The reviewed manifest is an exact 7,317-byte copy of the held proposal, SHA256 `0d73c16425cfeb76951a9cff3a25c2649edf2627d9637eb6cb43193a0f5e03b4`. It describes `cachy-asahi-zsh-autosuggestions` 0.7.1-1, MIT, `zsh>=4.3.11`, upstream revision `85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5`, twelve source files totaling 54,910 bytes and six exact regular payloads. The live reviewed manifest was absent at capture; this lane creates it only in the private proposal.

## Session graph and lifecycle

After the original view is prepared and before the first graph capture, the new mode loads only the captured `zsh_addon` and `zsh_session` bytes through `Sources.module`. It registers `development_zsh_addon` and `development_zsh_session` and adds the closed two-entry `source_graph['zsh']`. Both namespaces participate in the first observation. The second observation adds the actual original nine namespaces and two aliases and verifies all prior non-original identities. No third capture, new SourceAuthority, detached context dictionary, original view, BytesLoader or original producer is introduced.

Admission authenticates captured function code/globals/defaults/closures, class structure and descriptors, policy values and selected imported dependencies. The decorator exception is restricted to the captured addon `defer_cancel` using `contextlib.contextmanager` and adapter `owned_file` using its imported `contextmanager`. A same-name function or an arbitrary decorated function supplies no authority.

The four actual helper state objects are `_RECEIPT_FILES`, `_RECEIPT_FDS`, `_RECEIPT_UNCERTAIN` and `_PROCESS_DISPOSAL_UNCERTAIN`. Their identities remain fixed, with limits of 256 receipt records, 16 descriptors, 256 pending records and one process uncertainty marker equal to `True`. Active file and descriptor custody stays confined to `Development.output/zsh-addon`, with actual parent/inode/owner/mode/hash/FD checks. Only that exact live lifecycle can change; other namespace state remains frozen. Observed uncertainty is sticky and cannot be reset to recover PASS. The last accepted immutable proof in the existing graph observation rejects simultaneous resets of helper state, Source history and its returned closure proof.

Healthy adapter finalization validates retained receipt records and clears their custody ledger while retaining physical receipt bytes. Retirement requires all four registries empty and exact own module identities; it does not erase evidence or clear failed custody. Foreign registry slots and unresolved state remain intact and retirement fails. Returned guard closures are themselves bound by code, globals, defaults, function attributes, closure cells and fixed captured contents; object IDs alone are insufficient.

The controller calls the adapter only through the actual Session graph and `Session.original_context`. It passes the exact existing canonical runtime3 bytes and the same Controller. Zsh output is fixed at `output/zsh-addon`; only its exact `adapter-status` and `public` directories are selectable. Zsh must return provisional PASS, healthy cleanup and the expected non-release/non-hardware fields before the existing consumers run. Later consumer failure remains separate from the completed Zsh stage. Zsh failure, cancellation, custody drift, persistence failure or retirement failure keeps aggregate acceptance failed. Established first exceptions and reported error codes survive later status-persistence faults.

The same job deadline J is retained. The published adapter clips Zsh to `min(J, start+1200)`, work to `min(total-120, start+1080)`, and subordinate gate/build/comparison operations retain their existing caps. No runtime field or budget is renewed. Summed maxima are not a fit proof; actual finite job evidence remains required.

## Compatibility and source findings

Installer preflight explicitly pins the handoff issuer. The frozen private handoff is SHA256 `5a4a6d7cd7a58b40a89428da76fd882ab5d80bb12b6457844354589242469c0e`. Its count-neutral `ISSUER_SHA` literal rebind produces private installer source SHA256 `d240f9959e25851f8688ada75257de54dde40db492b8a2cf9780216bb53bf8eb`; the remaining installer AST is unchanged. No installer predicate is weakened and no installer path enters the 263-path Zsh union. [`mode-proposals.json`](../../artifacts/reviews/zsh-composed-session-admission-20261013/mode-proposals.json) records the exact maps and pins for all three selected modes.

The first actual pair-registration model found a published-helper snapshot obstruction: the helper's `execution_guard` records temporary bound-method IDs in its visited set, but its non-baseline snapshot does not retain those temporaries. Reuse can make an unchanged `sys.meta_path.remove` or `sys.stdout.buffer.write` appear as a different reference. The adapter does not invoke that helper guard. The private Session admission uses a Source-owned dependency snapshot with snapshot-local retention; it preserves the dependency checks and records the original self-refusal reproducer. It does not claim the published helper was corrected or exempt those dependencies.

Exactly three declared standard-library objects retain identity when reached through aliases: `sys.modules`, `sys.path` and `os.environ`. Their mutable contents are outside this snapshot. Other captured bindings and selected dependencies remain checked. Generic graph predicates remain closed; only the exact registered pair delegates to its complete Source-owned namespace snapshots and guarded executable capsules. The named Source admission/history fields receive the same verified graph traversal when reached through callback authority state.

Evidence also retains the initial fixture ENOSPC error. The failure was a temporary copy under `/tmp`, which had about 1.76 MB free; inode accounting did not establish project filesystem inode exhaustion. Ephemeral source fixtures moved to a private `/dev/shm` location and were cleaned up. No old artifacts were removed.

## Evidence and Root handoff

Final receipts separate manifest/controller controls, Session graph/lifecycle controls, preserved counterexamples and lane peer review. Source scans and validators run against captured private bytes. Models of callback/frame/actor boundaries are labeled; they establish no actual original-context or native authority. No real native, Docker, GPG, archive decoder, image, system, installation, network or Git actor runs here.

Root owns adoption of the changed files and installer issuer rebind, the complete selected source packet/grant, shared maps, workflow selection and publication. The published helper/adapter and original159/view160/generated125/recipes4/inputs71 remain exact. Actual native package pairs, whole-job timing/cleanup, installation, both M2 Air sizes and R1–R5 completion remain unfinished work.
