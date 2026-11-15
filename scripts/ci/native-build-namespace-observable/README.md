# Observable namespace image-build failure DATA

This constructor prepares a **future diagnostic Source family**, with no
execution or admission. It removes `--quiet` from the exact tools image build
and retains `--iidfile` as the image identity source. The existing merged
stdout/stderr actor log is preserved whole, including a naturally retired
nonzero failure. No additional Docker option, retry, namespace command, policy
change or package operation is introduced.

## Observed problem

Root's Source `6b5b5a8f20ad2698c2d7f14a8f59c9b0ad5da165`, run43651792536
attempt1/job132621675250, failed in the tools build. Its sole retained Original
artifact14136745648 was inspected passively using stdlib ZIP/tar/JSON only:

| Operand | Bytes | SHA256 |
| --- | ---: | --- |
| Original ZIP | 698250 | `e4ef762f4cb3eb09eaf6b649ecef71cadaaba484cb95acc71a4c698a63916d3e` |
| `public-tree.tar` | 7434240 | `b5ec0a5c91418053513ef58c5318cf9e1a2faaccd87dedf93953186c24dc763f` |
| Logical `actor-logs/0025.log` | 1101 | `9b122c663e510018ee5cfeb3a31d1b1efe4eda0ffded497127e1fb3f16ce13a5` |

All87 mapped file bodies rejoined their `index.json` rows and `data/NNNNNN`
payloads. Nothing was extracted or executed. The exact log fixture is
`fixtures/quiet-original.log.data`; `observed-failure.json` records the selected
original DATA. The log retains Dockerfile11/RUN/exit1 but no Python traceback.
The receipt says only `ValueError: actor direct waitpid exit: 1`. Namespace
outcome and underlying policy/cause remain **UNKNOWN**. No retry is authorized
by this work, and new evidence cannot be reconstructed from this quiet log.

## Finite source change

The sole declared parent is published6b above, tree
`a825d475d248f2254070d256d23780c4ef2d0f4b`, map
`7474683e198759876dcee6b31a036473f2129da351fce3bcc8e37770b4a70f79`.
`parent.raw` retains its exact raw commit, including original97 as its parent.
The existing preflight factory remains unchanged. `factory-inputs.json` pins
all18 of its operands; its whole hash is checked before importing that DATA
constructor. Published6b's complete200 bodies, modes, blobs and tree must match
the metadata independently reconstructed from that factory.

Only these four leaves change; the other196 remain byte/mode-identical:

| Leaf | Exact transformation |
| --- | --- |
| `native/owner.py` | Remove only tools-build `--quiet`. Keep all remaining argv, labels, bounds, `--iidfile`, and the subsequent read of `overlay/image-id`. Never parse verbose stdout as an image ID. |
| `native/image_lifecycle.py` | Require exact unquiet tools16 instead of quiet tools17. Base16 and every other image/ownership/retirement guard remain unchanged. |
| `native/build_tools_reader_v2.py` | Match tools16 in independent registration and namespace joins; add strict failure-log visibility before the failed return; bind this Source family marker. |
| `native/source-map.json` | Regenerate the complete199 rows, retaining NULL selectors, plus `namespace_build_log_visibility: UNQUIET_TOOLS_IIDFILE_V1`. |

Every byte substitution has an exact inverse. Restoring these four whole leaves
also restores the complete original200-file tree. The projection, its privacy
predicate/allowlist, producer registry, probe code, Dockerfile, contract,
workflows, invocation, resource bounds, package input/bootstrap stack and all
other source bodies stay unchanged. The operation remains exactly
`native-build-namespace-preflight-v1`, HEAVY_NON_KERNEL/native-arm-build.

The held actor writes stdout and stderr to the same raw log, with the existing
16MiB bound and owned wait/retirement rules. Owner retention already copies the
entire file and pin after failure; `receipt.error` is merely a summary. Existing
projection already selects the actor logs and scans every byte with its ordinary
DATA privacy predicate, without binary/archive exceptions. No projection policy
change is needed or made. Oversized, private or incompletely retired output
still refuses qualification. Unquiet mode preserves emitted diagnostic output;
it cannot guarantee a process emits a useful explanation.

The added pure Reader guard requires the sole terminal tools build, one original
owner actor and no hidden second tools build, exact tools16/labels/paths/options,
natural direct wait/reap and complete group retirement, and unique raw-log
ownership. It joins the entire log to actor, manifest and same-source projection
pins. The exact existing privacy regex is applied again. Both zero and nonzero
natural exits remain DATA with `native: NOT_ADMITTED`; text is never interpreted
as a namespace outcome or policy cause. An earlier failure explicitly reports
`TOOLS_BUILD_NOT_REACHED_DATA_ONLY`. Quiet, altered, duplicate, missing, truncated,
private, timed-out, forced or ambiguous records refuse. Image inspection actors
remain permitted and cannot be mistaken for another build.

## Prospective facts and validation

`profile.json` contains exact before/after bodies, modes, blobs and whole pins:

- Prospective tree: `0850f8b2d8e3098a4e65f6cda6ba44698d3381a0`.
- Source map SHA256: `bf6d956b671b4c3df38aa579277319c1f4030a9e5efd14778fd9db528072a726`.
- Matching future Reader:106215 bytes, SHA256 `3426a340d1cd95a88280e84c8eee3debcba638abdb84d72dc5f46d05b22511cb`.
- Whole profile SHA256: `6c1592dc2cb9d9e2dca0f01f02ebaaae6b1e1936daf6307d05d7536da262a0e5`.

Actual Source/ref/run/job/artifact selectors are NULL. These are in-memory
source-family facts, not a published Source SHA or a native result.

```sh
python3 -I -B scripts/ci/native-build-namespace-observable/test_observable_data.py \
  --parent-source /absolute/ordinary-complete-Source6b
```

The parent input is required; there is no private-path fallback. CI must stage
the exact published6b commit as raw DATA from its separately pinned checkout or
archive. Complete200-file body/mode/blob/tree/profile checks remain mandatory.
All50 controls also pass with the old private input path poisoned; an omitted
argument or nonexistent explicit input refuses.

Actual local result: **50 controls pass on Python3.14.7**:18 focused controls
and all32 unchanged preflight/image-lifecycle controls. The fence denies
subprocess, fork/exec, sockets, system commands and ctypes actors after stdlib
initialization. Only isolated pure guard definitions are evaluated on modeled
DATA; no complete Reader/Source/actor entry point is invoked. Controls cover
full source/profile/map/inverses, verbose success and nonzero logs, exact argv,
hidden retries, legitimate image inspections, identity-file sourcing,
retirement/ownership, raw/projection/manifest pins, privacy and old-log limits.
Filesystem alias/hardlink and NULL ingress refusals also pass. Python3.12 and
actual constructor publication were not run.
The exact Original log's line6 has trailing spaces emitted by Docker; its whole
1101-byte pin is preserved. It is the sole `git diff --check` exclusion.

Constructor validation with no Source written also passes using the complete
retained6b input:

```sh
python3 -I -B scripts/ci/native-build-namespace-observable/prepare.py \
  --parent-source /absolute/ordinary-complete-Source6b \
  --profile-sha256 6c1592dc2cb9d9e2dca0f01f02ebaaae6b1e1936daf6307d05d7536da262a0e5
```

Only future Root may add `--output /absolute/owned-safe-parent/fresh-source`.
This delegates to the unchanged descriptor-relative/atomic-no-replace factory
publisher, with fresh disjoint output and whole-profile checks. That output
would still be unexecuted Source DATA. Existing admission tools pin old6b,
old Reader and the quiet Source36 lifecycle helper; they deliberately cannot
admit this family. Root must separately review and bind the new exact Source,
map, sole-parent commit, Reader and changed helper, retaining all existing
lease, resource, metadata, Main CAS, privacy and retirement gates. No admission
tool or permission is supplied here.

Actual Source construction/publication, native dispatch, GET, namespace probe,
package build/install, full Reader execution and hardware/M2 are **NOT RUN**.
Old6b/Source36, publications, results, factory, admission tools, shared manifests,
workflows and consumed packets are untouched. Namespace policy cause, Doc315,
performance, installation and release acceptance remain unestablished.
