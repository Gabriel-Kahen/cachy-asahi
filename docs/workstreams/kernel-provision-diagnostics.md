# Kernel provisioning diagnostic correction — held source interface

Status: local source correction held after captured-source fixtures; independent peer review and coordinator source rebind remain pending. Run38279898941 remains FAIL; exact first inner cause UNKNOWN. Root owns source locks, packet/workflow bindings and Git. No new helper or daemon query is proposed.

## Compatibility and exact closed addition

Retain existing outer public schema4. Accept historical child diagnostic schema1 exactly with its current keys and behavior. New child diagnostic schema2 adds exactly `operation`; it retains all schema1 fields, input-binding/projection rules and the4096-byte bound. Schema1 cannot carry the new key and schema2 must carry it. Existing schema1 bytes are never rewritten. The parent public validator mirrors these two exact shapes; it does not accept arbitrary optional dictionaries.

`operation` has exactly three fields:

```
{
  "current": <closed observation>,
  "first_failure": null | <closed observation>,
  "cleanup_failure": null | <closed observation>
}
```

Every observation has exactly these fields:

```
{
  "action": "NONE" | "provision" | "probe" | "baseline" | "candidate" | "derive" | "cleanup",
  "gate": <closed source-gate enum>,
  "predicate": "NONE" | "UNKNOWN" | <exact reviewed fixed refusal-label enum>,
  "category": <existing finite failure category>,
  "query": <closed operation kind>,
  "query_return": {"kind": <closed typed return>, "code": null | <exact integer>},
  "daemon_return": {"kind": <closed typed return>, "code": null | <exact integer>},
  "create": "NOT_ATTEMPTED" | "UNKNOWN" | "CID_OBSERVED",
  "start": "NOT_ATTEMPTED" | "UNKNOWN" | "EXIT_OBSERVED"
}
```

Typed returns use NOT_RUN/UNOBSERVED with null, existing EXIT_ZERO/EXIT_NONZERO/EXIT_SIGNAL with exact integer range -64…255, and HTTP_STATUS with exact integer100…599. Booleans are never numbers. Daemon HTTP returns have their own slot so a post-query identity check cannot erase the already-returned create/start/inspect result. A fixed operation query kind identifies existing INFO, IMAGE_INSPECT, FIND_NAME, FIND_ID, CREATE, CONTAINER_INSPECT, START, REMOVE, IMAGE_INVENTORY IMAGE_TAG_INSPECT, IMAGE_ID_INSPECT, IMAGE_COMMIT and IMAGE_REMOVE API operations, plus NONE/UNKNOWN; no argv/path/ID/response body is retained publicly.

Source gates distinguish CHECKPOINT_WRITE and LAUNCH_VALIDATE, durable journal/name/create reservation, pre/post local and daemon checks, actual query execution/return, CID parsing, inspect identity/resources/mounts/command, and fixed derived-image API/cleanup boundaries. The exact proposed gate set is NONE/UNKNOWN, CHECKPOINT_WRITE, LAUNCH_VALIDATE, JOURNAL_READ, JOURNAL_WRITE, NAME_RESERVE, FIND_NAME, FIND_ID, CREATE_ATTEMPT, CREATE_ID, CREATE_JOURNAL, INSPECT_OWNERSHIP, INSPECT_RESOURCES, INSPECT_MOUNTS, INSPECT_COMMAND, LOCAL_PRE, DAEMON_PRE, QUERY_EXEC, QUERY_RETURN, LOCAL_POST, DAEMON_POST, DAEMON_CONNECT, DAEMON_RESPONSE, DAEMON_METADATA, START_ATTEMPT, IMAGE_JOURNAL, IMAGE_INVENTORY, IMAGE_COMMIT, IMAGE_INSPECT, IMAGE_CONFIG, IMAGE_REMOVE, CLEANUP_RESOLVE, CLEANUP_REMOVE, CLEANUP_ABSENCE and FINALIZATION. It will be mirrored exactly in the public receiver. Refusal predicates are accepted only on exact membership in a static list of reviewed source labels; dynamic or unknown exception messages yield UNKNOWN. Raw errors, paths, IDs, argv and log text never become public fields.

## Narrow instrumentation contract

Add an optional in-memory observer to the existing Broker, without altering query order or adding operations. Existing caller behavior remains valid without an observer. A scope records action/gate/query and restores its parent context; at the first existing exception it freezes a deep observation snapshot. Record an actual CLI return immediately after the supervised subprocess returns, before either local-pin or daemon postcheck. Record an HTTP status immediately after parsing the response status, before response/body/identity validation. Preserve the main query return across nested daemon checks.

Set create/start UNKNOWN at the existing durable create-attempt boundary or immediately before the existing start operation. CID_OBSERVED means a syntactically valid returned CID was observed, not verified ownership or deletion authority. EXIT_OBSERVED means a CLI result was returned, not accepted worker success. No new ownership/remove policy follows from those states.

The stage owns checkpoint-versus-launch scopes and takes a frozen observer snapshot when writing its existing receipt. Initial first_failure is null; once set it is immutable through later scopes, cleanup and cancellation. Cleanup records a separate first failure and never changes the earlier primary snapshot. Existing first_failed_predicate/category remain sticky and authoritative. No PASS is permitted unless every existing variant, base, signature, receipt, preservation and scoped-absence predicate passes, with no observed primary/cleanup failure.

Use existing broker.py/image.py/stage.py/evidence.py and the existing outer job.py/public.py plus their tests. No runtime.py, worker.py, new helper, timer redesign, query expansion, capability change, removal/prune change or B-preservation waiver is proposed. Cancellation and status capture remain bounded by the existing process/receipt authority. Parent captures the child receipt once and consumes the new projection from that same immutable capture.

## Required source tests and hold

Fake-backend causal schedules cover refusal before and after every existing query boundary, returned exit/HTTP status retained when postchecks fail, checkpoint failure before Broker.launch, unknown create/start commitment, immutable primary plus independent cleanup failure, unknown-label privacy, bool/range/type refusal, historical diagnostic1 byte compatibility, and the unchanged acceptance predicates. Tiny owned process controls may prove returned exit classification where useful; no Docker, kernel build, network, GPG or system mutation is authorized. Root's source rebind and independent peer/actual bootstrap review precede kernel4.

## Held local result and integration boundary

The twelve authorized source/test paths now implement this interface. The observer records process status immediately after the existing supervised runner returns and HTTP status immediately after the existing response parser returns its status. The separate daemon slot always refers to the existing GET /info operation; nested checks retain the primary CLI/API result. The query field identifies the latest requested primary operation, while the gate identifies the failing checkpoint, guard or response boundary. A new action resets current observations, preserving both failure snapshots. Uninstrumented propagation is UNKNOWN. A failed observation retains its originating action when a scope unwinds; returned nonzero create/start results are frozen before cleanup.

Exactly the current and two optional failure snapshots are published. Snapshot dictionaries do not alias live observer state or captured private receipt fields. Exact reviewed literal broker/image/runtime guards are in a static mirrored whitelist. Unknown exception text remains UNKNOWN; no message-prefix matching or runtime discovery occurs. HTTP statuses and process exits have disjoint allowed slots and exact integer types. All existing source guards are retained; the only extra stage acceptance check refuses COMPLETE with an observed primary or cleanup error. No timer, ownership, capability, deletion, image commit, protection or query sequence was changed.

Fresh captured source, with no retained or created foreign bytecode, passed the exact four owned stage-module suite: **78 tests, zero failures/errors/skips**,15.312s. The full job fixture suite passed **205 tests, zero failures/errors/skips**,4.400s. ResourceWarnings were errors. These include real owned fake-CLI success/TERM/timeout lifetimes and owned Unix HTTP responses, with modeled local/daemon/container authority. They do not contact Docker or compile a kernel. The separate earlier broader-stage discovery had125 passing tests and8 explicit skips because the captured tree omitted the unchanged private Asahi C compiler inputs. That discovery is not a no-skip acceptance result; prior full compiler-fixture baseline remains separate.

Causal schedules cover checkpoint write before launch, launch validation, pre-daemon/pre-local/runner/post-local/post-daemon refusals, actual daemon metadata, returned status before malformed body/header and daemon drift checks, syntactic CID/journal/inspect/start boundaries, each ownership/resources/mounts/command inspect guard, cleanup independence, late finalization cancellation, unknown-label privacy, strict schema/type/range limits and immutable single-capture job reception. Actual retained run38279898941 outer schema4/child diagnostic1 still projects to exact SHA256 `db71b7b81fb32f3fcd44e16242e467d3c4f4b6d70faa228b16602d7938eb6ed2`; the new receiver does not change that historical FAIL or identify its first inner cause.

The held receipt is `artifacts/reviews/kernel-provision-diagnostics-20261012/held-receipt.json`. Coordinator-owned stage26/job117 locks, workflow/source-count pins and Git are intentionally untouched and stale. The separately reviewed current FDK evidence dependency SHA256 `27d16ce1a89d949075b0fe85072575883de6e9021a4902747c4b8ed44ed71b27` is a dependency-selection proposal only; this lane has not adopted it or granted initial base authority. Root must select accepted dependency bytes, rebind locks, independently review this delta and prove committed bootstrap before kernel4. Native compilation, kernel runtime,16K/M2 hardware, installation and performance acceptance remain NOT RUN/NOT MEASURED.
