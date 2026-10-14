# Fresh peer review: KSM expression-split integration

**PASS for Root Source adoption; no open findings.** This is an independent Source review of the unadopted proposal, not an operational repair or native acceptance. Inputs are Source `866313782a97e2026bc8f6329f04ceb7d0f68755`, proposal receipt `293b5da35dd86c41c2698b04669fc0b863948d0ff10c71e1378b16d7bb82e55b`, and proposed packet `2aac0ffea8a53fd1211ca5746746021972cd3fb16ddafcbaffc64706c5d7c964`.

The [fresh evidence directory](../../artifacts/reviews/ksm-callsplit-integration-fresh-peer-20261014/) contains the independent audit, results, check names and sealed receipt. [copy-map.json](../../artifacts/reviews/ksm-callsplit-integration-fresh-peer-20261014/copy-map.json) is the authoritative eight-copy map: every absolute proposed source and managed-worktree destination, full SHA-256, byte count, mode, and immutable Git blob preimage. The destination root is `/home/gabe/.codex/worktrees/ksm-current-native-recovery/cachy-asahi`.

| Exact destination relative to managed root | Integration role | Git preimage blob at Source866313 |
| --- | --- | --- |
| `scripts/ci/native_arm.py` | Separate uname and asdict statements | `6f503553c031bf57b2bc8169228760ec487659b5` |
| `scripts/port/ksm-native-job/current_cache.py` | Select historical native donor buffer | `8d123382775b39597aa4260361bf02b991a58992` |
| `scripts/port/ksm-native-job/donor/current-native-arm.py` | Exact old native bytes; new transport Source data | Absent; new file |
| `scripts/port/ksm-native-job/executor_contract.py` | Bind active native SHA | `4da74ed0090dcb99e54a85226625bbf6f1d743ae` |
| `scripts/port/ksm-native-job/job.py` | Bind active native and current-cache SHA | `a78c2643f061412f619184e634ef5bbdad614c24` |
| `scripts/port/ksm-native-job/packet.lock.json` | Select complete resulting159 packet | `bd6e10afd5976152f88e34751d00a601810dc213` |
| `scripts/port/ksm-native-job/producer_driver.py` | Bind active native SHA and closed diagnostic lines | `f775286d83b1947f9abc2b9ce5400e363e91ff09` |
| `scripts/port/ksm-native-job/required_paths.py` | Add donor to finite Source membership | `ecfeba03e8d8eb06c3844423456143019484c3ff` |

The review passed 2,972 checks and independently authenticated the requested proposal receipt, all 366 sealed leaves, external guide/input pins, immutable Git commit bytes, all 159 preimage files including the old packet, and their captured and managed-worktree bytes/modes. The successor has six changed existing locked rows, 152 held rows and one exact donor: **159 locked rows, 160 complete Source files including the packet**. Packet rows match actual proposed bytes/modes and exact required membership; the workflow remains counted once. The old job checkpoint, cache intake and historical donor controller/packet are held byte-for-byte.

The active native Source becomes `7209d1f6a0a1acd38644a053d8956f3a1e17292122aef84d171368c984838924` in the driver, executor contract and job. Cache intake still requires original native SHA `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`. `BUFFERS[0]` supplies that exact historical native copy, with all four intake equality pins preserved. Source inspection confirms intake selects only `AcquisitionError`, `input_name`, `check_pin`, `fetch` and `acquire`; it does not select or launch the donor probe/main. The full donor is authenticated transport data, not the active native producer.

Rejoining the two kernel assignments recovers the entire original native AST. Inert controls cover success, uname failure, `_asdict` attribute lookup failure, `_asdict` failure and a deeper callee failure. They preserve call order, exact result and same exception object. Isolated real caller tracebacks distinguish line 300 `CALL_UNAME` from line 301 `CALL_ASDICT`. Synthetic closed-line controls succeed across arbitrary offsets with opcode/position access trapped; foreign frames and unrecognized locations stay conservative. These labels identify expression propagation regions. Attribute lookup and deeper callees can fail there, so labels do not prove body entry, completion or first cause. Local storage, bytecode and dictionary-allocation timing change; universal observational equivalence is not claimed.

Whole-driver operational AST conservation and exact inverse checks for each pin/path edit leave the operational guard bodies held. The review runs only selected AST kernel prefixes and the pure classifier with inert objects, plus passive hashing, AST parsing and Git reads. No product module, package body, provider, native actor, API or Git mutation executes. Seven changed/added Python files parse using Python 3.12 grammar locally under Python 3.14; no Python 3.12 runtime was used.

Root can adopt exactly the eight authenticated copies and select the resulting packet. This reviewer made no canonical Source change. Actual run `38647718228` remains `kernel_call=UNKNOWN`, underlying cause `UNKNOWN`, cleanup `FAIL` and ownership uncertain. No new actual trial, build, hardware result or performance evidence follows from this Source review.
