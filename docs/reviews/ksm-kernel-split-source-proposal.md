# KSM proposal: separate kernel expressions and closed line labels

This unadopted Source proposal is based on actual Source `866313782a97e2026bc8f6329f04ceb7d0f68755`. The complete preimage and proposed trees are in `artifacts/reviews/ksm-kernel-split-source-proposal-20261014/`, with an eight-file copy map in `changes.json` and `proposal.patch`. It is a diagnostic Source restructuring, not a demonstrated fix for the actual TypeError. No new trial was dispatched.

Actual run `38647718228` explicitly emitted `kernel_call=UNKNOWN` under `driver_error / TypeError / NATIVE_ENTRY / NATIVE_PROBE_BODY / RECORD_KERNEL`. Its numeric instruction offset, interpreter version, provider bodies and inner cause were not exported. Cleanup remains FAIL and ownership uncertain; its scoped absence and daemon-baseline observations remain separate facts. Actual review receipt `878d38b4a9a231e819a3ea0244fde45200e6a38ac8f32019035d8c9fe3112be8` is held unchanged.

## Why the old selector can miss

The independent Source audit pins official CPython 3.12.0 commit `0fb18b02c8ad56299d6a2910be0bab8ad601ef24`. A normal Python-function CALL path advances across three inline-cache entries before inlined dispatch, which stores the caller's previous instruction at `next_instr - 1`. Traceback creation preserves that byte offset. Public `co_code` is deoptimized with zeroed cache units. Consequently a caller traceback can index CACHE rather than the raw CALL opcode required by the old selector. The standard [disassembler explicitly handles the instruction's cache range](https://github.com/python/cpython/blob/0fb18b02c8ad56299d6a2910be0bab8ad601ef24/Lib/dis.py#L596-L602). The selector's `zip` of two-byte offsets and positions is not itself shown wrong. Exact primary citations and ten bounded retained Source files are sealed in `notes/cpython/`.

This explains a concrete Source path to conservative UNKNOWN. It does not establish that the hosted interpreter matched this revision, that its failing offset was a cache unit, or that any provider/runtime guard caused the actual TypeError. No actual private body was replayed.

## Proposed change

The native probe begins with two separate physical statements:

```python
kernel = platform.uname()
kernel = kernel._asdict()
record = {'kernel': kernel, ...}
```

Both calls remain in the same order, once each, before page-size and later record fields. The first result is the exact receiver for `_asdict`; its result is the exact kernel record value. No fallback, replacement provider, extra call, exception handler or wrapper is inserted. Exceptions propagate as the same objects. The existing record schema stays unchanged; its Source checksum naturally binds the new native bytes.

After exact held probe-code identity, the diagnostic maps traceback line 300 to `CALL_UNAME` and line 301 to `CALL_ASDICT`, in the same coarse `RECORD_KERNEL` context. This path reads neither opcode bytes nor column positions. Other statements retain their existing position-based classification, with spans regenerated for the shifted Source. The temporary opcode metadata import and raw-CALL gate are removed. Executor enums, strict route parser, natural exit/reap requirements and business refusal remain byte-identical.

These labels identify distinct Source expression propagation regions. Attribute lookup, descriptors or deeper callees can fail there; a label does not prove body entry, completion or first cause. Missing/foreign/unrecognized traceback context remains conservative. The split adds a local store and changes bytecode, Source lines and dictionary-allocation timing. It is not claimed universally observationally identical, a hosted-runtime result or an operational TypeError repair.

## Exact transport and pin cascade

The active native Source hash becomes `7209d1f6a0a1acd38644a053d8956f3a1e17292122aef84d171368c984838924`, rebound in the driver, job Source policy and executor contract. Cache intake previously consumed the active native file as its acquisition donor; its immutable historical packet requires original hash `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898`.

To preserve that equality check and historical provenance, the proposal adds an exact copy of the original native Source at `scripts/port/ksm-native-job/donor/current-native-arm.py`, under the existing project Source license. `current_cache.BUFFERS[0]` points there; the intake still selects only its original acquisition definitions. The donor is transport Source data: its full script, probe and main are not launched or imported. Cache-intake bytes, all its guards and the historical donor controller/packet stay unchanged. Required-path membership and job's current-cache digest are updated. No pin is widened to multiple alternatives and no historical packet is rewritten.

Six existing locked files change, 152 remain held, and the exact donor adds one: 159 locked rows and 160 complete Source files including the packet. The proposed packet is `2aac0ffea8a53fd1211ca5746746021972cd3fb16ddafcbaffc64706c5d7c964`. The workflow is unchanged and already counted once. The old job `source-checkpoint.json` stays byte-identical as historical cache-proposal evidence; its 158 count and old hashes are not presented as the successor descriptor.

## Validation and limits

The coordinator's 76 inert controls check call/value order, same exception identity, distinct labels without position access, unchanged strict-consumer roundtrips, privacy and natural-exit negatives. Its 1,560 passive checks authenticate immutable Git/preimage bodies, all proposed packet rows and exact membership, every job/driver/contract pin, whole-native AST inverse after rejoining the expression, and whole-driver AST inverse after restoring declared diagnostic metadata. All other operational guards, first-cause handling, custody, clocks, cancellation and cleanup bodies are held.

Separate independent notes audit conservation and the full packet; an independent peer reports four pure control methods and 851 passive checks with no open findings. Seven changed/added Python files parse under Python 3.12 grammar and compile locally under 3.14.7. No Python 3.12 runtime, full product suite, actual provider, uname, subprocess/native actor, package build, hardware check or performance measurement was executed. Selected AST controls use inert objects only. No actual cause, native acceptance or M2 compatibility follows from this work. Canonical Source, Git refs, variables and CI remain unchanged.
