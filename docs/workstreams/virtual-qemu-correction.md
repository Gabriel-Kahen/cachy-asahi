# Virtual QEMU tooling and capability correction

2026-10-12. **Owner source and21-package input correction adopted by the coordinator after independent canonical-hash closure and41 tests PASS. Shared adapter publication corrections and complete packet acceptance are still pending. Corrected native tooling/guest execution NOT RUN.** Historical19 inputs/pins and original proposed holds below describe their capture; current adoption is recorded at the end. Root owns shared manifests, Git and dispatch.

## Actual failure being addressed

Broader native run `38237127237`, source `ce3dd476…`, prepared the generic disk and a 364-package private tooling image but failed in run.py's QEMU capability checks before starting QEMU. Actual report says `pinned QEMU capability missing`; no guest events, frames or compositor/session acceptance exist. Four containers plus the private derived image and workspace were removed with verified PASS receipts. See [actual execution review](../reviews/native-development-execution-38237127237.md). Missing 2D GPU modules are a concrete input closure defect consistent with the observed failure. Historical projection omitted the four help-command outputs, so the exact failed check and sole hosted cause cannot be recovered from that export.

## Proposed authenticated module inputs

The frozen official ALARM extra.db `ba1bdb823c22936ba7c9f700d168da139403b1d65683e115b66bd9c9a82ce069` declares both split packages at **11.1.2-1**, aarch64. Source QEMU revision remains `4fc49f46dc95d4a27de2509e7fceb2931e91faeb`. Required runtime modules are `usr/lib/qemu/hw-display-virtio-gpu.so` and `usr/lib/qemu/hw-display-virtio-gpu-pci.so`. These are the 2D modules; no GL/rutabaga module was added.

| Module | Archive bytes | Archive SHA256 | Signature SHA256 (566 bytes) |
| --- | --- | --- | --- |
| qemu-hw-display-virtio-gpu | 36236 | `e4729661997f1f5879522a7866c872c80b90b8a67b90f5e500a7c70e6a516fcc` | `671fafcb82b172089ebd162a6b620e433eea0cb8eec67647ae62e1de6b24c363` |
| qemu-hw-display-virtio-gpu-pci | 16676 | `9dbb3bdffbeed7e8714ed6ee5693126fafdebc7082bbaa1618b3c12aa04d9ba4` | `a75573abb0b98ff517c2068a13b4634368fa27ba1716a8b5b86279929fcfbbc3` |

Detached signatures are the exact bytes carried in the hash-bound repository metadata. Both acquired archives match size/SHA pins and verify with the existing locked ALARM public keyring/expected primary signer in a private temporary GPG home, `--no-autostart`; no host/default trust or keys changed. The auditor inspected actual signed PKGINFO/BUILDINFO, paths and hooks, without extracting/executing packages. Both have no install script or ALPM hooks and include their license files. GPU depends on glibc, pixman, `libpixman-1.so=0-64` and exact qemu-common; PCI depends on exact qemu-common. Those dependencies are already in the existing closure.

An initial in-flight metadata construction used only database desc and omitted its separate depends file; the strict actual archive audit correctly refused it. The corrected rows include both records; the retained failed report `tooling-audit-incomplete-dependencies.FAIL.json` is diagnostic history, not an accepted candidate. The final audit reauthenticated all 21 packages, including the original 19, and passed. The resolver used a copy of frozen 341-package local metadata and all four pinned repository databases, `pacman --print --needed` with explicit private root/db/cache/config/log paths. It returned exactly the existing 19 plus both modules, with no base replacement or package/system mutation. No host installation or Docker operation occurred.

Coordinator candidates in `artifacts/virtual-qemu-correction-20261012/`:

| Candidate | SHA256 |
| --- | --- |
| tooling.lock.candidate.json | `a8060f5dab01277de200fb7c9a4418b565984eb6d1cfb4971f0a3bd013ee8073` |
| tooling-audit.candidate.json | `cd11a837b29e5c757b482a79b375f65170881d73f80db4ae645ed600a45378cd` |

`module-rows.json`, two public archives/signatures under cache, `resolver.txt` and `copied-candidate-tests.json` retain the proposal and actual checks. Do not mistake candidates for adopted active locks. Corrected counts are **21 tooling packages / 362 base-plus-tooling / 366 with the four installed overlays / 45 acquisition objects** (three keyring objects and two per tooling package). Historical active files still describe 19/360/364/41 and must be retained as historical evidence when root adopts the new closure.

## Bounded runtime diagnostics and consumer ABI

Run.py now uses the existing registered/group-cleaned `common.bounded` helper for four fixed QEMU commands. Each has a 15-second timeout and 128-KiB combined output cap. The existing version/TCG/machine/device acceptance checks remain enforced; a failure prevents QEMU guest launch. It writes `proof/capabilities.json` before each launch and after each outcome. The private guest result binds the same list. Partial/failed starts retain which fixed check was attempted. Output content/exception messages are absent from this diagnostic list.

The controller authenticates captured run.py bytes against its CORE literal before compiling the finite validator and projecting this list. It requires equality with the guest result when that result exists, then adds **qemu_capabilities** and **qemu_capabilities_sha256** to its result. If final guest result is absent but the capability file is present, the ordered partial list can still be projected as diagnostics. The hash is computed from the same captured, validated list without rereading/hash-binding mutable raw JSON. It binds the canonical list bytes (`json.dumps(rows, sort_keys=True, indent=2) + "\n"`, encoded UTF-8), which a receiver can independently recompute; it does not require publishing a new raw file.

The exact row keys are:

```json
{
  "check": "version",
  "status": "STARTING",
  "returncode": null,
  "reason": null,
  "stdout_sha256": null,
  "stdout_bytes": null,
  "stderr_sha256": null,
  "stderr_bytes": null
}
```

Consumer must apply the authenticated `run.capability_projection` semantics or an equivalent closed data validator:

- Ordered list, at most four rows, exact prefix IDs: version, tcg, virt-machine, virtio-gpu-pci. Exact key set above; exact string fields; preceding rows must be PASS. Only the last row may be STARTING/FAIL. Unknown, duplicate, reordered or raw-content keys refuse.
- Status only STARTING/PASS/FAIL. Return code null or exact integer -64..255, excluding booleans. PASS requires code 0 and reason null. FAIL requires one exact reason: timeout, output-limit, process-failed, capability-missing, launch-failed, cancelled.
- STARTING keeps every field except check/status null. FAIL with null returncode and launch-failed/cancelled keeps all four stream fields null: no captured output is asserted when execution returned no bounded observation.
- Otherwise stream hashes are lowercase 64-hex SHA256; sizes are exact nonboolean integers 0..393216, combined at most 393216. This allows the maximum UTF-8 re-encoding expansion of the bounded helper's replacement-decoded textual output; hashes/sizes describe those UTF-8 bytes, not unretained arbitrary raw process bytes. No raw stdout/stderr/help/exception text can be added.
- For CAPTURED_REQUIRES_VISUAL_REVIEW success, require all four rows PASS in addition to existing proof/cleanup/frame constraints. Failed/early owner receipts may have no diagnostics if preflight was never reached, or a valid partial list. Diagnostics never grant guest or hardware acceptance. Check canonical list hash when present; require field-pair symmetry.

The shared development adapter is root-owned and still needs these fields/schema and 21/45/366 count adjustments. Root must also refresh controller CORE common/run, AUDITOR_PIN, LOCK_PIN/AUDIT_PIN and any accepted packet literals. Until these coordinated changes, production source pin checks deliberately refuse the edited bytes; tests mock candidate pin values explicitly. No source pin was silently relaxed or auto-derived in production.

## Held owner source and actual tests

| Source | SHA256 (mode 0644) |
| --- | --- |
| audit_tooling.py | `6677f391f2de23540bc147770148729fe4c993850b7bbed0b71fb7e48d296fdc` |
| common.py | `b5099507b27fd9f86259c0096d0128b3a2480c546469312763a84438202fa4c3` |
| controller.py | `a42b774a6aa4c571ad8e23861ad1eab2170df805f6a87b85a0a3cec9cdd28a1c` |
| run.py | `60a495285968d44f176a2cb299f3c251562ebdd2a8e7c7ecbdb3007bdec4575d` |
| test_controller.py | `67f7c6ec45f15a56a32a1c84feb3ac583d16d34d47446f8647fb49f3183714d7` |
| test_virtual.py | `856668f473577834afa94afb3917ee3dd1e561d8d95292db3abafbc7395f55b3` |

Common.py changes only expected package count 360→362; all its process/guard/ownership behavior is unchanged. Controller counts become 21/362/366 and require both module names; auditor accepts historical 19-package data audits separately and validates corrected 21-package/362 shapes with both module names. Runtime/controller immutable Config, private tag ownership, uncertain commit failure, image/container cleanup and cancellation/final receipt behavior remain in place. Root will recompute source bindings after independent review.

Actual tests: `python -B -Werror::ResourceWarning -m unittest discover -s scripts/virtual -p 'test_*.py' -q` **40 PASS, zero skips**, 0.438 seconds on final working bytes. A fresh owned copied source tree with the candidate 21-package lock/audit also passed all **40**, zero skips, 0.439 seconds. Existing real signal/process cleanup regressions remain in the suite. Added checks cover all four exact before/after command schedules, each missing capability, timeout/output overflow/process failure, actual bounded Python output flood and reaping, unknown/secret exception/stream text, cancellation, absent observations, malformed types/keys/partial/order, projection source pin/equality, missing final guest receipt, and corrected runtime inventory positive/negative boundaries. Docker/QEMU/ARM commands and trust/image prerequisites remain mocked; the bounded flood uses only a temporary Python child. Diff whitespace checks pass. No actual native guest, DRM/compositor launch, target install, M2/16K or performance test occurred during this correction.

Forty local tests and signed archive audits support this narrow source/input correction. They cannot replace coordinator packet/source/Git proof, actual corrected native execution, frame visual review, or any physical acceptance gate.

## P2 peer correction and final owner hold

The independent CI peer passed the prior 40-source-test/21-data-authentication checks but identified P2: raw capability JSON hashing did not implement the documented canonical-list ABI. Controller now serializes the same captured validated list to canonical bytes and hashes those bytes directly. It does not reread or hash mutable raw capability bytes after validation. The new fixture changes raw JSON whitespace and key order while retaining identical parsed records; both project to the same canonical hash. Guest-result equality and source-pin/malformed-field controls remain strict.

Updated final suite **41 PASS**, zero skips, ResourceWarning-as-error (0.447 seconds); a fresh temporary copied source tree with candidate21 locks/audit also passes **41**, zero skips. Final copied receipt `/tmp/virtual-p2-final-copy-review.json` records all six exact source hashes. Only controller.py/test_controller.py changed for P2; common/run/auditor/test_virtual hashes and candidate21 data remain unchanged. Earlier 40-test copied artifact receipt is historical; the table above is updated. Independent P2 follow-up and root shared-pin/lock/packet adoption remain pending. No corrected native guest execution occurred.

## Adopted source/input checkpoint

Root adopts exact21-package lock `a8060f5dab01277de200fb7c9a4418b565984eb6d1cfb4971f0a3bd013ee8073` and audit `cd11a837b29e5c757b482a79b375f65170881d73f80db4ae645ed600a45378cd`. The six-source canonical-hash correction passed independent review; root's41-tests/zero-skips suite also passes after production pin refresh. Controller is now `3f083173494cfb1f6ac40bbc0cd8bb90d62c56272f882232fb8aa16d8fa2e09d`, derived by changing only five reviewed literal bindings in the final owner hold `a42b774a…`. All other owner source files retain their final held bytes. The old19 inputs are retained as private historical snapshots and in Git. No native execution, guest/frame acceptance or Apple compatibility follows from adoption.
