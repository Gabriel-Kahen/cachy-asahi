# Independent signal-wrapper compatibility Source review

The final proposal passes this bounded Source-only review. Author receipt
`e838148981b761871ed94c80d47e6af64c177c5239daa823e0ed4352800a438f`
is 170,871 bytes and authenticates all 562 leaves, 12,764,059 bytes. Its guide
matches `5e646a7f882a3d519e7e743653d08b2e699ef8f8d9881b9801067b4a5bf5c12d`.
No narrow-scope finding remains open. Earlier preparation is retained as
unaccepted history; this final review supersedes its pending status.

The exact primary capture is eight texts, 322,963 bytes, for CPython3.12.3
`f6650f9ad73359051f3e558c2431a109bc016664` and CPython3.14.0
`ebf955df7a89ed0c7968f79faec1de49f61ed7cb`, including commit metadata, signal
source, source loader and license bytes. Both signal function ASTs equal the
fixed assignment-then-return body. Both loader texts select `dont_inherit=True`.
This peer performs no network fetch or execution of primary module code.

Compiler-only controls on local Python3.14.7 confirm that each full primary
module's function code matches the exact `import _signal` reference, while its
`co_code` differs from the bare reference. The proposal admits exactly those
two closed contexts and compiles both with `dont_inherit=True`. Constants,
flags, typed code/names/variables/signature/closure fields remain exact; no
wildcard or ignored opcode is introduced. The offset check is tied to the
selected exact template's assignment-line code ranges. Future-flag, constant
and code/name corruption controls are rejected. This establishes current-host
compiler compatibility only. It is not actual Python3.12 execution or proof
of hosted actual06's cause.

Seven independent controls isolate the proposal's pure module/type/globals/
state/constants/flags/code predicates and obtain each expected closed refusal.
Both exact contexts pass those isolated predicates. The inert function objects
are never called; no Sourcewrapper API, full classifier or traceback probe
runs. API_FRAME identity and API_OFFSET are reviewed through Source AST and
code-line binding, without a live wrapper traceback. Existing ten handler-kind/
API-text codes and the exact nine new refusal enums remain closed and distinct.

The independent binding lane authenticates Source266 and metadata14, with
263 selected rows unchanged. The complete handoff AST changes only
`Session.service_failure_site` and the closed site enum in
`Session.startup_projection`. Prefix/suffix Source guards and handler logic
are preserved; `startup_failed`, `execute`, first-cause/cancellation behavior,
runtime/common, authority, grants, deadlines, views and original159/generated125
counters are unchanged Source. Common remains
`92ca41005397c6cccfd70497646c0de1f2ac88a697e0fcbec4165bf5326cfc08`.
All 16 old test classes remain, with four diagnostic expectation literals
updated and one new class appended. This peer reruns no author tests or old
suite. The binding harness's initial IndentationError from a sliced `else` is
recorded; the repaired complete-AST inspection passes and is not a proposal
defect or runtime result.

The exact cascade is:

| File | SHA256 |
| --- | --- |
| Handoff | `b1be6da0f38722a350b1981bacda038f2fac018fa67efe0c3fc78f22fd20e8e7` |
| Test | `366cfccfc95793e21b5d858789f1ecc8b45f0832346ced1b3fe8ea4d8b2f8f90` |
| Bridge | `65d254379b0cda07fa83e59abc95f693a22ff7ccbf7044e7208544af70f1aad7` |
| Packet | `4c0a54b2f09eb19e8b8cbff4c8a3de036656e7227ad80302a235a35d629bcebd` |
| Proposed workflow literal | `c026fada749136c563501d18b35f3c46deaf9286de6ef1479ab43436b5924582` |

Bridge, packet and workflow changes are the exact existing literal cascade;
no shared workflow is edited here. Baseline packet is preserved as
`06fa0a48e2031feaf3821c4829f3d6f87c3cae7f56b8531dab1b59ea109080a9`.
The author reports seven focused methods; this peer authenticates that retained
evidence and does not replay it.

Actual06 evidence is byte-identical: Source432, run38462431231 retains generic
`SERVICE_CANCEL_EXIT_SET_HANDLER`, false hook, controller1, initialnull and
Source-gated cleanup PASS. Its handler kind, wrapper refusal and runtime cause
under hosted3.12 remain UNKNOWN. No old evidence is backfilled, and no masking,
restoration, retry, handler coercion or runtime fix is supplied by this review.

The frozen receipt/index are under
`artifacts/reviews/maintained-composed-signal-wrapper-compatibility-root-peer-20261013/`.
Root owns adoption, new Source/Data/plan bindings and a separately selected
actual trial. No Sourcewrapper API calls, signal/process/native actors, GPG,
Docker, library or cleanup replay, network, shared manifests, Git or goal
mutation occurs here. Native acceptance, hardware/performance, release and
full R1–R5/M5–M9 completion remain false; the actual diagnostic trial remains
required before any runtime-cause or correction claim.
