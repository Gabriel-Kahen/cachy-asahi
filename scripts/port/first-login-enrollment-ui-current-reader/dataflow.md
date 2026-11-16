# Current onboarding dataflow

Source review of owner/route `bc47942d` and constructor v3 `aab07f3a`.
No operational roles ran; no Root private key was read.

| Stage | Required qualified image | Signatures required before entry | Outputs |
| --- | --- | --- | --- |
| Backend | Original349 + Setup8 =350 | Setup8 signature, public TEST key, retained Root decision/verification, and current owner GPG verification | Enrollment04 and CLI03 independent build pairs and byte comparisons |
| UI | Original349 + official23 + Setup8 + CLI03 =374 | Setup8 and CLI03 signatures/Root decisions, accepted CLI03 pair, current owner verification; independently admitted official signatures | UI02 independent build pair and byte comparison |
| Lifecycle | Original349 + official23 =372, project-free | Setup8, Enrollment04, CLI03 and UI02 archive/signature pairs under one Root-selected TEST primary; Setup8 decision and current verification; official trust | Two install/remove cycles, restored baseline and outer retirement evidence |

Each stage additionally needs its own genuine Source/run/job binding, closed
lock, image/inventory qualification, runtime/resources, owner and Reader
admission. Expected inventories are not observed images.

1. Backend builds Enrollment04 and CLI03 **before their project signatures
   exist**. Neither candidate's future signature or Reader binding is a backend
   prerequisite. The owner holds public verification trust only. The generic
   entry does not explicitly pass `--nosign`; its recorded configuration does
   not create a Root signing service.
2. Root accepts the actual backend pairs and signs the selected CLI03 archive.
   Root separately constructs/qualifies the374 image containing that exact
   CLI03, Setup8 and official23. Enrollment04's signature is unnecessary for UI.
3. UI builds its pair before its own signature exists. Root accepts/signs UI02
   and also signs the accepted Enrollment04 archive before lifecycle.
4. Lifecycle receives all four signed archives. Its owner pre-stage receipt
   verifies Setup8; `native.lifecycle()` verifies **all four** signatures before
   installation using the same TEST primary. Changing that primary requires
   a genuine new Setup8 signature/Root decision, not an edited fingerprint.
   Official signatures use their separate upstream trust domain.

Only after the builds, lifecycle's `build_stage_bindings` must contain actual
backend/UI Root Reader-binding references. The Reader independently checks
those retained pairs and joins their compressed archive bytes to the signed
lifecycle inputs. A signature, filename or populated future selector cannot
replace that producing-build evidence.

The current owner implements neither a Root package-signing callback nor actual
signing-job/key delegation. Root must separately provide that bounded handoff;
no private key belongs in Source, public carriers, builders or Reader inputs.
Image construction/qualification is likewise a separate, unimplemented Root
role. Constructor v3 packages committed code/public DATA while actual grants,
candidate signatures and image observations remain NULL. This document grants
no native, hardware or release acceptance.
