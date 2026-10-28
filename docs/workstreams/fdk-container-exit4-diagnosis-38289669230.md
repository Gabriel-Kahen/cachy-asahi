# FDK container exit 4: actual run 38289669230

October 12, 2026. **Actual FDK build1 remains FAIL.** The new diagnostic establishes a stopped-container exit4, separately from worker1 and builder1. The first inner entry/makepkg predicate and compiler invocation remain **UNKNOWN**. No deterministic precompiler source/data failure was reproduced, and no source fix or native retry is selected by this audit. The proposed next step is a finite inner observation, with original commands and acceptance gates preserved.

[Actual run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38289669230), source `602669753d5fce72b355bbf83b6875a10fee4a19`: job packet129 SHA `b91331eb4799718bf0700d8b9a81bbf39c99d5dad4a4f06f777e54d08392ac9d`, stage40 SHA `4db538d6292c6580c1eb1cc0d330fc84b9c27ae7b570dbfea5a0cdda6f403e3c`, workflow SHA `4e1f13bdab87cba0ae94e554e7d393f9dad23d0fe41e750ea4ceeda4e0e284dc`. Every packet source is authenticated against committed bytes and Git mode. A fresh131-file capture adds only the packet and workflow, totaling2,213,380 bytes. It is a source fixture, not a replay of the native build.

## Actual retained observations

| Boundary | Retained result |
| --- | --- |
| Stage / first build | FAIL / build1 |
| Worker returned | 1, EXIT_NONZERO |
| Original builder returned | 1; FAILED / CONTAINER_EXIT |
| Container create CLI | 0, EXIT_ZERO |
| Container attach CLI | 4, EXIT_NONZERO |
| Validated same-container terminal State | ExitCode4, Runningfalse; stopped exited/dead State supported by observer |
| First failed worker predicate | CONTAINER_ATTACH / COMMAND_NONZERO |
| Final observation | FINALIZATION; cancelledfalse |
| Cleanup / owned absence | PASS / PASS, as recorded by the remote receiver |
| Build2 / comparison | NOT_RUN / NOT_RUN |

The original builder rejects its nonzero attached result, writes failed provenance, and returns1. The worker retains the earlier CONTAINER_ATTACH boundary and rejects builder1. These are nested outcomes, not three independent compiler exits. The validated State result distinguishes actual container4 from an attach-only CLI failure; the public vector does not export full State, OOM/dead/error details or a first internal command.

The original private builder log is declared **5,989 bytes**, SHA `4a2303ee651954c30b39f93ace08e20291bfa88de2811d2564662a17dbfe4409`. Private provenance is **7,222 bytes**, SHA `1273c30cdce5121eb88d7eed7be80a77d9c8771997ebf56688c694db4d5f0f56`. Neither raw file is available in this public export. Their lengths/hashes cannot reveal a Python traceback, failed compiler, recipe function, disk/OOM condition or unsupported flag. Public binding `d2212765875dba6b5eb496d1b7b85ad2d6938dbe3e659dbd54d840c9ce38e3b8` is a receiver-validated declaration; missing private config/nonce/binding bytes prevent independently rebuilding it here.

The raw workflow ZIP247,705 bytes/SHA `144c85ef09a1378797094beaaa7dcff943f0fb8c42fac490feca3098f30b359c` has exactly9 checked members. The251,117-byte aggregate log hashes to `fc378a3186b121c970f4c47c77e82c87ca09a05a36f60c42cbfb17dbddd62c2a`. Its emitted public bundle is90,299 bytes/SHA `8932a7b6fcbbd6718de646071698156ebbcfe54a53239c928f6ba838f909479b`; all8 decoded JSON records and producer manifest hashes match. Five data-only mutations are refused by the retained schema. Root's summary was not used as authority in the receipt-peer replay.

The approved341-package lock is independently reconstructed from retained pinned inputs, SHA `89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`; producer records341 packages and pacman `7.1.0.r9.g54d9411-2` is in the retained package input. The actual private packages.lock/rootfs-inventory and installed makepkg bytes are not exported. The original four development-package comparisons recorded PASS; those separate successes do not make FDK or the complete port accepted.

## Exact makepkg semantics, conditional on command origin

Official upstream resolves54d9411 to `54d94116164b0b2202c6061c4a59c6f3e70820d8`. Four bounded primary source files are retained, with recomputed Git blob IDs matching official API responses. The [error definitions](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/libmakepkg/util/error.sh.in#L29) assign `E_USER_FUNCTION_FAILED=4`; [makepkg's runner](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/makepkg.sh.in#L362) maps an ERR-trapped function failure to that class. It does not retain the underlying command's code. A guarded recipe return2 can therefore become4. Logging plumbing shares this trap.

`--verifysource` performs download/integrity checks and exits before extraction, prepare/build/check/package/pkgver. Optional verify() can run through [integrity checking](https://gitlab.archlinux.org/pacman/pacman/-/blob/54d94116164b0b2202c6061c4a59c6f3e70820d8/scripts/libmakepkg/integrity.sh.in#L32); FDK defines neither verify nor pkgver. This excludes its four ordinary recipe functions from that stock mode, conditionally. It does not prove the first invocation succeeded. The build invocation can fail in prepare, build, enabled check, package or their wrappers.

These are exact upstream source semantics corresponding to the recorded version suffix, not an authentication of installed ARM script bytes or downstream patches. The actual container receipt does not identify makepkg as the source of4: the entry contains other commands. No failed function or compiler result follows solely from this code.

## Authenticated entry and recipe paths

Original entry `89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24` runs sequentially under set-euo-pipefail: isolated/nonroot/aarch64 guards, recipe copy, environment/inventory/config capture and exact lock comparison, printsrcinfo plus reviewed-field comparison, verifysource at line36, then makepkg cleanbuild/clean/force/log at line37. Package and function-log copying occurs only after successful build return at lines38–43. This ordering explains why the end-copy path cannot itself guarantee failed function-log export; it does not recover the unavailable log or prove its contents.

| FDK function in recipe739b828c… | Existing operations and ambiguity |
| --- | --- |
| prepare | Container/CARCH guard; source_check.py verifies selected raw packet. Contains no compiler call. |
| build | Guard; build-codec.py validates selected implementation, plans395 compilations+2links, writes command plan, invokes original subprocesses, then copies plan to /out. |
| check | Guard; three Python tests against immutable inputs; ELF/ABI/16KiB geometry check; separate C smoke compilation and bounded classic/xHE runtime smoke. Enabled check depends on makepkg configuration. |
| package | Guard; project stage.py copies two libraries/seven headers/pkgconfig; original grants, MIT and provenance documents are installed into package root. |

build-codec verifies selected bytes and grant strings before its compiler boundary. Its command plan is written before compilation and copied to /out only after the Python helper returns. A plan file alone proves neither invocation nor completion. Neither successful source checks nor architecture declarations prove an ARM library, ABI, runtime, package or M2 result.

## Bounded source/data replay and next observation

An independently rehashed selected raw USTAR is17,387,520 bytes/SHA `1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4`. Strict checks admit exactly900 regular rooted members and16,686,087 content bytes; no links, special/traversal/duplicate files or upstream scripts are executed. Extraction is only into this lane's owned project artifacts. Original verify_packet passes900 files; template_files passes22 assets/checksums; original verify_selected passes all898 implementation/header hashes, sizes, paths and both grant substrings. Pure planning yields395 compile arrays and2 link arrays without invoking a compiler or creating a build output.

This falsifies the narrow deterministic missing/changed selected-file, fixed archive or missing grant-string failure in these exact retained inputs. Hosted extraction, flags/environment and later compilation/link/test/staging remain unproved. No source-causal code fix is supported by this replay.

The smallest proposed observation is a fixed entry-command phase plus last entered PREPARE/BUILD/CHECK/PACKAGE label, captured from source-issued markers, with explicit predicateUNKNOWN where no actual check is instrumented. Reuse original attach/validated terminal State; add no daemon query. A phase is not a first predicate or successful check. If compiler evidence is also selected, record attempt immediately before each original subprocess call and natural returned code only after its actual completion; timeout/cancellation/cleanup reaping stays unobserved. Never infer invocation from a plan or an entered BUILD function.

[Finite observation proposal](../../artifacts/reviews/fdk-container-exit4-diagnosis-38289669230/finite-observation-proposal.json) specifies finite enums, one<=4096-byte fixed capture, copied-source/entry/recipe/selected-packet and receiver identity binding, hash/count-only log metadata, first-cause preservation and unavailable/refusal behavior. Keep exact original commands, Bash failure semantics and makepkg's ERR trap, all inventory/SRCINFO/source/compiler/ELF/ABI/smoke/package/pair/comparison/cleanup gates. Adoption and any native trial require a separate reviewed source/recipe/stage/job/workflow change. This lane does not implement that proposal or dispatch a retry.

Evidence is sealed by `artifacts/reviews/fdk-container-exit4-diagnosis-38289669230/final-review.json`, with receipt/source/makepkg peer packets and captured source bindings. No actual makepkg/compiler/Cargo/Docker/GPG/package/system actor ran here. Primary source retrieval and inert Python/source/data work are separate from the hosted native FAIL. All10 updater sources and the sealed corrected updater packetbb4e77…/guides remain unchanged; no FDK/updater/source map/workflow/Git edits occurred. Installation, consumer integration, physical16KiB/M2, performance, publication and full distribution acceptance remain open.
