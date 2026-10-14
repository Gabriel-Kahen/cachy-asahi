# FDK smoke compile: actual followup and bounded Source successor

The retained run 38574961503 remains FAIL at SMOKE_COMPILE, Bash status 1. Its exact
underlying compiler error remains UNKNOWN: the 6,481-byte private builder log body
was not retained. This followup establishes a concrete Source warning-policy
mismatch and proposes a correction plus closed diagnostic observation. It does
not attribute the actual failure to that mismatch or claim successful compilation.

The prior actual receipt 6a17c696ea4ecd04f157dec10aa05760399a37400f988f2059c4a52bb5922fdb
was freshly authenticated, including 230 owned leaves and 596 listed inputs.
Completion 0c28186bf033d309dcdf6132653a60d63d6642a9412f906496a0a6764a6089a4,
fourteen retained leaves and Source 7c51adff8716e153967d53586a0dbe666c2f9958
are conserved. The 139-body baseline is copied from the prior authenticated run
Source, not the unrelated current checkout. Root's supplied committed proof is
reused; there was no new Git/API query. Producer PASS, build-2/comparison NOT_RUN,
the 397-observation limitations, cleanup scopes and prior FAIL/UNKNOWN facts stay
unchanged. No missing stderr or all-zero compiler status was reconstructed.

FDK_audio.h expands FDK_AUDIO_INLINE to nothing for C. It defines three static,
non-inline functions: FDKinitLibInfo, FDKlibInfo_getCapabilities and
FDKlibInfo_lookup. The selected smoke C file references none. The recipe uses
C11, -Wall, -Wextra and -Werror with four ordinary third-party -I directories.
The local primary GCC manual documents that -Wall enables unused-static-function
warnings and -Werror makes warnings fatal; the CPP/GCC manuals document -isystem
and ordinary system-header warning suppression. This is a finite Source/policy
countermodel, not an actual-run compiler observation. The local manual version 16.2.1 differs
from retained aarch64 GCC package 16.1.1+r12+g301eb08fa2c5-1. Actual cc alias,
compiler-version output, warning emission and its relation to run 38574961503
remain unobserved. No other deterministic header/type/link mismatch was proved.

The separately authorized local GCC fixture tests this policy in an owned 0700
directory. Fixture compiler invocations provide local unit evidence; they do
not recreate the retained ARM run or establish its compiler error, package build,
ABI or M2 behavior. Compiled fixture outputs are not executed.

Five compile-only fixtures pass their expected outcomes on local GCC 16.2.1
20260810, x86_64-pc-linux-gnu. Synthetic vendor -I fails1, -isystem succeeds0;
an unused project function still fails1 with -isystem. The pinned seven-header
include-only fixture also fails1 under -I with exactly the three selected FDK
unused-static diagnostics and succeeds0 under -isystem. Two metadata queries
record the compiler version/target. No object is linked or executed. Two objects
remain inside the retained uid/gid1000 mode0700 fixture directory. An initial
reader rejected the legitimate local GCC binary's three hard links; that attempt
is retained and ran no compiler. Only this exact compiler has an explicit nlink3
readback exception; review artifacts retain nlink1 authentication.

The exact proposed parser recognizes the actual local selected-header fixture
diagnostics as C_FDK_AUDIO_UNUSED when bracketed by synthetic BEGIN/failure
markers. It refuses the same text without markers. This is a parser/unit-text
join, not an actual recipe-stage binding or recovery of the missing ARM log.

The correction changes precisely the four third-party include options from -I
to -isystem. Project smoke C still has -std=c11 -Wall -Wextra -Werror; library
arguments, command order, source files, selected 900-body archive, upstream codec
and grants remain held. This addresses the audited header-warning policy without
globally exempting unused project functions. It remains a proposed Source
correction, not a built package or demonstrated actual-run repair.

The recipe additionally emits one closed BEGIN marker immediately before its
existing smoke cc command. A failed printf cannot change the command's result.
The existing unique SMOKE_COMPILE failure marker and saved status are held. The
worker derives an optional compiler_detail enum only from already captured
private build.log bytes between that BEGIN and the unique failure marker. It
reads no new file and executes no new compiler command. Each detail names a
closed phase/callsite family: C_FDK_AUDIO_UNUSED, C_SMOKE_ERROR, LINK_ERROR or
DRIVER_ERROR. The three known unused header patterns coalesce; mixed classes,
unknown formats, malformed/duplicate/absent markers or bounded-parser uncertainty
omit this optional field. It is a textual diagnostic observation, not a proved
process termination kind, first compiler error or underlying actual cause.

The classifier requires exact basenames, the held header declaration lines
735/745/757 or a smoke C location within lines 1–139. Ordinary optional-parser
exceptions preserve the original three-field detail; cancellation still
propagates through the existing policy. An independent reviewer found basename
suffix matches and optional-exception metadata loss in an intermediate candidate.
Those probes and that candidate are preserved; both issues are corrected in the
final selected Source.

The old three-field failure_detail remains valid. The optional enum is allowed
only for SMOKE_COMPILE in the same failed-container context. Existing exit_status
remains 1–255 and the exact 128-byte detail, 4,096-byte observation and 8MiB log
bounds stay held; parser section/line bounds are narrower. No arbitrary text,
path, function message, credential, compiler operand or raw stderr is exported.
Independent worker/receiver recapture derives the detail again from the captured
private bytes; a syntactically known enum alone supplies no runtime binding.
This adds no grant, broad diagnostic framework, deadline window, cleanup rule or
success promotion. Missing optional diagnostics leave the old failure intact.

The copy-only successor contains eight targets: PKGBUILD, worker_evidence.py and
their six exact pin/manifest dependencies. Seven of 137 packet rows change and 130
are held; 44 stage rows retain their finite closure. All 139 Source rows join the
proposed selection. Workflow and recipe source checksums for unchanged inputs,
original four recipes, inventory, source grants, receiver actors and budgets are
held. The initial unsealed six-enum candidate and its nine passing methods are
preserved in history; the final common header enum avoids selecting a first helper
when all three warnings appear. No historical seal is rewritten.

The counts have different scopes: the 137 packet body rows exclude
scripts/port/fdk-native-job/packet.lock.json itself and the separately bound
.github/workflows/native-arm-fdk.yml. The 139-row committed Source selection
includes both. The workflow is byte-held; the packet's own digest changes.

Validation here consists of held byte/mode/hash/identity readbacks, finite Source
and manual comparisons, pure/extracted diagnostic controls, and authorized local
GCC fixtures. No FDK recipe/compiler build, preprocessor-only replay, Bash recipe,
compiled output execution, GPG, provider/SDK/native grant, daemon, socket/signal/
network/Git/API or workflow dispatch occurred. Writes stay
in this new review namespace and guide; canonical Source is unchanged. Root must
separately review/adopt exact Source, prove publication and run any native trial.
Actual ABI/16K/M2 installation, performance, publication and release acceptance
remain unpassed. Full R1–R5, M5–M9 and A01–A15 remain mandatory.

After seal, copy and retarget writer outputs for replay. Do not execute writers
in this frozen review or alter its predecessors.
