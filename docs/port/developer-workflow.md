# Local developer workflow component

`scripts/workflows/developer_workflow.py` runs a finite, offline user-space
journey on Linux. It contributes reusable software evidence for M6/D05 and M8
installed usability. It grants no milestone or installed-system acceptance.

From a source checkout with Python 3, Git, a C compiler (`cc`), a C++ compiler
(`c++`), and Vim already installed:

```console
python3 -I -B scripts/workflows/developer_workflow.py --output /absolute/new/private/developer-result
python3 -I -B tests/workflows/test_developer_workflow.py
```

The output directory must be new and its parent must exist. All mutations stay
inside that directory; keep it for inspection and delete it when no longer
needed. A read-only checkout is sufficient. `--tool-path /usr/bin:/bin` selects
existing tools; no tool is installed. Missing required tools produce
`MISSING_TOOLS`, an explicit name list, and exit 2. Missing Make, CMake, Meson or
Ninja is `MISSING_OPTIONAL`. Available Make and Ninja receive real project
workflows and `EXECUTED_REAL_PROJECT` only after those workflows pass. CMake
and Meson receive version probes only when present; their build workflows remain
`VERSION_ONLY_WORKFLOW_NOT_RUN`. An available backend failing its workflow fails
the overall run. A missing backend remains explicit and grants no workflow pass.

The runner initializes an original MIT fixture repository, makes one local
commit, clones it without hardlinks, and checks out its exact detached revision.
User Git configuration, templates, signing and hooks are excluded. Git traffic is
local-file-only; no network repository or preexisting project code is executed.
It then builds and runs C and C++, skips each unchanged build, edits each message
with isolated noninteractive Vim, and verifies changed source, executable hash
and output. Each language must reject an intentional `#error`; old executable
and successful-build state are invalidated before compilation. Restoring the
source must yield a working rebuild. Every compile attempt retains exact source
bytes, source/compiler pins, arguments and its outcome in `builds.json`.

The incremental adapter compares content and compiler/argv fingerprints rather
than mtimes. It is a tiny single-source builder. It does not validate dependency
tracking, linker/header/library/toolchain reproducibility, package rebuilds or a
general package build. The separate original Make/Ninja projects below exercise
actual build graphs; CMake/Meson and package rebuilds remain separate D05 work.

Python creates a private venv with `--without-pip`, executes its interpreter by
absolute path without activation, checks the fixture really runs in that venv,
and runs its one original unittest. A stripped command environment and `-I -B`
exclude caller Python configuration and bytecode writes. The fixture's fixed
private path is explicitly inserted only by the isolated test harness.

## Real Make and Ninja project workflows

The original C/C++/Python journey remains unchanged. Its command count is
recorded as `base_command_count` before project execution. On the current host,
the original 33 commands are followed by 15 Make and 15 Ninja commands.

Each backend gets a fresh copy of the tiny original MIT fixture in
`tests/workflows/fixtures/developer/project/`. The Python configure entrypoint
writes an actual Makefile or build.ninja with compiler and graph/source pins.
The graph compiles `hello.c` to `build/hello.o`, links `build/hello`, and exposes
`all` and an always-run `test` target. It uses the existing C compiler with the
same warning/optimization flags as the direct C workflow. Serial `-j1` keeps
this component bounded; no packages or project dependencies are downloaded.

The runner builds, executes the exact first output and invokes the graph's
self-test target. An unchanged `all` build must leave object and executable hash,
inode and nanosecond mtime unchanged. The repeated `test` target must still run
and print its expected marker. A real isolated Vim edit changes the project
message; both object and executable hashes, the normal output and the graph
test output must change. The runner makes the source mtime newer than existing
products and checks that the filesystem retained that timestamp. It does not
claim Make can detect edits whose mtimes are held unchanged; the direct v1
content-keyed builder separately tests that case.

A deliberate `#error INTENTIONAL_PROJECT_COMPILE_FAILURE` must fail the build
with the matching compiler diagnostic. Both build tools normally retain the
previous executable. That exact stale executable is retained as evidence: the
runner's source/binary-bound execution gate rejects it without a launch, and a
real `test` target invocation must fail on its build dependency without emitting
a self-test success marker. Restoring the source must recover build, execution
and test. A failed or mismatching graph test also revokes execution eligibility
until another successful build; it cannot leave a reusable passing receipt.

`project-make.json` and `project-ninja.json` retain each stage's artifact
before/after identities, source/build-graph/configuration snapshots and hashes.
`project_workflows` in `result.json` joins their outcomes to the shared raw
command logs. CMake and Meson are explicitly missing on the current host; their
workflows remain unrun.

Ninja executes command strings through its normal intrinsic shell launcher;
Make interprets recipes with `/bin/sh` as its declared shell. These are fixed,
original project-owned compiler and self-test recipes. Compiler paths are
shell-quoted then escaped for the selected build syntax, including spaces,
dollar signs and single quotes. No user recipe text, shell startup environment,
`source` operation or runner `shell=True` call is accepted. This intrinsic
build-system execution is explicit additional scope for real project workflows;
the original direct C/C++/Python path still uses argv commands only. Both build
tools and their recipe descendants remain in the group supervised by the same
reserved-child core and share that command's time/output budget.

## Existing journey adapter

The current606 onboarding source at
`scripts/ci/current606-onboarding-source/payload/developer/held/onboarding.py`
already implements a finite setup/shell/PTY/editor/C journey. Its `journey`
requires installed setup templates, Fish, Zsh and its guarded native environment;
importing that whole workflow would neither be portable nor preserve its gate.
`OnboardingAdapter` therefore retains its exact MIT `hello.c` fixture, compiler
flags `-Wall -Wextra -Werror -O2`, isolated Vim arguments, and first expected
output (`Hello from cachy-asahi`). The edit changes the message, extending the
older comment-only edit to prove real rebuild behavior. The existing source and
CI/onboarding receipts are unchanged. The source pins and explicit mapping ship
in this development packet's provenance record; the clean entrypoint depends
only on the proposed checkout paths, with no artifact-directory lookup.

## Process custody and retained evidence

The runner ships with the reviewed candidate `scripts/virtual/owned_process.py`
(SHA256 `83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`).
Its exact bytes are verified before execution. This caller uses the held default API; RSS remains opt-in. Earlier execution records retain their recorded supervisor source and were not rerun for this pin adoption. It uses main-thread, exclusive
wait ownership with default SIGCHLD; callers must not concurrently reap these
children or change that disposition. The runner launches each tool using an argv
list, closed stdin, a fresh session and one capped combined stdout/stderr pipe.
The build tools interpret only their fixed recipes as described above. The
supervisor retains the leader's wait ownership through its final TERM/KILL
decision, then obtains the raw wait status. ECHILD yields UNKNOWN and prevents
later numeric probes or signals. Late log writers only receive bytes.

Success requires a known matching exit, complete output, no timeout/error/signal,
raw reap, two empty group/session observations, and completion inside the cap.
The deliberate nonzero compiler exits are recorded as expected failures; they
cannot satisfy an ordinary compile success. `commands.json` retains every argv,
cwd, expected exit, supervisor result and raw `.log` byte/hash map. Output is
bounded to 128KiB combined per command; overflow fails rather than silently
truncating a successful receipt. Default command/run budgets are 15/180 seconds,
including a one-second retirement allowance per launched command. The run budget
is checked before each launch. SIGINT/SIGTERM cancellation is recorded while
supervision finishes, then prevents success or another command.

Popen creation and local file I/O are outside the supervisor's execution cap;
these are bounded workloads, not hard real-time guarantees. A group/session
census does not establish absence of escaped sessions or global process absence.
This is a trusted original-fixture runner, not a hostile-code sandbox. It neither
sets cgroup limits nor claims a complete host/toolchain snapshot. Executable
pins identify the observed command frontends; shared libraries and compiler
subprograms are not locked. Retained raw logs and directories are private inputs
for review and may contain absolute paths.

`result.json` records actual architecture, kernel, page size, UID, interpreter
identity, tool frontend bytes/hashes and version output, fixture/runner/core
pins, build evidence and limitations. Exit 0 means only
`PASS_LOCAL_DEVELOPER_COMPONENT`; exit 2 means missing tools, failed work or
unknown retirement. A 4K x86 host result is not native ARM, 16K, installed Asahi,
M2, independent-user, graphical editor, terminal, package-rebuild, performance or
release evidence. Target flags remain unqualified until a separate reviewed
integration decision uses real target results.

## Later native ARM invocation

Copy these proposed paths into the reviewed target source checkout, including
the pinned supervisor and fixtures. As the ordinary target user, run:

```console
python3 -I -B scripts/workflows/developer_workflow.py --output /absolute/new/private/arm-developer-result --tool-path /usr/bin:/bin --command-timeout 30 --total-timeout 300
python3 -I -B tests/workflows/test_developer_workflow.py
```

Inspect the retained `architecture`, `page_size`, interpreter/tool pins, every
command's retirement, exact edited outputs, the direct compile failures and
both project failure/recovery sequences. ARM
16K requires the actual `aarch64`/16384 observation and successful execution on
that environment. Repeat on each exact supported installed M2 Air composition
with independent contributor onboarding and the existing desktop, package
rebuild, lifecycle and recovery gates. This component does not accept those
gates by itself.
