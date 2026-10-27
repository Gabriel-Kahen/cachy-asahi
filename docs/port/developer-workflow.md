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
Ninja is `MISSING_OPTIONAL`. Their presence receives a version probe only, with
`VERSION_ONLY_WORKFLOW_NOT_RUN`. Their build workflows remain untested.

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
general Make/CMake/Meson/Ninja project. Those remain separate D05 work.

Python creates a private venv with `--without-pip`, executes its interpreter by
absolute path without activation, checks the fixture really runs in that venv,
and runs its one original unittest. A stripped command environment and `-I -B`
exclude caller Python configuration and bytecode writes. The fixture's fixed
private path is explicitly inserted only by the isolated test harness.

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
(SHA256 `80547f753dc7d13819d727783c669d10a56b7bf832dc05084b5c4b5302cb79d9`).
Its exact bytes are verified before execution. It uses main-thread, exclusive
wait ownership with default SIGCHLD; callers must not concurrently reap these
children or change that disposition. Each command uses an argv list, no shell,
closed stdin, a fresh session and one capped combined stdout/stderr pipe. The
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
command's retirement, exact edited outputs and both intentional failures. ARM
16K requires the actual `aarch64`/16384 observation and successful execution on
that environment. Repeat on each exact supported installed M2 Air composition
with independent contributor onboarding and the existing desktop, package
rebuild, lifecycle and recovery gates. This component does not accept those
gates by itself.
