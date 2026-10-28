# Local GDB developer workflow

`scripts/workflows/developer_debugger.py` adds the actual debugger portion of
the selected developer workflow. It complements `developer_workflow.py` and
`developer_build_systems.py`; it does not change their entrypoints. This is
finite local software evidence for the developer tasks in M6/D05 and M8.

Use a reviewed source checkout containing the runner, its fixtures, and the
existing pinned `developer_workflow.py` / `scripts/virtual/owned_process.py`:

```console
python3 -I -B scripts/workflows/developer_debugger.py --output /absolute/new/private/debugger-result
python3 -I -B tests/workflows/test_developer_debugger.py
```

Python 3, `cc`, `c++`, and GDB must already exist. `--tool-path /usr/bin:/bin`
selects the existing tool search path. Missing tools produce `MISSING_TOOLS`,
their exact names, `NOT_RUN` project statuses, and exit 2. In particular, an
absent GDB never receives version-only or simulated debugging credit. Any
available tool failing a required command fails the component. Exit 0 requires
`PASS_LOCAL_DEBUGGER_COMPONENT` with both real C and C++ workflows passing.

The output directory must be new, with an existing parent. The runner rejects
symlink ancestry and GDB path line injection, creates a mode-0700 directory,
and isolates HOME and TMPDIR beneath it. All fixtures and products live there.
No installation, package transaction, network, existing project, process attach,
user session, terminal, or host configuration is used. Keep the output for
inspection and delete it when no longer needed. This is a trusted original
fixture runner, not a hostile-code sandbox.

## Actual debugging and rebuild sequence

For each original MIT fixture, `hello.c` and `hello.cpp`, the runner uses its
existing compiler with `-Wall -Wextra -Werror -g -O0 -fno-omit-frame-pointer`.
Each language has its own fresh private project directory and license copy.
The fixture calls `workflow_step(10)` from `main`; a source breakpoint on the
return line observes the initialized volatile local `known_local=17`.

GDB runs in isolated batch mode with `-nx -nh`, auto-loading disabled before
loading the executable, debuginfod disabled and an empty `DEBUGINFOD_URLS`.
The fixed generated command file disables startup shell execution and ASLR
changes, loads only the new fixture executable, sets its absolute source-line
breakpoint and runs it. It prints the local, obtains a bounded backtrace,
continues, and prints the actual inferior exit code. Success requires exactly
one ordered observation of the source breakpoint, value, `workflow_step` and
`main` frames, expected program output, normal inferior exit, exit code zero,
and final completion marker. GDB exit zero alone cannot pass.

The edit changes the local expression from `seed + 7` to `seed + 11`, the
version message, and the fixture's expected result. A debugger request before
rebuilding must be refused without a child launch. A rebuild must change both
source and executable hashes; another actual GDB session must observe 21 and
the edited program output. The runner then introduces
`#error INTENTIONAL_DEBUGGER_COMPILE_FAILURE` and requires an actual nonzero
compile with that diagnostic. The compiler may retain its old binary; its
bytes are recorded but are ineligible for debugging. Restoring the source is
also insufficient: only a successful new build can authorize the final real
debugging session. Every ordinary successful build removes the previous
executable before invoking the compiler, so a zero-returning no-op compiler
cannot reuse an old executable for recovery.

Execution eligibility binds exact source bytes, compiler/GDB frontend hashes,
compiler flags and executable hash. Changes, failed compilation, failed GDB
commands, incomplete/wrong transcripts, and mutations during execution revoke
it. Content changes invalidate eligibility even when timestamps are preserved.
Command-file hashes are also checked after GDB exits. No passing state is
read back from an older run or used to authorize an arbitrary executable.

## Process ownership and evidence

The runner reuses `developer_workflow.Commands`, pinned at SHA256
`531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba`.
That helper checks and uses canonical `owned_process.py`, SHA256
`83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f`.
Neither dependency is copied into the proposed changes or modified. A changed
dependency is refused; Root must explicitly reconcile a future adoption.

The existing main-thread exclusive wait owner calls `prepare()` before each
fresh-session child and transfers supervision once. This runner adds no
supervisor, PID cleanup, wait, attach or signal operation. The core retains
leader wait ownership through its last signaling decision. ECHILD is UNKNOWN
and prohibits subsequent signaling. Success requires known raw reap, complete
bounded output, empty group/session census twice, no timeout, error or signal,
and the matching exit. The controlled compiler nonzero is required only at
its marked failure step. GDB owns the waits for its own inferior children.

Each tool command shares the existing supervisor's time and output bounds:
20 seconds per command, 180 seconds overall and 128KiB combined output by
default. CLI budgets permit command caps of 2–60 seconds and total caps up to
600 seconds; each launch reserves the existing retirement allowance. A failed
or unknown retirement cannot pass or produce a debugger observation receipt.
Cancellation finishes supervision and prevents subsequent launch/success.
Popen creation and file I/O are outside the execution cap. The census does not
prove absence of escaped sessions, and these controls are not cgroup isolation.

`result.json` retains actual architecture, kernel, page size, UID, Python and
tool pins/versions, fixture and runner/core identities, project outcomes and
commands. `commands.json` retains argv, cwd, expected exit, raw supervisor
results and hash-bound logs. `project-c.json` / `project-cpp.json` retain each
build/debug/refusal stage, source snapshots, compiler/GDB/source/binary binding,
source-line observations and command-file pins. Raw GDB command files and logs
remain available. Paths in these private records may identify the local tree.
Frontend pins do not freeze compiler subprograms, shared libraries, GDB system
libraries or the full host environment.

The focused tests use explicit unit stubs and synthetic transcripts for refusal
controls. They grant no debugger execution credit. The development packet's
separate real host CLI evidence records six successful GDB sessions, eight real
compile attempts (including two deliberate failures), and three version probes.
Its actual host is x86_64 with 4096-byte pages. An independent real CLI with only
the two compiler frontends in its search path records missing GDB and exit 2.

Native ARM and 16K execution, installed Asahi, each physical M2 Air size,
independent contributor onboarding, package rebuilds, graphical debugging,
performance and release acceptance remain unrun/unqualified. Later target runs
must use the reviewed source paths and the same command above, then inspect
actual architecture/page size and every retained observation. This component
alone does not accept a release, machine, or milestone.
