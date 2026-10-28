# Original CMake and Meson developer journeys

This standalone M6 component exercises an original MIT C executable and C++
shared library through CMake/CTest/Ninja and Meson/Ninja. It supplements
`developer_workflow.py`; it does not change or rerun its original 33 commands or
the separate Make/Ninja journey. It accepts only the checked-in fixture, with no
source fetch, package installation, privileged operation or signing material.

Run from a source checkout containing the module, fixtures, existing
`developer_workflow.py` and `scripts/virtual/owned_process.py`:

```console
/usr/bin/python3 -I -B tests/workflows/test_developer_build_systems.py
/usr/bin/python3 -I -B scripts/workflows/developer_build_systems.py --output /absolute/new/private/build-system-result --tool-path /absolute/tool-directory:/usr/bin:/bin --command-timeout 30 --total-timeout 240
```

The result directory must be absent, with its parent already present. Omit the
extra tool directory on systems with all tools in `/usr/bin:/bin`. The default
search path deliberately does not inherit the caller's full environment. Each
backend needs C, C++, and Ninja; CMake additionally needs CTest. Tool absence
produces a backend `NOT_RUN` and a list of missing tools. A pass for available
backends leaves missing backends visibly unexecuted. Nonzero CLI exit means a
workflow failed or no backend could run. No mock result qualifies a journey.

Each available backend performs these actual operations:

1. Configure, compile C/C++, link a shared library and executable, run exact
   output, and execute its native test command.
2. Build unchanged inputs, requiring byte hashes, inode and nanosecond mtime of
   both objects, library and executable to remain identical.
3. Edit the C++ source and test expectation, reject the old executable before a
   build, rebuild, and verify the changed C++ object/library and untouched C
   object. Run and test the changed output. A dynamically linked executable can
   retain identical bytes while the library changes.
4. Add a deliberate `#error`, observe a genuine compiler failure, and reject
   execution while the old executable and library still exist. Repair and
   rebuild/run/test.
5. Set an intentionally wrong test expectation, build and observe a genuine
   test failure. Revoke execution eligibility, repair, rebuild/test/run.
6. Install into a new private prefix and verify its exact three-file tree:
   executable, shared library, and MIT license. With both source and build
   directories renamed out of the configured paths, run the installed binary.
   Temporarily remove the installed library and require loader failure, restore
   it and require exact output again. All withheld paths are restored in
   `finally` blocks. No system prefix or package database is touched.

The execution gate binds all seven source files, tool frontends and observed
objects/library/executable to a successful build. Failed or mismatching tests
revoke execution until another successful build. Source/library/tool/installed
tree tampering is refused. The gate checks content even when an edit retains its
mtime; timestamp build graphs themselves do not promise same-mtime detection.
Test repair in this journey uses a later source timestamp explicitly.

`result.json` and `commands.json` retain executable paths, frontend hashes,
versions, explicit argv, cwd, expected and observed exit, raw combined logs,
output hashes, and owned-process retirement results. `project-*.json` retains
input snapshots and before/after product hashes/inodes/mtimes. `installed-*.json`
records the installed tree. Each command uses the existing pinned Commands
adapter and owned-process supervisor; no second PID retirement implementation
is introduced. Meson wraps disable downloads and both native test/install
commands disable implicit rebuilds. Compiler selection is explicit.

The runner launches argv without `shell=True`; CMake, Meson and Ninja execute
their own trusted generated build commands and compiler subprocesses. This is
a trusted-fixture exercise, not a sandbox for arbitrary project files. Tool
frontend pins do not pin every library, compiler subprogram or CMake module.
Per-command limits cover supervised children, with a finite aggregate command
budget; local I/O and process creation are outside those deadlines. Group
census establishes observed retirement for supervised groups, not the absence
of escaped sessions. All mutations are under the fresh output directory.

The retained host run used x86_64 / 4096-byte pages, CMake/CTest 4.3.3, GCC
16.2.1 and Ninja 1.13.2. It exercises CMake, including private-prefix install
and runtime. Meson is absent: adapter unit controls are source checks and its
real configure/build/test/install journey remains **NOT RUN**. Native ARM, 16K,
installed Asahi integration, both physical M2 Air sizes, independent-user
onboarding, package lifecycle, performance and release remain **NOT RUN / NOT
ADMITTED**. A private fixture install does not qualify an installed Asahi
system or M6 acceptance.
