# Python 3.14.8 candidate C consumers

This offline, ordinary-user host probe builds and executes three real consumers
of the unchanged `python 3.14.8-1.1` source candidate:

- `consumer_full.cpython-314-x86_64-linux-gnu.so` exercises full-API list macros,
  integer conversion, exceptions and compile/runtime version correspondence.
- `consumer_stable.abi3.so` defines `Py_LIMITED_API=0x030b0000`, uses limited API
  calls, and checks its actual imported Python symbols against CPython's stable
  ABI inventory for additions through 3.11. The inventory bytes are compared to
  the exact SHA-pinned source archive. Execution covers **3.14.8 only**, without
  claiming compatibility across Python versions.
- `embed` links with the relocated candidate's `python3.14-config --ldflags
  --embed` output, initializes an isolated `PyConfig`, and runs both consumers.

The fixtures and driver are original MIT code. Existing candidate sources,
licenses, builders and shared manifests are unchanged. This is a finite consumer
probe, not a packaging frontend, replacement Python installation, general build
system or native acceptance tool.

## Inputs and execution

Use the installed system Python only to orchestrate the probe. It never supplies
the consumer headers or runtime. The installed C compiler and `readelf` must
already exist. No pip, download, package installation, service, display or device
operation is performed. Full-archive extraction uses Python 3.14's standard
`tarfile` zstd support; there are no third-party Python dependencies.

From the prepared checkout, with a fresh absolute output path without whitespace:

```sh
mkdir -p work
python3 -B scripts/compat/python314-consumers/test_probe.py -v
python3 -B scripts/compat/python314-consumers/probe.py \
  --origin /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/python3148-source-candidate-host-20261114 \
  --output "$PWD/work/python314-consumers-core-final"
```

The original report must have SHA-256
`e83a377b23fb602c8e076b3a16eae81c356af9b209359f7089f1f7769529e1ef`.
The driver checks its candidate file pins against both the original paths and
this checkout. It compares the core stage interpreter, shared library and three
important headers to their retained build-tree counterparts. The original
core-only build remains **HOLD for missing Tk**, even when its C consumers pass.

An optional, separately pinned full-profile **second-run** package is supported:

```sh
python3 -B scripts/compat/python314-consumers/probe.py \
  --origin /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/python3148-source-candidate-host-20261114 \
  --full-evidence /tmp/cachy-asahi-python314-tk-full-second-20261114 \
  --output "$PWD/work/python314-consumers-full-final"
```

The full archive must be exactly 17,308,438 bytes with SHA-256
`8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e`;
the builder report is pinned separately. Candidate source hashes must match this
checkout. Before private extraction, the driver verifies that archive/report and
admits only bounded ordinary members and internal relative links. This input is
the builder's second run; it does not represent a later cleanup-version run.
The builder's full recipe/check/package and headless Tcl success remains its
own evidence. This consumer probe does not load Tk or repeat that full runtime
profile on the host.

## Identity, isolation and refusals

The probe seals every candidate file, mode and internal symlink, makes a private
copy, and renames that copy before compilation or execution. The initial copied
prefix is absent thereafter. The original stage is checked again at the end.
Output paths inside either input evidence tree are refused before creation.

Every consumer build uses explicit includes from the relocated configuration.
Both C extension sources reject headers other than 3.14.8 at preprocessing.
The candidate interpreter is launched with `-I -S -B`; prefix, executable,
sysconfig, extension suffix and actual `/proc/self/maps` libpython path are
checked. The embedding executable uses `dladdr`/`realpath` to refuse a different
library before initialization, including fallback to the host system library.
Its ELF dependencies must include `libpython3.14.so.1.0` with no RPATH/RUNPATH.
Standard compiler/libc headers and libraries still come from the recorded host;
this is not a hermetic or clean build claim.

Seven runtime/build controls are mandatory: wrong selected interpreter, actual
system interpreter execution, modified header custody, actual wrong-version
header compilation, missing library custody, actual missing-library/system
fallback embedding refusal, and modified library custody. Changed bytes are
restored and both runtime paths run again. All changes occur in the private
copy. Seven additional safety tests exercise source/output separation (including
a symlinked parent), escape-link/FIFO refusal, file-mode tamper, foreign archive
refusal and real timed-out child termination.

The whole probe has a 300-second alarm. Each subprocess has a maximum 60-second
wall deadline, 45 CPU seconds, 1 GiB address space, 4 MiB output-file limit and
disabled cores. Timed-out children are killed through their owned process group.
The environment is rebuilt with private HOME/XDG/TMPDIR and no inherited display,
Python or loader variables; only the selected candidate library directory is
added for candidate subprocesses. This environment isolation is not an OS
network or filesystem sandbox. The finite commands make no network requests.

## Actual November 14, 2026 evidence

The final core and full runs are retained separately under ignored `work/`:

| Run | Result | Scope |
| --- | --- | --- |
| `python314-consumers-core-final/report.json` | PASS | Original core stage; full candidate still HOLD missing Tk |
| `python314-consumers-full-final/report.json` | PASS | Exact separate full-profile second-run archive; C consumers only |

Both runs compile both extensions and embedding with existing GCC 16.2.1,
execute imports/arithmetic/exceptions and embedding before and after refusal
controls, and verify relocated 3.14.8 interpreter/library/header/configuration
identities. All seven negative controls pass. The observed missing-library
execution returns 41: the embedding guard refuses system-library fallback before
initialization. The stable extension imports eleven Python symbols, all in the
source inventory through the selected 3.11 ABI floor. Seven safety tests pass.

The first development attempt stopped at an overly restrictive link-flag parser
that rejected the legitimate `-lpython3.14` dot. It is retained as a failed probe;
the parser was corrected before successful consumer compilation. Earlier
successful development runs remain separate from the final source snapshot.

Each final report includes exact command/log hashes, compiler and consumer
artifact hashes, source hashes, mapped library paths and the stage seal. The
coordinator's private `work/handoff.json` identifies commits and report hashes.
No package archive or generated consumer binary is added to Git.

Native ARM, native 16K, coordinated installed consumer transactions, historical
ALARM binary correspondence, upstream signature freshness/legal closure, full
system acceptance, M2 hardware, GUI and performance remain unqualified. No
release is admitted, and the Asahi platform stack is untouched.
