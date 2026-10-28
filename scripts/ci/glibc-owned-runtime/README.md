# Owned glibc runtime smoke proposal

Original project-owned MIT C/Python sources. This is an unselected proposal for
the project-owned successor of held `glibc 2.43+r22+g8362e8ce10b2-2`. It includes
no GNU sources, packaging recipe or system installation operation. The build
owner supplies the pinned GNU source/build/package provenance separately.

## Integration contract

Call inside an already-created, disposable, native Linux aarch64 container as
an unprivileged user. Disable container networking and expose only `lo` in
`/sys/class/net`; provide `/.dockerenv` or `/run/.containerenv`. Set
`CACHY_ASAHI_GLIBC_RUNTIME_SMOKE=1` to declare the caller-owned container.
The runner does not create containers or change network settings.

Required tools: Python 3.11+ standard library, `/usr/bin/gcc`, its assembler and
linker, and bootstrap glibc development headers/libraries. The candidate needs
its loader, libc, libm, ISO-8859-1 gconv configuration/module, and an unpacked
`C.UTF-8` or `C.utf8` locale. For example, the build owner can generate private
locale files using its existing build process; this runner never runs
`localedef` or installs locales. Missing data fails the smoke.

Create an explicit input JSON, replacing hashes and paths with actual inputs:

```json
{
  "schema_version": 1,
  "stage_root": "/owned/candidate",
  "loader": {"path": "usr/lib/ld-linux-aarch64.so.1", "sha256": "64 lowercase hex characters"},
  "libc": {"path": "usr/lib/libc.so.6", "sha256": "64 lowercase hex characters"},
  "libm": {"path": "usr/lib/libm.so.6", "sha256": "64 lowercase hex characters"},
  "library_directories": ["usr/lib"],
  "gconv_directory": "usr/lib/gconv",
  "locale_directory": "usr/lib/locale"
}
```

All candidate paths are relative to the staging root; symlinks must resolve
inside it. Use absolute paths without spaces, colons or backslashes. The
workspace must be a fresh directory beneath an existing writable parent,
separate from the staging tree. All compiler outputs, child-created files,
temporary files, raw logs and the receipt go into that private 0700 workspace.
The caller owns external sandboxing and final workspace/container removal.

```sh
python3 /owned/smoke-source/runner.py \
  --inputs /owned/runtime-inputs.json --workspace /owned/fresh-smoke-work --execute
```

Omit `--execute` for input validation without compilation or candidate
execution. `--host-compile-only --workspace /ABS/FRESH` accepts no candidate
input; it only compiles and records the host architecture, never invoking the
produced binaries. It cannot establish aarch64 build or runtime compatibility.

## Behavior and proof

Eight parent groups cover allocation/reallocation/alignment; dlopen/dlsym;
pthread creation, barriers, joins, destructors and executable/plugin TLS;
UTF-8 conversion, invalid input, locale and iconv; numeric parsing/formatting
and libm identities; file descriptors/stat, clock and getrandom; offline
numeric IPv4/IPv6 lookup; and fork/exec/wait with CLOEXEC and private file I/O.
The exec child invokes the exact supplied loader again and has its own runtime
identity record. The suite opens no sockets and makes no DNS queries.

The candidate loader is invoked explicitly with `--inhibit-cache` and an
explicit `--library-path`; `GCONV_PATH` and `LOCPATH` point to staged data.
The runner rejects host fallback detected in runtime mappings. For both
processes, dl_iterate_phdr objects must join `/proc/self/maps` device/inode
identities to the pre-recorded candidate/workspace files and their SHA-256
hashes. Eight dlsym/dladdr symbol providers must resolve to the exact candidate
libc or libm. Both processes must map the exact candidate loader, libc and
libm. The parent must retain the plugin, candidate gconv module and candidate
locale mapping. The full inventoried runtime tree must remain unchanged.
The reported glibc version is informational and never sufficient for PASS.

The receipt records six source hashes, compiler/cc1/collect2/assembler/linker
hashes, per-source dependency/header hashes, three compiled ELF hashes,
loaded runtime hashes, exact argv, exit codes, elapsed time and bounded
stdout/stderr hashes/lengths. Raw NDJSON stays in private command logs. Compile
commands have 30-second limits; the candidate invocation has a 60-second
limit; each command has a combined 256-KiB output limit. The runner uses a
separate process session, retains the child until final TERM/KILL signals,
reaps it and requires process-group absence. SIGINT/SIGTERM trigger cleanup
and a FAIL receipt; SIGKILL/power loss require the caller's container cleanup.
Inventory is bounded to 8,192 files / 2 GiB; receipts to 2 MiB.

The compiler uses recorded bootstrap development inputs. This checks newly
compiled clients against the candidate runtime and does **not** establish
candidate-header ABI compatibility. It supplements upstream glibc tests;
it makes no completeness, performance, tuning, installation, boot or M2
hardware claim. Page size is recorded, not inferred from ELF alignment. ELF
max-page alignment is 16 KiB, which alone proves no 16-KiB runtime behavior.

## Verification available here

`test_runner.py` uses inert fake candidate files and mocked processes. It
checks input, mapping and provider rejection, incomplete results, source
drift, workspace separation, architecture refusal and finite command cleanup.
It executes no compiled binary, compiler, Docker actor or network operation.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s /ABS/runtime-smoke-proposal -p test_runner.py -v
```

The retained `host-check-final/receipt.json` is host **x86_64 compile-only**
evidence, with warning-as-error flags. `inert-tests.log` contains the inert
test output. Native aarch64 candidate execution, upstream GNU checks,
installation, M2 hardware and performance remain **NOT RUN by this worker**.
