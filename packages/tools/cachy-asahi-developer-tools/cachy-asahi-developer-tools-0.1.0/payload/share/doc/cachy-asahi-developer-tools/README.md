# cachy-asahi-developer-tools 0.1.0

An original MIT, opt-in developer journey package. Its fixed offline fixtures
exercise local tools from an installed prefix without a project checkout.
This is a development candidate for M6/D05 and M8 onboarding. It does not
establish native ARM, installed Asahi, physical M2, performance or release acceptance.

```
cachy-asahi-developer-tools --help
cachy-asahi-developer-tools --version
cachy-asahi-developer-tools verify
cachy-asahi-developer-tools workflow --output /absolute/new/workflow --tool-path /usr/bin:/bin
cachy-asahi-developer-tools build-systems --output /absolute/new/build-systems --tool-path /usr/bin:/bin
cachy-asahi-developer-tools debugger --output /absolute/new/debugger --tool-path /usr/bin:/bin
cachy-asahi-developer-tools python --output /absolute/new/python --python /usr/bin/python3 --uv /absolute/existing/uv
```

Every journey requires a NEW absolute evidence directory outside the package
prefix and retains logs, source/tool/product hashes, failures and actual results.
Default budgets: 30 seconds per command and 300 seconds total. Override with
`--command-timeout` and `--total-timeout`; held runners enforce finite caps.
Exit 0 means the selected runner's documented local component condition passed;
exit 2 means refusal, failure, missing tools or no runnable journey. Inspect
`result.json` for missing optional journeys even when the overall status passes.
`verify` checks the entire runtime manifest, file set and bytes before execution.

| Subcommand | External tools and behavior |
| --- | --- |
| All | Linux procfs and Python >=3.11 at /usr/bin/python3. Standard library only. The launcher uses Python isolated mode and disables bytecode writes. |
| workflow | Git, `cc`, `c++`, Vim and python3 are required. Local Git fixture, isolated scripted Vim edits, C/C++ rebuild/failure/recovery, venv without pip and unittest. Available Make and Ninja run fixed project journeys; absent optional tools remain NOT_RUN. CMake/Meson version probes here are not their journey evidence. |
| build-systems | CMake >=3.20 + CTest + Ninja + `cc` + `c++` for CMake; Meson + Ninja + `cc` + `c++` for Meson. Each available backend runs fixed shared-library build/test/edit/failure/repair/private-prefix install/runtime controls. Missing backend tools remain NOT_RUN. |
| debugger | `cc`, `c++`, GDB and permission to debug their own child. Fixed C/C++ breakpoints, local values, stack, continue, exit, stale-executable refusal and recovery. Debuginfod disabled. |
| python | Explicit absolute Python interpreter; optional explicit uv **0.11.28** matching the fixture's exact uv_build requirement. Fresh venv without pip, offline wheel/build/install/test/edit/failure/repair. Missing or incompatible uv leaves the package journey NOT_RUN; no tool is downloaded. |

`--tool-path` selects the search directories for non-Python journeys; it never
inherits the caller's PATH. Use a directory containing reviewed tool links plus
necessary system tools to restrict discovery. Selected frontends resolve to
absolute paths and are hashed by the held runners. Backends are explicitly
bounded to those present in these directories. The Python subcommand takes
explicit interpreter and uv paths; its subprocess PATH is the held os.defpath.
External tools and their runtime libraries are trusted host dependencies, not
bundled artifacts or a clean toolchain closure. A compiler's full transitive
toolchain closure and ARM availability require target package-manager evidence.
The package contains only scripts/data (`arch=any`); compiled example products
are generated in the user's private output and are never shipped in its payload.

Only the checked-in MIT fixtures are evaluated. There is no user project path,
shell command, environment activation, source fetch or package installation
interface. Existing process supervision, WNOWAIT/ECHILD ownership guards,
stale-product refusal and all historical source pins remain unchanged. Local
tools can execute their intrinsic fixed build recipes. This is an integrity
check of trusted package files, not isolation from hostile tool binaries or a
same-UID attacker racing filesystem changes.

## Package and source layout

`bin/cachy-asahi-developer-tools` discovers its prefix from its own file location.
`lib/cachy-asahi-developer-tools/0.1.0/` contains the exact original `scripts/`
and required `tests/workflows/fixtures/` relative layout. This lets the held
ROOT discovery and cross-module SHA256 pins work unchanged. `runtime.json` is
bound by an embedded launcher hash; no source-checkout fallback exists.
`share/doc/cachy-asahi-developer-tools/` contains this guide and exact source
provenance. `share/licenses/cachy-asahi-developer-tools/` contains LICENSE/NOTICE;
each included fixture license also remains beside its source.

The source distribution's `payload-map.json` enumerates EVERY installed regular
file with its prefix-relative path, size, SHA256 and mode. No links, hooks,
services, configuration ownership or package-manager callbacks are shipped.
Only declared payload files are copied. Python is the sole hard dependency;
journey tools are optdepends and independently reported missing when absent.

Build the local pinned source archive with `makepkg --nodeps --nosign` from the
recipe directory (no `-s` or `-i`). `check()` runs only packaging boundary
controls, not prior author suites or developer journeys. `package()` calls
`assemble.py --destdir "$pkgdir" --prefix /usr`; it refuses a live/nonempty or
aliased destination and never invokes a package manager. For a private staging
copy, run `python3 -I -B assemble.py --destdir /absolute/new/stage` from the
extracted source; move `stage/usr` to any private prefix, then invoke its launcher.

For a real target installation/removal, the coordinator must review the exact
package and authorize its normal package-manager transaction. Removal owns
only the enumerated payload; evidence directories and user settings are outside
it. Upgrade replaces the launcher and versioned package-owned runtime; previous
user evidence is preserved. Private copy/remove/reinstall controls do not prove
an actual pacman install/upgrade/remove transaction. No system install is run by
the package, tests or relocation demonstration.
