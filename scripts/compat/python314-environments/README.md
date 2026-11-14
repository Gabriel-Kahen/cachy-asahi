# Private Python 3.14.8 environment journey

`run.py` exercises the unchanged source-built `python 3.14.8-1.1` candidate in a
fresh ordinary-user private prefix. It reuses the pinned archive extractor,
file seal and bounded subprocess runner from `../python314-consumers/probe.py`
(commit `0e41b50a20d089ca1c35b7a246c7fb7aa433fd1c`), without editing that implementation
or the candidate/build helpers. The new driver and tiny wheel payload are
original MIT code; the wheel includes the project's license.

Run from the prepared checkout with already installed system Python 3.14:

```sh
python3 -B scripts/compat/python314-environments/run.py \
  --full-evidence /tmp/cachy-asahi-python314-tk-full-second-20261114 \
  --original-core /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/python3148-source-candidate-host-20261114 \
  --output "$PWD/work/python314-environments-final"
```

The output must be fresh, absolute, without whitespace and outside both input
evidence trees. Its parent must already exist. No privilege, dependency install,
network access, pip cache, build backend, compiler, display, service or device is
needed. The environment's pip is used only for the explicitly requested private
wheel workflow. No host packages are installed and no `--break-system-packages`
option is used.

## Actual workflow

The full-profile **second-run** archive must be exactly 17,308,438 bytes with
SHA-256 `8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e`;
its builder report and candidate sources are independently checked by the reused
extractor. The driver extracts privately, copies and renames the base, then:

1. Confirms 3.14.8 identities and that the base packages no pip module/frontend.
2. Creates a venv with `--copies --without-pip`, checks its base/prefix/executable,
   installation scheme, module paths and actually mapped private libpython.
3. Runs the candidate's bundled `ensurepip --default-pip` inside the venv. The
   recorded pip version is 26.2.1, with its module located inside that venv.
4. Builds an original deterministic `cachy_asahi_env_demo-0.1.0-py3-none-any.whl`
   using only `zipfile`, with metadata, console entrypoint, MIT license and
   SHA-256 RECORD. It installs the explicit local file using `--no-index`,
   `--no-deps` and `--no-compile`; no index or build isolation is involved.
5. Executes both import and the generated console script, compares version,
   executable, prefix, base prefix, module path and result 42, then uninstalls.
   Import, distribution metadata and the console script must all disappear.
6. Restores all tamper fixtures, repeats identity/absence checks, and verifies
   original evidence and system Python custody.

PEP 668 is tested outside the venv against the **private base**, without
bootstrapping pip into it. One explicit `sys.path` injection loads the exact
bundled `pip-26.2.1-py3-none-any.whl`; that process attempts the same offline local
wheel install and must exit 1 with `externally-managed-environment` and the
candidate's package-manager message. The injected wheel's hash is recorded.
The full base seal must remain identical, proving no pip frontend or package
was installed there. This limited injection is a test adapter, not a claim that
the candidate packages pip.

Nine controls require clear refusal: wrong selected interpreter, actual system
interpreter, wrong expected base prefix, changed `pyvenv.cfg`, actual changed
venv home, missing library, actual library fallback, changed PEP 668 marker and
changed local wheel. The system executable can load the candidate library when
the private loader path is supplied; prefix/executable checks still refuse it.
Version alone is deliberately insufficient.

## Evidence and limits

November 14, 2026: final `work/python314-environments-final/report.json` records
the completed journey and all nine controls passing. Both import and console
report 3.14.8, wheel version 0.1.0 and the private venv identity. The local wheel
is removed; bootstrapped pip remains only inside the private venv.

The report binds every command/log, source and wheel hash, the full input,
mapped library and private base seal. A before/after snapshot compares bytes,
modes and symlink targets across system Python executables/config frontends,
shared library, headers and the entire stdlib/site-packages (17,293 observed
nodes). Those snapshots match. The original full archive, core stage and core
report are also checked unchanged. Prior C-consumer evidence is retained
separately; the new private handoff is `work/environment-handoff.json`.

An initial development run completed the package journey but its aggregate
failed because the wrong-interpreter control expected only a version failure.
It actually refused on prefix identity while using the candidate library. The
assertion was corrected; this failed run remains separate from final success.

The whole journey has a 300-second alarm. Owned subprocess groups have 60-second
wall/45-second CPU deadlines, 1 GiB address space, 4 MiB file limits and no cores;
timeouts kill the group. HOME/XDG/TMPDIR and loader/pip configuration are private.
These are environment/resource controls, not an OS network/filesystem sandbox.
The commands use bundled/local inputs and make no network requests.

This is x86_64 host evidence. Original core HOLD for missing Tk remains
unchanged; the separate full-Tk builder and C-consumer results remain separate.
Native ARM/16K, coordinated installed transactions, M2, GUI, performance,
historical ALARM correspondence, source/signature/legal closure, full-system
acceptance, trust and release gates remain unqualified.
