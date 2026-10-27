# Offline Python developer component

`scripts/workflows/python_development.py` complements the existing Make/Ninja
and CMake/Meson workflows with an original dependency-free Python project. It
creates a fresh private venv, builds a real pure-Python wheel, installs it only
in that venv, and exercises installed unit tests, module execution and the
generated console command. The source checkout is never placed on the import
path of installed tests or commands.

From an integrated checkout:

```sh
python3 -I -B scripts/workflows/python_development.py \
  --python /usr/bin/python3 \
  --uv /absolute/path/to/uv \
  --output /absolute/path/to/new-private-python-workflow
```

Select the interpreter and uv explicitly. Python must support `venv` and the
project's Python >=3.11 contract. The project pins `uv_build==0.11.28`, and this
finite workflow requires uv 0.11.28 with its actual built-in backend. The uv
binary supplies both the build frontend/backend and installer. No custom wheel
writer or backend shim is used. No pip/setuptools/wheel installation is needed:
the venv is created with `--without-pip`. This is uv's real direct build path,
not an exercise of its optional PEP 517 subprocess path.

The runner supplies `--offline`, `--no-index`, `--no-config` and
`--no-python-downloads`, a fresh private cache, private HOME/TMPDIR and a scrubbed
environment. It installs the exact local wheel with `--no-deps`, `--reinstall`
and copy mode. It does not use host/user packages or a prepopulated build cache.
These are tool-level offline controls, not a network namespace sandbox.
Run only the included trusted fixture; this is not an arbitrary project executor.

An omitted `--uv` produces `NOT_RUN_MISSING_EXPLICIT_UV` after actual venv
creation. An incompatible selected uv version produces
`NOT_RUN_INCOMPATIBLE_OFFLINE_BACKEND`. Both exit 2 and leave build/install as
`NOT_RUN`; the runner never invents a frontend or wheel. Missing venv support,
failed commands and other errors produce `FAIL` and exit 2 with retained errors.

The journey checks initial installed behavior, skips an unchanged build without
launching either build or install, then edits project source and builds/installs
a changed wheel. A deliberate installed unit-test mismatch revokes execution
until the tests recover. Invalid version metadata causes an actual backend build
failure; the old venv installation remains on disk, but the runner refuses to
execute it. Restoring metadata rebuilds/reinstalls/tests/runs successfully.
Content hashes, rather than timestamps alone, govern reuse.

Retain the complete output directory. `result.json` binds selected interpreter
identity, executable hashes, uv version/hash, helper/core hashes, project fixture
bytes, exact commands and owned-process outcomes. `commands.json` and numbered
logs retain combined stdout/stderr and supervision records. `project.json`,
`snapshots/`, `dist/` and `venv/` retain per-step source snapshots, real wheels,
installed paths/hashes and the created environment. Every subprocess uses the
existing pinned `developer_workflow.Commands` and owned-process core, including
their finite output/time budgets and group retirement checks. Changed source,
interpreter, frontend, venv config, wheel or installed files revoke execution.

The interpreter executable hash and runtime metadata do not archive or fully pin
stdlib, libpython or system shared libraries. Reproduction requires provisioning
that interpreter/runtime and the exact uv tool separately; this is not a hermetic
toolchain rebuild or a general dependency resolver. Venvs and generated console
scripts contain absolute paths and should be rerun, not relocated. Pure Python
packaging does not exercise extension compilation, editable installs or sdists.

Focused refusal controls:

```sh
python3 -I -B -m unittest discover -s tests/workflows -p test_python_development.py -v
```

The retained host demonstration is Linux x86_64 with 4096-byte pages. It is local
userspace component evidence only. Native ARM, native 16K, system package
installation, independent onboarding, both physical M2 Air sizes, performance
and release acceptance remain separate and unqualified.
