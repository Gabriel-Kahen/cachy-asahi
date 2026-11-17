# Automatic successor DATA controls

This CI-only family registers 72 existing author controls and eight CI guards on
Python 3.12 and 3.14. It adds one PR/Main/manual workflow. Author test files,
production files, existing workflows, manifests and counts remain unchanged.
There is no native job, package build, installation, signing or Root dispatch.
The existing Source205104, Rust73, Fish v4 and Full Lua workflows are untouched.

| Author suite | Registered controls | Input |
| --- | ---: | --- |
| Audio79 adoption | 26 | Existing synthetic copy/refusal fixtures |
| Native Go VA source | 7 of 8 | Exact published Source62 |
| Libgit2 base | 23 | Exact original recipes and upstream archives |
| Libgit2 interoperability | 1 | Seven pinned consumer helpers; explicit MODEL records |
| Libgit2 VA successor | 7 | Same genuine DATA plus explicit MODEL records |
| Fish v5 | 8 | Exact Source50 reconstructed from published Source48 |
| CI guards | 8 | Adversarial tar, whole-file, result and selection boundaries |

## Explicit coverage gap

The native source control
`test_caller_constructor_seals_every_inherited_program_and_fixed68` and all 11
`test_caller_data.py` controls require an uncommitted sealed canonical caller
carrier and historical registration readback. Environment overrides do not make
all of their operands portable. These **12 controls are not registered**. No
carrier, registration, Root binding or replacement test is fabricated. The
native seven-method allowlist is explicit, and an AST census requires every
original source method to be registered or listed as blocked; additions cannot
silently disappear. Missing required inputs fail the registered suites; no skips
or expected failures are accepted.

## Exact public operands

`native-fish-inputs.lock.json` pins the published zero-parent Git Source62
`b36a1a6dba7dd42d55646582f3d1fa2002d78d5f` and Source48
`463377ba9c0b48c58dc112386c9b0203efd39b6e`, including complete file/byte/tree/map
tuples. Only Source48 is fetched for Fish. The 12 whole-pinned v4 constructor
operands from author `a729b1e5ff1027043c014931ce0b75a42290ff66` reconstruct exactly
50 files / 892625 bytes / tree `dff997f10bd4e917709f2b76d4c32f07ed379a03`.
This emits unissued DATA, not a new Source publication or Root profile.

`libgit2-inputs.lock.json` pins all 41 original recipe leaves from commit
`7e4d4ce45b19e45b6241af6f4fd787e67a1cdf18`, both upstream archive URLs, exact
sizes/SHA256 values, author descriptors and seven immutable consumer helpers.
The candidate checkout supplies the consumer only after all seven whole pins
match. No extra consumer checkout or local Root artifact directory is used.
Original source/license bytes are checked by the unchanged author suites; no
native/signature/official-trust acceptance is inferred from MODEL records.

Acquisition uses only these three exact public Git commits and two pinned HTTPS
upstream source archives. It disables Git credential helpers/global config,
checks the committed four-ID denylist against reachable object metadata before
reading archives, and removes only its own newly created input repository.
Existing shared object stores and denied blob bodies are never read or pruned.
The acquired inputs contain no private keys, Root grants or runtime selectors.

The separate preparation worker verifies raw Git commit identities, zero-parent
Source roots, complete file/directory censuses, modes, bytes, physical Git trees
and source maps before any pinned constructor import. Recipe namespaces and
upstream archive pins must match exactly. The filesystem helper itself is
whole-pinned. Traversal, aliases, duplicates, extra directories and nonzero tar
suffixes refuse. The setup and each suite run with 512 MiB address space, 120 CPU
seconds, 32 MiB maximum file size and 256 descriptors; orchestrator deadlines are
120 seconds for setup and 180 seconds per suite.

## Unchanged author commands and portable temporary directories

The runner executes each original test CLI through `runpy` with its original
`__main__` initialization. Fish receives its original `--base` argument and
`TMPDIR=/tmp` requirement. Native receives the seven explicit unittest method
names; other suites run in full. All test assertions, pins, MODEL records and
source paths are unchanged.

The only portability adapter maps the two historical temporary-parent literals
`/home/gabe` and `/home/gabe/.cache` **only when passed to `tempfile.mkdtemp`** to
an owned private CI directory. Input paths, `Path`, file reads, constructor
arguments and authority APIs are not replaced. Fish retains its original
fixture-only write fence. The runner opens its exclusive receipt descriptor
before invoking that CLI and writes the final count/result through that retained
FD, without opening a new path after the Fish fence is installed.

All DATA workers install an outer audit fence before author imports. Processes,
sockets, real resource changes, locks and signals are refused. Only the pinned
filesystem helper's current-process libc lookup and `renameat2` are allowed;
other dynamic library/symbol lookups refuse. Git/curl acquisition and bounded
Python worker orchestration happen outside this DATA boundary. Each worker
requires the exact test count, zero skips, zero expected failures and zero caught
outer-fence actor attempts, and retains complete rawlogs and result receipts.
These controls establish no Root authentication, real provider acceptance,
native startup/build, physical resource use, M2 behavior or release result.

## Local replay

Use a private existing output parent; both output children must be fresh:

```sh
python -I -B -Werror::ResourceWarning scripts/ci/native-successor-data/acquire.py \
  --output /absolute/private-parent/public-inputs
python -I -B -Werror::ResourceWarning scripts/ci/native-successor-data/ci.py \
  --inputs /absolute/private-parent/public-inputs \
  --output /absolute/private-parent/evidence
```

No local artifact path is compiled into the workflow or used as an input
fallback. Results and rawlogs remain under the explicit evidence directory.
