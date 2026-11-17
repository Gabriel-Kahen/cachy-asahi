# Qt612 hosted source controls

This isolated workflow checks frozen source bytes and deterministic MODEL/semantic
contracts. It does not configure/build Qt, execute a Qt smoke, create real package
archives, start a native producer, download inputs, upload artifacts or grant
native/TEST/release acceptance. Hosted Actions execution is separate from local
verification of this authored workflow.

`sources.lock.json` pins complete families from these original commits:

| Family | Commit | Entries | Existing controls |
| --- | --- | ---: | ---: |
| Serial recipe | `69a02851b87ca29daf2e197101b66bf75ff61889` | 256 | 27 |
| Artifact transport | `75cee7ea27e1c9f3d10959e824b261764b9b1c3d` | 6 | 28 |
| GUI recipe | `b05267833d497ef034576741bf31968019a526c3` | 36 | 65 |

The CI code independently pins the whole lock. Every selected file's complete
body, length, mode and node type must match before any frozen suite executes and
again after all suites finish. A shallow checkout suffices: verification consumes
the current committed bodies, without fetching historical objects or treating the
lock's commit labels as a Git ancestry proof. Intentional updates need a newly
reviewed source lock; frozen families are not edited by this slice.

`pins.py` bounds each family to 512 files, 2 MiB per file and 16 MiB total. It
requires the exact namespace, ordinary singly linked regular files and stable
directory/file identities. Missing/extra files, changed bodies/modes, private path
components, FIFOs, hard links and unexpected symlinks fail before suite execution.
The two passive serial `recipe-inputs/{arch,alarm}/LICENSES/0BSD.txt` links are the
only exceptions: their exact `../LICENSE` text and independently pinned ordinary
targets must match. They remain passive audit data, never active recipe inputs.

Twenty new adversarial pin controls exercise these rules, including sparse-file
oversize refusal before a body read, exact budget boundaries and replacement
races. Combined with the 120 frozen controls, the gate requires **140 tests and
zero skips** on each of Python **3.12.13** and **3.14.6**.

Each test file runs in its own interpreter. This prevents duplicate test-module
names and the GUI suites' persistent audit guards from affecting sibling tests.
All five GUI suites retain their own pre-import guards and guard self-tests.
Other suites use the wrapper's actor guard; only the two frozen scheduling suites
may invoke Bash with their existing empty-PATH operation stubs. No real compiler,
CMake, package, network or native actor invocation is allowed. Child environments
contain only a fixed system PATH, owned temporary HOME/TMPDIR, locale and timezone.

The controller and child address-space caps are 512 MiB. Each suite has a 30-second
CPU cap and 40-second parent timeout. A 256 MiB logical file-size limit permits
the intentional sparse 128 MiB+1 rejection fixture; this is not a Qt disk-usage
measurement. The workflow adds a 180-second command timeout and eight-minute job
limit. Run as an unprivileged Linux account with Bash, `/proc/self/status` and
ordinary temporary storage supporting modes and links. No third-party Python
package or package installation is needed.

```sh
/absolute/python3.12-or-3.14 -I -B -Werror::ResourceWarning \
  scripts/ci/qt612-source-controls/ci.py \
  --workspace /absolute/composed/checkout \
  --report /absolute/fresh/report-outside-checkout.json
```

The report must be fresh and outside the source workspace. A complete local JSON
report is written only after every suite and final pin recheck passes. Failure
returns nonzero with a bounded stdout/stderr reason. Success is
`PASS_QT612_SOURCE_CONTROLS_ONLY`, always with native acceptance false and Root
acceptance null. The new `.github/workflows/qt612-source-controls.yml` uses exact
existing checkout/setup-python action pins, read-only contents permission and no
credentials persistence. Reports remain in runner temporary storage; no upload
action or shared workflow is changed. Local command checks do not establish a
hosted run or any native/package/hardware result.
