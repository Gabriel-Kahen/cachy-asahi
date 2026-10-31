# Apps8 package source checks

This checks the exact original sixteen-leaf Apps8 recipe published as
`98a0a6ab18355604683bee42c84c393940a690a1`. It leaves Apps7, Runtime1, the
repository client and the three repository helpers unchanged. Apps8 changes
metadata-path parsing while keeping two complete fresh ALPM scans and their
existing raw-byte/identity/lock checks and shared30-second limit.

Run from the current canonical checkout with the installed test tools:

```sh
python3 -I -B scripts/ci/apps8-package/check.py \
  --repository-source "$PWD" --output /absolute/fresh/private-parent/apps8-check
```

`--recipe-root` permits a separate ordinary staged recipe for adoption checks.
The output must be fresh and outside source/recipe trees. The checker verifies
fixed recipe and held canonical source pins, calls the existing read-only
package inspector, then executes the unchanged PKGBUILD `check()` with real
makepkg-style local-source symlinks and explicit canonical helper/Runtime1
inputs. All45 original tests and four Apps8 inverse/lexical/fresh-scan controls
must pass without skips. Finally the actual `package()` body is staged under
the private output and its eight installed files are checked. The original
suite also stages Runtime1 and executes installed CLI default helper lookup.
The signed synthetic fixtures use disposable private TEST keys and retire their
owned agents; no host package installation, user key import or native actor runs.

The scoped read-only CI repeats this entry on Python3.12/3.14. Some unchanged
staged executable controls use their existing `/usr/bin/python3` shebang;
the main45+4 suites and source check use the matrix interpreter.

These checks supply source/package-fixture evidence. The local fixture median
reported during development is not ARM/M2 performance evidence. Apps8 requires
its own native pair, full composition lifecycle and GUI qualification; Apps7
acceptance does not transfer. Hardware, release and package selection remain
separate gates. The recipe README preserves the complete original API, bounds,
license, signatures and non-applying planner contract.

## Finite native Apps8 result

Root accepted native ARM run [39727987029](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39727987029),
source `f1984a2481c541add7eb99b311a3ae3228307aa6`, after once-only original
collection and the complete independent 269-file strict reader passed. The
result covers Runtime1/Apps8/client-v2 three build pairs, the signed Runtime575
dependency image, installed577/restored574 lifecycle transitions and two ordinary
homes with 15 Apps plus 2 client controls per installed phase. The Apps8 pair is
byte-identical 23528B with SHA256
`d4d83458765d732ae78664143c9042dcc1159b7d3e19f4b7976f8499c2619f4a`.

See [the native record](../../../docs/validation/apps8-client-native-20261022.md)
for exact scope and limits. Installed current606, GUI, generic16K and M2 remain
NOT RUN for this result; no native final-system performance or release claim is
made. Private preservation maps and successful installed unittest text are
source-enforced rather than fully exported; retirement was recorded by the
source and not independently reobserved live. The package checker, profile,
workflow and all sixteen exact 98a0 recipe files remain unchanged.
