# Finite Boot79 source factory

This additive factory closes the exact published Boot native source
`2c524830adb007e3b49392ceb54dd4cc5236c77d`. It reads a separate genuine source79
checkout and current Boot recipe inputs; it never replaces the historical
`welcome-native` tree, changes the package inventory or selects a default package.
No native source bodies or journal fixture binaries are copied into this namespace.

The current recipe must contain exactly the original six inputs plus reviewed
`.SRCINFO` (817 bytes, SHA256
`42d541331daf875b951d8583914bd889c24ddd46f7a1a22e11a927396584d046`).
The emitted trial recipe remains its original six inputs: reviewed metadata stays
at its original source79 native role. All historical47/705 source bodies remain
byteheld within the exact source79 closure.

```
python3 -B scripts/ci/boot-report-native-source/prepare.py \
  --current-root "$PWD" --native-root "$PWD/.ci-inputs/boot-report-native-source" \
  --output "$PWD/.ci-inputs/boot-unbound"
python3 -B scripts/ci/boot-report-native-source/prepare.py \
  --current-root "$PWD" --native-root "$PWD/.ci-inputs/boot-report-native-source" \
  --output "$PWD/.ci-inputs/boot-selected" --selected
BOOT_CURRENT_SOURCE="$PWD" BOOT_NATIVE_SOURCE="$PWD/.ci-inputs/boot-report-native-source" \
  python3 -B -m unittest discover -s scripts/ci/boot-report-native-source -p test_prepare.py
python3 -B -m unittest discover -s .ci-inputs/boot-selected/scripts/ci/welcome-native -p test_boot_native.py
```

Outputs must be fresh. Default output equals the complete frozen default79,
with UNBOUND recipe/version/input-map and NULL actual source/ref/run; its source
contract verifies but activation refuses. Selected output equals the complete
frozen selected79, still with NULL actual identities. Neither is an acceptance
record. The factory uses no Git, API, subprocess, package, journal or native actor.

Existing trusted Boot reader source validation and actual replay remain mandatory;
this factory is not a reader replacement. Local release validation must run the
unchanged whole214 Boot reader, including its original121 reader and complete
original47/705 source contexts, against emitted selected79. Historical native19
and caller8 controls run in their original705 source context; their historical
multi-product operands are not a Boot-selected suite. Boot-selected source has its
own unchanged12 source controls. No reader carrier or new collection route is
introduced. Root binds genuine publication/actual metadata with the existing
reader, and retains the original CI_SUCCESS, nonce, provenance, lifecycle,
retirement and clock predicates. No real boot history, crash diagnosis, Asahi,
M2, physical16K or release acceptance follows from these source controls.
