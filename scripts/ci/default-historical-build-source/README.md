# Fixed default native and desktop build source contexts

`prepare.py` emits one of eleven fixed historical source views for the default
static checks. It never builds, installs, invokes a native/GUI/VM actor, creates
an actual-run binding or grants acceptance. Current builder checks elsewhere
keep using the evolving builder.

The six native selectors are `apps7-client-native`, `dns-sysctl-native`,
`sysctl2-upgrade-native`, `dns2-native-upgrade`, `ksm2-upgrade-native`, and
`welcome5-native-upgrade`. Each whole original `source-manifest.json` has an
independent fixed byte-count/SHA-256 pin. The desktop selectors are
`desktop-user-session` and `desktop-file-manager-workflow`; each whole original
`source-pins.json` has its own independent pin. Their original SHA-only map
format is preserved. The caller cannot provide another map or pin.

Only build-helper roles actually declared by the selected original map are
substituted from the existing fixed shared snapshots in
`scripts/ci/historical-inventory-source/shared-build-v1/`. Native routes declare
`build.py`, `compare.py` and `container-entry.sh`. Each desktop route declares
only `build.py` and `container-entry.sh`: its view neither consumes nor emits
`compare.py`. Snapshot bytes have independent original pins agreeing with the
selected map; missing or changed snapshots refuse without fallback.

Current helper bytes are identified separately and never executed by these
historical controls. All other declared inputs must match their exact original
map. Fixed supplemental inputs cover the unchanged tests/contracts/runtime
files omitted from the desktop maps, and the registered workflow read by the
Apps7 test. These supplemental bytes have independent fixed pins in the adapter;
there is no arbitrary current-manifest authority. Original maps/tests/contracts
are copied byte for byte and remain unedited.

```sh
python3 -I -B scripts/ci/default-historical-build-source/prepare.py \
  --source "$PWD" --output "$RUNNER_TEMP/default-desktop-user-source" \
  --profile desktop-user-session
python3 -B -m unittest discover \
  -s "$RUNNER_TEMP/default-desktop-user-source/scripts/ci/desktop-user-session" \
  -p test_managed.py
```

For native lanes, run their unchanged `preflight.py --source VIEW` and
`test_lane.py` discovery from the emitted view. KSM2 first runs its unchanged
NULL-emitting `prepare.py` from the view, with both recipe inputs also in the
view, then uses its existing downstream commands. Existing NULL authority and
all historical guards remain intact.

Views must be fresh and disjoint in a caller-owned parent without group/world
writes. Inputs must be bounded single-link ordinary files without aliases or
group/world writes. All inputs are captured and checked before output creation.
Optimized Python refuses because it would disable original assertion guards.

The delivered `static.yml.patch` contains all eight context routes and one adapter
regression step. Apply it to Root's current integrated workflow; do not replace
that workflow with a baseline preview or drop its existing delivery checks.
The two desktop caller-control commands remain unchanged.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/default-historical-build-source/test_prepare.py
```

Controls cover exact eleven-view closure, direct evolving-helper refusal versus
success through a view, original native/desktop suites, original KSM NULL
preparation, map/snapshot/supplemental/unrelated-source drift, missing inputs,
aliases, hardlinks and overlapping paths. Desktop tests additionally prove that
undeclared `compare.py` and its snapshot are unnecessary. All runtime/GUI/native,
installation, VM, hardware and release acceptance remains `NOT_RUN`.

Three further fixed selectors cover the retained export consumers:
`full-root-upgrade-caller`, `full-root-failed-update`, and
`full-root-postcommit-failure`. Their exact original configuration files and
`code_pins` maps are independently pinned in full. Only their declared `build.py`
and `compare.py` roles are substituted; `provision.py` remains an ordinary exact
input and `container-entry.sh` is not consumed. The upgrade caller's original
`run.py`, omitted from its config map, has one fixed supplemental pin. Original
configurations, run modules, runtime validators, expiry and failure policies stay
byte-exact. These views add no authority to run expired historical transactions.

The release consumer harness verifies all frozen code pins in these views and
calls the original pre/postcommit `selected_api` implementations from the views.
Canonical exporter/endpoint API checks still read the current canonical source.
Causal controls verify direct enhanced-source refusal, frozen-view acceptance,
and snapshot/exporter drift refusal; exporter drift, configuration-byte seals,
failure-policy limits and exact original expiry assertions remain enforced.
