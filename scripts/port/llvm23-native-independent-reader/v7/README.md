# LLVM Reader7: closed BUILDINFO architecture encoding

Reader7 replaces only the inherited two-line `complete349 package BUILDINFO`
predicate in a new replay namespace, after the existing installer runs. Reader2
through Reader6 files, Source260, package payload predicates, v5 command/fact
namespace separation, v6 exact Docker absent-image encoding, signatures,
retirement, storage and resource budgets remain unchanged. The replay projection
and the small Reader entry changes have exact byte inverses to their held parents.
The closed failed Reader6-r1 is not reentered or reinterpreted as passing.

The old predicate compares `installed = name-version` with standard retained
`installed = name-version-ARCH` rows. Reader7 derives architecture independently
from three whole-pinned Source260 files: `expected349.lock`,
`original/bootstrap/scripts/ci/inputs.lock.json` and
`original/native/input-profile.json`. The inherited replay has already checked
the complete Source tree, signed-input observation and bootstrap proof before
this predicate. The new helper additionally joins the retained effective input
lock and rootfs ALPM metadata back to that Source. It imports no Source or artifact
code and performs no new signature operation.

There are 165 rootfs metadata rows and 256 selected archive rows (248 original
plus eight fixed additions). Selected versions replace 71 rootfs versions among
72 same-architecture overlapping names. Their complete merged name/version map
must equal all 349 lock rows. The actual independent map contains 300 `aarch64`
and 49 `any` packages; no external architecture evidence input is missing.
The pinned ALARM archive filenames include the complete version, including epoch.
Whole Source pins, not output BUILDINFO, select these identities and versions.
This is closed Source/signed-input metadata evidence; it is not a fresh raw rootfs
reparse, new signature verification, symbol/ABI audit or hardware qualification.

For each installed row, only one terminal `-aarch64` or `-any` encoding is parsed.
The remaining name/version must match one exact baseline label and its suffix
must match that package's independently derived architecture. Unknown or doubled
suffixes, wrong known architectures, malformed names/versions, source metadata
conflicts, missing architecture evidence, incomplete/counterfeit349 membership
and duplicate names/rows refuse. Duplicate-row and malformed installed-key
whitespace/CR refusals explicitly tighten the former set comparison; unrelated
BUILDINFO fields keep their inherited checks, including effective recipe hashing.

The actual retained BUILDINFO helper regression passes all 349 rows. That is a
bounded DATA check, not an operational Reader run or component acceptance.
Future Root binding/request/reader selectors and grants remain null. Root must
issue a separate Reader7 role, bind the complete new closure and Original, and
retain its terminal result before making a component decision. Reader6's closed
failure remains preserved. Native16K, M2, performance and release stay held.

Focused fenced controls (Python 3.12 and 3.14):

```sh
python3 -I -B -Werror::ResourceWarning scripts/port/llvm23-native-independent-reader/v7/test_v7.py
```

This is the single proposed addition to the existing CI Python matrix; no shared
workflow is edited here. The 19 controls cover standard/epoch versions, selected
replacements, exact terminal suffixes, architecture swaps, malformed/duplicate
rows and metadata, counterfeit cardinality, source content/metadata replacement,
installer order/repeated installation, exact inverse, preserved v6 retirement,
and unissued templates. Operational subprocess/socket/ctypes/lease primitives
are fenced. The full v5 Source-data suite and v6 controls remain separate checks.
