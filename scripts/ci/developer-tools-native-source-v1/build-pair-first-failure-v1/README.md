# First build failure propagation and exact package-control class

This finite successor uses actual Source
`dc36f6dda0bab4a72604aad3782c2f6b5e933a38`, tree
`72daab4c387cfba649b10f08ef919072ebeda2eb`. It changes only four Source
leaves: ALPM producer, matching reader, projector's producer pin and map.
All196 other leaves, owner/safe-diagnostic logic, package recipe/archive/payload,
privacy/pass/signature/resource/retirement/deadline predicates remain held.
Original f4bea/dc36 factories, profiles, modeled controls and evidence are
preserved as historical operands.

Root's bounded safe DATA from actual42550041932 reports phase `compare`,
ValueError, a28-byte message hash and no completed build stages. That hash
uniquely joins the source literal `exact native pair/source map`; this is a
source-literal hash join, not availability of the original raw message or the
earlier original exception. The selected last build-b command succeeded with
natural owned retirement. The omitted earlier dc36 cause remains unknown;
no earlier f4bea cause is inferred.

Source audit establishes two concrete defects independently of that missing
original context:

- `build_pair` caught a build/validation exception, stored it in `primary`, then
  continued without raising. The next build could run and a later compare guard
  could hide the first failure. A bare re-raise now propagates that same exception
  object through the existing `finally` block, which restores the owned slot.
  Source-retirement errors remain recorded and cannot replace a primary error.
  A retirement error without an earlier failure still propagates normally.
- The unchanged archived `test_package.py` defines `PackageControls`, but both
  producer and reader regexes required `PackageTests`. Only that exact literal
  is corrected in each parser. All13 method identities, ordering, count, positive
  check marker/summary/OK and no-skip/error predicates are held.

The two inert fixtures are complete actual local packaging-control transcripts
under selected Python3.12.13 and3.14.7, with13 passes each. Their class and ordered
methods are tied to the maintained test source AST and identical archived test
bytes. The selected3.12 parent still invokes the fixed launcher shebang under
host `/usr/bin/python3`3.14.7. These are host packaging controls, not native ARM,
makepkg, ALPM, M2 or performance evidence. Tests prepend only an explicitly
modeled makepkg check boundary; they do not call a native actor.

Nine new actor-fenced controls run with the historical27 through the maintained
Python3.12/3.14 workflow. They accept both genuine transcript shapes; reject the
old class, renamed/reordered methods, skips/errors/count/summary drift and repeated
or missing check boundaries; prove a first validation or command exception stops
before build-b and escapes only after slot restoration; preserve primary identity
when slot cleanup fails; propagate cleanup-only errors; retain successful two-build
behavior; and verify only the intended code/pin changes and complete virtual
parent/final200-tree/map/inverse. The historical fabricated PackageTests fixture
remains evidence only for its frozen historical parser, not for this successor.

Root-only constructor invocation:

```sh
python3 -I -B scripts/ci/developer-tools-native-source-v1/build-pair-first-failure-v1/prepare.py \
  --parent-source /absolute/retained/Sourcedc36/source \
  --profile-sha256 ROOT_BOUND_VARIANT_PROFILE_SHA256 \
  --output /absolute/private/fresh-source
```

Construction authenticates the physical parent/raw commit/map, all four new
operands, final closed200 namespace/tree/map and inverse before fresh no-replace
output. Constructor/publication, Source/native/ALPM, Original and actual Reader
roles remain Root-owned and NOT RUN for this successor. No16K/Asahi/M2,
performance or release acceptance follows.
