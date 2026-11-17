# Libgit2 finite Docker CLI address-space successor

This DATA-only successor starts from the frozen producer at
`83d95b33210483887fc0f423ec12008208cbc0be`. It binds the exact immutable
`go_cli_va.py` from `b156e3886a12f95cb3d364b84fc3a946bb7d2967`:
1996 bytes, SHA256
`3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3`.
The original producer and its dependency/source/native predicates stay frozen.
No actual accepted llhttp tuple or production Source is supplied here.

The helper exposes `controller_limit(policy)`, `child_plan(argv, tools, policy)`
and `child_limits(plan)`. The literal reviewed policy declaration is:

```python
dict(kind='OBSERVED_DOCKER_CLI_FINITE_VA_V1',
     normal_controller_AS_bytes=536870912,
     normal_child_AS_bytes=536870912,
     docker_cli_AS_bytes=2147483648,
     allowed_canonical_paths=['/usr/bin/docker','/usr/sbin/docker'],
     executable_observation_required=True,
     physical_cgroup_limits_unchanged=True)
```

The controller soft AS remains512MiB; only its hard ceiling becomes2GiB.
Immediately before each launch, the parent pair must match that declaration.
Only the exact canonical Docker executable already observed and freshly
rechecked by `H.checked` receives soft=hard2GiB. Every other observed child gets
soft=hard512MiB. No basename, PATH, wrapper, environment or unlimited fallback
selects the exception. Each child reads back its exact pair before exec, and
the command receipt retains the selected plan.

Controller cgroup memory512MiB/CPU1/PID64/swap0, owner2GiB AS/domain,
daemon6GiB/4CPU, all other memory/CPU/PID/swap bounds, physical storage, byte and
time bounds, ordinary executable custody, cancellation, natural reap and
retirement predicates remain unchanged. Four finite controller projections
have a complete inverse; no retirement or physical-memory waiver is added.

Root reports actual ARM Docker startup for this exact helper in Source68 run
`44038704344`: command010 `info` exited0, reported architecture `aarch64` and
the owned Docker daemon28.0.4. This work does not replay that observation.
That is startup evidence only, not llhttp/libgit2 package-build acceptance.
The same run then encountered an ordinary payload `ValueError` before a package
build and a failed-unit cleanup bug. Root's separate fixes remain integration
requirements; this successor preserves those paths and cannot claim successful
payload execution or cleanup.

## Closed successor construction

```sh
python3 -I -B scripts/ci/libgit2-reference-native-source/successor_v2/prepare.py \
  --parent /absolute/Root-reviewed-parent-Source \
  --parent-map-sha256 EXTERNAL_ROOT_REVIEWED_SHA256 \
  --output /absolute/fresh-libgit2-successor-Source
```

The parent map hash is an explicit independently selected operand, not authority
inferred by hashing a received directory. Static producer actors must match the
frozen predecessor pins. The complete parent namespace, every body/mode, map,
byte census and physical Git tree are checked. Construction changes only the
controller, policy and owner-program, adds the pinned helper, marker and review
README/manifest, retains
the four complete original before-bodies, and recomputes the closed Source map
and program. The inverse reconstructs every parent body, original map and tree.
The held-source subtree, manual workflow and original signed349, normal Required
TEST transaction, provider/loader, native pair, strict comparator and zero-host-
APT predicates remain byte-identical.

All actual selectors stay null. There is no default Source CID/ref, Root role,
registration, nonce, custody grant, runtime or dispatch. Root must independently
review and bind the new Source/program/policy bytes and issue fresh actual
admission and runtime documents, preserving current cache, resources, custody
and retirement gates. Missing native packages, signatures, public key, source/
license/native-pair evidence or Root acceptance have no substitute. No actors,
signing, installation, package build, native16K/M2 test, performance measurement
or release acceptance ran for this preparation.

## Actor-fenced DATA controls

```sh
LIBGIT2_CONSUMER_ROOT=/absolute/frozen-consumer-interface-checkout \
LIBGIT2_DATA_RECIPE_ROOT=/absolute/original-recipe-checkout \
LIBGIT2_DATA_ARCHIVE=/absolute/libgit2-1.9.7.tar.gz \
LLHTTP_DATA_ARCHIVE=/absolute/llhttp-9.3.1.tar.gz \
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/libgit2-reference-native-source/successor_v2/test_data.py
```

These controls check exact helper bytes, both finite plans and invalid-budget,
unobserved-path, policy, readback, source and inverse refusals. Resource calls
are mocked; real `setrlimit`, processes, network, native loading and cgroup
actors are fenced. With genuine explicit source/recipe operands, temporary
**MODEL** parent and successor Sources exercise the complete namespace/program/
policy inverse and are removed. Synthetic key/signature/native/Root-shaped
receipts grant no real authority or cryptographic/native acceptance. Missing
DATA operands report SKIP rather than inventing actual inputs.
