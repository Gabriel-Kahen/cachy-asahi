# Finite Docker CLI address-space successor v2

New Source and unissued caller preparation only. Native ARM startup/build pair,
signing, installation, native16K/M2 and release are NOT RUN. Source62, its consumed
r81 operation and all old code/callers remain immutable. No Root grant, runtime,
role, shared lease, native actor, push, POST, retry or secret discovery occurs here.

## Exact observed failure and scope

Root run44029730769/job133858489730 consumed Source62 and held before ordinary
owner submission. Its public command010 invokes the observed /usr/bin/docker
against the dedicated socket for info, exits2 naturally in0.036s and prints the
Go page-summary reservation fatal error. Existing12 host tools and zero-APT
qualification passed; owned daemon PIDFD exit/empty twice, storage absence and
zero cleanup errors are retained. failure.DATA.json pins those public inputs.

The exact source chain is hosted_owner.main -> Controller.setup -> self.docker
-> Controller.run -> Popen. main sets controller RLIMIT_AS soft=hard512MiB; run
has no child override. Thus this first Docker CLI inherits512MiB by source
semantics. The inner ordinary owner's separate2GiB cap is not reached. Public
records did not retain the actual child rlimit or failed mmap errno, so attributing
this Go failure specifically to that inherited cap is a source-backed inference.
It is not an observed mmap diagnosis or proof that ARM startup now succeeds.

## Official rationale and finite policy

[Go's64-bit page allocator](https://github.com/golang/go/blob/go1.24.1/src/runtime/mpagealloc_64bit.go)
reserves one array per radix level. Its
[page-allocation constants](https://github.com/golang/go/blob/go1.24.1/src/runtime/mpagealloc.go)
and [heap-address constants](https://github.com/golang/go/blob/go1.24.1/src/runtime/malloc.go)
yield five48-bit/8KiB-page reservations totaling613548032B, about585MiB.
[The Linux reservation implementation](https://github.com/golang/go/blob/go1.24.1/src/runtime/mem_linux.go)
uses PROT_NONE mappings. Reserved virtual space therefore differs from resident
memory charged to the cgroup. primary-sources.DATA.json records the exact upstream
revision, whole raw-source pins and calculation. This is audited Go1.24.1 behavior;
the actual failed ARM Docker binary's Go build version was not observed.

The proposed Docker-only VA budget is2GiB, leaving1533935616B beyond those summary
reservations for other mappings. It is a finite, testable allowance, not a
sufficiency guarantee for every Go build. Failure remains HOLD with no fallback.

Only the controller's hard AS ceiling becomes2GiB; its soft AS stays512MiB. A
pre-exec function raises soft+hard to2GiB ONLY for the already-observed exact
canonical /usr/bin/docker or /usr/sbin/docker. H.checked's whole executable and
alias-chain rejoin still precedes launch. All other qualified child tools have
explicit soft=hard512MiB. No basename, PATH, environment, wrapper or executable
fallback grants the exception. The finite parent hard ceiling is required because
an ordinary child cannot raise an inherited512MiB hard cap. Every child checks
its exact applied pair before exec; each command receipt records its selected
AS plan. The parent's soft/hard pair is checked before every launch.

Controller cgroup memory.max512MiB, CPU1, pids64, swap0 remain unchanged. The owner
2GiB AS/RSS domain, daemon6GiB domain, CPU/PID/swap bounds, storage, byte caps,
deadlines, ordinary executable whitelist, cancellation, natural reap and retirement
remain byte-identical or policy-identical. The original main/command mechanics
are restored exactly by four finite projection inverses. No unlimited AS is added.

## Source and caller construction

prepare.py consumes only the exact public62-file/928551B parent with map
 d6240a8a32bd363e75542e3e5896356e24d28e010f99e24edfff380b67afa050 and tree
 d09f9b9870f6b7b9c9eba9c6418178c775a54d43. It adds one small helper, a marker and
four complete before-bodies under previous-v1, changes controller/policy/program,
and recomputes the whole closed namespace. The inverse reconstructs every old62
byte/mode, map and Git tree. The signed349 package/source/license/dependency inputs,
normal build/check/comparator, XZ-only format and zero-APT policy are unchanged.
The6201B workflow is byte-identical; no Main workflow or manifest is edited.

```sh
python3 -I -B scripts/ci/llhttp-reference-native-source/successor_v2/prepare.py \
  --parent /absolute/retained-public-Source62 --output /absolute/fresh-Source68
python3 -I -B scripts/ci/llhttp-reference-native-source/successor_v2/prepare_caller.py \
  --parent /absolute/held-llhttp-canonical-ONCE-DRAFT \
  --source /absolute/fresh-Source68 --output /absolute/fresh-caller-DRAFT
```

The caller constructor verifies the exact held Source62 canonical programs and
new68 Source/inverse, then derives complete operator/primitive/issuer/joiner and
refusing templates. It updates only the new physical tuple/program/policy and
operation binding, leaves Source CID/ref/publication and Root roles NULL, refuses
Source62 replay and requires a new complete Root publication/readback. Same
workflow ID/path/body facts remain required with a freshly sealed registration
readback; its Main registration commit is an explicit Root-selected40-byte SHA,
not an automatically discovered selector. All runtime54, current Root-context,
exclusive HEAVY_NON_KERNEL custody, two-sweep global EMPTY, Main CAS, exact five
inputs, natural retirement, CLOSE_ONLY and one-POST/no-ambiguous-retry guards stay
held. Whole predecessor caller bodies are retained as inverse DATA. Constructors
perform no issuance or entry. Actual Root context/cache/retirement review, nonce,
output, runtime and any future role remain required; no label is reserved.

## Current verification

Eight source/VA controls and eleven canonical caller controls PASS with no skips
using actual retained parent/new Source DATA. The caller controls reach one
mocked POST boundary only, using modeled future publication/freshness and Root
custody/authority seams; no live transport or actual-run result exists. Both test
families fence process/network/lease actors. Missing external genuine-material
fixtures report explicit SKIP; no acquisition or constructor fallback occurs.

A separate actual local read-only /home/gabe/bin/docker --version probe reproduced
the same startup fatal at512MiB and passed at2GiB. It used a private empty HOME,
nonexistent daemon socket and finite AS/CPU/output/deadline caps. The binary is
x86_64, SHA e966e0e6ea215b74fdbee17fbe7ed8bff15b65930bfc8e131652ceae4ed0210e,
and prints Docker29.8.0. It differs from the failed ARM binary. This confirms the
VA mechanism locally, not native ARM startup, cgroup qualification or Docker actor
acceptance. local-startup.DATA.json retains the exact bounds/results.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-reference-native-source/successor_v2/test_data.py
python3 -I -B -Werror::ResourceWarning scripts/ci/llhttp-reference-native-source/successor_v2/test_caller_data.py
```

Source68 currently has980464B/treeff40c38eb5062ace3b46cb2f2c4c8c32fc010a00,
map14771B/SHA00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998,
policy1736B/SHA8e7c2e4359075d7b78763aeccf799ee663d39bb0ec96066e447dabec34c3ced1,
and program4244B/SHAfe6a77db55043037aba41c00ef87aad896402d313281637f38146be8e63abd12.
These are local construction pins, not a published CID, grant or native result.

For Fish/libgit2 reuse, go_cli_va.py exposes controller_limit(policy),
child_plan(argv, observed_tools, policy) and child_limits(plan); the declaration
is literal and two finite AS plans are the complete API. Adoption requires each
new Source's complete inverse, policy/program/map pins and separate Root review.
It is not a general executor or authority issuer.
