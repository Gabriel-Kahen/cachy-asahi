# Native image-build namespace observations, 2026-11-15

The matching Reader returned
`VALIDATED_NATIVE_BUILD_NAMESPACE_PREFLIGHT_DIAGNOSTIC_ONLY` for Source
`3937d8b9f3210f4e9868bf19f01dfa22de64ddfe`. Both actual requests were **DENIED**,
exit1, with no inside frame. Namespace errno, effective policy and denial cause
remain **UNKNOWN**. This is a completed diagnostic observation, not namespace
support, Doc315, package qualification, native16K, Apple/M2 or release acceptance.

[GitHub run43679486072](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/43679486072),
attempt1, workflow381664314, job132706782224 (`native`) succeeded. A successful
workflow means the bounded diagnostic and retention route completed; it does not
turn either denied namespace request into a supported result. The actual roles
were Native POST1, Original artifact-body GET1 and matching Reader1. No retry or
reentry is authorized by this document. The earlier failed trials, including
Source69455's incorrect UID1000 expectation, remain closed and unchanged; see
[the original-account correction](native-namespace-original-account-20261114.md).

## Bound source and retained transport

| Binding | Exact value |
| --- | --- |
| Source ref | `refs/heads/codex/native-build-namespace-alarm1001-v1-20261114` |
| Git tree | `f1757dbedeed1591cdb8538f6c91e493cd451966` |
| Source map |39985bytes, SHA256 `0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e` |
| Matching `native/build_tools_reader_v2.py` |106215bytes, SHA256 `58b258fde9c49aca7f8d4e8b7e61358f175da8650547df64dc96891c2e33b5cf` |
| Artifact |14148200639, `native-developer-workflows-43679486072-1` |
| Original ZIP |718589bytes, SHA256 `f3c1690dc85f2604ef4e1374ef4915d90f6917c6e8bb72cdf1d6248f67d839a7` |
| Sole ZIP member `public-tree.tar` |7618560bytes, SHA256 `356938ec13817c29a439c3aa6adc12b0daa5a0a1b653044f6a4ab2d5a6d86e49` |

The full200 source/tree/map/Reader and factory joins are retained locally under
`/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-original-alarm1001-once-r1/`.
The packet's seal is
`6cc3c96c35bda306db36f5e2a2e582f714bd20e9811af1db267793b2c5af3931`.
Its preparation templates contain historical pending fields; actual execution
receipts below establish the completed roles.

## Actual context and commands

Both pre-exec observations prove the original **alarm UID/EUID/GID/EGID1001**,
complete groups `[998,1001]`, aarch64, page size4096 and cwd `/tmp`, within the
held349-package image-build context. No account normalization or UID range was
introduced. These are outer observations; no inside identity, mapping or changed
namespace was observed.

The two fixed requests, under the unchanged supervised wrapper, were:

```text
/usr/bin/bwrap --die-with-parent --unshare-net --ro-bind / / --proc /proc --dev /dev --tmpfs /home --tmpfs /var/lib/pacman --chdir /tmp -- <inner>
/usr/bin/unshare --user --map-root-user -- <inner>
```

`<inner>` denotes the exact held `/usr/bin/python3 -I -B` invocation of
`/opt/native-native-build-namespace-preflight-v1/source/native/build_tools_tools_v2.py`,
with `--inner --case` set to the corresponding case, `--map-sha256` set to the map
above and `--token 96d826a4c6757be406d596fd`. These are retrospective records,
not instructions to replay closed roles. Each command had a20-second cap;
the diagnostic total cap was60seconds.

| Case | Actual outcome | Exit | Inside frame | Errno / policy cause |
| --- | --- | ---: | --- | --- |
| `bwrap-user-mount-net` | DENIED |1| absent | UNKNOWN / UNKNOWN |
| `unshare-mapped-root` | DENIED |1| absent | UNKNOWN / UNKNOWN |

The Reader classified each as
`TOOL_REPORTED_NAMESPACE_DENIAL_NO_CAUSE_OR_ERRNO`. It validated both natural
retirements: reaped ownership, complete output, `EMPTY_TWICE` group census,
no timeout, no signals and no supervision error. A nonzero denied result was
retained rather than silently skipped or forced into success.

The actual tools-image build actor used ordinary Docker build with
`--network=none --pull=false --no-cache --platform=linux/arm64` and the original
`RUN USER alarm` route. Its unquiet log is3347bytes, SHA256
`1f1b142bb83a93720e23fcb6abe3c7366470cb156d4bf21c8bff0a59efa6d007`.
The launcher receipt does not declare a builder or security options; effective
seccomp rules, matched LSM denial, daemon policy, context provenance and bwrap
exec-boundary cause remain UNKNOWN. Observed outer Seccomp2 does not identify
which policy caused the denials. No policy waiver or relaxation follows.

## Matching Reader and local proof

Root used fresh R7 custody and separate actual Reader authority:
`/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-namespace3937-reader-authority.ACTUAL-r2.json`,
1378bytes, SHA256
`105e6f3c85a86d157f217539cd3b8ed6c330eccced6dcde52618681895ab07a6`.
The actual once-intent records Reader budget1 and no Native POST or Original GET.
The completed passive Reader reports one Reader call, zero actor calls, zero
network GETs and zero Source/artifact actor imports. Its own wrapper exited0,
reaped naturally without forced retirement or timeout, and proved group absence.
Same-FD/PIDFD/independent nonblocking conflict and CLOSE_ONLY lease custody were
retained. Acceptance remains false; `Root_acceptance` remains null.

The local proof files are:

- Native dispatch: `/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-original-alarm1001-once-r1/receipts/execution-result.json`
  —1677bytes, SHA256 `f1b8ac2417a24b3824591c82856a16e5408d8f4a2cefaf4269b10961583a4072`.
- Original body intake: `/home/gabe/Documents/ChatGPT/cachy-asahi-native-lock-runtime54-20261114/work/namespace3937-artifact14148200639-body-r1/Root-body-once/body-qualified.json`
  —1652bytes, SHA256 `a3a040c014b3c4923a647dd7aaf85394d65c65d1507a4799ccb41bbff65e991c`.
- Reader result: `/home/gabe/Documents/ChatGPT/cachy-asahi-native-lock-runtime54-20261114/work/namespace3937-reader-r2/Root-reader-once/decode-result.json`
  —10858bytes, SHA256 `eeefd2e3e278a2481b47aa7d066307db2ab927aec8da989bc9570c2a556c11b5`.
- Reader execution: `/home/gabe/Documents/ChatGPT/cachy-asahi-native-lock-runtime54-20261114/work/namespace3937-reader-r2/Root-reader-once/execution-result.json`
  —1203bytes, SHA256 `ee642424ea331a3e7d379d2ad8cbaf7323a9fcf4f8aefbeab37d1fad647ccc6d`.
- Reader worker retirement: `/home/gabe/Documents/ChatGPT/cachy-asahi-native-lock-runtime54-20261114/work/namespace3937-reader-r2/Root-reader-once/worker-status.json`
  —217bytes, SHA256 `2711e71304e1486793d41fa7ba0101024924e6de32010531569b63d8b4542bfa`.

These paths describe local retention, not a published durable evidence archive.
The public run link alone is not a promise of indefinite artifact availability.
No raw payload is copied or evidence published by this documentation change.

## Consequence for ordinary Perl v2

The separate `perl5423-native-pair-v2` adapter uses ordinary configured makepkg:
Configure, `make -j2`, unfiltered `TEST_JOBS=2 make test_harness`, configuration
checks and staged installation. Its source audit found no selected operation
requiring nested bwrap/unshare. The optional standalone staged-command test that
uses bwrap is outside PKGBUILD source[] and the selected phases. The adapter marks
nested invocation `NOT_INVOKED` and nested qualification `NOT_QUALIFIED`.

That explicitly narrower contract does not claim these nested effects work and
does not weaken the existing container policy. Exact Source/daemon/signed349,
UID1001, cap0/NNP/read-only/network-none resources, actual entry/init/runtime proof,
unfiltered checks, independent Reader and retirement gates remain mandatory.
This diagnostic grants no Perl build, package, installation or ABI credit.
Doc315 remains NOT_ESTABLISHED; native16K, physical M2 and release remain open.
This docs-only pass read retained DATA and source text; it ran no Source, Reader,
namespace command, package workload or implementation test.
