# Fixed Core796 lifecycle source factory

This dedicated factory reproduces two fixed public **796-file source** views from
the complete **745-file parent** `d26819ea8c7dab41f498377e8433422c81a7256c`.
The explicit `--mode original796` preserves `7be4694ffaef6937bef7569ae7fcf45bf097c32d`
for historical byte fidelity; its dispatch was rejected with HTTP422 before any
run because `runner.temp` was unavailable in job-level environment expressions.
**Do not dispatch that historical view.** The default `workflow-launch` mode emits
the corrected public `4ae7b957288025f5ecf92222401e7698f04fcd92`, with its owned parent
as a `github.workspace` sibling outside all closed source/carrier directories. It does not fetch inputs, launch actors,
sign packages, install software or grant native lifecycle acceptance. Existing
GNU and Core build/default factories are independent and remain unchanged.

```sh
python3 -I -B scripts/ci/core-native-lifecycle-source/prepare.py \
  --runtime /absolute/path/to/d268745 --output /fresh/disjoint/Core796 \
  --mode workflow-launch
```

`profile.json` pins every parent file, all 49 readable `payload/` files and every
expected output file for both views, plus the exact one-literal launch template
inverse. The wrapper checks parent and payload before creating an
output, delegates to the byte-unchanged source-contained emitter, compares all
796 hashes for the selected fixed view and runs the actual emitted source-only entry. Sibling imports
are explicitly bound to each payload/output context and then restored. A checkout's
top-level `.git` metadata is excluded only when reading the supplied parent or
expected CI fixture. Payload aliases, extra files, source drift and reused or
overlapping outputs are refused.

The 49 payload files are the frozen lifecycle implementation, public key inputs,
fixed profiles and unchanged retained-input helpers; package/cache archives are
external pinned inputs rather than part of this maintained factory. Emission
preserves 744 parent files, changes the registered workflow alias, and adds the
49 payload files, generated manifest and dedicated workflow. The output's own
`prepare.py` reproduces that same selected view from the same parent. Launch mode
uses a private temporary copy of the exact payload with only the fixed workflow
template changed; the 49 maintained payload files stay byte-unchanged.

The source retains all seven accepted native Core archives as a build prerequisite,
the original 574-package producer, fixed 13-package support closure, original
32/20/8 CLI/index/seed gates and complete retained-input cache proofs. Current
signature checks, ephemeral TEST signer separation, complete graph/capability/
hardlink/configuration checks, both copied-root cases, install/reinstall/rollback/
repeat transactions, foreground readbacks and ordered actor/root/profile cleanup
remain in the emitted source. All clocks and old target261 provenance remain held.
The historical 795-file source was held undispatched because its signer import
was outside the source closure. Both factory modes include that signer correction; only `workflow-launch` also
contains the supported job-environment fix. A source map or local check does not
establish that GitHub created a run or that the native lifecycle passed.

The TEST signer is the complete original `sign()` function, with its fixed original
function/module provenance recorded in the profile. Its portable control executes
that entire body with **only its GPG subprocess boundary inert**: private home,
generation/list/export and all seven detach-sign calls, original flags and 30-second
limits. Its returned fixture fingerprint/public bytes are not cryptographic evidence.

## Source-only checks

```sh
python3 -I -B -Werror scripts/ci/core-native-lifecycle-source/test_factory.py
CORE_LIFECYCLE_RUNTIME=/absolute/path/to/d268745 \
CORE_LIFECYCLE_EXPECTED=/absolute/path/to/7be796 \
CORE_LIFECYCLE_LAUNCH_EXPECTED=/absolute/path/to/4ae796 \
  python3 -I -B -Werror scripts/ci/core-native-lifecycle-source/test_emitter.py
```

All three fixture paths are mandatory; missing fixtures fail rather than skip tests.
The integration control compares all output bytes with the separately supplied
public796 checkouts for both modes, checks source-contained self-emission, restores a deliberately
foreign module binding, exercises real isolated CLI help and source-only entry
paths, and runs the six existing portable lifecycle contract controls. These checks
use private temporary outputs and no GPG, Git, Docker, native actors or network.

The path-scoped `core-native-lifecycle-source.yml` workflow has read-only contents
permission and pinned checkout/setup actions, checks out only the exact parent and both
expected sources, and runs these checks on Python 3.12 and 3.14. It has no signing
secrets or native dispatcher. Source CI success is separate from the native trial,
independent original evidence replay and Root acceptance. Automatic hooks remain
disabled by the original copied-root boundary; full systemd scriptlets are explicit
separate operations. Asahi boot, physical M2, performance, release admission and
replacement of old target261 are not established here.
