# Development update fixtures

The generator derives four **DEVELOPMENT TEST ONLY** upgrade recipes from the
frozen original package inputs. It never runs a PKGBUILD, installs packages,
activates configuration, starts a session, or edits the source checkout.
These fixtures are not selected for release and provide no M2 evidence.

Owned implementation: `scripts/integration/fixtures.py` and
`scripts/integration/test_fixtures.py`. Existing recipes, canonical setup helper,
shared manifests, build tooling, and CI dispatch are unchanged by this workstream.
The roadmap and package inventory were reviewed before implementation.

## Frozen input and generated contract

- Original recipe lock: `scripts/ci/recipes.lock.json`.
- Required lock SHA256: `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.
- Supplied source commit: `ebd5812640b0b69f5c09a47752b739e37e338754`.
- Original setup helper SHA256: `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`.

The full commit is required and recorded as caller-supplied provenance. The
generator does not execute Git or attest that commit's tree; it independently
binds every recipe input byte to the reviewed lock. It rejects missing, extra,
stale, malformed, escaping, or symlinked inputs, inconsistent source checksums or
SRCINFO metadata, canonical helper/license drift, and non-upgrade versions.

Output must be a fresh directory outside the source repository, with an existing
real parent directory. All generated writes are confined to it. Default version
is one patch above the highest frozen version, with pkgrel 1. A custom numeric
major.minor.patch must exceed every baseline version. File bytes, modes, and
timestamps and directory modes/timestamps are deterministic; epoch defaults to 0.
No output metadata contains temporary paths or current timestamps.

| Package | Baseline | Upgrade | Observable installed change |
| --- | --- | --- | --- |
| cachy-asahi-hyprland-settings | 0.1.0-1 | 0.1.1-1 | Comment marker in `usr/share/cachy-asahi/hyprland/hyprland.lua` |
| cachy-asahi-fish-config | 0.1.0-1 | 0.1.1-1 | Comment marker in `usr/share/cachy-asahi/fish/config.fish` |
| cachy-asahi-zsh-config | 0.1.0-1 | 0.1.1-1 | Comment marker in `usr/share/cachy-asahi/zsh/config.zsh` |
| cachy-asahi-setup | 0.1.0-2 | 0.1.1-1 | Read-only `usr/bin/cachy-asahi-setup --integration-fixture-version` |

The three configuration markers are `DEVELOPMENT UPDATE FIXTURE <name> 0.1.1`.
The setup flag prints `cachy-asahi-setup 0.1.1 DEVELOPMENT-FIXTURE` and exits
without reading or writing user configuration. Package identities, ownership
paths, dependencies, licenses, hooks, and recipe function bodies are retained.
Upgrade PKGBUILD descriptions, notices, and review documentation are explicitly
labeled test only; original MIT attribution remains intact.

The baseline copies every frozen recipe input unchanged, including historical
evidence. Upgrade trees retain only build inputs and review documentation; they
do not reuse old validation receipts as evidence of fixture success. Both trees
contain matching canonical setup copies, project LICENSE, and a generated
DEVELOPMENT AGENTS marker so the original prepare-time sync guard remains active.

The derived setup recipe includes the unmodified helper as `base-setup.py`.
Its provenance records both the original a625 helper and checker hashes, original
commit and lock pins, and the derived helper hash. The derived checker adds an
origin declaration/hash guard and retains every original canonical path,
helper/license hash, and repository escape check. Existing synchronization
regressions are adapted to supply the original helper. The source recipe and
canonical helper are not modified to accommodate the fixture.

`fixture-manifest.json` contains per-package baseline/fixture input SHA256 maps,
PKGBUILD and unified-diff hashes, recipe/reviewed-input paths, installed payload
hashes and markers, read-only CLI expectations, and rollback expectations.
`baseline-recipes.lock.json` and `upgrade-recipes.lock.json` cover all recipe
files. `reviewed-inputs/{baseline,upgrade}/<name>.json` are the plain digest
objects consumed by `scripts/build/build.py --reviewed-inputs`.
`frozen-base.lock.json` preserves the supplied lock bytes. Diffs are under
`diffs/<name>.diff`; they include added origin input and derived guard changes.

## Reproduction and isolated build handoff

Generate into a new output path; its parent must already exist:

```sh
python -B scripts/integration/fixtures.py \
  --repo /home/gabe/Documents/ChatGPT/cachy-asahi \
  --lock /home/gabe/Documents/ChatGPT/cachy-asahi/scripts/ci/recipes.lock.json \
  --lock-sha256 20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63 \
  --source-commit ebd5812640b0b69f5c09a47752b739e37e338754 \
  --output /tmp/new-development-fixtures \
  --source-date-epoch 0
```

For each package in each phase, the existing isolated builder takes the generated
recipe directory plus its matching `reviewed-inputs` JSON. Supply the reviewed
pinned linux/arm64 image, image package lock, native/emulated mode corresponding
to the Docker server, epoch, and a fresh evidence output. The builder verifies
the complete input digest set, generates metadata in the container, compares it
to reviewed SRCINFO, and inspects the resulting archive. Do not run makepkg or
source PKGBUILD on the host. Static SRCINFO rendering is verified here; actual
isolated makepkg metadata/build comparison remains the CI owner's gate.

The integration controller must retain the baseline archives before upgrading.
After real package upgrade, verify installed versions and fixture payload hashes
and the setup flag. Rollback must reinstall those retained exact baseline
archives, then verify each baseline version and original payload hash recorded
in `rollback_expectation`. Recipe generation alone does not exercise pacman,
archive reproducibility, signed repository delivery, or rollback.

## Actual local results

Final generated pair:
`/tmp/cachy-asahi-update-fixtures-reviewed-08isu19j/{first,second}`.
Receipt: `/tmp/cachy-asahi-update-fixtures-reviewed-08isu19j/validation.json`.
Temporary output is inspectable now; regeneration is the durable reproduction
path. No generated recipes or receipts were added to the source inventory.

| Recorded input/output | SHA256 |
| --- | --- |
| Generator | `0042c17f99e5ff2d3af02ba343786c860d2a9c4c698dd67da2862cc203a60824` |
| Fixture manifest | `4439d90dfd43e8b6ae540f87a07c987f4ba2fbf64fd67d4872c89b9cbb41ca39` |
| Baseline lock | `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63` |
| Upgrade lock | `d52d1abfa58315e954aa5f53e9973911f32bf79d096391ce15515fb92c63d039` |

- `python -B -m unittest discover -s scripts/integration -p test_fixtures.py`: **15 PASS**.
- Two CLI generations: identical bytes/modes/mtimes across entire output trees.
- Existing static package checker: **8 PASS**, each input map exactly equal to
  its generated reviewed-input JSON; all eight PKGBUILDs pass `bash -n`.
- Original and derived setup checkers: **PASS**; both sync suites: **9 PASS** each.
- Upgrade Fish, Zsh, and Lua payload syntax: **PASS**.
- Read-only setup fixture flag: expected output, zero entries created in isolated HOME.
- Frozen source lock and all four original recipe trees: unchanged after generation/checks.
- Independent review found unquoted shell syntax could be mistaken for literal
  metadata; quote-aware validation now rejects it. No recipe was executed in the
  reproduction. Quoted punctuation remains valid.

**Fixture native builds, archive generation, actual package upgrade/rollback,
target installation, exact-model M2 checks, and performance measurements: NOT RUN.**
The original inventory's prior native-build evidence is not fixture evidence.
