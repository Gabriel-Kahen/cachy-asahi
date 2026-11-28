# Updater 4.4.2-3 qualification preflight

The candidate is based on Cachy-update
`e2b1b7144be71cf392809f48d1440f8da1d9c81a`. The Check command clears stale
Flatpak state when both user and default system discovery succeed with no
installed refs. Either discovery failure exits 20 and preserves existing Check
state. A nonempty result from either discovery still goes through the remote
update query. The two new empty-discovery regressions, one of which exercises
the upstream shell entry point, both reproduce stale state with the preceding
patch.

## Committed-source and native build-pair commands

Run these commands from the reviewed checkout. The package README, patched
source ledger, recipe checksums, materializer lock, reviewed source map and
workflow bootstrap are bound to each other. The preflight checks the selected
Git commit and its exact source closure without accessing Docker.

```bash
root=$(git rev-parse --show-toplevel)
commit=$(git -C "$root" rev-parse HEAD)
stage="$root/scripts/port/updater-native-stage/stage.py"
stage_sha=7da6bff04cbd5406272cb0bbeee95d50021c2fa1dfe7f255cb422f5038aeb16f
printf '%s  %s\n' "$stage_sha" "$stage" | sha256sum --check --status &&
  python3 -I -B "$stage" preflight \
    --root "$root" --source-commit "$commit" \
    --ready-sha256 e745cd8bfc44df327be5523718b53b33668b3497583fcba995cd31cb41ab34ef \
    --bootstrap-source-sha256 285983ec44ba40e130ba08d7238e4642cf98b4bfcfd2926ec32a4656ad76f7a2 \
    --bootstrap-stage-sha256 "$stage_sha"
```

The coordinator can dispatch against a published branch whose tip is exactly
`$commit`. The workflow independently checks the requested commit against its
own checkout and starts the native pair with the pinned 354-package build
inventory. Advance the native-build gate only after the two clean builds,
mandatory recipe checks, pair comparison and terminal cleanup evidence pass.

```bash
ref=${UPDATER_REVIEWED_REF:?Set to the published review branch}
test "$(git ls-remote https://github.com/Gabriel-Kahen/cachy-asahi.git \
  "refs/heads/$ref" | cut -f1)" = "$commit" &&
  gh workflow run native-arm-updater.yml \
    --repo Gabriel-Kahen/cachy-asahi --ref "$ref" -f "source_commit=$commit"
```

## Source and host results

On the x86_64 development host, the pinned materializer reproduced the
original, sanitized and vendor archive hashes from 167 locked registry
sources and the upstream source archive. Private recipe verification with
`makepkg --verifysource --ignorearch --nodeps` passed all 23 checksums.
`makepkg --nobuild --ignorearch --nodeps` extracted the inputs, ran both
zero-fuzz patches through `prepare()`, and produced a tree that matched
all 98 patched-source entries. The generated `.SRCINFO` matched the
committed file. The host ran 54 patched-behavior cases, 47 Apple-policy
cases and 216 native controller source controls. This evidence covers the
recipe inputs and preparation. Native `makepkg check()` is pending.

## Installed Check

The [installed Check harness](../../scripts/ci/updater-optional-check/README.md)
documents its source preflight and exact invocation within a future native job.
Its four source controls passed, including all eight optional-backend cases
against the patched upstream Check entry with inert command fixtures.
A future installed trial combines those cases with the seven historical signed
repository and refusal cases.

The pair workflow cleans up the private image and package as it exits. An
installed Check dispatch requires a reviewed same-job hook before that cleanup
and runner-readable authenticated inputs. All five runtime archive/signature
pairs and the ALARM keyring have local byte copies matching the historical
input lock. The [4.4.2-3 build-only run](updater-native-45699777848.md)
produced byte-identical native packages and verified cleanup. Signed
disposable installation, emulated and physical 16 KiB execution, the full
updater transaction and release acceptance are pending. The
[4.4.2-2 native results](updater-real-check-native-20261015.md) document the
historical package and its signed installation.
