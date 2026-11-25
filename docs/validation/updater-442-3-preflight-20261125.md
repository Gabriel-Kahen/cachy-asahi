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

The pair workflow's scope ends with build and comparison. Its cleanup removes
the private archives. Installed Check needs a same-job disposable runtime
that consumes the verified package before cleanup and installs all runtime
dependencies without waivers. The historical 4.4.2-2 result, documented in
[the October 15 validation record](updater-real-check-native-20261015.md), is
version-specific. The 4.4.2-3 build pair, signed disposable installation,
emulated and physical 16 KiB execution, full updater transaction and release
acceptance are pending.
