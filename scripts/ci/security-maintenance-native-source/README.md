# Maintained Security native source factory

`prepare.py` reads one exact, externally supplied Source200 parent and emits a closed Root stage as DATA. It never runs the emitted producer, package recipes, native helpers, pacman, GPG, Docker, or the network. Source publication and native execution belong to Root.

The basis is genuine accepted development Source `b6a02f11648738ded90084f7dcdcd4ea77c194fa`, tree `23b818ecb00e942f38678c4aa8a2acae0cc74d4a`. Its accepted finite component covers a native current-package pair, TEST-signed installation/removal, installed/moved offline workflows and cleanup; its upgrade was not exercised. That acceptance does not extend to this new source.

The new protocol uses the unmodified retained `0.1.0-1` development recipe and the accepted `0.1.0-2` candidate. The prior is neither a published release nor a prior native-qualified baseline. Its original bundle/profile/adapter and complete recipe/payload pins are embedded in the existing contract. A third native BuildKit stage must rebuild its original checked recipe. The two current clean checked build stages remain required. The factory does not invent an old version or rebuild package bytes locally.

The native protocol is intended to exercise Required/Required TEST-signed prior installation, tampered-candidate refusal, operator-declined precommit upgrade, actual prior-to-current upgrade, same-version repeat/reinstall, held installed/moved workflows, removal and reinstall/removal. It verifies complete inventory, payload bytes/modes/owners, removal of the prior private prefix, preserved sentinel user state, scoped signing/trust cleanup and unchanged global trust/configuration. Precommit decline is not a midcommit signal/power-loss recovery test; repeat is an explicitly labelled same-version reinstall.

`overlay/` contains only the native protocol, strict passive reader and versioned contract. The current main producer `8e71ba83…` and matching strict observer `cdb50b75…` are authenticated replacements in `producer-overlay/`; no unqualified native retirement-v2 migration is included. The two workflow aliases receive only the scheduling change to `native-arm-security-maintenance`, cancellation disabled, `queue: max`. The common source verifier remains byte-identical: total Source200/map199, with no named-profile exception or default cap increase.

The fixed `profile.json` binds the full parent, original raw commit, overlays, modes, exact generated tree/map and NULL new actuals. `assemble()` authenticates everything before output, writes a private stage, verifies the full emitted tree and uses no-replace publication. Its output contains `source/`, source authorization/modes/blob IDs, the full change map/inverse, parent raw commit and passive-reader/dispatch templates. It does not write Git objects or refs.

```sh
python -I -B scripts/ci/security-maintenance-native-source/prepare.py \
  --parent /absolute/path/to/exact/published-v5-source \
  --output /absolute/path/to/owned-0700-directory/new-root-stage
python -I -B scripts/ci/security-maintenance-native-source/test_factory.py \
  --parent-source /absolute/path/to/exact/published-v5-source
```

The second command runs only focused actor/network-denied DATA factory and passive protocol controls, using temporary emission. It does not mock or execute pacman and does not replay accepted v5 suites. See `docs/workstreams/security-maintenance-native-source.md` for provenance, dependencies, proposed native commands, results and limits.
