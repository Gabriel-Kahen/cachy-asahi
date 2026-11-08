# Opt-in offline development build tools

This independent `0.2.0-1` development candidate packages the maintained local-cache importer and recipe/source preflight without requiring project checkout code at runtime. It is unselected for development/release inventories. It does not replace `cachy-asahi-source-tools` or any existing command.

The only runtime dependency is `python>=3.12`. `/usr/bin/cachy-asahi-build-tools` uses isolated Python and selects six commands. The six frozen0.1.1 MIT modules plus the exact PR394 literal metadata checker are installed under `/usr/lib/cachy-asahi-build-tools/trusted/scripts/`; their relative import layout is preserved. `source-provenance.json` records the exact project commit, file paths, lengths, hashes and installed paths. A data/recipe workspace is never a code root; there is no code-root option or environment override. Python network and process audit events are refused by this DATA-only launcher. This is a narrow command boundary, not a general sandbox or permission to run arbitrary code.

```sh
cachy-asahi-build-tools cache-init --cache /absolute/private/source-cache
cachy-asahi-build-tools import-local \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 INDEPENDENTLY_REVIEWED_CATALOG_SHA256 \
  --id EXACT_MATERIAL_ID --local-archive /absolute/retained/upstream.tar.gz
cachy-asahi-build-tools cache-verify \
  --cache /absolute/private/source-cache \
  --inputs /absolute/reviewed/source-inputs.json \
  --inputs-sha256 INDEPENDENTLY_REVIEWED_CATALOG_SHA256 --id EXACT_MATERIAL_ID
cachy-asahi-build-tools recipe-check /absolute/reviewed/recipe/PKGBUILD
cachy-asahi-build-tools source-preflight \
  --recipe /absolute/reviewed/recipe \
  --source-plan /absolute/reviewed/source-plan.json \
  --source-plan-sha256 INDEPENDENTLY_REVIEWED_PLAN_SHA256 \
  --source-catalog /absolute/reviewed/source-inputs.json \
  --source-cache /absolute/private/source-cache
```

Use the installed launcher directly, or `python3 -I` on it. It refuses non-isolated Python invocation. The executable's own prefix locates its adjacent trusted modules, so a staged package may be moved as one tree for testing. Moving only the launcher is unsupported. Input paths identify DATA only. Preserve reviewed catalog/plan hashes independently; computing them from unknown inputs does not establish review, authenticity or trust.

Local import preserves the existing streamed hash/size checks, private no-clobber cache, held-file/path identity, deterministic generic and local-origin receipts. It accepts one owned ordinary0600/0644 single-link local source. Default import cap64MiB, explicit maximum512MiB; timeout120seconds by default, maximum600. Cached data is still checked against the caller's local file. It makes no HTTP claim and has no network fallback. A late failure may retain already validated cache objects or receipts; preserve and verify them.

Source preflight reads literal recipe metadata and validates its complete input map against the pinned source plan, ordered remote source coverage, catalog/URL/revision/hash binding, notices, private objects and receipts. It creates no locks, objects, receipts or staged source tree; ordinary access-time changes may occur. CLI wall-clock limit120seconds; existing alarm refusal and validator limits remain: 128 source bindings, 4MiB JSON, 512MiB/material, 2GiB selected material total. The original recipe validator's traversal behavior is unchanged. A later build must verify its inputs again.

The package installs only its launcher, seven trusted modules, this guide/provenance and MIT license/NOTICE. It has no install/remove hooks, services, global Python modules, configuration changes or automatic cache creation. Running the commands may explicitly create/populate the caller-selected private cache; uninstalling the package does not remove user caches. No package manager, Docker, extraction, signing, source execution or system mutation is exposed by the launcher.

Build/check without installing:

```sh
makepkg --nodeps --cleanbuild --noconfirm
```

`check()` runs eleven packaging controls through the actual `package()` staging function and moved CLI. Its finite `check-inputs.tar.gz` contains one real retained zlib1.3.2 archive (1,502,830 bytes/SHA256`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`), its notice/catalog and pinned project baseline/LTO recipe DATA. None is imported or executed. Fixtures and tests are not installed. Controls cover import/verify/both preflights, missing/tampered data, preserved cache conflicts, hostile workspace/Python environment, inert recipe shell text, offline-only dispatch, exact installed files/modes, relocation and versioned-dependency recipe/preflight use without .SRCINFO. Dedicated hosted Python3.12/3.14 DATA CI maintains them. The test interpreter invokes moved CLI calls using its own sys.executable; two explicit launcher calls exercise the fixed /usr/bin/python3 shebang separately. A selected Python3.12 CI job does not make that system shebang Python3.12.

Host package assembly and source controls are separate from native ARM build or ALPM installation/removal acceptance. Native ARM/16K/M2, performance, complete-source/legal clearance and release admission remain **NOT RUN / NOT ADMITTED**. This tool neither verifies publisher signatures nor grants native or hardware authority.

The 0.1.1 private checker accepts the standard quoted literal dependency comparisons (`>=`, `<=`, `=`, `>`, `<`; provides only `=`), numeric epochs and package releases without shell evaluation. `recipe-check` inspects one PKGBUILD and records complete input hashes, using `.SRCINFO` if present. The versioned owner is `scripts/checks/package_checks_v2.py`; the old central checker and SourceTools private runtime remain unchanged. Only the literal parser and single-recipe CLI dispatcher differ from the pinned checker basis; protected-platform, source integrity and archive checks remain held. Unquoted operators, command substitutions, redirections, compound words and nonliteral assignment tails refuse. This is static inspection, not dependency solving, version ordering or a Bash sandbox.

## Explicit literal metadata consistency

The new command is opt-in; `recipe-check` and `source-preflight` retain their existing routing, limits and `.SRCINFO` behavior. This same-name0.2.0 candidate is a separate recipe variant, not a second concurrently installable package. A package manager upgrade would replace0.1.1 files; no installation, upgrade or removal transaction has been tested here.

```sh
cachy-asahi-build-tools recipe-consistency /absolute/reviewed/recipe/PKGBUILD
cachy-asahi-build-tools recipe-consistency /absolute/reviewed/recipe/PKGBUILD \
  --srcinfo /absolute/independently-retained/.SRCINFO
```

The adjacent installed checker is byte-identical to PR394's `scripts/checks/recipe_metadata_consistency.py`, with source and merged-commit pins recorded in provenance. Both files must be ordinary canonical single-link inputs, each at most1MiB. It never executes PKGBUILD, regenerates metadata, invokes a shell/makepkg, fetches sources or changes user data.

Exit0/`MATCH_MODELED_LITERAL_DECLARATIONS` means only the modeled declarations agree. Exit1/`MISMATCH` reports stale name/version/release/epoch/architecture, dependencies or ordered source/checksum declarations. Exit2/`UNSUPPORTED` refuses dynamic shell, split packages or unsupported syntax; `INPUT_ERROR` identifies missing, aliased, unstable, nonordinary, oversized or invalid-text input. Neither exit2 status is a match. Common indented prepare/build/check/package stage bodies are opaque and unexecuted. Unmodeled fields, including licenses, options, install hooks and PGP keys, are explicitly ignored and receive no trust credit. Matching declarations are not recipe safety, dependency resolution, executed metadata, source authenticity, legal clearance or build acceptance.

The six frozen0.1.1 modules and launcher actor-denial function remain byte/AST held respectively. The only launcher change is this sixth dispatch. Installed moved-prefix controls compare matching declarations, stale metadata, unsupported command substitutions, missing input, poisoned workspace modules/Python environment and unexecuted stage bodies; retained real zlib cache import, verify and both offline preflights remain covered. Test inputs, tests and fixture archive are not installed.
