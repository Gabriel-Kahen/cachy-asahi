# Opt-in offline development build tools

This independent `0.1.0-1` development candidate packages the maintained local-cache importer and recipe/source preflight without requiring project checkout code at runtime. It is unselected for development/release inventories. It does not replace `cachy-asahi-source-tools` or any existing command.

The only runtime dependency is `python>=3.12`. `/usr/bin/cachy-asahi-build-tools` uses isolated Python and selects four commands. Six exact MIT project modules are installed under `/usr/lib/cachy-asahi-build-tools/trusted/scripts/`; their relative import layout is preserved. `source-provenance.json` records the exact project commit, file paths, lengths, hashes and installed paths. A data/recipe workspace is never a code root; there is no code-root option or environment override. Python network and process audit events are refused by this DATA-only launcher. This is a narrow command boundary, not a general sandbox or permission to run arbitrary code.

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

The package installs only its launcher, six trusted modules, this guide/provenance and MIT license/NOTICE. It has no install/remove hooks, services, global Python modules, configuration changes or automatic cache creation. Running the commands may explicitly create/populate the caller-selected private cache; uninstalling the package does not remove user caches. No package manager, Docker, extraction, signing, source execution or system mutation is exposed by the launcher.

Build/check without installing:

```sh
makepkg --nodeps --cleanbuild --noconfirm
```

`check()` runs seven packaging controls through the actual `package()` staging function and moved CLI. Its finite `check-inputs.tar.gz` contains one real retained zlib1.3.2 archive (1,502,830 bytes/SHA256`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`), its notice/catalog and pinned project baseline/LTO recipe DATA. None is imported or executed. Fixtures and tests are not installed. Controls cover import/verify/both preflights, missing/tampered data, preserved cache conflicts, hostile workspace/Python environment, inert recipe shell text, offline-only dispatch, exact installed files/modes and relocation. Dedicated hosted Python3.12/3.14 DATA CI maintains them.

Host package assembly and source controls are separate from native ARM build or ALPM installation/removal acceptance. Native ARM/16K/M2, performance, complete-source/legal clearance and release admission remain **NOT RUN / NOT ADMITTED**. This tool neither verifies publisher signatures nor grants native or hardware authority.
