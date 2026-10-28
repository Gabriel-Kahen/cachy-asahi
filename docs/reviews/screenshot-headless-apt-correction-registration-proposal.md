# APT correction: two-replacement registration materializer

Status: **reviewed metadata tool proposal; no actual correction commit/peer plan materialized here**. This [new packet](../../artifacts/reviews/screenshot-headless-apt-correction-registration-proposal-20261014/) provides the narrow successor to the old seven-addition materializer. It performs no Git/worktree write, variable change, Source publication, dispatch, Docker build or screenshot actor. All previous seals remain immutable.

The source correction is still the separately reviewed [two-file APT proposal](screenshot-headless-apt-path-correction-proposal.md), receipt `ae4b0aebf723caa2bccd6499501f54075b4bb63d033935243aa567d3d067b5f1`. Root's separately assigned external Source peer is not replaced by this metadata review. Corrected image installation and real screenshot acceptance remain NOT RUN.

## Exact bounded contract

The [materializer](../../artifacts/reviews/screenshot-headless-apt-correction-registration-proposal-20261014/materialize_plan.py) requires Root's real committed correction SHA, actual external peer receipt file and its independently authenticated SHA256. It reads Git objects through bounded read-only commands with optional locks disabled. No Git branch is created or changed.

| Held boundary | Required identity/check |
| --- | --- |
| Immediate parent | Exactly one parent: `85a84f9ff5437e139a284c73d9c02767e14d474f` |
| Actual Source ref | `refs/heads/codex/screenshot-headless-software-v1`, already pointing locally to Root's supplied correction commit |
| Delta | Exactly two `M` paths, no renames, additions, deletions, extra changed paths or merge commit |
| Modified paths | `scripts/ci/screenshot-headless/Containerfile` and `scripts/ci/screenshot-headless/source.lock.json` |
| Base preimages | Exact reviewed bytes, sizes and Git modes from Source `85a84f9…`; original seven selected files and ten locked rows also checked against the base |
| Final selected closure | All seven originally selected paths checked, combining the two corrected postimages with the five held original files |
| Final locked Source | All ten rows, bytes/sizes/Git modes; the lock file itself separately authenticated |
| Corrected Source-lock SHA256 | `5d2c1b75fae1bb1b93a001ce92d5a9afd5bafb745460e8cdfb4374cdf846515c` |
| Runtime-lock SHA256 | `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05` |
| Base digest | `sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483` |
| External peer | Supplied file bytes must match Root's supplied full SHA256; nonempty JSON is syntax only, not review authority |

Before accessing proposal leaves, the tool authenticates original implementation receipt `218b34a2…`, correction receipt `ae4b0aeb…` and their exact indexes; every consumed leaf's size/hash is checked. It does not reuse or weaken the old materializer's exact-seven-additions requirement. It checks this specific two-replacement successor shape and refuses any different adoption. An extra documentation commit, changed parent or changed Source needs a separately reviewed tool/contract rather than a bypass.

The seven selected files include the Source lock. The ten Source-lock rows exclude that lock itself and include the existing helper plus license/notice holds; checking both roles yields eleven distinct selected/locked blobs. Runtime package membership stays the original 196 packages; this tool changes no package, runtime backend, containment, guard or cleanup behavior.

## Root-only actual-data use

The `make` subcommand requires `--repository`, `--source-commit`, `--peer-receipt`, `--peer-receipt-sha256` and `--output-directory`. Values must come from Root's actual committed correction and authenticated external Source review. This proposal supplies no example SHA, invented peer receipt, valid pending plan or new run ID.

Only after all checks pass does the CLI create a new 0700 output directory and three 0600 data files: compact `root-plan.literal.json` without a trailing newline, one-ref `dispatch.json` and `source-object-proof.json`. The eight plan keys remain unchanged. The proof binds base and actual Source/ref/peer, two modifications, seven selected files, ten locked rows, lock-self SHA256 and the literal's full hash/size. The output status explicitly leaves external peer semantics with Root. Retain/authenticate that proof before registration; a peer file and a hash alone cannot demonstrate that the review accepted this Source.

Root then writes the actual literal to `SCREENSHOT_HEADLESS_SOFTWARE_PLAN`, captures a fresh repository-variable GET response and invokes `verify-variable` with `--plan`, `--response` and `--proof`. The verifier checks the exact eight-key corrected plan, held lane/ref/Source-lock/runtime/base pins, correction-proof shape, literal hash/size and Source/ref/peer identities, then exact variable name/value bytes and one JSON decode. Wrapped JSON, extra newline, stale original Source/lock, altered digest or mismatched proof refuses. Root must already authenticate the supplied proof; locally editing both proof and literal does not create Source or review authority.

No variable write/readback is performed by this packet. Root keeps actual data and API responses in a new Root-owned registration evidence namespace rather than modifying any sealed proposal. After exact readback, Root publishes the exact committed correction SHA to the held ref and verifies its remote SHA, accounts for publication-triggered static jobs, and chooses one changed manual trial under its existing reservation. The workflow/default registration bytes are held; no default-branch change or new workflow registration is needed from this metadata tool.

## Verification and limits

The [independent peer review](../../artifacts/reviews/screenshot-headless-apt-correction-registration-proposal-20261014/peer-review/) exercises real materializer functions against inert Git-query response models and owned transient readback files. Positive models are unit data, not actual commits or registered plans. Refusal cases cover wrong parent/preimage, wrong modification shape, old seven-addition shape, extra path, changed selected/locked closure or mode, wrong lock/runtime/base/peer, and wrong plan/proof/readback. No Git executable, network mutation, package manager, Docker, compositor or helper is needed for those controls.

An actual corrected Source commit and external peer are still required before `make` can produce authoritative Root data. A successful future metadata join/readback is not an image-build or capture result. The unchanged runtime must still report all 196 installed package rows and pass the real capture/PNG/negative/cleanup gates. Image/cache/context retirement remains the prior held limitation; ARM archive, Hyprland and M2 acceptance remain outside this software trial.
