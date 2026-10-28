# Upstream routing and duplicate check

The October 11, 2026 research below used read-only primary GitHub REST/API and repository/release pages and submitted no external message. Its exact query URLs, totals, states and response hashes remain in [history-observation.json](history-observation.json). The coordinator subsequently submitted a separate [kernel checksum fix](linux-asahi-config-checksums.md), draft PR #99, on October 12. The Hyprland drafts below remain unposted. Historical observations can change; refresh them before a new submission.

## Existing actionable work

[PKGBUILDS PR #1972 — Remove stale vapormark and legacy desktop settings](https://github.com/CachyOS/CachyOS-PKGBUILDS/pull/1972) is **OPEN, NOT MERGED** at the checked head `185c9cd1f6d50291f513312224b881a60ddf526b` (`merged_at: null`). Its file list removes `cachyos-hyprland-settings/PKGBUILD`, `.SRCINFO` and `.nvchecker.toml`. The source package repository remains active; [the settings asset repository](https://github.com/CachyOS/cachyos-hyprland-settings) is archived/read-only. Existing removal work is the right routing context for this task's reproduced parser failures.

**Recommendation:** hold the standalone issue draft. After coordinator review and submission authorization, prefer supplying concise new reproduction evidence to #1972 if it would aid the ongoing review. If it has merged, record the merged result and determine whether there is any remaining useful report; do not create a duplicate just to count an A10 submission. An open API PR can have a non-null test `merge_commit_sha`; `merged_at`, not that field alone, determines whether it actually merged.

## Related records checked

| Primary upstream record | Observed status | Relevance |
| --- | --- | --- |
| [Settings PR #26 — rename windowrulev2 → windowrule](https://github.com/CachyOS/cachyos-hyprland-settings/pull/26) | MERGED March 23, 2025; merge `c4efec1b81468dd9571675c2070183c78f51cc75` | Earlier 0.48 syntax migration; not a fix for the reproduced later rule/API errors |
| [Settings PR #32 — Hyprland dots updated](https://github.com/CachyOS/cachyos-hyprland-settings/pull/32) | OPEN, `merged_at: null` | Broader proposed dotfile/theme changes; no tested 0.56.2 result established by this task |
| [Settings issue #44 — Gestures don't work](https://github.com/CachyOS/cachyos-hyprland-settings/issues/44) | OPEN | Related user-visible configuration problem, not the five-line verifier reduction |
| [PKGBUILDS issue #634 — dependency question](https://github.com/CachyOS/CachyOS-PKGBUILDS/issues/634) | CLOSED May 15, 2025 | Dependency history, not later parser compatibility |
| [PKGBUILDS issue #860 — new version 1.4.4](https://github.com/CachyOS/CachyOS-PKGBUILDS/issues/860) | CLOSED September 18, 2025 | Tracks tag update; does not certify a later compositor |
| [PKGBUILDS PR #684 — cachyos hyprland changes](https://github.com/CachyOS/CachyOS-PKGBUILDS/pull/684) | CLOSED, NOT MERGED (`merged_at: null`) | Older package proposal; no accepted later compatibility fix inferred |

The pinned recipe still uses settings 1.4.4 with an unbounded `hyprland` dependency. [Pinned recipe](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-hyprland-settings/PKGBUILD)

The [asset tags](https://github.com/CachyOS/cachyos-hyprland-settings/tags) include 1.4.4 at `449635e3718f4f178503682b29b159b0a758e5e7`; [GitHub release objects](https://github.com/CachyOS/cachyos-hyprland-settings/releases) list 1.4.1 and 1.4.0. Do not mistake a sparse release-object list for absence of the recipe's tag.

Hyprland [v0.55.0 release notes](https://github.com/hyprwm/Hyprland/releases/tag/v0.55.0) explicitly remove `dwindle:pseudotile`. The [v0.56.2 release](https://github.com/hyprwm/Hyprland/releases/tag/v0.56.2) and its pinned Lua example supply the parser/API reference used in the draft. That documented removal makes the finding a stale profile compatibility issue; there is no evidence here of a new accidental Hyprland regression.

## Search coverage and limits

GitHub search was scoped to the two CachyOS repositories and included open/closed issues and PRs. The small asset tracker returned all 16 issues and all 30 PRs in single `per_page=100` responses; every response reported `incomplete_results: false`. Keyword searches for `lua`, `0.56`, `pseudotile` and `togglesplit` in that tracker each returned zero. The active PKGBUILDS query `hyprland settings` returned eight records, including the relevant #1972; `hyprland lua` and `hyprland 0.56` returned zero.

These scoped queries and inspected related bodies did not find a dedicated report with this exact five-line 0.56.2 reproduction. They **did** find an existing disposition for the same package. Search-index absence is not proof that a report never exists. Forums, private reports, unindexed text, renamed terms, and new activity remain outside this bounded check. No global claim that upstream is unaware of the incompatibility is made.

An initial unauthenticated REST search hit HTTP 403 rate limiting before its record could be written. The subsequent read-only `gh api` batch completed all recorded queries with no failures. `history-observation.json` contains the completed batch rather than a partial result labeled complete. Public response hashes identify the observations; raw full bodies were not redistributed as project material.

## Reviewable return and remaining gates

[The detailed report](hyprland-config-draft.md) has pinned recipe/assets/API inputs, verified archive checksums, a no-import minimal reproduction, full-tree import rewrite disclosure, actual parser diagnostics and a narrowly verified correction illustration. [The short existing-PR evidence draft](pr-1972-evidence-draft.md) is a separate reviewable option; no posting command is supplied or executed.

Discovering an existing PR, writing a draft and running x86 parsing checks do not establish an upstream return. The separate kernel correction now has an actual submitted URL/date/content; its OPEN/DRAFT status is distinct from merge and project acceptance. Actual native hosted-ARM component execution is documented separately in [ARM reuse](../arm-reuse.md); physical-board and full-port acceptance remain separate.
