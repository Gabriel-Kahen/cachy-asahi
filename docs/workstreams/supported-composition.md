# Supported Asahi candidate composition: actual retained DATA joins

November 14, 2026. New software connects current project SRCINFO plus real
candidate archives to the retained actual Asahi base/catalog inputs through the
existing private libalpm resolver. It is a DATA planning adapter, not a new solver,
a signed target transaction, installation, image assembly or hardware result.

Existing software already covered the historical 261-base/201-protected desktop
proposal and bound before/after transition planning. The concrete gap was adding
current project candidates with exact source/archive metadata correspondence and
explicit base-change/provider decisions. The frozen 21-root residual contract
and old desktop/platform defaults were not changed.

The [adapter contract](../../scripts/port/supported-composition/README.md)
describes inputs, holds, containment and the runnable interface. The source,
worker and focused tests are confined to `scripts/port/supported-composition/`.

## Retained inputs

Both demonstrations reuse the actual held image inventory and original tuple:

| Input | SHA-256 |
| --- | --- |
| 261-package image inventory | `5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941` |
| Original 201-package protected tuple report | `92c53bc28d5442ac1780c0b54094a3bd99eb5a3dd89d069e94da82a2e8fc0030` |
| Captured Asahi catalog | `bb500d9a8293142332189946b6fce5cf927ed677f73f749d35f4f3eff0a5d217` |
| Captured core catalog | `5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08` |
| Captured extra catalog | `66cfbeae024c325e19ba7334afcb0ff2ab892ba4f0789216b358648f7647b480` |
| Actual host FirstLogin0.1.0-2 archive | `d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839` |
| Actual host Setup8 archive | `175b11130bbe66f97cdef32c9e81aa5509390263dbd7c4d1470b9893946eb289` |

The two host-built `any` archives are unqualified candidate DATA, not native ARM
or signature/source acceptance. Their PKGINFO is actually inspected and matched
to the exact current SRCINFO references. No filename/hash placeholder is used.
The catalog snapshots remain October retained observations; this task performs
no refresh or acquisition and does not claim current mirror availability.

The local ignored `work/supported-composition-20261114/` directory retains both
input contracts, a derivation record linking the original 55-target report and
proposal, and the outputs. Commands actually executed against the finalized
adapter were:

```sh
python3 -B scripts/port/supported-composition/compose.py \
  --contract /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/minimal.json \
  --contract-sha256 e6ef19356ceb099e5cc584295be8d193af183b6cd9b4b3a5313e50e174db3581 \
  --output /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/minimal-final
python3 -B scripts/port/supported-composition/compose.py \
  --contract /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/full-held-desktop.json \
  --contract-sha256 af4622c393f1fb0ec8d3ba81b1ff3f9179e6033049c375e8d209f28a83b0fd45 \
  --output /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/full-held-desktop-final
```

Outputs are exclusive; use new output paths when repeating these commands.

## Actual results and next decisions

| Observation | Minimal current project join | Held full desktop + current project join |
| --- | ---: | ---: |
| Actual exit | 2: metadata PASS, authority HOLD | 1: metadata FAIL |
| Base → tentative final packages | 261 → 263 | 261 → 626 |
| Additions | 2 | 365 |
| Protected versions preserved | 201/201 | 201/201 |
| Explicit roots | 2 | 57 |
| Final dependency relations | 1025 | 3202 |
| Unapproved base changes | 0 | 2 |
| Named catalog exclusions/holds | 26 | 26 |
| Total custody/exclusion holds | 289 | 652 |

The minimal graph genuinely prepares FirstLogin0.1.0-2 and Setup8 against the
retained Asahi base without changing any baseline version. It is not a full
desktop or supported release; every selected package still has missing custody,
signature authentication, payload/source/license/hook/maintenance acceptance.

The full route keeps all original 55 target pins and four explicit providers,
then adds the two current project packages. Its available-target preparation has
return0/errno0, but the complete profile **fails** because:

- Python `3.14.8-1` is requested while original protected Python remains
  `3.14.7-1`; the target is excluded/refused and final Python stays `3.14.7-1`.
- NetworkManager `1.58.1-1 → 1.58.1-2` and Perl `5.42.2-2 → 5.42.3-1` are real
  proposed base changes without exact caller allowances.

A follow-up can supply a separately reviewed compatible root profile or a new
coordinated base/protected tuple with its consumer/recovery evidence. This tool
never drops Python's target or weakens the old protected list to obtain PASS.
The two unprotected transitions can be represented as exact caller DATA entries,
but doing so does not approve ABI/signature/source/recovery behavior. No proposed
allowances were silently added to either actual run.

The 26 exclusions remain named: 18 protected-version/mesa-dummy decisions, one
invalid package name, one sparse unavailable entry, one invalid version relation
and five descriptor-field limits. Filtered required roots remain unsatisfied;
none disappears into a successful complete transaction.

Final retained report identities:

```text
minimal-final/composition.json: 653709 bytes
SHA-256 22c2f514d2a58aec17ba2a120912fd155dd1fb1a0200da03d6e40fdbb3a9339a
full-held-desktop-final/composition.json: 1977646 bytes
SHA-256 dd1bdb3709dcd3e2b1fb0144caa75bac464a0f848f9b576bab20a26b9c5058c8
```

Private DBs were removed after both runs. Worker inputs/diagnostics and explicit
holds remain for review. No packet code, install scriptlet or hook was executed.

## Verification and limits

All 12 focused cases pass with real private libalpm and clearly labeled
synthetic metadata/archives: actual SRCINFO/PKGINFO correspondence, no fabricated
archive identity, missing archive, excluded selected root, protected Python,
exact unprotected changes, ambiguous/explicit providers, inert source strings,
input drift, full-system coverage refusal and simulated C-worker failure with
retained DATA/FAIL output. Source inspection initially found missing filenames
could cause a real libalpm C crash; complete input admission and child containment
address that path without altering the frozen engine or claiming an ABI defect.

Original static/project selections and platform/native modules remain unchanged.
Actual supported Asahi transaction execution, image authentication, corresponding
source/license grants, installed ownership/hook/ABI/16K behavior, production
signatures, maintained update/recovery and both M2 models remain open. Metadata
preparation and architecture declarations cannot satisfy those gates.
