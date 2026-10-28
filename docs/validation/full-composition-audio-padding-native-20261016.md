# Current audio packages: signed installation, removal and cache preservation

[Actual38857117019](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38857117019)
passes the complete generic offline lifecycle:587→593→592→587 packages. Source
is `e6654a439d7aa62149ae448aa7fa28488dd09d89`, workflow
`e368f6d68eb792e535a55432903baf4cd6876d27`, comparator
`3e9b0f0f153a1fade1ff98606dafd93a654730eea0a8e44464415112922fc552`.
Root joins the result to the coordinator, all four checkpoints and cleanup,
and independently replays the retained B0/B1 raw-cache comparison.

The six additions are asahi-audio4.1-2, alsa-ucm-conf-asahi10-2,
speakersafetyd2.0.1-3, bankstown1.1.0-4, triforce-lv2 0.3.2-3 and the official
LSP LV2 package1.2.35-1. Five signatures are TEST signatures; LSP retains its
pinned ALARM signature. The separately built headless LSP candidate is not
installed by this trial. Scriptlets are disabled and hooks are masked.

After the six-package install, dependency checks have no waivers, and all
selected payload hashes, modes and ownership pass. Removing asahi-audio gives
exact592; removing the other five gives the original587. Final dependencies,
original database records, removed-payload absence, pre-existing directory
metadata and all original project payload checks pass. The restored inventory
hash is `c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463`.

All four cache checkpoints preserve the original helper, configs, aliases,
library scan, explicit targets, ordered mappings, generator and cache metadata.
The main-cache hash is unchanged across all four. Each auxiliary transition
has995 unchanged named associations,1021 source-selected hash buckets, and the
exact expected initialized record/string bytes and order. Four alignment bytes
per record are reported separately:3854 padding bytes change at B1 and185 each
at B2/B3. Their before/after hashes and slot counts remain in the result.

This replaces the earlier overly strict padding equality assumption using the
pinned producer/consumer and AArch64 record layout. It does not normalize or
rewrite caches, rekey libraries or add regeneration calls. B2/B3 raw bytes were
not exported; their acceptance comes from the selected runtime checks. The
implicit ALPM helper exit remains NOT OBSERVED, and exact packaged-helper
source-to-binary correspondence remains an unfinished provenance requirement.

The ordinary composition step succeeds. Coordinator cleanup passes with no
failures, and all seven private audio input copies are removed. Historical
failed trials remain failed. No live audio/service/device execution, acoustic
safety, Apple/M2 compatibility, performance or release selection follows.

Retained logs:3384981bytes, SHA256
`f8babb8fcd82a3363f5f0804e4c2eaf34f6934110e9e8a0d64f66475b5c15c97`.
The public frame is161919bytes, SHA256
`ed2310b03186d3a25604f8d540746c5de0327d28a401bc14d71699368b21c039`.
Root retains the results, transaction landmarks and B0/B1 diagnostics under
`artifacts/development/full-composition-audio-padding-run38857117019/review/`.
