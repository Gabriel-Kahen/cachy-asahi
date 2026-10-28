# Native development composition with six audio additions — 2026-10-15

**PASS for the bounded signed package transaction and restoration:** the exact existing 587-package development composition accepted six audio additions, reached 593 packages, removed asahi-audio first to reach 592, then removed the remaining five and restored the exact original 587 inventory. Required signatures, dependency checks, selected payload/database/directory preservation and owned cleanup passed. No audio service, plugin processing, speaker output or target hardware was exercised.

## Exact actual run and retained evidence

- [Actual run 38797262875](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38797262875), terminal SUCCESS reported by Root.
- Adopted audio/retrieval Source `d17f1e638f15ab842c313bfc797c0b490a799035`; workflow `b093eb48917dd8e70a0387be1beb3c5820380f98`, isolated branch `codex/full-composition-audio-v1`.
- The workflow's exact AUDIO_SOURCE_COMMIT agrees with the retained provider-source checkout. Held composition sources remain product `a58fca33c4db5f2ab3ea6111f4d7842a932cc336`, updater `1aea667aec50a62ba0ab2dad44be24a4dc3bd098`, desktop builder `8d8e2f5d5a94ab3ebee2d8b1cc20aecf98e435e2`; original-four/FDK builds retain their frozen workflow pins.

Root collected logs once at `artifacts/development/full-composition-audio-run38797262875/logs.zip`: 3,290,245 bytes, SHA256 `54cd2867a0b0c68da3ce133ac017209851d390820a24186dc8f027a4a2d07016`. This review decoded only the dedicated step 17 public bundle once, checked declared compressed size 120,442 bytes and SHA256 `df4a083fcf4b14bbeff262d64432879d7a6b1a236bbaa8b12ea1f1df98f7a922`, and read safe regular tar members. Aggregate duplicate bundles and earlier audio source/package frames were not decoded again. No network recollection, build, CI dispatch or runtime replay was performed.

The extracted unchanged public evidence, bundle/member hashes, source-checkout binding, retrieval/cleanup step logs and `verified-readout.json` are retained under `artifacts/development/full-composition-audio-run38797262875-review-20261015/`. The public result exactly equals the coordinator's composition result. Source-defined checks below were read from the frozen Source using local git show; relevant source hashes are recorded separately, not represented as independently exported per-run source measurements.

## Signature and inventory results

The fixed retrieval succeeded for five retained native outputs plus the official LSP archive and its original detached signature. Canonical policy SHA256 is `01f8f2cdefddbb5bb86748817935777186a64ec18371922d2c7a14ec2a116f5a`; all six archive hashes in the retained audio summary match that policy.

| Addition | Exact version | Required signature scope |
| --- | --- | --- |
| asahi-audio |4.1-2 | Private development TEST signer |
| alsa-ucm-conf-asahi |10-2 | Private development TEST signer |
| speakersafetyd |2.0.1-2 | Private development TEST signer |
| bankstown |1.1.0-3 | Private development TEST signer |
| triforce-lv2 |0.3.2-2 | Private development TEST signer |
| lsp-plugins-lv2 |1.2.35-1 | Original pinned ALARM detached signature |

The exact executing container source sets both SigLevel and LocalFileSigLevel to Required and imports only the retained upstream certificate plus the exact ephemeral TEST signer into its private trust directory. Audio input preparation preserves LSP's official signature; the five other archives receive private TEST signatures. The retained result reports `REQUIRED-five-TEST-one-pinned-ALARM`. This combines executed required-signature policy, pinned signature bytes and successful pacman transaction; it is not production signing-key custody or release trust acceptance. LSP archive SHA256 is `dd6295c2735fd69c258cb21c219138fe444eb131998cd4fa442e9026805bb31b`; original signature 566 bytes, SHA256 `5c190f59648a2fe99611665f7fff887a00a2a6ff3eeffc9131f8ea64771c3b79`.

| Checkpoint | Count | Evidence |
| --- | --- | --- |
| Original full composition |587 | Exact inventory SHA256 `c309aaeb12e2e2d51cb0aceb1b4acc9e5b95cbba87df1880936bc2bf1b125463`; existing composition checks passed before audio. |
| Six additions installed |593 | Exact inventory SHA256 `ff70e71ad067cb3cf261645b15173be315f02a3e91cd35e6bea5732125cce564`; explicit audio result PASS. |
| asahi-audio removed first |592 | Retained ordinary `-R asahi-audio` command and executed source assertion require exactly the 593 inventory minus this one dependent. No separate 592 inventory snapshot is exported. |
| Remaining five removed |587 | Exact original inventory/hash restored, database check passed and original project payloads rechecked. |

The removals use ordinary dependency-aware `-R`, without -Rdd/-Rs. The audio packages declare 22 dependency entries, deduplicated to 21 distinct versioned/SONAME requirements because bankstown and triforce-lv2 both declare lv2. Transaction log line 1318 contains precisely those 21 requirements in `pacman -T`; source-data comparison confirmed equality. `pacman -Dk` and the dependency check passed without waivers. The original composition's dependency/provider checks and installed FDK provider load also passed; they do not execute the newly installed LV2 plugins.

## Preservation, isolation and cleanup

The executed audio branch rejects pre-existing incoming file paths, collisions, and archive conflict/replaces/backup mutations. It checks the six additions' installed hashes, modes, numeric UID/GID ownership and pacman owner, then rechecks original project payloads after removal. All added package files must be absent after removal. The original 587 local package database snapshot compares file bytes, types, modes and ownership; original records remain intact during installation and the complete snapshot is restored after removal. Pre-existing payload ancestor directories retain their modes and ownership. The retained result explicitly reports these checks passed.

This branch does not run the separate lifecycle user-home fixture or snapshot arbitrary user data. Therefore user configuration/home preservation is not newly established by this run; package-owned path/metadata and database preservation are the specific accepted scope. No audio devices or running systemd instance are allowed in the disposable container. Services, app sessions, audio processing and Bluetooth transport remain NOT RUN.

Scriptlets were disabled and hooks masked. **The three audio ALPM mutations still permit implicit ldconfig when eligible. ALPM ignores its auxiliary return, and cache/SONAME-link correctness or restoration was not checked.** Package database/payload restoration must not be described as restoration of all system state or proof that no executables ran. No ldconfig waiver, stub or removed binary was introduced.

Coordinator cleanup reports PASS with failures=[] for the owned composition container, selected newly built images and private trial files. The frozen cleanup source requires owned container/image absence checks and removes private raw work on success; this is scoped cleanup, not a global daemon/image audit. The final workflow step independently reports `AUDIO_INPUT_COPIES_REMOVED=PASS scoped-seven-files`, after verifying the exact seven private retrieved filenames, ownership/types and directory mode, deleting them and checking absence. Public retention remains bounded diagnostics/status/hash metadata; this review exported no package binaries or source bundles.

The audio-summary diagnostic is written during preparation and still says transaction NOT RUN. It is preserved unchanged; final result.json and coordinator.json contain the later executed audio PASS and restoration result. The records describe different stages, not contradictory final outcomes.

## Remaining acceptance limits

This establishes one generic native ARM disposable package transaction, including six installed audio packages and their normal removal back to the original 587 checkpoint. The six inputs were reused rather than rebuilt in this audio lane. It establishes no new audio/plugin execution, acoustic or speaker-safety behavior, service/daemon graph, Bluetooth operation, Apple/M2 or 16KiB-page compatibility, target lifecycle, performance gain, complete source/recipe/license closure, production repository trust or release/full-port acceptance. Source is already adopted; manifests and subsequent integration/status decisions remain Root-owned.
