# Exact platform baseline archive acquisition

Status: **211 exact archive/signature rows acquired and authenticated as data; seven names remain unresolved**. The coordinator accepted the per-file boundary and all 211 eligible rows passed fresh GPG verification and exact package metadata checks. This does not change the historical payload-report exit1 or establish installed image payload, transaction, runtime ABI, hardware or recovery acceptance. The proposal sections below retain the earlier pre-download checkpoint; completed evidence follows.

Read current roadmap/package inventory, platform transaction and source-correction workstreams, and held archive coverage/authentication/recovery/payload helpers. Only this document and new private ignored `artifacts/platform/baseline-acquisition-20261012/` files were written; no implementation/shared lock/Git/system mutation.

## Exact retained metadata result

All 218 missing names were matched against the hash-bound final transaction and observed 261-package image inventory. Each exact name/version/architecture tuple is equal between the selected final baseline and observed image. The retained three catalogs were rehashed against their existing contract references and parsed with the held bounded repository reader; current package names alone do not substitute for old versions.

| Classification | Count |
| --- | ---: |
| Exact catalog tuple with complete filename/hash/size accepted by held per-file spec helper | 211 |
| No exact version in retained catalogs | 6 |
| Exact tuple present, but existing filename contract refuses | 1 |

The 211 eligible rows comprise 155 core, 45 extra and 11 asahi-alarm. Archive plus maximum detached-signature byte allowance is **612,665,260 bytes**, below the 1 GiB task budget. They need 422 archive/signature files; private metadata, keys, journal and bounded ephemeral verifier homes must also remain below 512 files and the inclusive byte allowance. The largest file is `noto-fonts-cjk` 190,682,128 bytes; planning has not downloaded it. Core/extra 200 rows carry embedded signature hash/size pins; 11 community signatures do not, and require post-download hashes plus exact accepted-primary cryptographic verification, separately labeled.

Six unresolved old versions are `groff` 1.24.1-1, `libnm` 1.58.1-1, `nss` 3.130-1, `openssh` 10.5p1-1, `vim` 9.2.1046-1 and `vim-runtime` 9.2.1046-1. Retained current versions are respectively 1.24.2-1, 1.58.1-2, 3.131-1, 10.6p1-1 and 9.2.1164-2 for both Vim packages. Their old URLs/hashes were not guessed. Neither the failed nor successful existing 16-package superseded-recovery receipt contains these six names.

`grub` 2:2.16-3 has an exact aarch64 row in the retained asahi-alarm catalog. The catalog filename does not satisfy the existing helper's literal name/version/architecture filename rule because of the epoch. The exact row/reference remains in the gap map, but no version rewrite, filename guess or URL bypass occurred. Inspecting an existing baseline GRUB artifact does not introduce a PC boot assumption or authorize installation.

## Reviewable private proposal and bindings

The new private directory contains mode 0600 JSON:

- `gap-map.json`, SHA256 `e94464870fb86b502433c5d1369967d8eed1b523e9bbd613a03eff9b4037ecd4`: all 218 identities, complete exact matched metadata, catalogs and gap reasons.
- `exact-download-plan.json`, SHA256 `75379976eb6f5bde1fccbc462b19f38779de3039554528a3914474d292b6dc39`: 211 exact held-helper specs and locked key references, bound to the gap map.
- `boundary-proposal.json`: source/contract gap and proposed finite acquisition/authentication boundary, with zero transferred bytes/files.

The plan binds the corrected payload report and input contract, coordinated transaction, original strict contract/image inventory, all three retained catalog byte/hash references and both public key references. Helper source hashes are retained in the gap map. The ALARM primary is `68B3537F39A313B3E574D06777193F152BDBE6A6`, public key SHA256 `6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f`. Community primary is `12CE6799A94A3F1B5DDFFE88F576553597FB8FEB`, certificate SHA256 `bd5a05085bc9ec99bc17156e60f5c7f1cd29f2b550bb80f652e0ba4a4820d5b2`. Existing key bytes were rehashed; no default trust/import or new signature verification occurred.

## Required acquisition boundary before execution

Held `authenticate_missing.run` is specifically contracted to 150 missing candidate rows plus one Python change, while `recovery_inputs.run` requires 16 superseded protected rows on its separate actual operator index. Neither whole-run contract admits 211 ordinary baseline rows. The individual held `archive_spec`, `download` and `verify` functions fit those 211 pinned records, but a finite baseline orchestration boundary must be accepted by the coordinator before using them as a new whole task. This concrete proposal/gap map has been sent to the coordinator; sources stay held.

The proposed run must journal exact action/input identities before transfer, use only the metadata-derived canonical approved URLs, retain failure/partial observations, enforce 20 minutes aggregate including authentication and cleanup, bound all downloaded/private retained data to 1 GiB and all files to 512, and perform fresh public-only isolated GPG verification against exact locked primary fingerprints. Rehash archives/signatures afterward and retain structured receipts. No stale version substitution, guessed superseded URL/hash, host installation, default keyring mutation or source execution is allowed. Full helper contracts must not be relabeled to fake a successful 150/16-package run.

Catalog checksum identity is not repository database authentication, and cryptographic validity against these locked public keys is not independent owner-trust acceptance. Package license declarations do not establish full grants/notices. Acquiring 211 or212 archives would still leave precise old-version gaps and require subsequent actual data/payload correlation; it would not close 218 merely by downloading. Runtime, protected platform transaction, target ownership/hooks, Asahi/M2/physical16K, complete recovery and production publication remain unaccepted.


## Completed bounded acquisition

The coordinator explicitly accepted the exact 211 per-file plan after independent catalog/image/spec/key/source review in private `root-plan-review.json`. Acquisition used a **fresh 13-file source snapshot** from actual Git commit `761525881bd95f47c6d8c937f2654bd23926faec`, with every file's actual committed byte/mode retained in `helper-snapshot.json`, SHA256 `09723887ec88f3a828a1da926366a1afdb13e0198fd35d1084b876034ca90bb1`. Its four helper pins match the gap map. No preexisting PYC entered that snapshot; the isolated runner imported those captured sources with bytecode writing disabled. Only the existing reviewed per-file transfer, public-only GPG verification and package metadata APIs were used, never the incompatible 150+1/16 whole-run contracts.

**All 211 rows passed**, with zero failed/not-run rows in the final aggregate. Each archive matched exact retained catalog SHA256 and compressed size. Each detached signature was freshly cryptographically verified in a disposable public-only GPG home with the exact locked primary; 200 ALARM and 11 community checks passed. The raw signed `.PKGINFO` name, version, architecture, dependencies, provides, conflicts, replaces and declared licenses match the exact catalog record. Archive/signature hashes were rechecked after verification and replayed independently for all 422 final files, including exact mode 0600, regular-file/nlink/size checks. No archive payload was installed or executed.

| Private evidence | SHA256 |
| --- | --- |
| Final `acquisition-receipt.json` | `984f0740060b87d01be968acd849a634a06c857ffffc1f04b7f7b7938157d4a0` |
| Rehashed `handoff.json` | `363be4f4523c90fdf4182b7b8ded561847ee36f5951cdb9e08f527ba963ef5dc` |
| Preserved first incomplete receipt | `3cc24a794b932821bf6d17d830550124c784a17a33fa4228ebea71d6fa8b9c55` |
| Corrected private wrapper `acquire.py` | `5d3dead4a2d8dce2fae6710bfbf3f43ce6a97c409d3a4a90940dae10e304b24a` |

Final archive/signature bytes total **598,951,672**. Inclusive private retention was 601,766,643bytes across 448files before the handoff JSON, or 601,925,031bytes across 449files afterward, below 1 GiB/512 files. No partial downloads or GPG scratch homes remain. Verification child processes returned and were reaped through the held bounded helpers. Cumulative finite command time was **181.979 seconds**, including 35.909 seconds from the first incomplete wrapper run, below 20 minutes.

The original conservative plan used 65536 bytes for every signature, giving 612,665,260bytes. The accepted execution ceiling was 599,671,259bytes, using the 200 exact embedded signature sizes and a 65536-byte allowance for each of 11 unpinned community signatures. These are consistent upper bounds, not conflicting artifact hashes. Actual retained signature bytes are smaller still; observed community signature hashes are labeled post-download observations. No signature prehash was invented.

### Preserved orchestration failure and correction

The first wrapper successfully downloaded and cryptographically verified 49 archive/signature pairs, then mislabeled each FAIL because its identity comparison expected normalized `name`/`version` fields while the held PKGINFO parser returns raw `pkgname`/`pkgver` lists. The reviewer stopped only that owned runner, preserved `acquisition-receipt-initial.json`, `acquisition-progress-initial.jsonl` and `acquire-initial.py`, corrected the private wrapper's field comparison to the held inspector's exact raw-field rules, and resumed. All 49 retained pairs were rehashed and freshly GPG-verified without repeat downloads. The original failure remains recorded; only the corrected final receipt establishes 211 data checks. The cumulative 20-minute budget deducted the first run rather than restarting it. Held source helpers, shared metadata and Git were unchanged.

### Remaining acceptance

`groff`, `grub`, `libnm`, `nss`, `openssh`, `vim` and `vim-runtime` remain unresolved exactly as listed above. The old 218-unavailable payload audit/report was not overwritten or reclassified; consuming these 211 artifacts in a new bounded payload/ownership audit is a separate next step. Signed package metadata/versions do not establish identity of already installed image files, complete declared payloads, source grants/notices, complete recovery retention or a protected target transaction.

The handoff retains complete per-row archive/signature references, exact primary identities and the final aggregate receipt hash. Source database authentication, independent key-owner trust, complete corresponding-source/license closure, hook execution, runtime ABI, target installation, Asahi/M2/physical16K behavior, recovery and production publication remain unaccepted. This closes only the accepted finite data acquisition task; it does not close 218 by downloading or alter any historical failed platform result.

## Coordinator retained-data review

Root independently rehashes all422 retained archive/signature files (598,951,672bytes), validates exact211 plan/catalog/image/missing-row associations, byte counts/regular-file/link controls and the producer's actual fresh GPG exit/status/expected-primary observations. Receipt `984f0740060b87d01be968acd849a634a06c857ffffc1f04b7f7b7938157d4a0` and handoff are cross-bound; `artifacts/platform/baseline-acquisition-20261012/root-acquisition-review.json`. Root did not replay cryptography: these are actual acquisition/verifier observations plus independent retained-byte/status binding. Allseven unresolved names remain explicit.

The earlier description of the GRUB filename as epoch-omitted was inaccurate: the exact retained community catalog declares `grub-2.2.16-3-aarch64.pkg.tar.xz` for full version `2:2.16-3`, a dotted epoch representation. No alternate filename/URL was guessed or downloaded. A narrowly reviewed helper correction is being implemented, preserving full signed package identity checks. Merging the211 archives with the406 prior payload inputs totals1,298,106,720 compressedbytes and exceeds the historical1GiB audit ceiling; an explicit2GiB compressed-input policy revision is under source review, with every per-archive/decoded/node/deadline/link guard preserved. The actual full merged payload audit has not run. Installed image/runtime, source grants, full recovery/custody and hardware acceptance remain open.


## Completed GRUB acquisition and merged payload audit

The preceding seven-gap/406-payload sections remain historical. After coordinator acceptance and commit `9140bcaf939bd15b82a2a8c3f020b842c9f03c48` of the narrowly reviewed filename/accounting correction, **GRUB acquisition/authentication passed as data, and all 618 supplied archives passed inert payload inspection**. The new aggregate remains **FAIL / exit 1** because six exact baseline versions are unavailable. No failed historical receipt, catalog, package version or old payload report was overwritten or reclassified.

Execution used a fresh local committed source clone, with 15 delegated helper/test files independently matched to actual Git bytes/modes and no preexisting PYC. The two corrected executable pins are authentication `6af079cf10f8ebcc9416bf64bca4336ea03dbbf13f99ebd98a83808365f2fe59` and payload audit `a7cb3a1c469f88fdb37d17e2414eb283bc53e0ef7211d0723af2b9037fa7689c`. Private wrappers, exact schemas, all source/input references and returned/captured report bytes are hash-bound in the new handoff.

### Actual one-pair GRUB result

Only the exact retained catalog URL for `grub-2.2.16-3-aarch64.pkg.tar.xz` and its `.sig` were fetched. Full VERSION remains `2:2.16-3`, aarch64. The archive is 9,800,024 bytes, SHA256 `e43b968d72cde70752ca82450a72fb65644c1a324c03eaee820446c9ba5827da`. Its 119-byte detached signature has post-download observed SHA256 `98762011b9ff9bf3d139f05bb652a2cb564641eca7021f0dffd056f2df89affd`; the exact catalog lacks embedded PGPSIG, so no signature prehash was invented.

Actual isolated public-only GPGV returned exit 0 and VALIDSIG for pinned primary `12CE6799A94A3F1B5DDFFE88F576553597FB8FEB`. The retained notice is a good signature from the Asahi Alarm keychain master; independent key-owner trust is still not accepted. Full signed PKGINFO name, epoch-bearing version, architecture, dependencies, provides, conflicts, replaces and declared licenses matched the exact catalog record. No source grant, runtime dependency, bootloader installation or boot compatibility is inferred.

Acquisition plus verification/inspection took 1.124 seconds under the 30 MiB/five-minute task bound. Six final private files total 9,967,864 bytes, all mode 0600; no GPG scratch home or partial download remains. No additional network request, stale URL guess, default keyring mutation or package execution occurred. Receipt: `artifacts/platform/baseline-acquisition-20261012/grub/acquisition-receipt.json`, SHA256 `a1d7c7fddb4027b18adfad10d9e23edfa9a55715f83e365b8912fad86f8acaac`.

### Actual 618-archive data audit

The new contract preserves the exact original 406 archive references, transaction and ownership/final metadata references, then adds the 211 validated baseline cache rows and the authenticated GRUB reference. Original authentication provenance is retained separately; the 211 earlier GPG checks were bound by their actual receipts/statuses and signature-byte hashes rather than claimed as replayed. GRUB alone received new cryptographic verification in this task. All 618 archives were freshly checksum-checked and streamed as inert payload data by the unchanged committed reader.

| Actual result | Value |
| --- | ---: |
| Selected final packages | 624 |
| Supplied / successfully inspected archives | 618 / 618 |
| Failed inspection or package metadata/file-list mismatch | 0 |
| Missing exact-version archives | 6 |
| Compressed input bytes | 1,307,906,744 |
| Decoded bytes consumed | 5,624,033,280 |
| Observed nodes | 134,548 |
| Observed non-directory overlaps | 0 |
| Link observations | 15,158 |
| Packages with inert hooks/scriptlets | 51 |

The six gaps are unchanged exact old versions: `groff` 1.24.1-1, `libnm` 1.58.1-1, `nss` 3.130-1, `openssh` 10.5p1-1, and `vim` / `vim-runtime` 9.2.1046-1. None was substituted with a current package. Their absence alone causes the actual helper-equivalent exit 1; the complete 618-row report and failure status are retained.

There are 13,301 links to observed archive targets and 1,848 same-archive regular-file hardlinks. Four `ex-vi-compat` links target declared `usr/bin/vim` whose payload remains unavailable. Five targets are not declared in this proposed archive namespace: three CA certificate links to `etc/ca-certificates/extracted/tls-ca-bundle.pem`, `etc/mtab` to `proc/self/mounts`, and `var/lock` to `run/lock`. The audit records these as unobserved targets; generated/runtime behavior was not exercised. No cycle, escape, non-directory-ancestor or unsafe-hardlink finding was reported. All target filesystem/link and hook execution flags remain false.

The data process completed in 51.226 seconds with a 2 GiB address-space limit and a 20-minute outer envelope. No cap was raised: compressed aggregate 2 GiB, each archive 300,000,000 bytes, decoded per archive 1 GiB / aggregate 8 GiB, node/deadline/link limits and the helper's existing 64 MiB output bound all remained intact. Its 44,964,520-byte report fits that output bound. The unchanged filesystem output guard writes inside the fresh source clone; the report was then copied into the new owned private directory and rehashed byte-identically. Retained new primary data plus the temporary clone report totaled 100,372,750 bytes including the handoff, below the 256 MiB private-data ceiling. These elapsed values establish task bounds, not performance improvement.

| New private evidence | SHA256 |
| --- | --- |
| `baseline-payload-audit-20261012/payload-inputs.json` | `fedd63e28006f391ae4abe19633690d36853b27a0bda2722c8ae2e3d7f289369` |
| `baseline-payload-audit-20261012/authentication-bindings.json` | `e7d8119e70324b989216c1460f5441ce98f5e96ceaf1dc19877baf5ace035467` |
| `baseline-payload-audit-20261012/execution-journal.json` | `b7e77a42ef944d6c74175cf3a833c5ab55b8d81fc7c4bcc29aac60c8c9a1ae0e` |
| `baseline-payload-audit-20261012/payload-report.json` | `e518010b43cd81366688642efc209466cacd61e241f281d510ee46738a82a72f` |
| `baseline-payload-audit-20261012/handoff.json` | `a198c200e9c8072a444c4a2192f71c8b80829e3350151663404a3fc4237963ce` |

The historical 406 report, 218-gap report and old source/authentication observations were rehashed unchanged. The coordinated Python alternative and original strict transaction retain their prior adoption/acceptance status. The new report does not authenticate installed image bytes or repository database ownership, execute hooks, test ABI/import behavior, close corresponding-source/license grants, prove complete recovery or accept a target transaction. Installation, production publication, Asahi/M2/physical 16K execution and hardware/performance acceptance remain unestablished. Only the assigned new private artifact paths and this append-only section were written; no implementation, shared lock, project Git, mount, module or host package mutation occurred.
