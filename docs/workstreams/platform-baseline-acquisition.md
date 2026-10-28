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


## Completed five-version recovery handoff and 623-archive audit

The earlier 406/618 reports and six-gap outcome remain historical and unchanged. A separately owned actual acquisition recovered the exact old baseline archives for `groff` 1.24.1-1, `libnm` 1.58.1-1, `nss` 3.130-1 and `vim` / `vim-runtime` 9.2.1046-1. Its held handoff is `six-baseline-recovery-20261012/handoff.json`, SHA256 `36320f5093d6b4a2c62a25a243355926267cc9fe9a1e352f5b4c12cfa76fa0b8`; the actual acquisition receipt is `3ae755b7943d2447dd06b7c72949af4b66e74b14320dd994d398a213bca9a01f`.

Those five archives total 14,541,564 compressed bytes and detached signatures 2,830 bytes. The producer freshly verified each signature in an isolated public-only GPG home, with exit 0/VALIDSIG for locked primary `68B3537F39A313B3E574D06777193F152BDBE6A6`, and matched full signed PKGINFO identity/dependencies/provides/conflicts/replaces/licenses to unchanged final baseline metadata. Transfer authority is the exact observed operator index href; archive/signature SHA256 values are **post-download observations**, not invented catalog pins. The acquisition uses the retained 13-helper Git-byte snapshot from `761525881bd95f47c6d8c937f2654bd23926faec`. This payload phase independently rehashed all ten archive/signature files and bound the producer's actual GPG statuses/metadata, without claiming cryptographic replay or independent key-owner trust.

A new contract preserves all **618 old rows verbatim**, including unchanged transaction, ownership and final metadata references, and adds only these five authenticated archive references. The new actual bounded inert audit inspected **623/623 supplied archives**, with **zero failed inspection rows, zero metadata/file-list mismatches and zero observed non-directory overlaps**. Aggregate remains **FAIL / exit 1**, solely because exact `openssh` 10.5p1-1 aarch64 remains unavailable in this contract. A pending acquisition lead cannot reclassify this historical result.

| Actual 623 result | Value |
| --- | ---: |
| Selected final packages / supplied archives | 624 / 623 |
| Compressed input bytes | 1,322,448,308 |
| Decoded bytes consumed | 5,698,887,680 |
| Observed nodes | 138,225 |
| Link observations | 15,220 |
| Packages with inert hooks/scriptlets | 52 |
| Process elapsed seconds | 52.329 |
| Report bytes | 45,927,419 |

The recovered Vim payload resolves the four formerly unknown declared Vim targets as archive data. Links now comprise 13,367 observed targets, 1,848 same-archive regular hardlinks and five `target-not-declared` observations. The latter are the three CA certificate links to `etc/ca-certificates/extracted/tls-ca-bundle.pem`, `etc/mtab` to `proc/self/mounts` and `var/lock` to `run/lock`. No unsafe link/cycle/escape/non-directory-ancestor finding appeared; runtime/generated target behavior remains untested, rather than presumed broken or accepted.

Execution uses the exact 15 helper/test byte/mode pins from committed `9140bcaf939bd15b82a2a8c3f020b842c9f03c48`, captured anew inside the owned project artifact tree. The unchanged reader writes within that source snapshot's guarded artifact root and its report is copied/rehashed byte-identically. Heavy reports therefore stay on the project filesystem; no large temporary-system report is required. The 20-minute outer envelope, 2 GiB address space, 256 MiB private retention, 2 GiB compressed aggregate, 300,000,000-byte archive, 1 GiB decoded per archive / 8 GiB decoded total, 500,000 aggregate nodes and all other filename/link/deadline/output limits remain unchanged. Inclusive new source/data/both report copies plus handoff total 92,469,211 bytes. All 24 indexed pre-handoff files were independently rehashed with exact size/mode; no PYC entered the snapshot.

| New private 623 evidence | SHA256 |
| --- | --- |
| `baseline-payload-audit623-20261012/payload-inputs.json` | `155465f84a02dd2088ca1b37b1c3b17c182fc34f9a1de81b55ca0f98ded66de0` |
| `baseline-payload-audit623-20261012/authentication-bindings.json` | `bf2e7072a8a06d7bb55ee16540d4d478b67e4b5b661f8ab2a1a9883665321f47` |
| `baseline-payload-audit623-20261012/execution-journal.json` | `99dcd13f64aa8be7757bd51e5def355d66f8c98f325e58e3a02421a1264200ac` |
| `baseline-payload-audit623-20261012/payload-report.json` | `a92761b6d6ee3b7da5862194a54ae0255f8e14be512dab36f7afd730dfdc9840` |
| `baseline-payload-audit623-20261012/handoff.json` | `45d64bb035c680646801ec4b5ebc94e6da9d894200de625bb8a894294992ea86` |

No archive extraction, payload execution, install, mount, host-system or shared metadata/Git mutation occurred. Catalog database authentication, independent owner trust/custody, installed-image identity, corresponding-source/license grants, complete recovery retention, runtime ABI/import/hooks, protected target transaction, production publication and M2/physical 16K/hardware/performance acceptance remain open. A separate 624-archive audit is authorized only after an actual held exact OpenSSH archive/signature/metadata PASS; it must preserve this one-gap FAIL report and use the same reader/caps.


## Completed exact OpenSSH recovery and 624-archive inert audit

The separately held OpenSSH acquisition then passed for exact `openssh` 10.5p1-1 aarch64. Its authority is the actual operator `2026/10/05/core` index archive/signature hrefs, rather than a guessed package-pool URL; earlier pool/index lookup failures remain recorded. Archive size is 1,215,644 bytes, post-download SHA256 `a297cd3a571d2658adf13ab03017cec61f2f9d88834e2ef113729a521daa1c67`; signature size is 566 bytes, post-download SHA256 `395f6f93182b290f31f63f85db386d2fa3400eb60a6da5e802b18fc9f5cfd084`. The producer's actual fresh public-only GPG verification returned exit 0/VALIDSIG for locked ALARM primary `68B3537F39A313B3E574D06777193F152BDBE6A6`, digest 10, and full signed PKGINFO identity/metadata matched the unchanged exact final baseline.

Six-data handoff `six-baseline-recovery-20261012/six-handoff.json` is SHA256 `be5d4447e0da53a4582f5e30085a1ceb0af730da76e2a502842dab61361537df`; the one-row acquisition receipt is `96724d25f9659b3349bb45032c91242e172761773234ac2ea4a1fbd6d55bfeea`. Before the new audit, all referenced archive/signature/key/plan/lookup/receipt bytes were rehashed, the five earlier handoff rows matched verbatim, and the new metadata/signature status was independently bound. This phase did not replay GPG cryptography or accept independent key-owner trust.

Under the coordinator's conditional authorization, a **separate 624-archive contract and audit** preserved all 623 prior archive rows verbatim and added only the authenticated OpenSSH reference. The actual unchanged reader returned **PASS / exit 0**: **624/624 supplied archives inspected as inert data**, no unavailable exact archive, no failed inspection row, no metadata/file-list mismatch and no observed non-directory overlap. The historical 623 one-gap FAIL, 618 six-gap FAIL, original406/218-gap reports, all original contracts and authentication histories remain unchanged.

| Actual 624 result | Value |
| --- | ---: |
| Selected final packages / supplied and inspected archives | 624 / 624 |
| Compressed input bytes | 1,323,663,952 |
| Decoded bytes consumed | 5,709,117,440 |
| Observed nodes | 138,317 |
| Packages with inert hooks/scriptlets | 53 |
| Process elapsed seconds | 52.250 |
| Report bytes | 45,966,493 |
| Inclusive new source/data/both report copies and handoff bytes | 92,533,862 |

The same five `target-not-declared` archive-namespace observations remain: three certificate links to `etc/ca-certificates/extracted/tls-ca-bundle.pem`, `etc/mtab` to `proc/self/mounts`, and `var/lock` to `run/lock`. Other links comprise 13,367 observed targets and 1,848 same-archive regular hardlinks; no cycle/escape/non-directory-ancestor or unsafe-hardlink finding appeared. This does not execute generated/runtime targets or hooks.

The exact committed9140 15-helper source/mode pins, copied snapshot/no-PYC control, 2 GiB compressed aggregate, 300,000,000-byte archive, decoded1GiB-per-archive/8GiB-total, 500,000 aggregate-node, all other filename/link/deadline limits, unchanged64MiB helper output bound, 20-minute outer envelope, 2 GiB process address space and 256 MiB private retention were preserved. Heavy reports remain on the project filesystem. All 24 indexed pre-handoff files were rehashed with exact size/mode, and both guarded-source and primary report copies match byte-for-byte. These bounded elapsed observations are not performance comparisons.

| New private 624 evidence | SHA256 |
| --- | --- |
| `baseline-payload-audit624-20261012/payload-inputs.json` | `e77ce4f77f8bef40e011b710cc1ffcef3d10a5d778454c00e9eaac4936f8bca6` |
| `baseline-payload-audit624-20261012/authentication-bindings.json` | `beed7e78a57e121ee13922194882803f6eae1cd989293005250016ca81cd637f` |
| `baseline-payload-audit624-20261012/execution-journal.json` | `c9ecf280133ccf399794a463f1ac62c0cc76bde7d8767cdaff3ee66bfff3890e` |
| `baseline-payload-audit624-20261012/payload-report.json` | `7df4b87a2d8d31455fa0e8cf30e2f53eed65cacbb2d2dbe7dd395b9484ecf314` |
| `baseline-payload-audit624-20261012/handoff.json` | `4d2e056c3812610efbc842a23b45560800e3d0e11a4e8e0ebb53e0f671686aad` |

This closes the exact missing archive-data/inspection gap for this unchanged 624-package proposed final inventory. It does not adopt the coordinated Python alternative or turn the original strict transaction into PASS. Archive signature verification belongs to the separately bound acquisition provenance; the payload helper itself asserts no signature verification. Its complete-installed-payload, image authentication, target symlink resolution, hook execution, installation and hardware flags remain false. Installed-image correlation, runtime ABI/import behavior, corresponding-source/license grants, catalog/owner trust/custody, complete recovery retention, protected platform installation, production publication and Asahi/M2/physical16K/performance acceptance remain unestablished. No package payload was extracted or executed, and no installation, mount, host-system, shared manifest or project Git mutation occurred in either new audit.
