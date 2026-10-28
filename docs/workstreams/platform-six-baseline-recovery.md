# Six exact baseline archives recovered as private data

Status: **six actual archives and detached signatures acquired; six fresh cryptographic checks and exact signed metadata comparisons PASS**. This is a data acquisition result. The immutable 618-input payload audit remains FAIL, and the intervening 623-input audit remains historical. A separate 624-input audit can consume the final handoff. No image, installation, runtime, full recovery, source-grant, production or hardware acceptance follows from acquisition.

Read current roadmap, package inventory, platform transaction/source-correction workstreams and held baseline acquisition evidence. The immutable 618 handoff was checked against SHA256 `a198c200e9c8072a444c4a2192f71c8b80829e3350151663404a3fc4237963ce`; the original gap map against `e94464870fb86b502433c5d1369967d8eed1b523e9bbd613a03eff9b4037ecd4`. The six required name/version/aarch64 tuples match retained image and final baseline metadata. Those local descriptors declare no old archive filename, size, checksum or signature; no such field was invented.

## Actual source lookup and authority

[ALARM's official mirror policy](https://archlinuxarm.org/about/mirrors) describes synchronized current-package mirrors. The [official mirror list](https://github.com/archlinuxarm/PKGBUILDs/blob/master/core/pacman-mirrorlist/mirrorlist) identifies the California and New Jersey hosts checked. California core/extra indexes exposed newer versions, which were refused as substitutions. The [ALARM developer forum's archive listing](https://archlinuxarm.org/forum/viewtopic.php?f=8&p=73989) identifies `pkgmirror.sametimetomorrow.net` as a community archive. It establishes a lookup lead, not ownership authentication or an official ALARM archive guarantee.

Actual HTTPS operator package indexes exposed unique exact archive and signature hrefs for groff, libnm, nss, vim and vim-runtime. OpenSSH's package index exposed only 10.6p1-1. The operator's dated **2026/10/05/core** index, corresponding to the retained image ZIP's observed last-modified date, exposed actual hrefs for OpenSSH 10.5p1-1 and its signature. These observed links were selected and bound to captured index hashes before acquisition. The prior 2026/10/04/core lookup returned HTTP404; the legacy community archive refused connection; New Jersey mirror TLS validation failed and was not bypassed. Initial sandbox DNS failures are retained separately and were not described as source unavailability. All actual bodies, URLs, response status, byte counts and hashes remain in the private lookup receipts.

Neither the operator index nor the old image provided a predeclared archive/signature digest. Archive and signature hashes are explicitly **observed after download**. Data acceptance instead required a fresh detached signature verification against the previously accepted locked ALARM public primary certificate, followed by exact signed package metadata comparison. The acquired filenames below are observations from those actual index hrefs, not guesses from package names.

| Exact acquired aarch64 filename | Archive bytes | Observed archive SHA256 |
| --- | ---: | --- |
| groff-1.24.1-1-aarch64.pkg.tar.xz | 2,393,752 | `8ec9305434a4c012e9384aec68010e52033b93ad98bc0ad8869d947ee5d8684d` |
| libnm-1.58.1-1-aarch64.pkg.tar.xz | 865,536 | `9219404664cc04bcb9575f9a16d2eeb13f7aeaa062c601623a2c4c4571fb3013` |
| nss-3.130-1-aarch64.pkg.tar.xz | 1,555,316 | `2e6b6bbdffe3f0b1e858e86cdf2cce7a71ed52bdb6fbc3fe5ac870defe2e55d6` |
| openssh-10.5p1-1-aarch64.pkg.tar.xz | 1,215,644 | `a297cd3a571d2658adf13ab03017cec61f2f9d88834e2ef113729a521daa1c67` |
| vim-9.2.1046-1-aarch64.pkg.tar.xz | 2,077,172 | `d827a48f6bc120a4d757988d6efea2cfca6c45efb40123d9d93f67ad4e0fcb3f` |
| vim-runtime-9.2.1046-1-aarch64.pkg.tar.xz | 7,649,788 | `4fe6b8e08603dbd96758f02ac9927bb5c0b36782d2b4e3eaefa08d88119521ea` |

## Verification and finite resource evidence

All six checks used primary `68B3537F39A313B3E574D06777193F152BDBE6A6`, locked certificate 3,098 bytes/SHA256 `6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f`. Each actual GPG verification exited zero, reported exactly one accepted `VALIDSIG` for that primary with digest10, and contained no bad/expired/revoked/missing-key status. Only that public certificate was imported into a new explicitly private temporary home; no default/installed keyring, private key, key retrieval or owner-trust operation was used. All disposable homes and partial downloads were absent on final inspection.

The held per-file `recovery_inputs.exact_links/fetch` and `authenticate_missing.verify/pkginfo` APIs were used through a fresh 13-source snapshot of committed `761525881bd95f47c6d8c937f2654bd23926faec`, excluding all preexisting PYC files. Snapshot SHA256 `09723887ec88f3a828a1da926366a1afdb13e0198fd35d1084b876034ca90bb1` records exact bytes/modes; these source bytes were independently read from Git and rehashed before/after use. Historical source helper SHA256s remain explicit: recovery `09be69917bf74b50a65841243e8e4cfef264a56074945b609264c76a0f387430`, authentication `28d7d4e007b9d856733eb64e250f8c24ecfedf409ce4c0b0221329e443e1f1fa`. The fixed whole-run 16/150+1 contracts were not invoked as six-row contracts. The assigned coordinator task authorizes this finite per-file data orchestration; no implementation was changed.

For every signed archive, streamed inert `.PKGINFO` parsing matched exact name, full version, architecture, dependencies, provides, conflicts, replaces and declared license values to the retained baseline metadata. Archive/signature bytes were independently rehashed after verification and at handoff, and are single-link regular files mode0600. No package was installed, executed or expanded into a working root filesystem. Declared licenses remain distinct from complete corresponding-source/notices permission.

Six archive bytes total **15,757,208**; six signatures total **3,396**. Acquisition commands were individually bounded to 32 MiB per archive, 64 KiB per signature, 256 MiB private retention, 96 files and ten minutes. Index lookup commands had separate finite request/response/deadline bounds. Four actual network/verification commands cumulatively took **30.312 seconds**, well within the authorized aggregate twenty-minute ceiling. Retention before the final aggregate handoff was 52 private files/21,448,787 bytes; final handoff adds one file/26,492 bytes. Parent output is mode0700. No network failure or newer version was silently skipped and counted PASS.

## Held evidence and limits

All refs are below `artifacts/platform/six-baseline-recovery-20261012/`.

| Evidence | SHA256 |
| --- | --- |
| `six-handoff.json` — six full archive/signature refs, actual signature observations and signed metadata | `be5d4447e0da53a4582f5e30085a1ceb0af730da76e2a502842dab61361537df` |
| `acquisition-receipt.json` — first five actual data results | `3ae755b7943d2447dd06b7c72949af4b66e74b14320dd994d398a213bca9a01f` |
| `openssh-acquisition-receipt.json` — sixth actual result | `96724d25f9659b3349bb45032c91242e172761773234ac2ea4a1fbd6d55bfeea` |
| `handoff.json` — earlier five-only handoff retained unchanged | `36320f5093d6b4a2c62a25a243355926267cc9fe9a1e352f5b4c12cfa76fa0b8` |
| `five-download-plan.json` | `268c50084ca10d4696f80addf7368fd353479313d9a6a551b274040f26214140` |
| `openssh-download-plan.json` | `1b95f54ee356f79589e8da07800e27daefbff338fa73c0cc2691a748ab0f5f06` |

All six exact archive gaps are resolved as retained signed archive data. The final handoff deliberately leaves `complete_baseline_archive_authentication=false`: historical inputs and independent trust/database authority are not newly accepted by these six checks. The separate payload coordinator owns the new full 624-input report; no old contracts/results were replaced here.

The considered rootfs fallback is not needed to acquire these six. It would nevertheless require a distinct typed installed-image observation contract and independent authenticated image/manifest authority before acceptance: the retained Asahi ZIP `42df228b8bb7a3fc980a94d1eca01bc44a4e29efaf002bf77ffac2fbc08bbbd7` and derived root.img `76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db` are explicitly HTTPS-observed, without independent image signature. Current [Asahi Alarm installer metadata](https://asahi-alarm.org/installer_data.json) supplies image URLs and partitions, not an accepted signed image hash. An installed local package database or its `VALIDATION=pgp` label cannot authenticate image bytes, and the existing authenticated native bootstrap inventory has a different OpenSSH tuple. Image-file observation cannot reconstruct compressed archive bytes or waive retained recovery requirements.

Only this new document and the assigned new private artifact directory were written. Source code, shared locks/manifests, project Git, system trust, mount/module/package state and historical results were unchanged. Runtime ABI, hooks, source grants, complete retained recovery/custody, production publication, Asahi/M2/physical16K behavior and performance remain unaccepted.
