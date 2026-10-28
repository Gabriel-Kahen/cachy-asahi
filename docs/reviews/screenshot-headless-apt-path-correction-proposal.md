# Screenshot image APT pathname correction proposal

Status: **exact APT 3.0.3 source trace and two-file Source proposal; corrected image installation/build NOT RUN**. This work responds to retained [pilot 38628618206](screenshot-headless-software-run-38628618206.md), which failed with APT100 → Dockerbuild1 before inventory, Sway or screenshot capture. The failure evidence, runtime closure and prior seals remain unchanged. No host package install, APT execution, Docker build, CI retry/cancel, default-branch change, canonical Source/Git write or variable update occurred here.

The [new packet](../../artifacts/reviews/screenshot-headless-apt-path-correction-proposal-20261014/) proposes only `scripts/ci/screenshot-headless/Containerfile` and its one row in `source.lock.json`, based on committed Source `85a84f9ff5437e139a284c73d9c02767e14d474f`. The driver remains byte-held, including its numeric `.deb` staging, all 196 URL/size/hash gates, Root guard, network-disabled build call and runtime containment/evidence/cleanup checks. The 196 package hashes/versions/architectures, 597 dependency joins, inventory gate, image base and runtime backends are not changed.

## Cause: local acquisition is required even without network

The actual log's first diagnostic was:

```text
E: Internal Error, Pathname to install is not absolute 'libexpat1_2.8.3-1~deb13u1_amd64.deb'
```

The pinned base contains APT **3.0.3**. Its exact official source archive is authenticated against the already sealed runtime source metadata: `apt_3.0.3.tar.xz`, 2,422,096 bytes, SHA256 `5b5f6f6d26121742a83aa80d4ed0eb0c6ce9bea259518db412edefd95760e4ef`. The source audit captures the archive, Debian source descriptor, license and relevant implementation; nothing from it is executed. See [APT source audit](../../artifacts/reviews/screenshot-headless-apt-path-correction-proposal-20261014/apt-source-audit/).

The traced path explains how an absolute `/debs/53.deb` argument becomes that relative diagnostic:

1. The CLI accepts the absolute local `.deb` argument as a volatile binary source; the file's own package/version/architecture fields identify `libexpat1`. Staging under a numeric filename does not reclassify its package identity.
2. `pkgPackageManager::GetArchives` gives `pkgAcqArchive` a reference to the package manager's `FileNames` slot. The constructor initially sets that slot to a generated **relative cache basename**, using package/version/architecture and the extension. For this package it is exactly the basename in the retained error.
3. A suitable existing canonical cache file can resolve the slot immediately to an absolute cache path. The failed pilot instead had the input files under `/debs/`; no matching populated APT cache is established by that Source path.
4. For an uncached local archive, the constructor queues a local `file:` acquisition. The acquire queue recognizes the method's `LocalOnly` flag and marks the item `Local=true` before the file method has completed.
5. `--no-download` sets `APT::Get::Download=false`. The installation code retains items already marked local, then calls `Fetcher.Shutdown()` before acquisition. Shutdown deletes those queued items. The local file method and `pkgAcqArchive::Done` callback never get to replace the relative cache basename with the actual absolute archive path.
6. The package manager still holds the nonempty relative name. `pkgDPkgPM` rejects it with the exact retained absolute-path diagnostic before passing the install path to dpkg.

This is a source-supported mechanism matching the real command, empty-cache path and diagnostic. It is not a reproduced corrected APT installation. The error names `libexpat1` because that is an item encountered by installation ordering; this review does not claim a complete observed order beyond the first logged rejection. The pathname does not show malicious input or an invalid absolute shell argument.

Renaming staged files to their repository basenames would not repair the shutdown/unfinished-callback path. Prepopulating APT's canonical archive cache is an alternative, but introduces cache-name construction, including epoch encoding for 23 locked versions. That larger change is unnecessary. The numeric driver staging stays held.

## Minimal corrected command

The candidate allows APT's ordinary acquisition machinery to process the already verified local archives, while keeping actual network isolation and preventing repository/index inputs:

```dockerfile
 && rm -rf /var/lib/apt/lists/* \
 && DEBIAN_FRONTEND=noninteractive apt-get \
      -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null \
      --no-install-recommends -y install /debs/*.deb \
```

The rest of the Containerfile is held: exact Debian base digest, copied deb context, policy-rc.d service-start suppression, final deb/list/cache cleanup, environment, working directory and entrypoint. The unchanged driver still invokes Docker build with `--network=none --platform=linux/amd64`. There is no apt update or additional package source. The source-list options disable configured repository lists, and the private image's old list files are cleared before resolution; local volatile `.deb` inputs remain available. Removing `--no-download` permits local file-method completion, not host installation or a relaxed network namespace. A missing required input must fail rather than obtain a replacement from a repository.

| Proposed replacement | Before | After |
| --- | --- | --- |
| Containerfile | 545 bytes, mode 0644, `14283ad9259b6f95532bd38455abab5c754eaec104931571165e6ee46a38f375` | 650 bytes, mode 0644, `e0b98f019bb7a574d2a8d18d4d38277db245b51362239bb95b86397a585e0e3c` |
| Source lock | 2,152 bytes, mode 0644, `d5d0c30600b824c972ebd3c8f2efd0bcee70f2045f83109da4856afffeccbb11` | 2,152 bytes, mode 0644, `5d2c1b75fae1bb1b93a001ce92d5a9afd5bafb745460e8cdfb4374cdf846515c` |

[`copy-list.json`](../../artifacts/reviews/screenshot-headless-apt-path-correction-proposal-20261014/copy-list.json) records exact committed preimages and postimages. Only the Containerfile row changes within the ten-row Source lock; the other nine rows, schema, lane and self-lock policy are held. Runtime lock SHA256 remains `dc19e9dd0d67fd9710fab57c3cddc211be931d61ef730e147dd53f4f148cbc05`; driver SHA256 remains `c5fc8f7aeab691d41539415f04a7f3c6a84d7ca62bb288e106aa9becd54b190b`.

## Verification and Root boundary

The [independent peer review](../../artifacts/reviews/screenshot-headless-apt-path-correction-proposal-20261014/peer-review/) checks the exact before/after shell arguments, APT source branch/callback model, local-versus-cache naming including epoch cases, two-file delta and all held closure/runtime/guard inputs. These are inert argument/data/source-path controls. They are not an APT, package-install, image-build or screenshot result.

Root's next step is external adoption of only these replacements against the actual Source, regeneration/authentication of the complete seven-file Source closure and ten locked rows, then a new actual commit and peer-bound plan. The new Source-lock hash must enter that plan; the old Source commit/literal must not be reused. Root reads the actual variable back before publishing the exact changed ref and choosing one manual changed trial. The unchanged workflow file/default registration needs no capability change. No new Source SHA, peer receipt, literal plan or run ID is invented in this proposal.

The old `b3079982…` materializer requires a commit containing exactly seven additions and will correctly refuse this later two-replacement commit. Root must use a separately reviewed actual two-file adoption/full-closure proof and plan-data path, or a narrowly reviewed materializer successor; do not weaken or reuse the old check as though it accepted correction commits. No materializer change is included here.

A future image must still install and report exactly all 196 locked Package/Version/Architecture rows before any runtime gate, then complete the same real captures, independent PNG checks, negative cases and owned cleanup. Base image/build-cache/context retirement remains a separate held limitation of the existing driver; this narrowly scoped APT correction does not claim to fix it. ARM archive execution, Hyprland compatibility and M2 hardware acceptance remain outside this software trial.
