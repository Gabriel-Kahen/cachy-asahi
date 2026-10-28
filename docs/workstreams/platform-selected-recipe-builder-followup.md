# Selected platform recipes: official builder UI follow-up

This bounded follow-up retrieves and binds the previously uninspected official builder UI Source, but still finds no exact selected PKGBUILD or authoritative selected-build transformation record. The useful result is a concrete boundary: this repository is a historical browser/router frontend for a separate builder. The missing input remains two selected recipe/build custody entries, not an inferred architecture rewrite.

Full R1–R5/M5–M9 remains required. Contributor instructions, goal, outline, roadmap, package inventory and the prior correspondence guide were retained. Work owns only `artifacts/reviews/platform-selected-recipe-builder-followup-20261014/` and this guide. No canonical file, Git ref, manifest, account file, package/archive, maintainer message or target actor was touched. No retained JavaScript, recipe or builder code was evaluated.

## Exact selected inputs remain unchanged

| Package | Selected tuple | Required exact PKGBUILD SHA256 | Inherited held BUILDINFO SHA256 / bytes |
| --- | --- | --- | --- |
| systemd | 262-1 / aarch64 | `9ea4d4fa1341fa640f98cbf4bd9b42b7d7c77c2344db2a243b703a6b73b24433` | `8a850564e425c013cdf516327f4bf89992506f89202eae594f6f1a4f8e5350eb` / 9218 |
| pacman | 7.1.0.r9.g54d9411-2 / aarch64 | `3064461fa0821e329e5c9fce4962016e358e1b0d5d259c5d18f7a77174c80219` | `09fb0c1f076f86969614996ce143b5acfa3a7948424baa628c9e484e63ab1f69` / 6909 |

These are inherited selected-package metadata requirements. No binary package or BUILDINFO archive was reacquired. Prior receipt `b6596110026618a9b650e38d65d210d7bd34bd6872dc5abeadde3f0853615c3a`, its exact leaf index, selected next-input request, finite builder inventory/report and systemd input metadata authenticate for the reused paths. The previous unmatched recipe candidates and all earlier negative/failure seals remain unchanged. Neither requested recipe hash was found in this follow-up.

## Concrete official Source custody

The old official organization inventory names [archlinuxarm/plugbuild-UI](https://github.com/archlinuxarm/plugbuild-UI). A new public repository API response confirms owner archlinuxarm, repository ID 3085697, description as a browser management interface, default branch master and archived=true. It records last push in March 2012. These are current retained API observations, not an assertion that the present private builder is archived or uses this implementation.

The branch response resolves to immutable commit `853e993eba55285abbd09db082f38edb5fef83ad`. Its commit API records 2012-03-22T20:55:31Z and root tree `981296f026c5fc3247363a08fd048b4a22da480a`. The exact tree-SHA request returns that root and 408 nontruncated entries. Direct root-tree object encoding independently reconstructs the same Git tree hash. A request using the commit as tree parameter instead reports the commit SHA at the top level; its entries equal the exact-tree response, and this anomaly is explicitly preserved rather than silently rewriting the response. Git object hashing establishes content identity here, not a signature or selected build association.

One fixed ten-entry history page at the full commit records March 2012 commits, including the HEAD and its listed parent. It is not an exhaustive branch/repository history audit. No other branch, private record or renamed/external backend is ruled out.

Six text blobs are retrieved from exact tree-listed Git blob IDs and independently rehashed using ordinary Git blob encoding. Each retained raw Source file is mode 0600; repository mode is separately recorded as 100644.

| Source path at the pinned commit | Bytes | Git blob | SHA256 |
| --- | ---: | --- | --- |
| README.markdown | 1155 | `15d272e7a4647495ecf98c1afc36e62477b0eb74` | `9ef850e55e6b62252d864b798955727c6c89c7e2e490dac4c0890827210e8f12` |
| server.js | 6837 | `fa96de743c6806092284a2069f2aa4c01234d200` | `655fdeac0079be1a9a48db5002dd53e8c9a74ec481cc3d107e42befabf5e65b3` |
| static/app/Packages.js | 958 | `95b20c1bb8c4d1f4154f4830de5e43f50b64a251` | See source-bindings.json |
| static/app/PlugBuild.js | 4272 | `3830311f5215b03d938097aebe03dc3521f5c2fc` | See source-bindings.json |
| static/app/BuilderView.js | 2834 | `5022ed63c5045cf91698ae33ac2e87eb94be22eb` | See source-bindings.json |
| static/PlugBuild-extjs/model/Package.js | 145 | `f3cc82defcc94589f1dd934ec2239872c9186ffa` | See source-bindings.json |

## What the inspected Source establishes

The [pinned README](https://github.com/archlinuxarm/plugbuild-UI/blob/853e993eba55285abbd09db082f38edb5fef83ad/README.markdown) describes unfinished UI/router work, browser Socket.IO communication and a separate TCP builder. It supplies no backend implementation or exact recipe transformation link.

In [pinned server.js](https://github.com/archlinuxarm/plugbuild-UI/blob/853e993eba55285abbd09db082f38edb5fef83ad/server.js#L26), BHOST is localhost and BPORT is 2122. The router serializes commands to that connection, receives package dumps/updates and builder state, and forwards them to clients. Its TLS server requests client certificates and rejects unauthorized clients at lines 108–109. Those are Source statements only; no server or certificate was read or tested.

The [pinned client](https://github.com/archlinuxarm/plugbuild-UI/blob/853e993eba55285abbd09db082f38edb5fef83ad/static/app/PlugBuild.js#L51) contains `https://archlinuxarm.org:7050` as a Socket.IO endpoint. It is retained as a literal, not contacted: the task authorizes public Source GETs, not a live authenticated builder session or command. Package models display package/version/repository and v5/v7 status fields; the builder view displays state/name/package/architecture. The inspected six texts provide neither matching target recipe bytes, a transformation implementation, nor a selected build identifier linked to either BUILDINFO hash. Absence of those tokens in six files is not absence proof for the separate backend, uninspected assets, other branches or private history. UI status fields are not binary/build provenance.

The repository API license is null, and inspected text has copyright notices without a complete redistribution grant. This pass does not settle license completeness for the UI, backend, recipes or selected packages. It transfers no conditional upstream sysusers/libalpm semantics to unmatched binaries.

## Finite network accounting and exact next input

Twelve credential-free public GETs completed with HTTP 200; zero HTTP failures or redirects occurred. There are 247516 response-body bytes and 16201 decoded Source bytes: **263717 counted bytes**, within one unchanged 24-response / 8 MiB allowance. The work paused after four requests during a higher-priority Source correction, then resumed the same ledger without renewing its count or byte caps. Per-request timeout was 20 seconds; summed recorded request elapsed time is 1.9658230959321372 seconds. No hard-wall or failure-path custody proof is claimed. Headers, statuses, URLs, timestamps, exact bodies and hashes are retained in http-index.json; TLS wire framing is not counted as a captured body. Retrieval Source is retained separately. Network is now closed.

The next external input is exactly two custody entries: unchanged recipe bytes matching the required SHA256 with immutable official path/revision binding, or authoritative selected-build records linking those BUILDINFO hashes to exact original/result recipe bytes, immutable backend implementation revision and complete transformation input values. The missing concrete component exposed by this pass is the separate builder behind the historical local TCP service, and its selected 2026 recipe/build records. No public implementation or record URL was discovered in the inspected UI texts; no endpoint or transformation is guessed.

After exact recipe/build correspondence, selected upstream sources, patches/notices, build helpers/arguments and generated constants still require their separate custody. Signature, complete license, account/NSS prestate, allocator/effects/order, runtime/install/image/recovery, 16K, M2 hardware and performance acceptance remain open. The task yields a bounded useful negative with Source custody, not an accepted platform package or full-port result.

Twelve reused input paths, twelve response bodies, six Source blobs and finite joins are recorded. A preseal metadata-only check requested a nonexistent pacman/inputs.json path and refused before its remaining checks; attempts.json preserves that mistake and correction, with zero extra GETs or target actors. No implementation test or new universal proof framework was added.
