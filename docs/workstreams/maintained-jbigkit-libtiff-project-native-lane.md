# Private project JBIG-KIT and libtiff native lane

This is an actor-free implementation proposal, based on Root's retained Source
`50e81e326cc55451a5f41ddfdcfb00fa7f703d85` and parent-selected Data
`b8c2fdff544b8b3b94fd49899ccbe114f1ac51c9`. The proposal does not register a new
Source, dispatch CI, run a build, install on the host, or admit public artifacts.
The current retained selection's 266 Source files were rehashed. These filesystem
joins corroborate the selection; no new Git or remote identity check was run.

The frozen project recipes remain at root receipt
`57891aa0cd2f95211e618093e16efec89816e88e705d0393d02eb7c2c827846b` in
[the filtered-source proposal](../../artifacts/reviews/maintained-jbigkit-libtiff-project-source-filter-proposal-20261014/receipt.json).
Its 155 support files and guide were freshly rehashed. The native proposal is
[a separate packet](../../artifacts/reviews/maintained-jbigkit-libtiff-project-native-lane-proposal-20261014/).
The historical Source `0744…` and run `38495479762` are provenance only. Their
original-cache/build results do not establish a current cache lease or a passing
project-library build. Run `38500392517` is a separate Root diagnostic run.

## Source and publication boundary

The public copy delta carries exactly the original project's thirteen authored
assets, the materializer/controller Source, and plain pin/filter metadata. It
does not copy an original archive, filtered archive, excluded image, generated
PBM, upstream-context patch, private cache chunk, package, build log, extracted
upstream notice body, or a review/Source bundle. Root must use the finite copy
delta, rather than adding the proposal directory recursively.

The job fetches four pinned public objects: JBIG-KIT 2.2 from the author's HTTPS
URL, libtiff's exact GitLab commit archive, and the shared-library patch plus
REUSE declaration from an immutable ALARM packaging commit. The existing source
hashes and sizes bind the responses. Redirects, excess bodies and count/byte
overruns fail the lane. Pinning content does not guarantee URL availability.

The project materializer operates inside a fresh private owned job directory. It
reproduces all twenty JBIG-KIT and seven libtiff recipe inputs byte-for-byte,
including filtered archive hashes `b9de6158…` and `c63abdba…`. The filters retain
37 JBIG-KIT and 318 libtiff Source files. They exclude the frozen image/fuzz,
documentation and historical-generator inputs identified by the recipe packet.
The four downloaded originals and fourteen generated/fetched pack inputs remain
private. The authenticated checkout is not modified to materialize them.

Publication remains false even after a private native PASS. Release work must
resolve the selected combined-work licensing basis and actual preferred-source
coverage, including the separately recorded generator chains, then review the
complete corresponding-source/provider/output association. Existing notices are
preserved; an unresolved publication question is not converted into a private
build prohibition. Private construction is not permission to export a body.

## Fixed build sequence

The lane consumes the existing original 341-package / 501-object maintained
base through the same-job prerequisite. The original input lock, cache
controller and nineteen private descriptor names stay unchanged. The original
165 rootfs packages and 248 declared package rows produce the 341-name union.
It includes the old upstream `jbigkit 2.1-8` and `libtiff 4.7.2-1`; neither is
relabelled as a project result.

1. Authenticate the selected Source, contracts, active callback, original native
   producer context and one Root-issued clock. Accept the exact original base
   image and 341-package lock through the maintained prerequisite.
2. Fetch the four source objects, materialize the frozen twenty/seven inputs,
   and verify every expected input hash before running a recipe.
3. Fetch and verify exactly five builder-only package archives and five detached
   signatures: CMake `4.4.4-1`, cppdap `1.58.0-3`, jsoncpp `1.9.8-1`, libuv
   `1.52.1-2`, and rhash `1.4.6-1`. These are an explicit extension because the
   original base has no CMake. The retained extra database supplies candidate
   pins only; it was not signature-verified. Runtime acceptance requires exact
   archive/signature hashes, a natural zero GPGV result under the pinned public
   certificate/full primary fingerprint, and package metadata/ELF checks.
4. Build project `cachy-asahi-jbigkit 2.2-1.1` twice in different clean native
   aarch64 containers using the original base. Run the frozen serial codec and
   own synthetic conversion checks; require a byte-identical package comparison.
5. Construct an owned, network-disabled, disposable OCI builder layer. Remove
   only the old `jbigkit` package in that layer and immediately install the
   verified project JBIG-KIT artifact plus the five accepted builder packages.
   Require the exact resulting 346-name/version package lock and project-owned
   image identity. A failed transaction remains failed. This image is a private
   build tool, not a tested target or upgrade transaction.
6. Build project `cachy-asahi-libtiff 4.7.2-1.1` twice in separate clean native
   containers from that exact layer. Require the recipe's exact three
   source-generated CTests and a byte-identical package comparison. The excluded
   upstream image suite remains NOT RUN.
7. Inspect all four resulting package archives: exact package/version/AArch64
   metadata and provides, recipe/input/build-image/package-lock association,
   no unexpected install hooks, and structural 16K `PT_LOAD` alignment. Probe
   each selected library's dynamic tags in an isolated network-disabled
   container, matching its archive member hash. Require libtiff's actual
   `DT_NEEDED` on the own `libjbig.so.2.2`, and libtiffxx on `libtiff.so.6`.
8. Record the exact provider/Source/output association privately, then clean up
   only the owned containers/layer. Retain uncertainty after an unobserved
   submission or failed cleanup; a deferred cancellation cannot yield PASS.

The four extra source objects and ten builder-extension objects are finite
additional requests in the same original job frame, not a new acquisition
window. The builder archives total 24,199,992 bytes; signature and source bounds
are separately pinned. No extra fetch, latest-version resolution or fallback
package is authorized by the schedule.

The maintained workflow keeps the original 10,800-second Root clock and the
controller cutoff `min(workflow_end - 120, controller_entry + 10080)`. Source
acquisition, crypto, builds, comparison, inspection and cleanup use that retained
deadline. A consumer does not receive a fresh `now + allowance`. Existing
`common.command`, build/compare tooling and the native prerequisite provide the
execution route; this proposal does not introduce another runner framework.
The existing command helper gains one optional, validated environment argument;
its old default remains unchanged. The new mode passes the Root-bound environment
so the existing builder's Docker calls resolve through `/usr/bin:/bin` and the
registered local endpoint. Both Docker and GPGV bytes/identities and the socket
are checked under the held Source context, including cleanup.

## Root adoption and evidence

Root owns the copy delta, exact Source packet and graph/callback/class
registration, trusted tool/endpoint binding, Code/Source/Data identities,
external plan, branch publication and dispatch. The candidate uses an explicit
`project-libraries-maintained-v1` consumer mode on
`codex/project-private-libraries-v1`, preserving the maintained initial producer
without invoking the unrelated broad development stages. The existing installer
mode returns before a broad-stage library hook; changing only that loop would
not run this lane.

The registered consumer is `Development.consume_libraries_private`. The new
Session path also avoids the added repository producer interposition and its
pending/terminal consumers. Their input acceptance and restaging remain
explicitly NOT RUN, with no phase-public descriptor. The original maintained
producer and its own integration/cleanup results retain their meanings; a
private library PASS cannot certify repository admission.

Root must rehash the exact old joins before copying, regenerate packet/Source
selection and launcher pins for the reviewed candidate, and register actual
future commit identities. This proposal invents none of those identities and
does not treat the current selection as admission of the new mode. A stale
Source or a changed descriptor/body requires a new explicit reconciliation.
No main merge is part of this handoff.

Public job output is a positive, bounded status/hash projection. Internal paths,
exception text/notes, source packs, original inputs, signatures and packages are
excluded. Private records retain the first cause and close/cleanup uncertainty.
All failed packages remain visible; unavailable CMake, signature refusal,
non-reproducible artifacts, dependency conflicts, deadline exhaustion and cleanup
failure are failures of this lane.

Preparation checks execute only project-owned inert helpers and modeled actor
interfaces. Source materializer controls reproduce the frozen twenty/seven
inputs and exercise corruption, traversal, type, callback-cancellation and
first-cause preservation. Those checks are not native compiler, codec, CMake,
CTest, GPGV, Docker or hardware results. The final sealed receipt names the exact
checks and independent review status.

Actual native builds, library runtime/ABI acceptance, installation/removal,
target integration, both 13-inch and 15-inch M2 Air hardware checks,
performance/power measurements, public promotion and complete corresponding
source acceptance remain NOT RUN or unresolved. Structural ELF alignment does
not establish 16K-kernel execution or M2 compatibility. This lane advances the
R1/A05/A12 source/build track only. R1–R5, M5–M9 and A01–A15 remain incomplete.
