# Updated roadmap: bounded software-gap review

October 12, 2026. **Keep the active runtime corrections moving; add two small, separately owned software deliverables: complete baseline installed-payload correspondence and one selected opt-in shell function.** Neither requires inventing a hardware PASS or another general execution framework. The six requirement/status documents and nineteen supporting inputs are hash-bound in [snapshot.json](../../artifacts/reviews/updated-roadmap-software-gap-20261012/snapshot.json). This review changes no implementation, shared document/map/workflow or Git state and runs no actor or test suite. The prior runtime7 review remains frozen.

## Requirement and queue reconciliation

The current goal, outline, roadmap and A01–A15 contract consistently require R1–R5 on one maintained release. M5 requires the declared base/desktop/application closure; M6 requires applicable management/shell/desktop functions or reviewed working replacements; M7 requires maintained protected-platform integration and measured target behavior; M8/M9 require complete installation/recovery and a subsequent release. An overlay, feasibility report, generic ARM build or emulated desktop cannot finish these requirements. Physical baselines, both Air sizes, boot/session recovery and final power/performance records remain outside this software review.

The development manifest explicitly is not an install list. It lists four original templates/setup recipes, KSM, updater and FDK as development candidates, with release selection false. The tools and desktop audits propose broader coverage but do not select a release. The current native builder lock supplies Zsh5.9.2-1 and Fish4.9.3-1; those signed-input records do not prove a target shell/module lifecycle.

I reconciled the written backlog/latest19:43 status with the coordinator's actual queue rather than treating historical pending descriptions as new work:

| Active lane | Necessary gate it advances | Do not duplicate |
| --- | --- | --- |
| FDK package-function/build diagnostics | A05/A12 actual codec builds, then provider/PipeWire integration | Another source serializer or generic compiler harness |
| Updater checked mount/private-IPC correction | A13 concrete entry failure before compiler; then build/pair and actual update/recovery | New tray/upgrade framework before this actor can compile |
| Guest SVG/client loader diagnosis | A02/A13 generic software compositor/client frame proof | Treating a virtual monitor/IPC reply as a usable frame or M2 graphics |
| KSM RPC observations and kernel resource labels | A13/A14 existing native producer/provision failures | Changing transport/resource semantics without a causal observation |
| Repository runtime7 correction, adapter, public ACK and issuer callback | A06/A12 missing fresh same-job raw/CID/checkpoint/341-metadata custody | Another authority schema/collector instead of finishing the reviewed callback path |
| Installer interrupted capsule disposal, peer review and tiny transaction | A03/A15 real copied-root payload operation with correct final failure custody | New installer/partitioner or premature ARM/full624 admission |
| Protected closure c21 successor and camera cancellation/adapter work | A12/A13 concrete unresolved providers/protected witnesses and camera API | Another resolver/preview framework; a camera preview cannot accept a missing backend |

The kernel backlog row still describes the earlier Labels retry, while the latest status/actual queue is resource diagnostics after kernel5. Other old rows similarly retain earlier execution points. Reconcile those summaries through the coordinator after review/adoption; this is not a new implementation blocker. The existing runtime7 correction is source-ready, but the complete adapter/issuer path is still an active dependency.

## Batch S01: verify the complete installed baseline against retained archive payloads

**Confirmed omitted input:** full261-package baseline file correspondence. This is distinct from already acquired archives, metadata resolution and the install worker's seed preservation.

- `scripts/platform/capture.py:image_inventory` reads package database descriptors through read-only debugfs; it does not inspect the complete installed file payload.
- `scripts/platform/payload_audit.py` observes exact archive nodes/links/hooks and explicitly leaves `complete_installed_payload_verified:false`. The actual624 audit closed unavailable archive data; the static ELF result still retains27 missing requests/22 firmware refusals.
- `scripts/install/local_transaction.py` hashes/copied-seed state, checks complete before/after inventories and added payload, and preserves declared protected files. That proves preservation of the supplied seed. It does not establish that every preinstalled package's seed files correspond to independently authenticated archives. Its current synthetic scope also refuses real-candidate inputs and suppresses hooks/scriptlets.
- The earlier [complete-install software review](complete-install-software-gap-review.md) names this same remaining distinction. No current lane owns the full baseline comparison; the active installer correction addresses terminal disposal, and c21 addresses metadata/provider choices.

**Small deliverable:** a finite read-only correspondence checker for exactly one pinned baseline image/tree and its261 exact baseline package identities, using the retained signed archives and archive-node report. Require types, bytes/hashes, link targets/relationships, modes, uid/gid, and local package file ownership to agree. Report generated/modified/missing/unexpected nodes separately; no wildcard generated-file exemption or metadata-only PASS. Preserve mismatch evidence, old reports and all trust/installation/hardware flags. This can be developed with tiny inert tree/archive fixtures before any new image inspection grant.

| Proposed exclusive ownership | Scope |
| --- | --- |
| NEW `scripts/platform/installed_payload_correspondence.py` | Narrow comparison and bounded read-only image/tree adapter, reusing the frozen capture/payload contracts; no package execution/extraction, mount, installation or trust mutation |
| NEW `scripts/platform/test_installed_payload_correspondence.py` | Causal file/type/mode/owner/link/inode/replacement and incomplete-inventory controls; source/image/archive digest drift and finite-reader refusal |
| NEW `docs/workstreams/platform-installed-payload-correspondence.md` + private artifact namespace | Exact input/source/cap bindings and actual mismatch/gap report, without promotion authority |

**Exact prerequisites:** root grants the retained raw image/tree bytes and image digest/length, complete261 inventory/ownership records, exact same-name/full-version/architecture baseline subset of the624 archive contract, each archive/signature and signer-evidence binding, frozen reader/helper hashes, and explicit existing file/aggregate/time/report caps. The current platform pointer keeps image authentication and independent key-owner trust unaccepted; a comparison must not manufacture those. Use the existing read-only debugfs route only after its binary/command grammar and resource contract are captured/reviewed; never mount the image or execute its packages. Reject an absent reader/source grant rather than inventing a tool dependency. Do not silently enlarge any cap for the complete image.

**Done for this batch:** source reviewed, tiny causal fixtures pass, and an authorized read-only full261 comparison has exact actual counts/mismatches and immutable inputs. Any generated-file policy stays explicit and unfinished until separately reviewed. The result supplies a software prerequisite for a later real-candidate copied-root transaction; it does not accept the image issuer, full release transaction, ABI, hooks, target installation or physical platform. The existing worker's real-candidate refusal remains intact until its own reviewed extension.

## Batch S02: ship one bounded selected shell function, using the existing build path

**Confirmed unassigned implementation:** tools audit T02. Fish currently defines only `caa_ll` and `caa_mcd`; Zsh initializes completion and optionally sets a plain prompt. They do not implement the audited autosuggestion/history/highlighting functions. KSM/update progress cannot stand in for these shell functions. Themes, fonts, every plugin and the whole ungranted Cachy configurations are not mandatory imports: the coordinator must select the finite functions or qualify working baseline alternatives.

Select one first function: **opt-in Zsh autosuggestions** from the audited full pin `85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5`, with renewed selected-file/notice verification. This is a concrete package/runtime behavior increment and avoids compiled gitstatus/theme/font dependencies. Prefer an exact maintained ARM-base module if the retained catalog/archive actually supplies the selected source; otherwise package the pinned licensed module. Do not infer a base package/version exists from its name or a license audit.

| Proposed exclusive ownership | Scope |
| --- | --- |
| NEW `packages/shells/cachy-asahi-zsh-autosuggestions/**` | Recipe, selected upstream source/provenance/license/notices, original opt-in activation snippet, README and tests; no login-shell change, startup downloads, global rc edit or hooks |
| NEW `docs/workstreams/zsh-autosuggestions.md` + private source/build evidence | Selected function/alternative, exact dependencies, tests, two-build proposal and remaining acceptance |

**Exact prerequisites:** coordinator function selection; actual retained module bytes from the full source pin plus per-file grant/notices and checksums; explicit dependency on the selected Zsh (the current builder record is5.9.2-1); archive/file ownership and metadata review; exclusive ownership separate from the four original package directories. Native registration/dependency/source-map changes stay with root. Do not overwrite the original Zsh source/helper or setup's packaged mirror to make this first increment work.

**Concrete checks:** noninteractive sourcing does nothing; opt-in interactive behavior actually produces the selected suggestion/accept operation; repeated source and existing module/widget/keybinding cases preserve user choices; history files/content/permissions remain unchanged; interruption/removal leaves only package-owned files affected; no notification/network/install action or printed command-history secrets occurs. Use isolated temporary Zsh/PTY fixtures, not the user's home/session. New compiled/binary ARM or16K claims are unnecessary for this source-only module. Static recipe/source checks and the existing clean build/compare path should supply two independent native attempts after root registers the exact input closure—no new Docker/controller/workflow family.

**Done for this batch:** reviewed module/activation recipe, actual finite shell-behavior controls and two clean native package builds, with opt-in lifecycle limitations recorded. This advances A05/A13 but does not finish the complete shell matrix, target login/keybinding behavior or both-model A04. If a reviewed base-shell alternative is chosen instead, the coordinator must bind its actual tests and functional coverage; absence of a plugin is not itself a hardware blocker or permission to waive the function.

## Later dependencies and stop conditions

Complete release selection is still required: the proposed46 desktop roots, four originals and actual target platform are not an accepted manifest. C21's two protected witnesses, graphics alternatives and missing target consumers need explicit coordinator selection and retained source/authentication before any full transaction. Finish those existing paths instead of adding another name-only graph or public acceptance vocabulary.

The read-only Apple management/status interface T04 remains a later software gap: capture-baseline reports facts, while current KSM and kernel build tools do not provide a shared accepted platform/update/recovery backend. Start its narrow status consumer only after the selected platform/capability inputs and intended manager contract are frozen; unknown models/recovery sets must remain unsupported. Do not design a privileged kernel/boot backend or Welcome GUI ahead of those inputs. Desktop service/session/portal/audio integration likewise needs the selected base launcher and compatible package set; a generic guest frame supplies useful exercise, not that selection.

A08/A12 require repeated maintenance/security updates and named custody/capacity. Existing package/release helpers check pins and stage/promote bound artifacts; no source result appoints a maintainer or proves an operational update. Root should bind the actual release package set, staffing/keys/endpoint and one concrete subsequent-update exercise. Another generalized monitor, signing framework, certification layer or unchanged broad test rerun would not supply those missing inputs. Add automation only for a selected repeated operation with a responsible maintainer.

The next implementation batch should therefore keep the active failure fixes/callback integration in flight and assign S01/S02 to nonoverlapping owners, each with one independent reviewer. Their source work can proceed now from explicit inputs, with actual full-data/native execution admitted separately. Physical access, maintenance custody and publication terms stay visibly open. No both-M2,16K, performance, installed full port or maintained-release PASS is inferred.
