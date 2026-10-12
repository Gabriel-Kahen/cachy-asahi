# Tools/defaults workstream report

Completed October 11, 2026, within `docs/audits/tools-defaults.md`, this report,
`packages/shells/` and `packages/settings/` only. Shared manifests, root docs,
LICENSE, Git state, other workers' paths and the host package/system state were
not edited. No other chats were messaged by this worker.

## Delivered

- [Consolidated audit](../audits/tools-defaults.md): exact pins for Fish v16,
  Zsh v1.0.3 and settings 1.4.1; source grants/notices, declared/transitive
  dependency observations, config ownership, hooks, platform effects, and
  coordinator-only manifest proposals.
- [Settings audit](../../packages/settings/AUDIT.md) and
  [49-file inventory](../../packages/settings/upstream-inventory.json): every
  installed file and individual sysctl is assessed. No default is selected and
  no settings recipe/installer is created.
- [Original Fish recipe](../../packages/shells/cachy-asahi-fish-config/README.md):
  only `caa_ll`/`caa_mcd` interactive helpers, preserving existing functions;
  runtime fish + coreutils; three files under `/usr/share`.
- [Original Zsh recipe](../../packages/shells/cachy-asahi-zsh-config/README.md):
  explicit completion setup and separate plain-prompt opt-in; runtime zsh;
  four files under `/usr/share`.

The shell alternatives are original minimal implementations, not wholesale or
feature-equivalent CachyOS derivatives. No third-party config, theme/plugin,
font or binary is included. Both copy the actual coordinator-selected MIT root
LICENSE into the package, with local source checksums and notices. The original
licensing blocker was cleared by that selection; upstream grant gaps remain.

Installation owns no skeleton, global rc or user file and selects no login shell.
No install/remove hook or service/config/system mutation is added. Users opt in
with documented guarded source lines; missing files after removal leave those
lines harmless. Existing process state lasts until a new shell. Package-manager
lifecycle behavior on the target is documented but **NOT RUN**.

## Actual checks and review

| Check | Result and limit |
| --- | --- |
| Pinned Fish tag archive checksum | PASS against upstream recipe's declared SHA256; commit archive and each source file also hashed |
| Settings inventory | PASS, 49 unique paths and every byte hash compared with full pinned archive; archive/extracted/Git modes distinguished |
| Fish Bash/Fish syntax and isolated-home behavior | PASS, Fish 4.9.3; noninteractive guard, existing functions, repeated source, spaces/leading dashes, invalid arguments, no privileged aliases or universal writes |
| Zsh Bash/Zsh syntax and isolated-home behavior | PASS, Zsh 5.9.2; completion, opt-out/reuse, optional prompt, unchanged user files/history/aliases, noninteractive/repeated/removed-source behavior |
| Recipe `.SRCINFO` consistency and local source hashes | PASS for both; generated metadata matches final recipe and MIT grant matches root byte-for-byte |
| Fish package assembly | Two final MIT-source `makepkg --config /etc/makepkg.conf --noconfirm` builds PASS in separate temp directories on x86_64; check() ran, no install/syncdeps flags |
| Zsh package assembly | Two final MIT-source `makepkg --nodeps --nocheck` builds PASS in separate temp directories on x86_64; dependency/recipe check skipped, syntax/runtime checks separate |
| Repeat payload comparison | PASS for both final MIT packages; archive bytes differ due generated metadata, not a reproducibility claim |
| Static recipe checker | PASS both with build worker's `package_checks.recipe`; body/source review remains separate |
| Fish actual archive inspector | PASS both with build worker's `package_checks.package`; no binary/hook/protected paths |
| Independent source review | Fish reviewed read-only by settings audit subagent; Zsh reviewed read-only by this worker, with syntax/behavior checks rerun; settings archive/coverage independently verified by this worker |
| Clean native aarch64 builds/rebuilds | NOT RUN; no verified builder |
| Chosen Asahi snapshot dependency/conflict resolution | NOT RUN; metadata availability is not target resolution/signature trust |
| Installation/upgrade/removal/reinstall | NOT RUN |
| M2 Air 13-inch/15-inch validation | NOT RUN |
| Performance/power results | NOT RUN; no improvements claimed |

Final actual commands, source hashes, package file lists, payload/archive checksums,
and retained logs/build metadata are under each recipe's `host-validation.json`
and `evidence/`. Fish temporary archives are referenced for development review;
Zsh temporary archives were removed after evidence capture. Neither is a release
artifact. ARM runtime observation JSON files pin exact fetched catalog/database
bytes, while explicitly leaving trust, version constraints and target snapshots
unverified. Research and checks retrieved files and built only in temporary areas.

Independent Fish review originally covered two payload files; final MIT selection
added a third license file and refreshed notices/metadata/builds. The code behavior
is unchanged apart from its license header. A second independent Fish review verified root-license equality, checksums,
metadata, both final artifacts and behavior; final source/metadata checks and the
archive inspector cover those updated inputs. Zsh's final source/metadata and
checks were likewise refreshed after MIT selection.

## Coordinator manifest proposals and blockers

Do not mark M0/M1 complete or call these packages installed/hardware-tested.

| Package | Proposal | Blockers or next gate |
| --- | --- | --- |
| cachyos-fish-config | deferred/source-audited | Missing main-config grant, history-plugin notices, unavailable module recipes, protected boot/mirror aliases, selected-base dependency solution |
| cachyos-zsh-config | deferred/source-audited | Missing main-config grant, absent framework/theme in observed ARM repositories, imported source/license closure and broad overrides |
| cachyos-settings | deferred/source-audited; select zero defaults | GPLv1 recipe/GPLv3 source mismatch, service enablement without restoration, PC effects, target baseline and individual acceptance/restoration evidence |
| cachy-asahi-fish-config 0.1.0-1 | candidate/host-packaged, MIT, explicit opt-in | Clean native ARM build/repeat; target dependency/ownership solution; actual config/package lifecycle; M2 functional evidence |
| cachy-asahi-zsh-config 0.1.0-1 | candidate/host-packaged, MIT, explicit opt-in | Same clean ARM/base/lifecycle/hardware gates |

Attach exact upstream commits and this consolidated audit path to candidate
records. If the manifest supports only coarse statuses, keep original alternatives
candidate and store host build evidence separately. Kernel-manager/chwd remain
deferred; no x86 tuning or platform-stack replacement is introduced.

Later settings work should extract one licensed, needed optional diagnostic or
one measured experiment at a time. The audit identifies zram, swappiness,
page-cluster, THP geometry, per-device scheduler, explicit wireless-country and
Zink candidates with their own prerequisites. Missing baseline/hardware evidence
is a named gate; no broad settings bundle is justified by source declarations.
