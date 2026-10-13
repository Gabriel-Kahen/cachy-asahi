# Actual hosted ARM observation 38347013591: independent retained review

**PASS for the retained actual read-only hosted observation. No broader acceptance follows.** [Run38347013591](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38347013591) and [job115130661003](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38347013591/job/115130661003) completed successfully at source/workflow commit `42fcd8c07b2d63798833f0f00f31a7ba2f37cba8`. This peer reviews retained evidence only; it did not retrieve network data, hash current host tools, rerun the observation, execute actors or repeat the earlier31 synthetic controls.

Root completion `artifacts/native-arm-runner-observation/run-38347013591/completion.json` authenticates as `3b4f26df587958c15ceb5f61143f41ca2c7c72306ada29ef95edd2240ef38cc5`. All three bound artifacts—run metadata, full log and observation JSON—authenticate exactly. Run metadata records completed/success for the run and its sole `observe` job; setup, `Trusted read-only observation before checkout`, and completion steps are all completed/success.

## Output and code provenance

There is exactly one complete actual JSON output record in the log, at line298 and remote timestamp `2026-10-13T04:33:35.7887868Z`. It occurs after the echoed script/heredoc closes. Parsed and canonicalized, it exactly matches the retained5059-byte `observation.json`, SHA-256 `d937889c44695a0fb1533daec04bbea979bc310383e25708654ebc117cdccb16`. The echo is source text, not a second observation or an output result.

Removing only log timestamps and the runner's literal color markers reconstructs11740 bytes of inline observer source, SHA-256 `ad6d7908ef1dca36356cc5c8450f655c323021ec1ab89b4569708d4297989b4b`. Those bytes match the previously reviewed observer, primary helper and primary workflow inline body. Root's retained committed-source proof binds that helper and workflow to `42fcd8c0…`; workflow bytes authenticate `8413190ba16aa817414828fd86080a44536e8896bd2a0c211471cb9fb202093d`. The proof's earlier `PENDING_JOB_RESULT` field remains historical; later completion is established by the separate completed run/job evidence.

The adopted workflow uses `ubuntu-24.04-arm`, group `native-arm-build`, cancellation disabled and a five-minute scheduler cap. The single inline `/usr/bin/python3 -I -B -S` observation precedes any checkout and has no action/project checkout step. Body identity, declared job source/workflow SHA, retained Root committed-source proof and Actions run/job metadata agree. No fresh Git query or remote provenance retrieval was performed by this peer; the exact retained Root proof and log are the provenance basis. Root's separate static run38347013551 PASS is handoff context and was not re-fetched or independently revalidated here.

## Actual observed facts

The report records `aarch64`,4096-byte pages, UID1001, ImageOS `ubuntu24-arm64` and ImageVersion `20261004.142.1`. All tool/interpreter/socket/workspace sections are `OBSERVED`.

| Fixed file | Observed bytes | Actual SHA-256 |
| --- | ---: | --- |
| `/usr/bin/git` | 4460200 | `4cda0087547ee12bef91952e1123debb4bd2ec621838b347b5ca4fdaa6fecb58` |
| `/usr/bin/docker` | 41651784 | `94128e4afada0d46de642165e79dd70beb08e6775014648013283ed901b68248` |
| `/usr/bin/python3.12` | 7845048 | `c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960` |

Each hashed file records UID/GID0, mode0755, one link and stable named/descriptor identity under the reviewed code. Interpreter entry `/usr/bin/python3` is one root-owned, single-link symlink to `python3.12`; the symlink mode is0777 and the final regular target is0755. This observes on-disk bytes and custody checks, not the complete running interpreter dependency chain or memory image.

The socket is `/run/docker.sock`, root-owned, GID118, mode0660, recorded as stat-only and not connected. No Docker CLI command or daemon behavior is tested. Socket metadata alone does not prove permissions, daemon isolation or trusted images.

Original workspace `/home/runner/work/cachy-asahi/cachy-asahi` and temporary path `/home/runner/work/_temp` are disjoint. Retained ancestry metadata independently agrees with the three true fresh-sibling prerequisite flags: parent UID matches runner, parent excludes group/other writes, and original/temp UID match runner. No sibling was created, no Git/Docker commands were invoked, no project checkout ran, and no execution grant or real development clock was issued by the observer. The previously reviewed read-only source plus exact executed echo and successful step support those bounded claims.

Remote job completion is `2026-10-13T04:33:37Z`. Root's completion artifact records local retention/finalization timestamp `2026-10-13T04:40:11.882261+00:00`; it is a separate later record. Neither that local timestamp nor the coarse remote job/step timestamps is a performance measurement or development-clock attestation. The implemented60-second observation allowance and remote scheduler cap are not treated as physical syscall or disposal guarantees.

## Root selection and remaining gates

Root can use these retained actual hashes/metadata for explicit runtime selection. Every later job must rehash the selected binaries, recheck ownership/mode/path/socket/workspace constraints and bind the runtime contract for that job. Image/version labels and current checksums cannot guarantee future byte identity or silently renew pins.

This completed observation does not establish private-runner isolation, usable/trusted Docker daemon or images, complete descriptor disposal, native package/build/runtime/P0 acceptance,16K page compatibility, Asahi integration, either exact M2 machine, maintained releases/lifecycle or measured performance. Existing Source265/bootstrap registration is unchanged by the observation adoption and by this peer. R1–R5/M5–M9 remain incomplete project requirements. This peer writes only its new retained-review namespace and this review; primary/maps/workflows/Git and prior sealed artifacts are unchanged.
