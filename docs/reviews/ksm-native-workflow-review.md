# Independent KSM native workflow review

**PASS for coordinator source registration within this bounded workflow scope. No actionable workflow finding. GitHub server validation, upload and native execution were not run.** Reviewed 2026-10-12 after reading project instructions, roadmap and inventory. The separate 229-test source/J1/J2/J3 review is outside this review; that suite was not rerun.

## Held inputs and actual checks

| Input | SHA256 |
| --- | --- |
| `.github/workflows/native-arm-ksm.yml` | `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae` |
| `scripts/port/ksm-native-job/source-checkpoint.json` | `e54715b27d8ff753be0e4a07b3301485f80f3cd1e619205a641732d80b39d099` |
| `/tmp/cachy-root-ksm229-candidate-20261012.json` | `631df29044c624ef0c6d0d2d0c178e7cff489e2395071a679125a1fa7adb80a5` |

These actual byte hashes remained held before and after the local checks. The candidate's 152 entries, totaling 2,180,717 source bytes, matched every actual file's hash, size and mode and the exact `required_paths.EXPECTED_PATHS` set. The candidate was read only; no production packet was written or registered.

The installed primary parser `yaml-cpp` 0.9.0 successfully parsed the actual YAML. A small locally compiled C++ helper preserves scalar mapping keys, extracts the actual structure and rejects duplicate keys. Python assertions checked the resulting tree, including the literal `on` key. Actual inline bash passes `bash -n`; its extracted Python parses and compiles. The parser/helper and six bounded bootstrap fixtures are retained under `artifacts/reviews/ksm-native-workflow-root-peer-20261012/`; `receipt.json` records actual outcomes. No dependency was installed.

## Trigger, trust and time boundaries

The workflow has only manual `workflow_dispatch`, a required string packet digest, read-only contents permission, the exact repository guard, pinned checkout/upload actions, checkout at `github.sha` and disabled persisted credentials. It selects `ubuntu-24.04-arm` with a 150-minute job limit and the same `native-arm-build` concurrency group used by the other native workflows; `cancel-in-progress: false` preserves the running job. This shared group serializes running jobs, not an unlimited queue guarantee.

GitHub currently documents `ubuntu-24.04-arm` as a standard ARM64 hosted runner and standard runner use as free for public repositories. This supports the selected runner category for the public repository; it does not establish current VM capacity or execution readiness. [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The startup reads the external digest from the environment, refuses malformed digest text, captures the packet through nofollow directory/file descriptors and checks its actual digest/mode before executing either initial module. Acceptance and required-path modules are themselves captured and checked against packet hash/size/mode before execution. `acceptance.capture` then requires the exact finite source schema/set, includes the workflow, checks current bytes/modes, binds both GitHub SHA variables to the expected commit, checks actual Git HEAD/tree/blob bytes and modes, and rechecks HEAD. Its Git subprocesses disable hooks, replacement objects, credentials/network/lazy fetch and optional locks. This is a source inspection of the held implementation, not new committed-source acceptance evidence.

Only authenticated captured bytes enter the fresh exclusive bootstrap tree; copies are reread and compared. The executor launches from that tree with `-I -B -S` through `os.execve`, retaining the workflow's initial monotonic source clock and the child's actual exit result. The executor repeats source acceptance. Its shared-source elapsed check is 180 seconds; the aggregate deadline remains initial source clock plus 8,460 seconds (141 minutes), within the 150-minute hosted limit. Original producer 6,600 seconds, two builds at 360 seconds each, comparison 120, lifecycle 600, cleanup 180 and public export 30 retain their existing phase/aggregate limits. This workflow review verifies timer wiring and held values; the separate runtime review covers enforcement. Checkout and action upload remain subject to the outer job timeout.

## Actual exit gate and closed artifact set

The native step has no `continue-on-error`, uses bash and ends with the single Python heredoc. Upload requires `steps.native.outcome == 'success'`; saved PASS JSON is not its decision input. The exact unmodified inline bootstrap was executed locally using freshly pinned, owned fake acceptance/required-path modules and a tiny executor. Source/Git/native acceptance in those fixture modules was deliberately mocked.

| Fixture | Actual bash exit | Executor ran | Local upload-gate model |
| --- | ---: | --- | --- |
| Normal zero exit | 0 | Yes | Admit |
| PASS JSON followed by nonzero exit | 75 | Yes | Refuse |
| PASS JSON followed by SIGTERM | 143 | Yes | Refuse |
| Wrong external packet digest | 1 | No | Refuse |
| Tampered initial module | 1 | No | Refuse |
| Mock source-preflight refusal | 1 | No | Refuse |

These are real local bash/Python/execve/signal results, not GitHub expression-engine or native-job tests. They establish that the bootstrap does not mask a failed or signaled executor exit.

Upload names **five literal candidate paths**: build-1 and build-2 each permit the exact `.xz` or `.gz` package filename, plus `evidence.json`. The successful exporter produces **three actual files**: one archive per build and one evidence file. Held `public.validate` requires exactly two builds, an allowed exact filename and the same filename/hash for the pair; `public.export` creates fresh exclusive directories, writes one file per build and one evidence file, and verifies exact namespace contents, bytes, identities and modes. Thus both archive alternatives cannot coexist in a successful accepted namespace. The native exit must also remain successful. No wildcard, source tree, logs, key, signature, recursive directory or arbitrary filename is uploaded. The action excludes hidden files, forbids overwrite, errors when no files are found, retains one day and applies no compression. This conclusion assumes the existing cooperative owned namespace; it adds no stronger same-UID race guarantee than the source documents.

## Scope and remaining work

Ready for coordinator registration within this review's scope; actual committed packet/Git acceptance still requires the coordinator's final freeze and external digest registration. Local YAML parsing is not GitHub server acceptance. Actual hosted bootstrap, daemon operations, producer, KSM builds/comparison/lifecycle, cleanup, upload, hardware and performance remain untested here. The source checkpoint's worker-era parser-unavailable statement is supplemented by this actual root-side parser result, without changing that held checkpoint.

Only this review document and its owned review artifact directory were written. No workflow/source/checkpoint/packet/shared lock, project Git state, registration or dispatch was edited; no real Docker, native job or network upload ran. Public GitHub documentation was read only. The prior kernel review remains untouched.
