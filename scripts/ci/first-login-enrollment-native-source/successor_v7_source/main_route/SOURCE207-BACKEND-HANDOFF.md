# Source207 backend evidence handoff

Source207 is `5c6bc061d547017fd9be412e3addfc2f8bbf9e65`, workflow `420175404`, with one original attempt. The admitted case binds the separately committed Main launcher for that attempt. Keep the static projection for that Main and the original once-entry operands together.

## Review the original terminal

Run `python3.14 -I -B backend_stage_review.py --selection "$SELECTION" --selection-sha256 "$SELECTION_SHA256"` from this directory. Use canonical JSON for the selection and an independently retained whole SHA-256. Its fields are `schema: 1`, `kind: SOURCE207_BACKEND_STAGE_REVIEW_SELECTION_V1`, `packet` and `inputs`. Each input has an ordinary absolute `path` and a whole `pin` with `bytes` and `sha256`. The packet path is its directory and its pin covers `PROJECTION.PASS.DATA.json`.

| Input | Retained operand |
| --- | --- |
| `prepost` | The Root once runner’s durable pre-POST marker |
| `execution` | Its `execution-result.json` with the one unambiguous original attempt |
| `case`, `request` | Exact admitted case and request body retained by the same runner |
| `run`, `jobs`, `artifacts` | Whole original GitHub terminal run GET, attempt-1 jobs page and artifact inventory |
| `archive` | Optional original control ZIP joined to the exact listed artifact ID, size and SHA-256 |

Keep a successful roster and a missing archive as separate observations. The reviewer can report metadata while the original is absent or awaits retrieval. The retained ZIP reader replays Native248 command 2 and the complete material intake with staging closure when those are present. The classifier also shows whether the prerequisite report, natural retirement, scope absence and refreshed job context were retained. A matching final controller report can show its natural retirement and twice-empty scope. A HOLD preserves the observed failure phase and earlier evidence.

The registered artifact has seven allowlisted control members. Source207 can independently establish the retained Native248 checkpoint and report controller retirement from that artifact. Full package replay needs the backend capsule and the independent Root support below. First usable login additionally needs a later authorized runtime observation.

## Select private same-job custody

`python3.14 -I -B backend_private_handoff.py` reports the existing public-control-only mode. An explicit same-job caller may run the same command with `--mode private-same-job --selection "$SELECTION" --selection-sha256 "$SELECTION_SHA256"`. This helper is available for a selected successor integration. Source207’s registered workflow has no such hook and its upload scope remains unchanged.

Use a canonical `ROOT_SOURCE207_PRIVATE_BACKEND_SNAPSHOT_V1` object with `schema: 1`, `issuer: Root`, `approved: true`, exact local `owner_root`, `control_root` and `private_root`, the admitted `nonce` and runtime `binding`, and `expected` with the five separately whole-pinned roles below. Bind `source`, `ref`, `source_lock`, string `run` and `job`, and numeric `attempt: 1`. Use the owned `cachy-current-<nonce>` executor directory and `cachy-current-hosted-<nonce>` launcher control directory. The caller supplies a separate mode-0700 job-local directory owned by the non-root job user. Its path must be disjoint from both trees. Run the hook only after the executor and the outer material domain have naturally closed.

| Role | Input path | Private output |
| --- | --- | --- |
| `capsule` | Executor `evidence/public/delegated-backend-public-v4.tar.gz` | `backend.capsule.tar.gz` |
| `manifest` | Executor `evidence/public/delegated-backend-public-v4/retention-manifest.json` | `retention-manifest.json` |
| `owner` | Executor `evidence/owner-result.json` | `owner-completion.data.json` from the bounded completion fields |
| `executor` | Executor `executor-report.json` | Original pin and successful clean-retirement validation in `handoff.json` |
| `launcher` | Control `public/launcher-report.json` | Original pin and successful controller and material closure validation in `handoff.json` |

The helper checks the retained manifest against the identical member in the bounded capsule, joins owner completion to exact capsule and manifest pins, and requires natural retirement and absent owned storage. It creates `backend-handoff` once under the private root. Retained files have mode 0400. Keep this directory out of every artifact upload. The caller independently retains the emitted `transfer_pin` before consumption.

## Replay packages and progress to runtime

Call `backend_private_handoff.replay` with the retained directory, independently retained transfer pin, canonical `ROOT_BOUND_DELEGATED_PUBLIC_READER_V4` bytes and whole pin, exact Source file map, complete whole-pinned `support_refs` and trusted observation time. The unchanged Source207 Reader is the package replay authority. It requires:

- Runtime inputs, runtime receipt, domain and image qualifications, and command observations.
- Base lock, bootstrap profile and baseline inventory.
- Prerequisite timing, report, initial context, launcher, controller and qualification.
- Material grant, assembly request, staging, close and qualification.
- Separate same-run completed-producer evidence plus enrollment and first-login component records.

The owner’s completion projection serves custody. Root’s completed-producer evidence independently joins the successful hosted attempt. A selected successor must retain the supporting native observations before runner retirement and bind its exact Source and Reader anew if its commit identity changes. A local capsule handoff alone establishes neither the supporting qualifications nor a path for exporting them.

Carry the independently replayed enrollment and first-login archive and payload pins into an exact Root package adoption. The next runtime admission needs the selected packages, source, actor and stage contracts. Establish a real first usable login from its owned runtime observation and terminal evidence under that separate admission.

## Controls

Run `python3.14 -I -B test_backend_handoff.py`. Add `--packet "$PACKET" --projection-sha256 "$PACKET_SHA256"` for a known original static projection. The controls exercise the genuine pinned static Source packet paired with synthetic terminal metadata, modeled prerequisite retirement, bounded capsule custody and refusal of foreign, unsafe or incomplete inputs. They create no hosted trial result.
