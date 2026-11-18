# Source207 backend

Source207 uses the registered workflow 420175404 with the same YAML, canonical
launcher path, and standard `backend` stage. The explicit Main commit must
contain the Source207 launcher and `reader_current_v3_source207.py` at the
exact whole-file pins in [source207.py](../request_generation/source207.py).
The existing provenance operand at `successor_v7_source/payload/hosted.py`
binds the historical caller used by Source205 and Source206.

The four initial HTTPS routes are the exact archive and detached signature
for each of cmake 4.4.4-1 and libuv 1.52.1-2. They select already public bytes
from commit `ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad`. The 517 frozen
archive, signature and keyring pins, the 21 download identities and all
existing package trust gates carry forward. Supply an empty redirect list
for the four retained URLs when Root issues the 21-entry grant.

Use the [backend checkpoint guide](BACKEND-CHECKPOINT.md) with these selectors.

| Operation | Selection kind |
| --- | --- |
| Prepare unissued backend DATA | `SOURCE207_BACKEND_DATA_SELECTION_V1` |
| Check the separately Root-bound request | `SOURCE207_BACKEND_QUALIFICATION_SELECTION_V1` |
| Replay bounded terminal metadata and the retained Original | `SOURCE207_BACKEND_TERMINAL_SELECTION_V1` |

Source207 retains the [Source206 TEST certificate and expiry](SOURCE206.md).
The independent Source207 Reader verifies the entire Source207 body and mode
tree, reconstructs the exact Source206 and Source205 trees using the two
retained DATA inverses, and checks the original Source205 through Source139
inverse chain. It independently recomputes the four effective download URLs
and the child request pins while retaining the frozen archive and signature
pins. The terminal checkpoint verifier recognizes native248 command 2 and
reports the finite outcomes described in the backend checkpoint guide.

Replay Source205 or Source206 with its original Main commit and Reader.
Source206's immutable Reader verifies its C908 policy projection and finite
terminal diagnostic, but its full Source-data function still requires the
Source205 tree. The Source207 Reader independently verifies the exact
Source206 predecessor during its Source207 full-source replay.

The actor-fenced CI checks export the pinned Source207 commit, reconstruct
the exact 21,451-byte profile, and exercise checkpoint projection with a
synthetic publication fixture. Supply the retained profile and the exact
1,149-byte Root publication readback to check those actual operands as well.
Running without arguments checks the fixed identities and command request pin.

```sh
python3 -I -B -Werror::ResourceWarning test_source207.py \
  --source-root /absolute/source207-export \
  --profile /absolute/profile.UNISSUED.json \
  --publication /absolute/Root-publication.ACTUAL.json
```
