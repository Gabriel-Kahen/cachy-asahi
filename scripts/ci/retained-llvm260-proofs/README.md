# Retained LLVM260 public TEST proofs

This opt-in, trusted-main workflow retains seven public DATA files for three days.
It does not build, install, sign, verify cryptography, run Reader7, qualify hardware,
or grant release acceptance. Root remains responsible for authenticating the
original evidence, actual signature verification, Rust source/legal review and
final admission. A syntactically joined Root statement is not authentication.

Dispatch `retained-llvm260-proofs.yml` **on main** with `sourceRef` (a full
`refs/heads/codex/...` ref), `sourceCommit` (40 lowercase hex), and `manifestSHA`
(the independently Root-pinned SHA256 of the whole actual `manifest.json`).
Root owns preparation, publication, dispatch and later artifact admission. No
publication or dispatch is performed by this collector or its tests.

The Source branch must have exactly eight ordinary Git `100644` blobs at its
root: `manifest.json` and the seven names below. No extra path, executable,
symlink, submodule or nested namespace is accepted. The collector checks out
no Source tree and never imports or executes Source code. The only Source
network operation is a shallow filtered Git fetch from the fixed public project
repository; it requires the fetched ref to equal the externally supplied commit.
The collector itself comes from `github.workflow_sha` on main, with the existing
pinned checkout action and credentials persistence disabled.

Each leaf, including the manifest, is capped at 8 MiB. Every public leaf has an
exact length and SHA256 in the externally pinned manifest. The total public ZIP
bound is at most 32 MiB, conservatively reserving deflate, ZIP64, local/central
headers and entry overhead; the pinned upload action uses compression level 0.
The workflow has a five-minute job cap. The collector has a 60-second external
wall cap, 256 MiB address space, 30 CPU seconds, no core dumps and a 40 MiB
per-file write cap (including fetched Git packs).

Before staging, it joins fixed LLVM260 Source/run/job/Original/map/package pins,
Reader7's exact PASS status, result-to-binding SHA256, signature/public-key hashes
to Root's verified TEST proof, and that proof to Root's final accepted TEST-only
decision with preserved holds. `source_audit` is a whole-body pinned, bounded JSON
object; its Rust source/legal content is reviewed separately by Root, without
inventing LLVM tuple fields. JSON duplicate keys and nonfinite numbers are
refused. Every public leaf is scanned for private-key armor markers, and the
public key must have a single public armored certificate block. No GPG runs.

All validation precedes creating a fresh owned output directory in `RUNNER_TEMP`.
Only the seven validated public bodies are staged, without the manifest or Git
metadata. The upload name is `llvm260-root-proofs-<run>-<attempt>`; overwrite is
disabled. Actual run/job/artifact IDs and archive pins are future results, not
provided or invented here. Private key homes, package bytes, execution receipts
and unrelated sources must not be put in this Source branch.

## Manifest contract (inert example)

The null pins below are deliberately unset. Root must populate them from the
actual reviewed whole files, hash that final manifest, and pin its Git ref and
commit separately. This avoids a self-referential commit field in the manifest.
Neither this example nor the synthetic test fixtures are acceptable evidence.
`verification_proof.Root_issuer` must be `Root`; all other proof/decision fields
follow the existing private LLVM260 signing proposal and contain actual values.

```json
{
  "schema": 1,
  "scope": "LLVM260_RETAINED_PUBLIC_TEST_PROOFS_DATA_ONLY",
  "case": {
    "source": "031bf1634429446cd0068f4842d56af276cf40f4",
    "ref": "refs/heads/codex/llvm23-source-reference-native-v2-20261115-r3",
    "run": "43760769287",
    "job": "132954847327",
    "artifact": "14186236728",
    "attempt": 1,
    "map_sha256": "75426d36fae416d1bc3606b8d1a7165408964996bb6467e3223842612221e187",
    "package": "cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst",
    "package_bytes": 192385078,
    "package_sha256": "689621ffa5261bdc7d382448529f6fa5d6e30f473d7470101cd0ab7d94140042"
  },
  "reader_expected_status": "PASS_INDEPENDENT_LLVM23_BUILDINFO_ARCHITECTURE_SUCCESSOR_DATA_ONLY",
  "files": {
    "llvm_signature": {
      "name": "cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst.sig",
      "bytes": null,
      "sha256": null
    },
    "public_test_key": {
      "name": "llvm260-TEST-public.asc",
      "bytes": null,
      "sha256": null
    },
    "verification_proof": {
      "name": "llvm260-TEST-verification.json",
      "bytes": null,
      "sha256": null
    },
    "reader_binding": {
      "name": "llvm260-reader7-binding.json",
      "bytes": null,
      "sha256": null
    },
    "reader_result": {
      "name": "llvm260-reader7-result.json",
      "bytes": null,
      "sha256": null
    },
    "source_audit": {
      "name": "llvm260-source-audit.json",
      "bytes": null,
      "sha256": null
    },
    "root_decision": {
      "name": "llvm260-Root-decision.json",
      "bytes": null,
      "sha256": null
    }
  }
}
```

## Local verification

Run `python3 -I scripts/ci/retained-llvm260-proofs/test_collect.py` from the checkout.
The 21 controls use synthetic metadata and tiny temporary local Git repositories.
They exercise exact pins/joins, unset/refused decisions, key markers, JSON,
path/mode/namespace guards, leaf/ZIP caps and fresh staging. They never fetch,
execute Source/package code, call GPG, or dispatch a workflow. Passing them is
host DATA validation only; the actual hosted upload remains NOT RUN until Root
dispatches and independently checks its output.
