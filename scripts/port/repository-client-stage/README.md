# Repository release-client follow-up

This directory implements a separate temporary TEST-signer restaging adapter.
[interface.json](interface.json) records its gate order and reviewed source pins.
Original A/B signatures remain input lineage; the adapter creates different
signatures and a four-package database. It never claims original B continuity.

The [workstream review](../../../docs/workstreams/repository-client-stage.md)
explains the missing producer handoff. A complete, independently checked native
repository export must precede client execution. Repository component PASS alone
does not satisfy that gate.

`gate.py` is a data-only validator of an externally SHA-pinned acceptance packet.
It requires actual aggregate/repository PASS, the exact eleven cases, complete raw
and projected records, public artifact maps, cleanup and a typed external
cryptographic acceptance attestation. **It does not itself verify original A/B
cryptography.** That work must be accepted by the coordinator before it supplies
the authority hash. A manifest's self-declared hash is insufficient.

`adapter.py` then requires separately SHA-pinned reviewed generic base, policy,
license and four-package provenance metadata. The complete package/version set
must equal the accepted 341-package inventory. Real dependency/provides/conflict
and file-ownership records are required; version-only inventories cannot pass.
Generic policy has no declared supported M2 models. The adapter constructs a
synthetic DEVELOPMENT bundle directly and uses frozen `release.verify_release`;
it does not use `release.stage`, whose model declarations do not describe this
generic experiment. It preserves the four archive byte strings, excludes the
probe and exercises seven frozen client CLI cases with a fresh private signer.

The signer home, agent and checkpoints are removed before public output is
written. Only signed bundle/envelope data, public key material, bounded command
logs and a development receipt leave that private scratch directory. Publication
uses retained directory descriptors and checks current-path identity. Failed or
cancelled publication invalidates its own PASS receipt. Cleanup has an independent
deadline and defers cancellation through agent stop and directory removal.

```sh
python3 scripts/port/repository-client-stage/adapter.py \
  --inputs /absolute/accepted-inputs \
  --authority /absolute/coordinator-authority.json \
  --authority-sha256 EXTERNALLY_SUPPLIED_SHA256 \
  --metadata /absolute/reviewed-generic-metadata.json \
  --metadata-sha256 EXTERNALLY_SUPPLIED_METADATA_SHA256 \
  --output /absolute/private-owned-parent/new-public-output
```

Omitting metadata returns **NOT RUN** with specific missing-data blockers after
input acceptance, without generating a signer. Invalid or incomplete authority
returns **FAIL** before signing. Current run `38227121568` is not eligible because
aggregate/public export acceptance failed. The exact authority schema is declared
by `gate.FIELDS`/`gate.REFS`; its modeled test fixture is a schema example, not a
native acceptance packet. CI, native wiring, Git and shared locks belong to the
coordinator. No installation, host trust import, endpoint publication or platform
mutation occurs.

The adapter enforces local process/time/output bounds and private scratch
ownership. It does not create a container or network namespace. The coordinator
must provide the frozen worker isolation and source/toolchain freeze for any
native job; these local fixture runs do not establish that worker acceptance.

Local checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/port/repository-client-stage -p 'test_*.py' -v
```

Acceptance fixtures are explicitly modeled; signing, repo-add, release verification
and client CLI checks use real tools. These tests cannot establish actual native
repository acceptance, production promotion, Asahi compatibility or M2 behavior.

Verified locally: **79 tests PASS, zero skips** (45 admission-gate, 21 adapter,
8 child-process bounds and 5 complete modeled-pipeline checks). The full pipeline
test does not mock the gate; its native, base-metadata and original crypto
observations are deliberately fabricated fixture data. See `review.lock.json`
for held source/test/document pins and the exact validation command.

The gate binds the current 15-file projection protocol: six known legacy log
aliases and exactly nine reset/relation operation copies with their typed index.
Raw/public bytes and every projected receipt reference must match. Raw positive
diagnostics are checked in both streams; negative transactions require the
producer's signature/trust diagnostic, with the exact missing-DB exception.
Cancellation is deferred through child spawn assignment and reaping, and terminal
publication closure is caught before returning success. A cancelled closed
publication is invalidated only after recovering its recorded output inode.
