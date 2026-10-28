# Repository signed-row receiver correction

October 12, 2026. Source implementation and isolated fixtures are verified;
coordinator acceptance and source-packet rebinding remain pending. Native
repository binary acceptance and M2 hardware validation remain **NOT RUN**.

The immutable fixture archive rows contain five canonical fields. Before the
repository stage, the controller copies each original TEST signature and adds
`signature_sha256` to its in-memory rows. The repository input contract therefore
contains six fields. The broader receiver previously compared those signed rows
directly with the immutable five-field rows and refused the producer contract
before inspecting repository binaries. The retained actual-record/source-contract
diagnosis is `/tmp/cachy-actual-repository-receiver-diagnosis-bneym3el/diagnosis.json`;
the native repository binary bundle is absent, so it proves the interface
mismatch rather than binary acceptance.

The corrected receiver reconstructs the exact six-field rows from the canonical
fixtures and authenticated original signer receipt. It requires the initial
signer stage to have passed and retains the existing source/image/archive,
complete eight-signature set, TEST-only, full-primary VALIDSIG and manifest
bindings. It independently reads the original public certificate and all eight
`work/test-signatures/public/signatures/<archive>.sig` files, checking bounded
regular single-link files, real parents, no symlinks, producer-defined mode 0644
and receipt hashes. Original package signatures retain the existing complete
SHA256 packet/MPI/private-marker checks. The repository's independently generated
signatures cannot replace those original signer bytes. Exact row equality
rejects missing annotations, unknown fields, changed canonical fields and order.
The separately reviewed SHA512 policy for 22 repository database signature paths
is unchanged; no generic credential or signature-policy waiver is added.

Focused **19 tests PASS, zero skips**, with ResourceWarning treated as an error.
An isolated 0700 TEST GPG home signs the eight source-fixture archive byte streams
with Ed25519/SHA256, obtains actual VALIDSIG records and a public certificate, and
supplies the producer-shaped six-field contract to both signer and repository
receivers. GPG independently verifies those signatures; the receiver performs
structural parsing and receipt binding without running GPG. The fixture archive
streams are test data, not built packages. Negative cases cover unsigned and
extra-field rows, canonical/order drift, missing or private signer material,
authority/image/hash drift, wrong modes, links and coherent row/byte substitution.
A coherently rehashed SHA512 original package signature is still refused. All
TEST keys and agents are removed through the explicit temporary homedir.

The committed pre-correction receiver refuses a producer-shaped fixture with
`accepted-repository-contract-required`; the corrected receiver passes that same
fixture. Receipt: `/tmp/cachy-signed-repository-row-wb9qui6w/before-after.json`.
Focused log: `/tmp/cachy-signed-row-focused.log`. The full development suite ran
170 tests in 62.312 seconds: **169 PASS, one ERROR, zero skips**. The sole error
is `test_virtual_stage.test_actual_source_literals_match_current_files_without_importing_owner`,
which refuses current independently changing virtual owner pins with
`virtual-owner-constants-differ`. This worker did not alter or restore those
files. Full log: `/tmp/cachy-signed-row-development.log`; full-suite acceptance
remains pending the coordinator's virtual-source reconciliation and recheck.
Both changed Python files pass AST parsing. No other broader module,
workflow, shared lock, Git state or dispatch was changed by this worker.
