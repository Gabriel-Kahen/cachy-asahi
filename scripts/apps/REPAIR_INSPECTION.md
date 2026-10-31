# Readonly authenticated full574 reinstall inspection

`repair_inspection.py inspect-reinstall` prepares fresh before-pins for the existing explicitly owned offline disposable full574 copy. It does not repair files, create an ALPM handle/transaction/DB lock, commit, authorize future repair, or loosen ordinary `transaction.py inspect`. No transaction/backend changes are required.

Supply the same exact Apps source/provenance/runtime, workspace owner marker, full574 policy/lease, signed release/catalog/keyring/signer and saved explicit `reinstall` plan used by `transaction.py apply`. The plan alone is not authority: this entrypoint recollects actual inventory, snapshots inputs with the original bounded helper, authenticates and regenerates the byte-identical plan before measuring the damaged target. Its internal authorization is the existing full574 adapter seam used by apply; no new repair permission or trust schema exists.

```bash
python -I -B scripts/apps/repair_inspection.py inspect-reinstall \
  --workspace /work/main --ownership-sha256 OWNER_SHA \
  --apps-source /inputs/apps-source --apps-provenance-sha256 APPS_SOURCE_SHA \
  --repository-source /inputs/candidate/usr/share/cachy-asahi/repository-runtime \
  --full574-policy /inputs/policy.json --full574-policy-sha256 POLICY_SHA \
  --full574-lease /work/lease.json --full574-lease-sha256 LEASE_SHA \
  --release /inputs/release --release-sha256 RELEASE_SHA \
  --catalog /inputs/catalog.json --catalog-sha256 CATALOG_SHA \
  --catalog-signature /inputs/catalog.json.sig --keyring /inputs/public.gpg \
  --signer FULL_SIGNER_FINGERPRINT --plan /out/explicit-reinstall-plan.json \
  --plan-sha256 PLAN_SHA --applications selected-catalog-id
```

Paths above are illustrative; original owner/source/policy checks require real exact caller bindings. Live-host, incomplete generic/tiny scopes, changed selected version/metadata/archive, expansion, unselected damage, changed original574/base/user/trust state, capability/auxiliary changes and unsafe leaf/parent/hardlink shapes refuse. ALPM DB locks and pending-attempt markers are refused without deletion. The original workspace flock spans authentication and all target observations; ordinary foreign ALPM tools do not honor that flock, so repeated complete observations and no-lock checks are not a future ALPM reservation.

Success `INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL` includes four `before` SHA256 values with the exact existing apply schema, actual damaged/missing selected node records, policy/lease/source/capability binding, raw-auxiliary preservation result and original signed-plan binding. A missing leaf appears as JSONnull; changed files include hashes/metadata, never file contents. Copy target bytes and ALPM DB remain unchanged; only temporary snapshots outside `workspace/root` are created and removed. Output is bounded512KiB on stdout; caller may retain it outside the target. No full user-data map is exported.

Pass those four before-pins to the unchanged `transaction.py apply --operation reinstall` with its original explicit transaction confirmation and same authenticated inputs/plan. Apply still authenticates/replans, requires complete before-pins and original ALPM exclusion, and verifies ordinary ALPM dependency/signature checks and full preservation after commit. This readonly result is not accepted in place of any apply gate. Any intervening drift requires fresh inspection. A prior interrupted commit remains unknown; false commit fields describe only this readonly invocation, not historical attempts. Original600s full574 backend/610s caller budgets are unchanged.

Source controls use real temporary file bytes, missing leaves and real flock exclusion; namespace, cryptographic-context, ALPM inventory and auxiliary-capability positives are explicitly inert models invoking the original full574 repair shape/selection rules. No new signing/GPG/ALPM/native actor is run. Genuine full574 inspection with authenticated inputs remains pending a dedicated original native trial; the ongoing frozen native fixture is unchanged.
