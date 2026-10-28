# Original view directory correction independent recheck

Disposition: **PASS for the bounded source correction** at held receipt
`dd970ff3935b69e4dad3fe68a2772de5c532c6ff27a78d630ed20aa38f788e3a`.
The prior directory-shape finding is closed. Root registration, execution grants
and a valid actual native Controller.run/main invocation and return remain
**NOT RUN / NOT ISSUED** as applicable.

The correction's adapter is
`7202c974547c05ca8b7f0ad9772d4ac849d9d684d4105a979a3290e7d6622acb`
(90,252 bytes,0644); its adapter tests are
`6231ae51ec6f8c6ba69abdae22b13cb7bf29ab8c4b5bb4d270c27f5843192c47`
(65,313 bytes,0644). Both authority files are byte/mode-identical to the prior
hold: `29aee4efc3bcac63476ae3b0a1ac840aba48f86017a82a11d9533a34b39981b2`
and `e65fd6224833f6917e985301603fc868814bc10dd0e3e8505700bd6f0226649f`.
All held file, artifact and log rows authenticate independently.

`Session.verify_view` now derives the exact directory set from the parents of all
160 locked files and the sole root `.`. Other names must satisfy the existing
canonical relative-name rule. Receipt keys must equal that expected set before
traversal; the actual visited set must also equal it afterward. Directory-node,
ownership, mode, device, depth, cancellation, file custody and source checks
remain. The production diff changes only that verification method.

The independently retained reproducer uses the actual captured Session context,
replacing canonical private receipt bytes and matching SHA while leaving the tree
unchanged. Results on the preserved blocked source versus the corrected copy:

| Control | Blocked source | Corrected source |
| --- | --- | --- |
| Extra `ghost` directory row | ACCEPT | REFUSE |
| Invalid `../ghost` directory row | ACCEPT | REFUSE |
| Eight additional unsafe path aliases | ACCEPT | REFUSE |
| Missing root and child directory rows | REFUSE | REFUSE |
| Directory list/null/bool/int; invalid node type | REFUSE | REFUSE |
| Actual context before and after controls | ACCEPT | ACCEPT |

The eight additional aliases are `./ghost`, `ghost/`, `a//b`, `/ghost`, the empty
name, `..`, `scripts/../ghost` and `scripts//ci`. The exact original two controls
are reused from the blocked peer's script. Replaced code/globals, fake same-class
Controller/direct observer, typed/nonfinite/expired/renewed deadline controls and
receipt type/unknown-field controls continue to refuse.

Independent authorized fresh-copy and working-tree runs each pass **95 tests,
exit0, zero skips** using `-B` and `PYTHONDONTWRITEBYTECODE=1`. All prior92 test
method AST bodies remain identical; three tests are added. The held capture
authenticates 255 files /5,131,456 bytes:253 unchanged and only the two adapter
rows changed from the prior255 capture. The fresh copy contains zero PYC files.
Authorization is limited to private Python/filesystem/pipe/socket fixtures. The
earlier sandbox EPERM evidence remains retained in the historical blocked peer;
it is distinct from these authorized replay results.

The unchanged original source lock remains
`d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`.
The actual160 copy scans159; four recipe freezes /71 inputs pass in the suites.
The same unchanged scanner comparison refuses held expanded171 and accepts
view159. Current full-root scanner175 = original159 +Zsh12 +installer4 is retained
without filtering or waiver. Minimum255 is still a source proposal, not whole
current-root admission. Actual context remains nine original namespaces plus two
projection aliases. Schema2, argv/view selection, status22/live12, source graph,
fixed E/reserve and callback crypto/custody/PASS gates are unchanged.

The prior `b340a6470c615914f76f02a83f44e4b71d61608c48298c93b91bfc9b1406c263`
hold and `8d76a1f9e4df09d82b23169d8a91565beb603a66a8f9ea5e4f5c365603d6d1f5`
BLOCKED peer remain historical and unchanged. New evidence is under
`artifacts/reviews/repository-original-view-directory-root-recheck-20261012`:
`authentication.json`, `old-controls.json`, `new-controls.json`, the source copy,
test logs and sealed `final-receipt.json`.

No primary source, shared packet/map/workflow/Git or dispatch changes were made
by this recheck. No native/daemon, build/compiler, GPG/image/mount/network/install
or hardware actor was run. Namespace readiness is not native-return proof or an
actor grant; cooperative source/process custody is not hostile same-UID memory
isolation. Generic policy input is not Root-issued authority. Root must reconcile
and register the final packet before any later execution. R1–R5/M5–M9 remain
mandatory and incomplete; no model or hardware support is admitted here.
