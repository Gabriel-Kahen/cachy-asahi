# Independent initial PTY source rebind review

**PASS: exact source rebind, canonical freeze and fresh/copy preflight.** No blocker was found in the proposed initial lock. This review accepts the candidate's source identity and fixture reproducibility; it does not establish a new native integration result or M2 behavior.

Read the current roadmap and `manifests/packages.toml`. Reviewed the externally supplied candidate `/tmp/cachy-root-initial-pty-20261012/initial-candidate.lock.json`, SHA256 `d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`, against the previous lock `9503d0583417956ef39da5e862eb9abd2f2d01cbdfffcfe26a25da25c53bbc35` and fresh clone commit `6ac0719b597d7f2e33b420ae2603b71e42ccc942`.

Before importing clone helpers, independently read the actual 159 Git blobs and modes and checked them against single-link regular workspace files, candidate hashes and modes. All match; complete source bytes total 2,718,801. No source row was inferred from a Git title, author receipt or architecture declaration.

The old and candidate lock have identical field sets and identical values everywhere except two source rows:

| Changed source | SHA256 |
| --- | --- |
| `scripts/integration/onboarding.py` | `e3412aedee16deca867a5e76f6ce90216904d4243f8197caff8c717fcd4613e9` |
| `scripts/integration/test_onboarding.py` | `f66078c1e1574a942eb28647407b2ddeb9d9d87c0547165fae4e6b5a59570aa8` |

The complete source path set remains159, with157 unchanged hash/mode rows. All125 generated fixture hash/mode rows are unchanged. The candidate preserves:

- Original four-recipe map: `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.
- Original signed-input map: `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
- Original recipe source commit: `ebd5812640b0b69f5c09a47752b739e37e338754`.
- Epoch: `1791748800`; development-only true, release selection false and hardware validation NOT RUN.

Independently invoked the verified clone's production `integration.freeze` twice into newly owned temporary paths. Both actual serialized files are byte-for-byte identical to the supplied candidate and hash to `d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`. Each freeze copies the source and regenerates all125 fixture inputs before comparing their complete maps. This checks canonical serialization and deterministic fixture regeneration, beyond comparing two caller-supplied manifests.

Production `integration.preflight` passed against the fresh clone and external candidate pin. Production `integration.snapshot` then created a new159-file copy with its exact source map; a second production preflight passed against that copied tree and regenerated the same125 fixtures. The clone and copied source contained no `__pycache__` directories or `.pyc` files before/after these checks. No primary workspace cache or source file was removed or changed.

Private independent harness `/tmp/initial-pty-rebind-independent-review.py`, SHA256 `9b53b3f754c11345fedeea4a99ad99e1508102b241d2f873958983ebedfa818c`, records the exact Git/map comparison, two freezes and both preflights. It only reads project Git and writes owned temporary review copies; no project Git, source, shared lock or workflow was edited. Fixture generation performs source/data work, without package installation, Docker, system changes, network or native workloads. The coordinator's13 PTY and19 signed-receiver checks and the author/peer broader source suites are separate evidence; this review does not claim to have rerun those suites or GPG authentication.

Only this review document was edited in the project. Root owns adopting the lock, committed source/workflow binding and any native dispatch. Historical aggregate native failures are preserved; signed repository/onboarding acceptance, headless guest execution, full kernel builds, installation, M2/16K hardware and performance remain separate gates.

## Coordinator adoption

Root adopts exact candidate `d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31` as `scripts/ci/integration.lock.json` after independent159-file Git/mode, canonical regeneration and copied/fresh preflight review. Existing125 fixture map, recipe/input pins and epoch remain identical. Root separately passed13 onboarding and19 signed receiver tests (approved temporary TEST GPG); source650PASS is the owner's report, not a root/native rerun. The broader211 packet still needs virtual source/input/adapter integration and complete copied checks before dispatch. Historical native38237127237 remainsFAIL.
