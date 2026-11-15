# Three pinned stage0 archives: actual DATA intake

This new intake retains exactly the candidate's rustc/cargo/rust-std 1.98.0 AArch64 archives. Existing `inputs.json`, PKGBUILD and qualification example are unchanged. Full details and retained paths: [`docs/port/rust199-stage0-intake.md`](../../../../docs/port/rust199-stage0-intake.md).

Actual acquisition: 108,298,076 bytes, three verified-TLS HTTPS GETs, no redirects/retries, all three whole SHA-256 values match the retained exact stage0 declarations. Opaque archives remain ignored in `work/artifacts/` on `/home`, not in Git or tmpfs. Named-path searches covered 43 project directories; four inaccessible paths remain unexamined. No global absence claim.

Actual data audit: pinned-root unique namespaces with no links/special entries, observed component layouts, complete installer-manifest/payload path joins, full regular-file hashes, 12 retained notice copies, and program/dynamic metadata for 14 top-level ELF files. All 14 headers identify AArch64 and satisfy the reported PT_LOAD 16 KiB alignment/congruence test. **No loader, compiler or installer was run.** Thirty-three nested ar/rlib payloads were not parsed. Neither static ELF data nor filename/dependency joins qualify runtime or hardware behavior.

`records/component-prefix-model.json` and its digest model the candidate's directory merge from actual archive metadata. No prefix was assembled on disk; that digest is not an observed assembled-image qualification. The bundled stage0 LLVM SONAME is 22.1, distinct from the candidate's external build LLVM 23.1.1 requirement. External loader/libraries and source/notice/compatibility qualification remain open.

```sh
python packages/port/rust199-source-reference/stage0_intake/verify.py
python -m unittest discover -s packages/port/rust199-source-reference/stage0_intake -p 'test_*.py'
```

The verifier reads/checksums the retained archives and pinned reports; it does not repeat tar parsing or authenticate a release signature. Seven controls cover unsafe names, ELF header/16K conditions, separate RPATH/RUNPATH semantics, stream-range capture, manifest gaps, component collisions/model digests and qualification holds.

`acquire.py` refuses an existing attempt ledger and implements no automatic retries. Do not delete/reset the ledger to re-fetch; reuse these exact retained bytes. `audit.py` streams the archives without extracting binary payloads. It keeps at most a bounded ELF prefix plus selected metadata. `join.py` models this observed link-free corpus only. Two bounded local audit runs are recorded: the final run follows parser precision fixes; no additional HTTP requests were made. The final audit took 4.115 s and peaked 206,472 KiB, below the 512 MiB address-space cap. No containers, leases, signing, makepkg, compilers or hardware jobs were used. All license108 and four original recipe holds remain unresolved.
