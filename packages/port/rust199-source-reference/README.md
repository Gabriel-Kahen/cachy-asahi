# Rust 1.99 private source reference

Original, unselected candidate `cachy-asahi-rust199-source-reference` 1.99.0-1 for **native AArch64 Linux only**. Installs only under `/opt/cachy-asahi/rust199-source-reference`; no global rustc/cargo provider, replacements, alternatives, installation hooks, services or PATH changes. Package removal is ordinary package-owned file removal; user Cargo homes are not package payload.

**Actual status:** static/refusal controls only. No source or stage0 archives acquired/extracted here; no makepkg, bootstrap, compiler, build, package assembly, installation or hardware execution. The supplied admission example deliberately refuses. All existing license108/source-closure holds and all four original binary recipe hash mismatches remain unresolved. This candidate is not a reconstruction of those official recipes and is not approved for publication.

See [`docs/port/rust199-source-reference.md`](../../../docs/port/rust199-source-reference.md) for the input contract, commands and remaining work. `inputs.json` fixes the exact previously retained Rust/LLVM archives, the three stage0 archive declarations derived exclusively from retained `src/stage0`, source metadata and the candidate configuration. URLs are provenance only: PKGBUILD sources are local basenames and all archives are `noextract`, so makepkg has no upstream URL/fallback acquisition path.

The helper first checks explicit opt-in, native/non-root context, a separately supplied SHA-bound qualification record, a complete read-only dependency-image inventory, and exact local archive bytes. Prepare then copies/rechecks the materials before extraction, assembles the three declared stage0 components without executing their installers, checks the qualified resulting tree, validates root/library Cargo configs, four active locks and every vendored file checksum, joins external LLVM source and writes the fixed bootstrap config. These checks enforce finite material assertions; they do not prove Cargo resolution, compatibility, authentication or licensing by themselves.

The planned build uses bubblewrap with all namespaces unshared, a read-only admitted environment root and stage0 at **both** accessible stage0 paths, new private HOME/CARGO_HOME, cleared environment and `CARGO_NET_OFFLINE=true`. Missing namespace support or tools is a refusal, never an unsandboxed retry. makepkg source symlinks are accepted only after exact content checks; a real helper copy is used inside the sandbox. Packaging allows fakeroot only when kernel process UIDs remain nonzero.

Run only the author-owned static/refusal tests:

```sh
python -m unittest discover -s packages/port/rust199-source-reference -p 'test_*.py'
bash -n packages/port/rust199-source-reference/PKGBUILD
```

Fourteen controls cover metadata/SRCINFO/checksum agreement, stage0 pin derivation, private native configuration, default and unqualified refusal, missing/changed materials, makepkg symlink handling, fakeroot versus real-root handling, tree inventories, Cargo source containment, vendor checksums, sandbox command construction and private staged layout. Sandbox execution and complete package integration remain NOT RUN.
