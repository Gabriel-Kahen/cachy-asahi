# Retained proposed Rust recipe: source consumption plan

This is a finite, source-audited data plan for the retained `../recipes/rust.PKGBUILD`, not a recovered original binary recipe or an executed build. See `docs/port/rust-build-source-plan.md` for findings. All four original binary recipe hashes remain **UNRESOLVED**. ARM, M2, 16K behavior, performance and release remain untested/unadmitted.

Run from the repository root:

```sh
python scripts/port/arm-rust-toolchain-inputs/source-closure/build-source-plan/check.py
python -m unittest discover -s scripts/port/arm-rust-toolchain-inputs/source-closure/build-source-plan -p 'test_*.py'
```

`check.py` reads the pinned parent recipe/SRCINFO/submodule report and parses the recipe's literal bootstrap TOML heredoc as data. It merges the pinned dist profile and applies explicitly reviewed rules for the twelve identities. It does not interpret arbitrary shell/bootstrap code, resolve Cargo dependencies, run patches, execute fetched code, access the network, or mutate the system. `--write` replaces only this directory's `report.json`. Unknown submodule identities and changed pinned inputs fail closed. It sets a 128 MiB address-space limit. Tests exercise altered feature selections and tampered evidence, not a compiler build.

`records/pins.json` binds retained evidence bytes; its digest is fixed in the checker. Full small config/lock metadata also has replayable Git blob identity. The large bootstrap files were verified against Git blob OIDs at collection, then only the listed relevant original line spans were retained in `sources/*.excerpt.txt`. Their full-file hashes/OIDs describe that acquisition observation; the checker verifies excerpt integrity, not reconstruction of discarded full blobs or authentication of GitHub's responses. Source commit: `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4` in `rust-lang/rust`.

The exact Rust root MIT/Apache-2.0 grants and COPYRIGHT accompany these retained Rust snippets and metadata in `notices/`. This narrow retention does not establish third-party archive/submodule license completeness.

`records/request-ledger.json` and eight read-only GraphQL query documents record 8 sequential requests / 1,015,552 response bytes, within the 12-request / 4 MiB limits. Raw full responses and private extraction scratch remain ignored under `work/`; credentials are never retained. No new archives were fetched or scanned. A `library/.cargo/config.toml` Git lookup returned null; this does not establish its absence from a generated release archive.

`records/archive-cross-check.json` is a compact derivative of earlier archive report commit `3c76059f0031b2433f25bd1e0fd1400a0a8bfcb5`, report SHA-256 `a0eb6bec3b63d4d4f4a937e3e1e8b42a2e87d9e49b8608b96d51762b456abc8f`. At acquisition, 120 bootstrap and 30 library registry lock entries all matched earlier vendor name/version/package-checksum declarations. The checker pins this derivative; it does not repeat that comparison against the earlier 2.7 MB report. Archive membership of these Git lockfiles, all per-file checksums, Cargo resolution and notices remain unverified.

The classification is conditional on this exact recipe/profile and source mode. Its hypothetical feature-toggle diagnostics are not a replacement for tracing a changed recipe. Do not turn an inactive source gap into a build blocker or turn observed archive path counts into source/license completeness.
