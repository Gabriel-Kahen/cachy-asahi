# Sixth native run independent evidence review

Run **38212287407**, source
`932cf45818edd37eccfe1d22b74ca9b1e8ecdf61`, October 12, 2026.
**Overall integration remains FAIL.** The fresh installed-image/lifecycle and
installed software onboarding executed successfully; repository acceptance
failed and desktop evidence publication failed. No compositor, hardware or full
independent onboarding acceptance follows from this review.

Read the current roadmap and package inventories first. Reviewed retained
evidence only: no Docker/native execution, package installation, workflow,
source/shared-lock or Git mutation. Local checks parsed and hashed existing
bytes, compared receipts and read the frozen source through `git show`.

## Provenance and independent byte checks

Input directory: `artifacts/ci/38212287407/decoded`.
The coordinator decoded compressed bundles only after matching their workflow
markers. This review did not repeat remote GitHub/workflow-marker attestation.
It independently checked all **756 regular archive members in 12 retained
compressed bundles** against the decoded bytes and all **464 accepted exporter
entries** against their retained size/SHA-256. All matched. Compressed inputs
total 1,563,589 bytes; decoded files total 10,429,604 bytes.

The frozen integration-lock hash is
`e8fad9905d743c3287fbed9ca4041272e925bc4ba4aab339ecdc4430d05b3dac`;
157 is its separate source-file count, not an alternate hash. Frozen repository
runner SHA-256
`519c1bbc12a2fd02e036f67c162190f2b017e86ed7b7c192b6bbb994809fe5d9`
matches the retained repository input contract. Frozen onboarding entry SHA-256
`2aeb0bfdad5aec6bbc969b3c008a10fa9cfb3a91775d9969a48e78e284c0e560`
matches its retained execution contract.

Observed execution is a native aarch64 hosted VM/container, Docker 28.0.4/API1.48,
four Neoverse-N2 CPUs and 4096-byte pages. These are recorded runner observations,
not independent physical attestation or M2/16K execution.

## Fresh 345-package image, Config and owned lifetime

Builder image:
`sha256:0cc5f4852a6c4e8198239e320743cf7f0dfba4230ed09b6f20fc58c676452a81`.
The accepted derivative during this job was
`sha256:24f41b02bfad714dfe862ea986f412ff05c20166016804eefaeaece3b895f81b`.

Independently rechecked the exact installed inventory: **341 base packages plus
all four originals equals 345**, with no extra/missing/replaced rows. Installed
lock SHA-256
`3906ca525dac6bec9820db85ecbd9b8d66dc9af7c7b419a41941230807c8b456`
matches READY, installed-image, fresh read-side and onboarding contracts. The
base lock and READY receipt hash bindings also match. All **18 complete original
payload hashes** and versions agree across READY, fresh image verification and
installed onboarding receipts; original archive hashes agree between fresh
verification and onboarding. READY contains 347 PASS checks,
including actual underlying image-tmp emptiness and private-state removal.

`committed-config.json` records identical accepted/derived semantic Config:
USER `alarm`, WORKDIR `/tmp`, empty executable arrays, empty Labels and the exact
base PATH Env entry, without test identity. The handoff controller records no
changed Config fields. The fresh read-only verifier returns PASS for this exact
image and installed lock, explicitly recording underlying tmp/payload inspection.
The retained Config receipt is canonicalized; it is not a raw daemon Config dump.
The reviewed source's exact empty-entrypoint sentinel semantics explain that
canonical representation without relaxing Env or nonempty commands.

Ownership records bind a valid reply and image ID to private tag
`cachy-asahi-private-installed:0a59b80b2183b7d7fdbd7145275643ff`.
Lifecycle temporarily reports RETAINED for subsequent consumers; this is not its
final lifetime result. Handoff container removal records verified absence.
The final summary records owned image cleanup PASS, `absence_verified: true`,
`cleanup_uncertain: false`, for the same derivative. Thus the accepted image was
deleted after consumers and is not reusable across jobs. The retained receipts
are provenance, not an exported runnable image. Parent-layer erasure is expressly
not claimed by the fresh verifier.

## Installed native software onboarding

Both `onboarding/provenance.json` and `onboarding/artifacts/result.json` report
**SOFTWARE PASS**, with matching complete contracts and the accepted derivative
ID. The inner receipt records aarch64, 4K pages, UID/GID1001, zero capabilities,
loopback-only network, no Docker socket and a read-only image.

All 13 recorded journey commands exit zero: setup preview/apply/repeat, software
terminal, Fish/Zsh startup, scripted Vim edit, compiler version, compile/execute
hello, setup removal and subsequent Fish/Zsh startup. The setup suite ran 40
tests and release suite 19; both have zero errors/failures/skips. Original
installed payload ownership/hashes are retained and align with the handoff.
The PTY is software-only, Vim is noninteractive, and compiler execution is not
a performance comparison. Full independent contributor onboarding and hardware
remain explicitly NOT RUN. No GUI/editor usability or target installation is
accepted. The container used Docker `--rm`; its cleanup receipt records no such
container on follow-up removal, rather than a separate daemon-list absence proof.

## Desktop execution and publication are different results

Raw `desktop/desktop/desktop.json` reports
`desktop-container-verifier-pass`: installed payload/inventory, Lua syntax,
Hyprland default/optional config verification, Waybar JSON syntax, GTK3 CSS
parsing without a display, and the audited Mako subset passed. The two native
Hyprland config checks exit zero. Their embedded stdout exactly reproduces the
recorded raw log hashes and contains eight ESC bytes each.

The public exporter rejects precisely `desktop/command-19.txt` and
`desktop/command-20.txt` as `binary-control-content`. Component execution was
PASS, exporter/control stage FAIL, and the final summary correctly keeps desktop
FAIL. Publication failure is not a config-verifier runtime failure and cannot
be silently converted into an accepted desktop stage. The receipt explicitly
records headless compositor BLOCKED/not attempted because this Docker fixture
excludes DRM; acceleration, portal/audio/session and optimization are NOT RUN.
Neither Waybar nor Mako application execution occurred.

## Repository snapshot failure: no transaction acceptance

Repository result and control stage are FAIL:
`untrusted-A-rejected: rejected transaction changed inventory/payload`.
The untrusted transaction returns 1, but the rejected-transaction snapshot
comparison fails before recording any successful case; `cases` is empty.

Independent snapshot comparison finds the **same 19 tracked file hashes** and
the **same 341 package/version lines** before and after. The raw merged inventory
strings differ: before includes a missing `integration` database warning; after
includes unknown-signer/key-lookup errors. Their log hashes differ accordingly.
The failure therefore reflects diagnostic bytes included in the inventory
comparison. This recheck narrows the cause; it does not retrospectively pass the
untrusted case, repository upgrade/rollback/trust rotation or complete repository
transaction. The repository receipt binds the correct source, builder, nonce,
daemon architecture, runner hash and explicitly synthetic upgrade kind. TEST
private state was removed and its container removal records verified absence.
Production trust, publication and stable promotion remain NOT RUN.

## Builds, suites and final limits

The coordinator's `root-build-verification.json` reports PASS for all four actual
original archive pairs: complete bytes, installed contents, PKGINFO and BUILDINFO
are equal, with no errors. This review read that independent comparison receipt;
it did not duplicate its comparison execution or rerun a build. Distinct recorded
containers do not attest independent machines.

Independently summed the retained native source-suite receipts: **560 tests,
zero skips, all PASS**, including 309 CI tests. This proves those recorded software
checks ran; it does not override the overall FAIL or establish Asahi/M2 hardware,
16K pages, a headless virtual guest, performance, full independent onboarding,
supported release or R1–R5 completion. No discrepancy was found in the retained
hash/image/source chains after the hash/file-count clarification.

| Key retained receipt | SHA-256 |
| --- | --- |
| `summary/result.json` | `271ae4232f6bce23860d5558097e4111edae001e579be3084ab884c2dbe6b8df` |
| `lifecycle/commit-receipt.json` | `80d3b9d286f9d89d23a9a9f51789bb4993bc78b2af28d7eaef46273c5c892238` |
| `lifecycle/committed-image/result.json` | `8d0d089f95dd2e68e3731bf33df1077a9ab09e458ed945b40b989839ad1944fe` |
| `onboarding/artifacts/result.json` | `2be1f8fc1f6a35dfb3bc8fdc4ab3aa330b0a456eb08420ad5a9b3ba7a9748113` |
| `desktop/desktop/desktop.json` | `21c9056ee1848e0ef5566d1a0ff6f1f1d75934b00291f4c6704900520fe95ba3` |
| `repository/result.json` | `0bb83b347517a3ef6851912f4691dfeecd8dd69a387413429d70a12dda61dd34` |
| `source-suites/result.json` | `d6bed2b2402793621c16b1b0bcff457d8de4f1999fe973f04ea04be8baf4b26d` |
