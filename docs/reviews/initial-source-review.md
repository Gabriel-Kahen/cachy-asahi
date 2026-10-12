# Initial independent source review

Reviewed October 11, 2026, during the first implementation batch. This is a
source review with isolated synthetic tests, not a native ARM build, installation,
compositor session, or M2 hardware result. Workers were still changing source;
findings below describe the observed versions and require coordinator regression
verification after fixes. No implementation, manifest, or Git state was changed.

Read `AGENTS.md`, `outline.md`, `docs/roadmap.md`, `manifests/packages.toml`, and
`docs/orchestration.md` before reviewing package recipes/configuration,
`scripts/build/`, `scripts/checks/`, release signing/promotion, and installation
and recovery documentation. Missing in-progress deliverables were not findings.

## Findings requiring correction

### R1 — P1: Build success does not bind package metadata to the reviewed recipe

Observed in `scripts/build/build.py`, generated-metadata comparison and artifact
checks (original lines 111–128). Generated metadata is compared only for keys
already present in the reviewed metadata. Consequently an unexpected dependency,
provide, conflict, or replacement is ignored. Architecture-specific keys such
as `depends_aarch64` are absent from `FIELDS`, so they are also ignored. Artifact
metadata is checked for package name, architecture, and license only; the actual
version and dependency/provide/conflict/replacement sets need not match either
the reviewed recipe or the generated metadata.

Reproduction: ran the actual `build.main()` in a temporary directory, mocking
Docker inventory/execution only. The simulated container produced a real tar
package consumed by the unmodified package inspector. Reviewed recipe metadata
was `pkgname=review-fixture`, `pkgver=1`, `pkgrel=1`, `arch=any`, `license=MIT`,
with a fixed local-source checksum. Generated metadata preserved all reviewed
fields but additionally declared `depends_aarch64=hidden-dep` and
`provides=linux-asahi`. The artifact `.PKGINFO` declared version `999-1`,
`depend=hidden-dep`, and `provides=linux-asahi`.

Actual result:

```text
build.main exit: 0
provenance status: built-package-static-pass
validation errors: []
accepted .PKGINFO: review-fixture / 999-1 / any / MIT
                  depend=hidden-dep / provides=linux-asahi
```

This bypasses the build's review-consistency gate. The separate release checker
can reject a protected provide when its policy lists that package, but that does
not repair the false build success or validate other unreviewed dependencies.

Fix: compare the union of supported reviewed/generated fields, including target
architecture fields and absent-versus-present values; resolve inheritance before
matching each actual `.PKGINFO` version and relation set. Reject unsupported split
package metadata rather than flattening it. Add rejection tests for extra
generated relations and differing artifact versions/relations.

### R2 — P1: Release verification accepts an expired signing key

Observed in `scripts/release/release.py::verify_signature()` (original lines
216–224). Verification requires a successful GPG command and a matching `VALIDSIG`
fingerprint, but does not reject invalid-key status records. GPG can return zero
and emit `VALIDSIG` for a cryptographically correct signature made by a key that
has since expired. This contradicts the documented signing policy, which requires
key validity and says an expired-key incident needs an authenticated transition.

Reproduction used a disposable GPG home outside the checkout. Generated an
Ed25519 signing key with fake time January 1, 2026 and one-day expiration, signed
a harmless local fixture at that time, then verified at the real current time.
No real signing identity, host keyring, or project artifacts were used.

Actual result:

```text
gpg --verify exit: 0
[GNUPG:] KEYEXPIRED 1767312000
[GNUPG:] EXPKEYSIG ... Source Review Fixture
[GNUPG:] VALIDSIG <matching full fingerprint> ...
release.verify_signature: ACCEPTED expired key
```

Fix: parse GPG status defensively and fail closed for expired/revoked keys,
expired signatures, bad/error signatures, missing keys, or ambiguous signer
results; require the expected valid signature identity. Add a real isolated
expired-key regression and revoked-key/signature-validity coverage. The signing
and stable verification paths should enforce the same policy.

### R3 — P2: A copied build record satisfies the second-build comparison

Observed in `scripts/build/compare.py::compare()`. The only independence check
rejects identical evidence directory paths. Distinct paths can contain the same
single build record. The result nevertheless states “Distinct recorded container
runs” and returns `contents-reproduced`.

Reproduction: created a valid synthetic package and recorded evidence directory,
then used `shutil.copytree(first, second)`. The copies included identical recorded
Docker container name, command, timestamps, image/recipe/input hashes, log, and
archive. Ran the actual comparator and artifact inspector.

```text
status: contents-reproduced
errors: []
installed_contents_equal: true
pkginfo_equal: true
bytes_equal: true
independence_limit: Distinct recorded container runs; ...
```

Fix: record a unique build execution identity bound to the uniquely named
container and reject reuse when certifying the second build. Preserve the limit
that records do not independently attest physical-machine execution. Pure copied
artifact comparisons can remain useful if explicitly labeled content comparisons,
but cannot satisfy the separate clean-rebuild evidence requirement.

### R4 — P2: The ignore rule excludes the implemented build tooling

Observed root `.gitignore` contains the unanchored directory rule `build/`.
It ignores `scripts/build/` as well as generated root build output.

```text
$ git check-ignore scripts/build/build.py scripts/build/provision.py
scripts/build/build.py
scripts/build/provision.py
```

This hides the tooling from ordinary `git status`, `rg --files`, and normal
staging. A source integration can omit the build scripts unless they are forced
into Git individually.

Fix: anchor the generated-output ignore rule to `/build/` or add explicit
exceptions for the complete `scripts/build/` tree. Verify all required build
entry points are tracked in the integrated change.

## Other observations and limits

- The three observed recipes install original opt-in files below `/usr/share`.
  They do not install bootloader, kernel, firmware, graphics, audio routing,
  speaker-protection, `/etc/skel`, login-shell, or service defaults. No concrete
  unsafe user-file overwrite was found in their current package functions.
- Desktop activation and optional Waybar/Mako references have documented removal
  behavior. Shell source blocks guard missing files; current configuration is
  deliberately narrow. These source observations do not certify lifecycle or
  session behavior on the selected base.
- The read-only recipe inspector discovered all three recipes and reported no
  recipe errors after the desktop worker supplied reviewed `.SRCINFO`.
- The coordinator had already assigned broader protected-platform paths and
  ELF load-segment validation to the build worker. Those known corrections were
  not duplicated as new findings here.
- All reproductions used temporary directories; no package installation,
  service/compositor launch, host trust mutation, publication, or hardware testing
  occurred. No current recipe was alleged to contain the malicious synthetic
  metadata used to exercise the build gate.

All four findings were sent to the coordinator. Treat them as open until fixes
and relevant negative regression results are recorded by integration.

## Independent fix validation

Rechecked later on October 11, 2026 after owners implemented fixes. This section
supersedes the preceding open-status sentence for R1–R4. It records independently
rerun reproductions, not merely inspection of the owners' regression tests.

| Finding | Independent outcome | Status |
| --- | --- | --- |
| R1 | Original combined metadata mismatch rejected; separate version and relation mismatches rejected; matching fixture passed | Resolved for the reproduced cases |
| R2 | Real expired-key signature rejected; real revoked-primary/subkey signature rejected; valid signer identity controls behaved correctly | Resolved for the reproduced validity and binding cases |
| R3 | Copied single-run evidence rejected because its clean container identity is reused | Resolved for the original copied-record case |
| R4 | `git check-ignore` no longer reports either build entry point | Resolved |

### R1 results

Reran the full isolated `build.main()` reproduction with only Docker
inventory/execution mocked. The original combined case now exits 1 with:

```text
isolated generated metadata differs from reviewed depends
```

Then kept generated metadata consistent with the reviewed recipe to exercise the
artifact checks separately. Added required format-2 `.BUILDINFO` identity and
recipe-hash fields to the fixtures so incomplete synthetic metadata could not
mask the intended assertion:

```text
wrong artifact version: exit 1
  artifact metadata differs from reviewed pkgver
unexpected artifact dependency/provide: exit 1
  artifact metadata differs from reviewed depend
  artifact metadata differs from reviewed provides
matching artifact and generated metadata: exit 0
  built-package-static-pass
```

Source inspection confirms absent fields are now significant, target-specific
fields are included in effective metadata, unsupported split recipes are
rejected, and artifact identity/relations and `.BUILDINFO` recipe hash are bound
to reviewed inputs. These results establish the corrected source-validation
behavior; the synthetic passing control is not an actual native build.

### R2 results

Repeated the original disposable-key reproduction: Ed25519 key generated and
used on January 1, 2026 with one-day expiration, then verified at current time.
GPG still returned zero with `KEYEXPIRED`, `EXPKEYSIG`, and matching `VALIDSIG`;
the project verifier now rejects it:

```text
unacceptable signature/key status: KEYEXPIRED
```

Also generated a separate real certification primary key and signing subkey in
another temporary GPG home. Forced the signature to use that exact signing
subkey. Verified the following identity controls:

- Authorized primary fingerprint: accepted through the GPG-validated binding.
- Exact authorized signing-subkey fingerprint: accepted.
- Unrelated full fingerprint: rejected with signer mismatch.
- After importing the primary's generated revocation certificate, verification
  of that existing subkey signature rejected both the primary and subkey pins
  with `unacceptable signature/key status: REVKEYSIG`. GPG itself returned zero
  with `REVKEYSIG`, `VALIDSIG`, and `KEYREVOKED`.

The updated verifier explicitly rejects expiration/revocation/error status
records and weak digest identifiers; signing invokes that verifier afterward.
No current residual of the original expired-key or revoked-binding acceptance
was reproduced. Temporary GPG agents were terminated and temporary key homes
removed. This does not test public trust distribution or key custody.

### R3 and integration results

Repeated `copytree(first, second)` with a complete, valid synthetic artifact and
identical recorded container name, timestamps, hashes, log, and
`clean_environment_id`:

```text
status: fail
errors: ["different recorded clean container IDs required"]
```

The artifact bytes and installed contents remained identical, so rejection was
attributable to reused execution identity. The build driver now records its
uniquely named container as that identity. This is still a check of recorded
executions, not independent attestation that hardware or separate machines ran
them; the output explicitly retains that limitation.

Confirmed root `.gitignore` now anchors `/build/`; `git check-ignore
scripts/build/build.py scripts/build/provision.py` produced no matches. Confirmed
the original project `LICENSE` contains MIT terms. This removes the observed
original-license blocker, without granting a license to excluded upstream code
or substituting for package-specific notice review.

Independently ran:

```text
python -m unittest discover -s tests -p test_build_validation.py -q
Ran 25 tests ... OK
```

Only this review file was edited. Native clean ARM builds, actual installation,
M2 functional checks, public repository/trust operation, and physical recovery
remain outside this review and require their existing execution gates.
