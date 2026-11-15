# Source-signature successor

The public successor explicitly excludes four PlugBuild UI payload/base64 copies
for which the pinned redistribution audit found no grant. Their hashes, URLs
and reasons remain in `manifest.json`; reappearance fails verification. The
exact earlier manifest/report are retained under `stages/`, and the complete
private pre-redaction packet remains outside the repository. The current
`successor-evidence.json` is a fresh public-material replay with both actual
source signatures passing. The older stage evidence was not rewritten.
See [notice and redaction provenance](../history-search/licenses/NOTICE.md).

This separate stage authenticates the **compressed bytes** previously retained
for Rust 1.99.0 and LLVM 23.1.1. Both detached signatures actually verify with
host GPG/GPGV in disposable private keyring directories. No archive is unpacked,
no recipe is evaluated, and no source payload is executed. The original opaque
report, source-input manifest, acquisition ledger and earlier histories remain
unchanged; their earlier “verification not performed” state is a past snapshot.

`successor-evidence.json` records the actual offline result. `manifest.json`
pins the public keys, signatures, documentary evidence, original report/ledger,
and finite successor history search. The tool verifies the parent manifest and
all 17 original recipe/patch/license material pins as well as the two archives.

| Source | Verified primary fingerprint | Actual result |
| --- | --- | --- |
| Rust | `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE` | GPGV exit 0; one allowed VALIDSIG |
| LLVM | `D574BD5D1D0E98895E3BF90044F2485E45D59042` | GPGV exit 0; one allowed VALIDSIG |

The [Rust public key](https://static.rust-lang.org/rust-key.gpg.ascii) came from
Rust's official distribution host. Its fingerprint is already declared in the
retained Rust PKGBUILD and SRCINFO. The
[LLVM official key bundle](https://releases.llvm.org/release-keys.asc) includes
all four primary keys declared in the retained LLVM/lld recipes. LLVM's
[release instructions at the exact release commit](https://raw.githubusercontent.com/llvm/llvm-project/6dfe1677ab8dffbc6ec13d53a1e0215d75147689/llvm/docs/HowToReleaseLLVM.rst)
describe signing source artifacts and name Tobias Hieta for odd releases. The
LLVM signature was acquired from the exact official GitHub release asset URL;
the Rust signature is reused byte-for-byte from the original acquisition.
Raw inputs and HTTP receipts are retained; temporary signed asset query strings
are redacted with their URL hashes preserved.

The served LLVM bundle also contains Tom Stellard's key with an expiration of
2025-05-02; that key did **not** sign this source. No current revocation or
freshness policy is established by this stage. HTTPS acquisition plus fixed
declared fingerprints and successful mathematics establish this bounded source
authentication result, without asserting a broader trust-policy decision.

All four exact original PKGBUILD hashes remain unresolved. The separate
`../history-search/` contains official build-window histories, exact revision
trees, additional Arch recipes, and bounded devtools/PlugBuild UI inspection.
The verifier hashes each retained candidate and compares it to the required
BUILDINFO hash. Seven candidate comparisons produce zero exact matches. Public
history does not exclude private, removed, locally modified or unqueried inputs.
No reconstructed recipe is represented as an original.

Added network use across all three workers: **246,979 response-body bytes in
38 requests**. The largest observed body is 28,162 bytes. The delegated limits
were 32 MiB total, 8 MiB per response and four concurrent requests; workers were
each sequential, with at most three workers active. No new source archive was
downloaded. Original acquisition bytes are not charged again or rewritten into
the new ledger. The subsequent notice audit adds 169,231 bytes in seven
requests; cumulative added acquisition is 416,210 bytes in 45 requests, with
zero new archives. See `controls.json` and the three request receipts (the history
receipt is in `../history-search/requests.json`).

Replay using the existing opaque cache; outputs must be a new file under `/tmp`:

```sh
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/authentication/authenticate.py \
  --source-cache /tmp/cachy-rust-source-closure-a3megt_w/cache \
  --original-report /tmp/cachy-rust-source-closure-a3megt_w/cached-replay04/report.json \
  --original-ledger /tmp/cachy-rust-source-closure-a3megt_w/http-ledger.json \
  --output /tmp/source-auth-replay.json
python -I -B scripts/port/arm-rust-toolchain-inputs/source-closure/authentication/test_authenticate.py -v
```

Replay makes zero network requests. It checks compressed byte pins before and
after signature verification, uses only pinned public key material, refuses
unexpected primary fingerprints, multiple VALIDSIG records, bad/revoked/expired
status and nonzero GPGV exit, and never imports into a host keyring. It binds archive descriptors to the
original manifest, refuses nonregular/symlink or oversized inputs before bounded
reads, and gives GPG a minimal explicit environment. Twelve
controls passed, including an actual GPG negative check against
unrelated data and altered input-pin checks. These controls complement the two
real opaque-source positive verifications recorded in the successor evidence.

Source-to-binary correspondence, archive/submodule/crate completeness, license
completeness/legal acceptance, compilation, installation, native ARM/M2 behavior,
Source/Reader/Root acceptance and release admission remain held or not run. The
five original pinned license files are unchanged; detached signatures do not
resolve those separate gates.
