# Source-only GPG diagnostics successor

The closed corrected r5 trial held at trust verification: gpg exit2, source
line81. Normal PAM/session retirement and cleanup passed separately. Retained
sanitized report/serial evidence contains **zero GnuPG status-code lines**.
The prior `/run` receipts are volatile; recovery is not assumed. The cause remains
unknown. This source correction has not been prepared into a new image or booted.

`arm16k-project-lifecycle-root` now maps to the fixed public source label
`guest-root.sh`. A new fixture-private receipt helper handles only five fixed
operations: the existing two-key import, the existing two-key ownertrust input,
and verification of the exact Python, mpdecimal and KSM archive/signature pairs.
No caller-supplied GPG arguments or other archive names are accepted.

The future guest would keep receipts under
`/var/lib/arm16k-project-lifecycle/receipts/`, directory0700/files0600. Fixed labels
are `trust_import`, `ownertrust`, `python`, `mpdecimal`, `ksm`. Each operation keeps
separate `.status`, `.stderr`, and private supervisor stderr. Each GPG process has
a32KiB file-size ceiling (possibly stricter under512-byte shell limit units),20s
timeout and2s kill grace. Supervisor output consists only of bounded fixed
invocation/signal diagnostics and remains private. Existing/symlink receipt leaves
are refused rather than overwritten. First failure additionally records bounded
`.keys`/`.keys.stderr` from a10s read-only listing of the exact expected key.
Raw receipts stay on the guest disk for an independently authorized later intake;
the normal-user serial proof never reads them.

Only a generated `gpg-failure.env` is appended to the nonce-bound HOLD summary.
Its export contract is:

- Fixed operation and archive labels (`none` for pre-archive trust operations),
  original exit status, recognized GnuPG status-code names, numeric documented
  ERRSIG/ERROR/FAILURE codes and their code source. Unknown formats stay unknown.
- Error categories limited to unknown, bad_signature, missing_public_key,
  unsupported_algorithm, signature_check_error, expired_signing_key,
  expired_signature, revoked_key, invalid_signature_data, gpg_error, timeout,
  receipt_limit and diagnostic_unavailable.
- Actual guest UTC epoch/UTC text observed after failure and bounded key listing;
  matching key creation/expiry epochs and pub/sub scope; signature creation/expiry
  epochs; whether the observed primary matches the pinned expected primary.
- Explicit numeric before/after comparisons between UTC and those dates. These
  are informational comparisons, not an alternative validity policy.

Key dates come from matching fingerprint records in GnuPG's colon listing.
Signature dates prefer actual runtime VALIDSIG metadata. If verification fails
before that metadata exists, a small injected `signature-dates.lock` supplies the
dates independently obtained from fresh host gpgv verification of these exact
pinned archive/signature bytes; the summary labels that source explicitly.
Unsupported/missing date formats remain unknown. See the official
[GnuPG2.4.9 status/colon format](https://github.com/gpg/gnupg/blob/gnupg-2.4.9/doc/DETAILS).

No user IDs, fingerprints/raw keys, arbitrary error text, raw commands, arguments,
credentials or environment are exported. An original nonzero verification exit
always remains nonzero, even with GOODSIG/VALIDSIG or apparently acceptable dates.
`Required TrustedOnly`, exact keys/archives, normal GPG temporal validation,
ordinary ALPM hooks/scriptlets and111+3 package counts are unchanged. There are
no clock changes, fake-time flags, ignored validity errors or trust relaxation.

The helper and diagnostic date file become explicit read-back fixture files in a
future preparation; `boot.py` binds the helper's source hash. `date` is the sole
additional command and belongs to the existing coreutils package in the exact111
namespace. The source-bound guard now lists32 baseline commands; no package is
added. Source/data controls pass46 cases, including installed-name mapping,
redaction, date-source/unknown handling, bounded private persistence, refusal to
overwrite and preservation of the original failing exit. GPG child behavior in
these controls is modeled with a private test executable; it is not a new guest
verification result. Binary comparison controls still exercise the real helper.

No fresh prepared-input hash, marker or actor is issued by this source-only
change. The previous r5 input is closed and cannot be reused with this successor.
Root must separately review this diagnostic contract before any new preparation
or boot. C01 remains independently owned and the KSM transaction remains held.
