# Minimal206 public-input authentication entry

This is a prepared, unselected entry for the exact `e947d24c3cb2f9facfd897d5e65ce6f19942cbca`
minimal builder. It verifies public input DATA. Root runs the actual attempt and
separately decides whether to issue the input-authentication adoption. No actual
GPG verification, native build, installation, old349 admission or M2 test is
claimed by the source or MODEL tests.

Running without `--execute-public-verification` returns HOLD (exit 2), reads no
selection/cache, creates no output and launches no process. There is no network
acquisition, install, signing, keyserver, agent, baseline or native interface.

## Root selection and invocation

Copy `SELECTION.TEMPLATE.json` into an external, owned location. Root must review
the current official trust/revocation state and fill the complete selection:

- `issuer`: `Root`; `accepted`: `true`; `status`:
  `ROOT_SELECTED_MINIMAL206_PUBLIC_INPUT_VERIFICATION_ONLY`.
- `entry`: absolute canonical path, byte count and SHA256 of this `verify.py`.
- `builder_lock`: absolute path to the unchanged sibling
  `minimal-native-builder-inputs/builder.lock.json`, with the supplied fixed pin.
- `cache`: the existing exact 0700 `packages` directory containing all 422
  operands. No missing/extra/partial files or links are permitted.
- `output`: a nonexistent external directory under an owned parent with no
  group/world write permission. It must be outside the checkout and input cache.
  Prior failures are retained; each retry needs a new output path.
- `tools`: canonical single-link, non-group/world-writable `gpg` and `gpgv`
  executables, each externally pinned by whole byte count and SHA256. The
  executable FD is retained and passed directly to `Popen`; no PATH lookup occurs.
- `trust_review`: `current_official_trust_reviewed: true`, integer Unix review
  and expiry times covering the actual run (at most 24 hours apart), and an
  absolute whole pin of Root's nonempty public review evidence (at most 64 KiB).
  A fingerprint or the old empty revoked list alone does not establish current
  official trust. This entry does not create or fetch the review evidence.

Pass the SHA256 of the final external selection:

```sh
python -I -B scripts/port/minimal-native-builder-input-authentication/verify.py \
  --execute-public-verification \
  --selection /absolute/external/Root-selection.json \
  --selection-sha256 WHOLE_SELECTION_SHA256
```

The selection is a trusted external Root instruction, not an authenticated
message from an arbitrary caller. Root controls issuance and the external hash.
The helper never fills in the Root issuer, acceptance or adoption status itself.

## Exact verification and custody

The entry pins the original complete source family and three maintained helpers:
`owned_process.py`, `native_arm.py` and its `package_checks.py` dependency. Pinned
Python bytes are compiled directly under a default-deny process/network fence.
No existing GnuPG home, environment, configuration or secret keyring is consulted.

All 422 ordinary single-link files, totaling 1,473,694,724 bytes, must match their
original whole size/SHA256 before any GPG process starts. They remain open by FD.
Namespace and identity checks surround every actor; every operand and tool is
whole-hashed again before a successful transcript is written. The entry does not
extract or execute package/rootfs/source archives. PKGINFO evidence remains the
separate original prerequisite.

The exact official public key inputs come from PKGBUILDs revision
`29432c01130efc4ad297dfe8f487d5b79cbaf8e9`: 3098-byte armored public key,
44-byte trusted fingerprint list, and zero-byte revoked list. The primary is
`68B3537F39A313B3E574D06777193F152BDBE6A6`; its encryption subkey is
`EA5AE14634B0DA39F927DC9EA517E8E924321745`. Only the exact decoded 2228-byte
public keyring (SHA256 `9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae`)
is written. Armor, CRC24 and the independent binary pin must match.

One selected offline `gpg --show-keys` checks public identity, key usability and
creation/expiration fields with unusable identities exposed. It uses no options
file, default keyring, autostart, dirmngr, automatic retrieval/import or trustdb
update. Its dedicated public-only state directory must remain empty. Colon trust
`-`/`q` means no local trust assignment; Root's explicit public anchor supplies
the trust decision. Invalid, disabled, revoked, expired, extra or secret keys fail.

Then `gpgv` verifies exactly 206 package detached signatures and the rootfs
detached signature, with an explicit public keyring and held input FDs. Machine
stdout is kept separate from bounded diagnostic files. Unknown or malformed
status, bad/missing/expired/revoked signatures, wrong signing/primary fingerprint,
multiple signatures, incoherent dates, or an algorithm differing from the exact
original signature packet fail. The committed package signatures use RSA with
SHA256 (40) or SHA512 (166); no weak-digest fallback is provided.

GnuPG documents that [gpgv trusts its keyring and does not check key expiration
or revocation](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html).
The public key listing supplements it; it is not a claim of an independent full
self-signature audit or fresh revocation retrieval. Root's fresh current trust
review remains required. The [colon/status API](https://github.com/gpg/gnupg/blob/master/doc/DETAILS)
and [show-only behavior](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html)
define the parsed fields. The upstream llhttp/libgit2 source tarballs have no
detached signatures; they receive their existing whole-pin check only.

Every one of the 208 actual children uses the unchanged maintained
`owned_process.prepare()/supervise()`. Acceptance requires natural integer exit
zero, raw reap, REAPED ownership, no timeout/signal/error, complete output and
`EMPTY_TWICE` original-group census. These scans do not prove global absence of
escaped processes or daemons. No logger threads or shell are used. Diagnostics,
machine stdout and every retirement result remain in the attempt report, even
when a later check fails.

Bounds: 900 seconds for the entire attempt; 60 wall seconds per child including
two seconds for retirement. Parent limits are 1 GiB AS, 900 CPU seconds, 4 MiB
files and 512 FDs. Children use 512 MiB AS, 45 CPU seconds, 128 KiB output/files
and 512 FDs; core dumps are disabled. These are verification bounds, not a native
builder fit measurement. Selected tool hashes do not pin the host dynamic loader
or shared-library runtime closure; Root remains responsible for the host runtime.

## Report consumed by the source worker

Only complete success writes `signatures.DATA.json`: an exact map of 207 original
archive filenames to `exit_code`, machine `status`, retirement evidence and input
pins. It is at most 4 MiB. `verification.DATA.json` records all 422 pins, every
actor and final checks. Failed/partial attempts never write a usable transcript.

`Root-authentication.UNISSUED.json` uses the unchanged original nine-field schema.
It contains the actual transcript whole pin and natural-retirement fact but
leaves issuer/acceptance/current-trust decision unset and status UNISSUED. Root
must review the report and issue a separate adoption with:

- `issuer: Root`, `accepted: true`,
  `status: ROOT_ADOPTED_MINIMAL_NATIVE_BUILDER_INPUT_AUTHENTICATION_ONLY`;
- fixed `builder_lock`, exact `signer_fingerprint`, whole `signatures` path/pin;
- `all_verifiers_naturally_retired: true`,
  `current_official_trust_reviewed: true`, `Root_native_authority: null`.

This is the exact `minimal_inputs()` prerequisite in source-author
`6651ad8c6f02a1a5c6c5683b40571af7512aedf1`,
`scripts/ci/llhttp-minimal-builder-source/prepare.py`. The identical adoption goes
in both `admission.builder_input_authentication` and
`runtime.builder_input_authentication`. The original
`minimal-native-builder-inputs/preflight.authenticated()` accepts the same map
and schema. This helper does not issue native selection or source admission.
The libgit2 project llhttp provider stays UNISSUED; old349 and M2 remain outside
the report's authority.

Run the focused source/MODEL controls (no GPG, package bodies or network):

```sh
python -I -B -Werror::ResourceWarning scripts/port/minimal-native-builder-input-authentication/test_data.py
```
