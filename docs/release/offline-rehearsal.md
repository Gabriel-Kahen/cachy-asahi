# Offline signed release lifecycle rehearsal

`scripts/release/rehearse_lifecycle.py` runs a finite synthetic release pair using
the existing release, repository-certificate inspection, expiry, comparison and
endpoint-selection code. It requires already installed Python 3.11+, GnuPG,
`gpgconf`, `repo-add`, `bsdtar` and `vercmp`. It downloads and installs nothing.

Run with a **new absolute directory** whose parent already exists:

```sh
python3 -I -B scripts/release/rehearse_lifecycle.py --output /tmp/my-new-rehearsal
python3 -I -B scripts/release/test_rehearse_lifecycle.py
```

The output directory is created exclusively with mode 0700. Existing paths and
symlink components are refused. Every rerun needs a different output path; the
tool never deletes a previous receipt. It creates only synthetic inputs, a
private repository and a separately named `rehearsal-selection/current`. No
package installation, live pacman configuration, system keyring or platform
component is accessed or changed. The package archive contains an inert version
file. Both fixtures retain the same modeled Asahi base inventory.

The sequence is:

1. Generate a one-day TEST-only signing identity in a fresh `/tmp` home; export
   its public certificate and inspect it with the existing enrollment parser.
   Use the maintenance expiry checker at the current time and exact deadline.
2. Create deterministic package archives for `1.0-1` and `1.1-1`. Stage/sign and
   verify both with the real release CLI, including `.PKGINFO`, dependencies,
   provenance, repository databases, package signatures and full payload maps.
3. Compare the authenticated pair and require an actual artifact/version
   upgrade. Attempt real stable promotion for each release and require the
   specific `synthetic fixtures cannot enter stable` refusal. No gate is
   replaced or fabricated into acceptance.
4. Exercise the existing endpoint atomic-symlink primitive against the private
   rehearsal selector. Refuse a deliberately partial successor while preserving
   the predecessor selection, then select the complete successor. This selector
   is private single-writer fixture logic; its initial-state assertion is not a
   concurrent compare-and-swap guarantee or a production recovery API.
5. Corrupt the selected successor archive on disk and require verification to
   reject it. Withdraw it with the real release CLI, verify the signed incident,
   require the specific withdrawal verification refusal, and refuse reselection.
6. Reverify/select the retained predecessor, compare every retained file/link
   against its earlier state, and sign a recovery receipt. The corrupt successor
   and incomplete copy remain available for inspection.
7. Stop only the TEST home's agents and remove that home, including private
   keys. Public certificates, signed bundles, commands/results and receipts
   remain under the output directory.

`report.json` records each named check and the actual subprocess arguments,
return codes, stdout and stderr. `comparison.json`, `expiry-current.json`,
`expiry-deadline.json`, signed `recovery.json`, public `TEST-public.asc`, retained
bundles and signed withdrawal records provide independently inspectable inputs.
Tests reverify the predecessor and receipts in a different public-only GPG home.
Package fixture bytes repeat exactly; keys, timestamps and signatures are fresh,
so complete output directories are not expected to be byte-identical.

Each release CLI and each directly invoked release-library tool has a 90-second
deadline. Identity generation has a 30-second deadline and agent cleanup has a
10-second deadline. Timeout/interruption kills only the command's own newly
created process group. SIGTERM and ordinary Python exceptions unwind the TEST
identity cleanup. SIGKILL, machine loss and power failure cannot run cleanup;
inspect and remove the identified TEST home manually in those cases. Existing
certificate-inspection helpers retain their own 30/45-second subprocess bounds.

The new targeted suite also exercises mid-stage database creation failure after
real copying/signing, no published partial successor, unchanged predecessor,
successful retry, command timeout cleanup and real SIGTERM cleanup. Existing
release/export tests model stable gate acceptance in some storage tests; those
tests exercise filesystem/signature mechanics and never supply real hardware
evidence. The rehearsal CLI itself keeps all stable gates intact.

`PASS_SYNTHETIC_REHEARSAL` means these finite offline operations passed. Stable
promotion remains `NOT_ACCEPTED`; package installation, actual trust bootstrap,
key rotation, publication, native ARM, generic ARM/16K, M2 Air 13-inch and M2 Air
15-inch remain `NOT_RUN`. Repository pointer recovery does not restore an
installed package/database/base combination or a boot/session. Full A06, A08,
A12 and A15 acceptance still needs the project's existing real release,
maintenance, trust, custody, endpoint and exact-machine evidence.
