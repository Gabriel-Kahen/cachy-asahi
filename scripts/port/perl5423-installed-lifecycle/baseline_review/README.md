# Exact old Perl baseline archive DATA review

This isolated reader and its actual retained output review the exact
`perl-5.42.3-1-aarch64.pkg.tar.xz` needed for normal rollback. Core lifecycle source
commit `e819582c0b450144bdf4c287e0206bb620d029d1` remains read-only. No package code,
Perl, GPG, network, process/socket actor, daemon, lease, build, installation or
Root authority runs here. Signature-byte pinning is **not authentication**.

The existing bounded `read_rows`/single-frame decoder is frozen byte-for-byte
under frozen/; origin.json pins both helpers and the read-only core interface.
It validates complete compression/tar termination, finite headers/bytes/window/
time, root-owned canonical paths and links, and maps every node without extracting
payload into an installed tree. A second bounded DATA pass retains only small
explicit UTF-8 metadata/profile/hook texts, each ≤64 KiB / aggregate ≤512 KiB. Neither
pass imports, sources, evaluates or executes text from the package.

Actually run:

```sh
python3 -I -B -Werror scripts/port/perl5423-installed-lifecycle/baseline_review/review.py \
  --archive /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-baseline-retained-r2/perl-5.42.3-1-aarch64.pkg.tar.xz \
  --signature /home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-baseline-retained-r2/perl-5.42.3-1-aarch64.pkg.tar.xz.sig \
  --output /tmp/cachy-asahi-arm16k-systemd-tcg-20261114/scripts/port/perl5423-installed-lifecycle/baseline_review/actual

python3 -I -B -Werror scripts/port/perl5423-installed-lifecycle/baseline_review/test_controls.py
```

The actual review completed in 1.22 s with exact archive/signature hashes equal
before/after. Repeating the command requires a fresh output; it never overwrites
retained originals or an earlier output. The closed pinned mirror 404 attempt is
separate and unchanged; this reader uses retained bytes and retrieves nothing.

## Actual package facts and interface

- Archive 16017184 bytes SHA256
  `f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f`;
  detached signature 566 bytes SHA256
  `f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca`.
- Complete 3234-node map: 2868 regular files, 364 directories, 2 hardlinks; 54
  ELF64/little-endian headers. Interpreter and libperl header machine is 183
  (aarch64). This is header DATA, not execution, LOAD/16K compatibility or ABI proof.
- Hardlinks are perlthanks→perlbug under usr/bin/core_perl, and corresponding
  compressed manpage aliases. Both target prior regular files with exact inherited
  size/SHA. They are mapped, never materialized as host links.
- Actual PKGINFO: perl 5.42.3-1/aarch64; dependencies gdbm>=1.17, db5.3, glibc,
  libxcrypt, libcrypt.so=2-64; 113 versioned provides. Declared licenses are
  Artistic-1.0-Perl and GPL-1.0-or-later; this does not establish legal completeness.
- Controls are .PKGINFO/.BUILDINFO/.MTREE; **no .INSTALL**. There are two
  package-owned etc/profile.d files, with no declared backup paths. Their text
  adds the site/vendor/core Perl script directories to the shell path. No claim
  is made about preserving operator edits to these package-owned, non-backup files.
- The real detect-old-perl-modules hook triggers Install/Upgrade of
  usr/lib/perl5/*/, runs PostTransaction, and executes the shipped shell helper.
  Static review finds version querying through Perl, find/pacman ownership queries,
  sed/wc and warning output. It was **not executed**. Normal trusted rollback must
  retain ordinary hook/scriptlet behavior; this DATA review authorizes no suppression.

`actual/payload.json` is the COMPLETE original helper projection.
`actual/baseline-review.json` is byte-shape compatible with core prepare.py:61:
exact status ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION, old archive/signature
pins, metadata_config_hook_paths selection and original note. It does not alter
core preparation or grant approval. Root can compare its hash with the packet
core preparation later emits, then separately review the original paths/texts.

`actual/review.json` records full metadata, all hardlink associations, exact
interface paths, raw text map and output hashes. Six texts are retained as
non-executable .data: PKGINFO, BUILDINFO, both profiles, hook and shell helper;
MTREE remains an exact binary-node hash in the complete map. The actual review
packet/payload hashes are recorded in RESULTS.json.

26 fenced controls pass, covering benign synthetic maps/hardlinks, unexecuted
INSTALL sentinel text, bounds/path/link/frame/metadata refusals, missing backup,
wrong exact pins/no output, helper tampering and actual output/interface hashes.
Process creation, socket creation, fork/exec and dynamic CDLL calls are denied
throughout tests. No Root signer/trust/qualification is invented. Authentication,
frozen349 target provenance/dependency context, normal ALPM install/upgrade/
rollback and inherited hook execution remain Root gates. No native lifecycle,
M2/hardware, performance or release acceptance follows from this review.
