# Retained Perl5.42.3-1 baseline archive review

The [DATA-only reader](../../scripts/port/perl5423-installed-lifecycle/baseline_review/README.md)
completed the exact retained old package map needed to review normal rollback.
It used the existing bounded archive helpers; no package code, Perl, GPG/network,
lease, process/socket actor, build, installation or authority ran. Authentication
is still pending Root review; matching detached-signature bytes do not verify it.

The 16017184-byte archive matches
`f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f`,
and its 566-byte signature matches
`f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca`.
Both hashes were unchanged after inspection. The 3234-node map contains 2868 files,
364 directories, 2 bound hardlinks and 54 ELF headers; this is aarch64 header DATA,
not runtime/16K compatibility. Full actual metadata/config/hook paths and bounded
raw text are retained under the new baseline_review/actual directory.

There is no .INSTALL. There ARE two package-owned profile scripts (no backup
entries), a real Install/Upgrade PostTransaction old-module detection hook and
its shell helper. That helper queries the installed Perl version and package/file
ownership, then prints warnings; it was read, never executed. Normal rollback
must review these actual interfaces and retain ordinary ALPM hooks. Absence of
an install script does not mean absence of package hooks or shell integration.

The 2600-byte baseline-review.json SHA256
`cc3ac3191cef6f91f4c89b94f5f0635f2d03aec25431d03d86bd351bee49fdb6`
matches the exact field/status/selection/note contract emitted by read-only core
prepare.py:61. It remains ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION. The full
payload map 767438 bytes has SHA256
`cbb6e485e988279c737a8a43144eb235fb223ba92a04e62c4841513ee18a7aff`.
The actual review receipt 9822 bytes has SHA256
`58f329f0a782e045e4f6ba1e4d335e79f363371f4c88aa2b5e7eb0f0ac8d1705`.

26 fenced synthetic/actual-output controls pass. Core lifecycle source
`e819582c0b450144bdf4c287e0206bb620d029d1`, original retained archives and the closed
mirror 404 attempt remain unchanged. Root owns signature/trust/target349 context
review and any separately admitted normal lifecycle/rollback. Source/license,
native/M2, hardware, performance and release acceptance remain separate.
