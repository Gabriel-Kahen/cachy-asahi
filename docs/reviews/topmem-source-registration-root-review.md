# Current-user memory tool source registration

Root registers `cachy-asahi-topmem`0.1.0 as an original MIT development candidate.
It supplies the named process-memory convenience in the tools coverage matrix,
using the existing Python>=3.11 dependency. The command reports current-real-UID
processes by kernel VmRSS, with safe quoted names, deterministic ordering,
JSON output and visible race/permission/read-error/truncation counts. It reads
no command arguments and changes no process, tuning, service or configuration.

Root authenticated all18 author artifacts, captured exact command/test sources,
and reran13 functional tests with zero failures/errors/skips/PYC or process actors.
Four independent cases verify real-UID filtering when effective UID differs,
duplicate identity fields and overflowing RSS rejection. All five recipe source
checksums and their paired SRCINFO rows match. The command's SHA256 remains
`96c1b49a92cb6e97d1fe5c51c23f452d79341f2d71cd624cd3197d33b29633b1`.
Root changes only development-status wording, its paired README checksum and a
recipe comment after copying the reviewed seven-file package.

An actual local x86 CLI smoke exits0, reports three correctly ordered rows in
the execution namespace, and emits valid structured data with visible skip
counts. This verifies local command execution, not a complete desktop process
inventory or performance measurement. The private record is
`artifacts/reviews/topmem-primary-registration-root-20261013/local-smoke.json`.

The package installs four owned paths: the executable and README/NOTICE/LICENSE.
There are no hooks, services or user-state files. The manifest selects development
only. Two clean native ARM package builds, actual signed install/upgrade/remove/
reinstall ownership checks, independent terminal use on both M2 Air sizes and
maintenance/release enrollment remain required. No native,16K,M2,performance or
full R1–R5/M5–M9 acceptance follows.

Author receipt: `33ee2d620c63b95159201a4ae1f13c898b2ec10db1dd2291175ee18f48ec527f`.
Root source review and registration records are under
`artifacts/reviews/topmem-primary-registration-root-20261013/`.
See the [bounded implementation audit](full-port-next-functional-increment-20261013.md).
