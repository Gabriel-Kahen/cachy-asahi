# Onboarding PTY cancellation correction

Status: source correction and local source tests PASS; corrected native replay,
installation and M2 hardware checks NOT RUN.

Native development run `38237127237` remains FAIL historically. Its retained
source-suite record reports 649 tests, zero skips and one integration failure:
`test_sigterm_runs_bounded_pty_cleanup_and_retains_diagnostics`. The bound
`scripts-integration.log` SHA-256 is
`bf92a3e8b53b73267dedf7893605627620e44c627c9096ac35c0f72d84261ecc`.
The traceback ends at the cleanup `os.close(fd)` with `EBADF`.

Cancellation could arrive after the parent closed the PTY slave but before it
cleared the owned handle. Cleanup then closed that stale descriptor again and
failed before retaining diagnostics. The existing signal-blocked spawn
transaction now includes the slave close and handle clear. Child cleanup,
timeouts, signal restoration and evidence handling otherwise retain their
existing behavior.

The deterministic regression sends actual SIGTERM immediately after the real
slave close. It fails with the original `EBADF` before the correction. After the
correction it checks the original interruption reason, retained stdout/stderr
and command record, restored signal mask/handler, closed master, reaped child
and absent child process group. It also reuses the slave descriptor number for
an unrelated file and verifies that cleanup leaves that replacement open.

On local x86_64/Python 3.14.7: 13 focused onboarding tests and all eight initial
unittest categories (650 tests, zero skips) PASS. The complete integration suite
passes with `ResourceWarning` treated as an error. These are source fixtures;
they do not establish a corrected native run or explain the separate repository
publication failure. Logs and the exact source hold receipt are in
`/tmp/cachy-source-suite-sigterm-diagnosis-mh7dwa5j/`.
