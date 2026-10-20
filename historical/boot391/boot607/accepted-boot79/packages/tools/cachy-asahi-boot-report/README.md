# cachy-asahi-boot-report 0.1.0

Explicit local boot diagnostics for the Apple-safe replacement of PC crash/boot
management. List the system-journal boot IDs visible to your existing account:

```sh
cachy-asahi-boot-report list
```

Then copy one **exact 32-character lowercase boot ID** from that list:

```sh
mkdir -m700 "$HOME/boot-reports"
cachy-asahi-boot-report export --boot-id EXACT_32_HEX_ID \
  --output "$HOME/boot-reports/new-report"
```

No current/previous boot is silently chosen, and relative offsets such as `-1`
are refused. Export uses fixed `journalctl` arguments for the chosen boot's kernel
records; arbitrary options, remote sources, shell commands and inherited systemd,
pager or loader overrides are not passed to the child. Python's installed entry
uses isolated mode. This does not defend an interpreter already compromised by
its own loader or a hostile same-user process.

**Reports may contain sensitive data**: device identifiers, addresses, kernel
command lines, paths and crash contents. Raw journal fields remain intact; these
reports are not sanitized. They remain local; review them privately before sharing.
The tool does not upload, send notifications, use a network client or escalate.
Do not use sudo merely to get a more complete report. Missing permissions/history
are reported as unavailable or incomplete, never as a clean bill of health.

Pstore capture is separately explicit:

```sh
cachy-asahi-boot-report export --boot-id EXACT_32_HEX_ID \
  --include-pstore --output "$HOME/boot-reports/another-new-report"
```

Pstore can contain records from another boot, records already handled by the
system's pstore service, or no accessible records. Its `boot_attribution` always
stays `UNKNOWN`; it is never assigned to the selected journal boot. The command
only reads regular single-link files; it never clears/unlinks pstore, requests a
crash, loads kexec, changes boot/kernel/firmware settings, restarts a service or
manages a package. Existing Asahi boot and recovery paths remain in control.

`--journal-directory /absolute/local/journal` reads saved local journal files
instead of the live system journal. `--pstore-directory /absolute/local/copy`
(with `--include-pstore`) reads a saved local copy instead of `/sys/fs/pstore`.
These are local paths, not URLs or extra journalctl options. The report must be
outside either source. Source paths traverse ordinary directories without
following symlinks. A saved directory is not certified as genuine kernel pstore.

The report directory must be new, with a caller-owned parent that is not group
or world writable; it is created mode0700. Each new file is mode0600 and never
overwrites an existing file. `report.json` is written last, with raw output file
lengths/SHA256, fixed argv/environment, selection, command outcomes and pstore
before/after identity/metadata. `boots.stdout.json`, `kernel.jsonl`, their stderr
files and indexed binary pstore files preserve the exact captured bytes. Journal
records are checked again for the exact boot ID, kernel transport and retained
cursor/realtime/monotonic timestamps. These hashes describe local captured bytes,
not trusted provenance, signatures or crash authenticity.

`captured` means a nonempty, selection-validated command response was captured
within bounds; it does not mean complete boot history or a diagnosed crash.
`history_completeness` always stays `UNKNOWN`, and `kernel_crash_diagnosis` stays
`NOT_ESTABLISHED`. Permissions, rotation/vacuuming, missing persistent storage,
concurrent journal changes and abrupt crashes can leave incomplete history.
Pstore absence likewise proves no absence of a crash. A live export is not an
atomic snapshot. Ordinary read atime can change under filesystem policy; metadata
stability checks do not establish immutable or authentic content.

Bounds: boot listing1MiB/4096 boots; kernel JSONL8MiB; stderr64KiB per command;
20seconds per journal command plus2seconds to reap its direct child; pstore32
files/1MiB each/8MiB total/5seconds checked between filesystem reads. Over-limit
responses preserve only a bounded raw prefix and report `incomplete`; no valid
record is invented to complete a prefix. Direct children are reaped before return
or retirement is explicitly unknown. Same-group pipe holders receive the final
kill; escaped groups are not claimed retired. Filesystem calls can block beyond
a checked deadline; there is no storage-latency or power-loss guarantee. Interrupts
or filesystem errors can leave a partial private directory without `report.json`;
keep it for inspection and choose a new name on retry. No automatic deletion or
resumption is performed.

Exit0: listing obtained, or requested journal/pstore capture completed within the
stated bounds. Exit1: unavailable, incomplete or refused. Exit2: CLI syntax error.
An empty listing may exit0 and still says history `UNKNOWN`. Unsupported journal
JSON schemas fail closed. Journal boot-list JSON requires systemd251 or later.
No accepted Apple policy or known-good recovery kernel is inferred from a report.

This original MIT package is a development proposal. Host tests use disposable
sources only. Native package builds, package-manager lifecycle, target journal/
pstore behavior, physical16K/M2 operation, actual crash recovery and full R3–R5
acceptance remain **NOT RUN**. There is no service, timer, hook, automatic startup
scan, privileged helper or dependency on a PC bootloader.
