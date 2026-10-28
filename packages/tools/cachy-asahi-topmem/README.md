# Current-user process memory

Development candidate. Source controls pass; package builds, installation, native
ARM runtime, both M2 Air sizes and release acceptance remain open.

`cachy-asahi-topmem` lists the current real UID's largest resident-memory processes,
by descending VmRSS and then PID. `--limit 1..50` defaults to10. `--json` returns
the same data plus scan/skip counts for tools. It reads process names, not command
arguments, so command-line passwords and tokens are not requested.

```
cachy-asahi-topmem --limit 10
cachy-asahi-topmem --json
```

The implementation is
original MIT material; only Python>=3.11 and Linux procfs are needed. Python is an
existing reviewed setup-package dependency and a retained ARM builder input.
There are no Lua/luv modules, ELF artifacts, network fetches or privileged actions.

VmRSS is the kernel's per-process resident-memory estimate, reported in KiB. This
uses1024 bytes per KiB and assumes no4K/16K page size. Shared pages can appear in
multiple processes. Rows must not be summed into unique physical usage, a memory
budget, a performance result or an application fault diagnosis. Snapshots are not
atomic: processes can change/exit/reuse PIDs during the scan. They provide no PID
lifetime or descriptor-generation guarantee.

Reads are bounded to16385 bytes per status file and4096 directory entries; oversized
or malformed status data is skipped. Other-user, raced, denied, unavailable and
ordinary read-error counts remain visible. A truncated scan is labeled, so the
result does not claim to include every current-user process. An unreadable proc
root returns exit1. KeyboardInterrupt/SystemExit propagate. There is no kill,
priority, KSM, allocator, sysctl, scheduler, service, boot/kernel or user-config
change. No watch loop, daemon, upload or stored process history is installed.

The package recipe installs one command below/usr/bin and docs/licenses below
/usr/share. It has no hooks, services, autostart, configuration or system mutation
in check/build. Removing the package removes only its package-owned files; no
user state is created. Target package ownership/conflict/install/remove checks,
two clean native ARM builds, both M2 Air sizes and independent terminal use remain
required before release selection.

Finite synthetic proc/CLI controls run with:

```
python -B test_topmem.py
```

They never read host/proc, spawn a process or change host state. This reviewed development candidate is one R4/M6
functional increment, not full-port A13 or R1–R5 acceptance.
