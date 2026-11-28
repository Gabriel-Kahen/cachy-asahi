# SPDX-License-Identifier: MIT
"""Read supplemental memory counters for the scoped Asahi629 host monitor."""

from pathlib import Path

MEMORY_STAT = frozenset((
    "anon", "file", "shmem", "active_file", "inactive_file", "file_mapped", "file_dirty", "file_writeback",
    "swapcached", "slab", "slab_reclaimable", "slab_unreclaimable", "workingset_refault_file",
    "pgscan", "pgscan_direct", "pgscan_kswapd", "pgsteal", "pgsteal_direct", "pgsteal_kswapd", "pgmajfault",
))
SWAP_PAGES = frozenset(("pswpin", "pswpout"))


def _bounded_text(path, cap):
    with path.open(encoding="ascii") as source:
        body = source.read(cap + 1)
    if len(body) > cap:
        raise ValueError(f"Telemetry exceeded {cap} bytes")
    return body


def _counters(path, label, wanted, cap):
    observed = {}
    try:
        for line in _bounded_text(path, cap).splitlines():
            fields = line.split()
            if not fields or fields[0] not in wanted:
                continue
            name = fields[0]
            if (name in observed or len(fields) != 2 or not fields[1].isdecimal()
                    or len(fields[1]) > 20 or int(fields[1]) >= 1 << 64):
                raise ValueError(f"Invalid counter row: {name}")
            observed[name] = int(fields[1])
    except (OSError, ValueError) as error:
        return {label: {}, label + "_error": f"{type(error).__name__}: {error}"}
    result = {label: observed}
    if missing := wanted.difference(observed):
        result[label + "_missing"] = sorted(missing)
    return result


def actor_memory(group: Path):
    """Read bytes and reclaim counters from the already-selected actor cgroup."""
    result = _counters(group / "memory.stat", "memory_stat", MEMORY_STAT, 16 << 10)
    try:
        result["memory_pressure"] = _bounded_text(group / "memory.pressure", 512).strip()
    except (OSError, ValueError) as error:
        result["memory_pressure_error"] = f"{type(error).__name__}: {error}"
    return result


def host_swap(vmstat: Path = Path("/proc/vmstat")):
    """Read cumulative host swap-in and swap-out counts, measured in pages."""
    return _counters(vmstat, "host_swap_pages", SWAP_PAGES, 64 << 10)
