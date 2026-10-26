#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure bounded resolution in an observed root; no filesystem or permission API."""
from collections import deque
import os

MAX_STEPS = 4096
MAX_LINKS = 40
MAX_PATH_BYTES = 4096


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def text(value, *, empty=False):
    need(type(value) is str and (empty or value) and '\0' not in value,
         'invalid root path text')
    need(len(value) <= MAX_PATH_BYTES, 'root path byte limit')
    try:
        size = len(os.fsencode(value))
    except UnicodeEncodeError:
        raise ValueError('invalid root path encoding') from None
    need(size <= MAX_PATH_BYTES, 'root path byte limit')


def resolve(nodes, path, *, limits):
    """Return (canonical endpoint, ordered dependency trace); root is ''.

    Queries are canonical relative names, or ''/'/' for root. Only visited node
    shapes are checked; this does not validate or authorize a whole observation.
    limits supplies max_nodes, max_depth and tick(), as full_root.Limits does.
    """
    limits.tick()
    need(type(limits.max_nodes) is int and limits.max_nodes > 0 and
         type(limits.max_depth) is int and 0 < limits.max_depth <= 256,
         'finite root path limits required')
    need(type(nodes) is dict and len(nodes) <= limits.max_nodes, 'root path node limit')
    text(path, empty=True)
    need(path in ('', '/') or all(part not in ('', '.', '..') for part in path.split('/')),
         'canonical relative root query required')
    pending = deque([] if path in ('', '/') else path.split('/'))
    parts, trace, seen = [], [''], set()
    kind, steps, links = 'directory', 0, 0

    def spend():
        nonlocal steps
        limits.tick()
        steps += 1
        need(steps <= MAX_STEPS and len(pending) <= MAX_STEPS, 'root path work limit')

    def record(name):
        need(len(trace) < MAX_STEPS, 'root path trace limit')
        trace.append(name)

    while pending:
        spend()
        part = pending.popleft()
        need(kind == 'directory', 'root path parent is not directory')
        if part in ('', '.'):
            if part == '.':
                record('/'.join(parts))
            continue
        if part == '..':
            need(parts, 'root path escapes observed root')
            parts.pop()
            record('/'.join(parts))
            continue
        need(len(parts) < limits.max_depth, 'root path depth limit')
        name = '/'.join(parts + [part])
        text(name)
        node = nodes.get(name)
        need(type(node) is dict and type(node.get('type')) is str and
             node['type'] in ('file', 'directory', 'symlink'),
             'root path node missing or unsupported: ' + name)
        record(name)
        if node['type'] != 'symlink':
            parts.append(part)
            kind = node['type']
            continue
        spend()
        state = (name, tuple(pending))
        need(state not in seen, 'root path symlink cycle')
        seen.add(state)
        links += 1
        need(links <= MAX_LINKS, 'root path symlink expansion limit')
        target = node.get('target')
        text(target)
        if target.startswith('/'):
            parts.clear()
            record('')
        pending.extendleft(reversed(target.split('/')))
        need(len(pending) <= MAX_STEPS, 'root path work limit')
    limits.tick()
    return '/'.join(parts), tuple(trace)
