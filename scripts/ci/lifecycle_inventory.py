#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project only known lifecycle inventories after exact authoritative equality.

This pure reader never installs packages, edits raw evidence or weakens the
generic exporter. The caller supplies its already accepted native base inventory
and independently inspected original/upgrade archive rows. Unknown paths remain
the caller's responsibility and must pass the ordinary exporter unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMIT = 4 * 1024**2
PACKAGES = frozenset(('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
                      'cachy-asahi-zsh-config', 'cachy-asahi-setup'))
NAME = re.compile(r'[a-z0-9][a-z0-9@._+-]{0,127}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+:~-]{0,255}\Z')
STAGES = {
    'before': 'base', 'final': 'base', 'removed-before-reinstall': 'base',
    'baseline-installed': 'baseline', 'baseline-handoff': 'baseline',
    'clean-baseline-handoff': 'baseline',
    # The actual lifecycle producer reinstalls the changed upgrade fixtures.
    'reinstalled': 'upgrade', 'upgraded': 'upgrade',
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def validate_map(value):
    need(isinstance(value, dict) and 0 < len(value) <= 2048, 'nonempty bounded inventory map required')
    for name, version in value.items():
        need(isinstance(name, str) and NAME.fullmatch(name) and isinstance(version, str)
             and VERSION.fullmatch(version), 'invalid package/version inventory token')
    return dict(value)


def overlay(rows):
    need(isinstance(rows, list) and len(rows) == len(PACKAGES), 'four accepted archive authority rows required')
    versions = {}
    for row in rows:
        need(isinstance(row, dict) and isinstance(row.get('name'), str)
             and row['name'] in PACKAGES and row['name'] not in versions, 'duplicate/unknown archive authority')
        versions[row['name']] = row.get('version')
    validate_map(versions)
    need(set(versions) == PACKAGES, 'complete archive authority required')
    return versions


def real_directories(path):
    need('..' not in path.parts, 'inventory parent traversal refused')
    for parent in (path, *path.parents):
        need(stat.S_ISDIR(parent.lstat().st_mode), 'real nonsymlink inventory directories required')


def read_inventory(path):
    real_directories(path.parent)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'singly linked regular inventory required')
    need(info.st_size <= LIMIT, 'inventory exceeds byte limit')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
             and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), 'inventory changed before open')
        data = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    need(len(data) <= LIMIT and len(data) == info.st_size
         and (after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
         (info.st_size, info.st_mtime_ns, info.st_ctime_ns), 'inventory changed or exceeded bound while reading')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate inventory JSON key')
            result[key] = value
        return result

    def constant(_value):
        raise ValueError('nonfinite inventory JSON refused')

    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
    return data, validate_map(value)


def projections(raw, base, baseline, upgrade):
    """Return {relative_path: public_json_bytes}, at most eight existing paths.

    Validate all present known files before hashing or returning any projection.
    Missing files are omitted so a failed partial lifecycle can retain receipts;
    this function does not certify lifecycle completion. Every returned JSON must
    still pass the unchanged generic public-content exporter.
    """
    raw = Path(raw)
    need(raw.is_absolute(), 'absolute raw inventory directory required for complete ancestor checks')
    real_directories(raw)
    base = validate_map(base)
    need(not set(base) & PACKAGES, 'accepted base must exclude overlay packages')
    original, changed = overlay(baseline), overlay(upgrade)
    need(all(original[name] != changed[name] for name in PACKAGES), 'distinct accepted upgrade versions required')
    authority = {'base': base, 'baseline': {**base, **original}, 'upgrade': {**base, **changed}}
    try:
        (raw / 'lifecycle').lstat()
    except FileNotFoundError:
        return {}
    real_directories(raw / 'lifecycle')
    loaded = []
    for stage, kind in STAGES.items():
        relative = 'lifecycle/' + stage + '-inventory.json'
        path = raw / relative
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        data, rows = read_inventory(path)
        need(rows == authority[kind], 'lifecycle inventory differs from complete accepted stage authority: ' + stage)
        loaded.append((relative, stage, kind, data, rows))
    result = {}
    for relative, stage, kind, data, rows in loaded:
        record = {'schema_version': 1, 'record_type': 'validated-lifecycle-inventory-projection',
                  'stage': stage, 'authority': kind, 'complete_inventory_matches_authority': True,
                  'original_sha256': hashlib.sha256(data).hexdigest(), 'original_bytes': len(data),
                  'package_count': len(rows), 'packages': [{'name': name, 'version': rows[name]} for name in sorted(rows)],
                  'raw_bytes_exported': False}
        encoded = (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')
        need(len(encoded) <= LIMIT, 'inventory projection exceeds public byte limit')
        result[relative] = encoded
    return result
