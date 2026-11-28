# SPDX-License-Identifier: MIT
"""Rebind the passive reader from the qualified Build Tools source.

Only package identity, the exact test and payload grammar, producer pins,
and the native 4 KiB claim change. The original validation stays in place.
"""

import hashlib
import re


READER_SHA256 = 'b0e3dcf2762ce6b106ab1df4c9748456a958e8054433948bd0c08bd037b3b71d'
PROJECTION_SHA256 = '9fe4ab4ab29a3f6e662f0ac6ee0214f58700bc9e1be5278c915e6eaf15e5c2c4'
PRODUCERS = frozenset({
    'native/build_tools_alpm_v2.py',
    'native/build_tools_tools_v2.py',
    'native/build_tools_guest_v2.py',
    'native/build_tools_probe_v2.py',
    'native/build-tools-contract-v2.json',
})


def _predecessor(raw, digest):
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('qualified Build Tools predecessor bytes differ')
    return raw.decode('utf-8')


def _replace(source, old, new, count=1):
    if source.count(old) != count:
        raise ValueError(f'qualified Build Tools substitution seam differs: {old!r}')
    return source.replace(old, new)


def _bind_producers(source, producer_pins):
    if producer_pins.keys() != PRODUCERS or any(
        not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin)
        for pin in producer_pins.values()
    ):
        raise ValueError('Build Tools requires the exact five SHA-256 producer pins')
    lines = [line for line in source.splitlines() if line.startswith('PRODUCERS = ')]
    if len(lines) != 1:
        raise ValueError('qualified Build Tools producer assignment differs')
    return _replace(source, lines[0], f'PRODUCERS = {dict(sorted(producer_pins.items()))!r}')


def adapt_projection(raw: bytes, producer_pins: dict[str, str]) -> bytes:
    """Bind the public projection to the same exact producers as the reader."""
    source = _predecessor(raw, PROJECTION_SHA256)
    return _bind_producers(source, producer_pins).encode()


def adapt_reader(raw: bytes, spec: dict, producer_pins: dict[str, str]) -> bytes:
    """Emit a release-specific reader from the exact qualified predecessor."""
    source = _predecessor(raw, READER_SHA256)
    version, payload_count, source_count, consistency = (
        spec[key] for key in ('version', 'payload_count', 'source_count', 'consistency')
    )
    shape = {'0.1.1-2': (11, 15, False), '0.2.0-2': (12, 16, True)}
    if type(consistency) is not bool or shape.get(version) != (payload_count, source_count, consistency):
        raise ValueError('Build Tools release and reader shape differ')
    test_count, controls, commands = (11, 9, 6) if consistency else (8, 6, 5)
    names = spec['test_names']
    if (not isinstance(names, list) or len(names) != test_count
            or any(not isinstance(name, str) or not re.fullmatch(r'test_[A-Za-z0-9_]+', name) for name in names)
            or sorted(set(names)) != names):
        raise ValueError('Build Tools requires ordered, unique named package tests')

    source = _bind_producers(source, producer_pins)
    source = _replace(source, '0.2.0-1', version, count=10)
    test_lines = [line for line in source.splitlines() if line.startswith('    expected=[\'test_consistency_')]
    if len(test_lines) != 1:
        raise ValueError('qualified Build Tools test grammar seam differs')
    source = _replace(source, test_lines[0], f'    expected={names!r}')

    for old, new in (
        ("and len(value['recipe'].get('payload_files', {})) == 12 and len(value['recipe'].get('source_files', {})) == 16,",
         f"and len(value['recipe'].get('payload_files', {{}})) == {payload_count}"
         f" and len(value['recipe'].get('source_files', {{}})) == {source_count}\n"
         f"         and value['recipe'].get('expected_test_count') == {test_count}"
         f" and value['recipe'].get('expected_test_names') == {names!r},"),
        ("len(rows)==len(set(rows))==11,'all eleven actual package checks exactly once and in order'",
         f"len(rows)==len(set(rows))=={test_count},'all named package checks exactly once and in order'"),
        (r'^Ran 11 tests in ', f'^Ran {test_count} tests in '),
        ('eleven positive tests without skip/failure', 'all required positive tests without skip/failure'),
        ('tests=11,names=rows', f'tests={test_count},names=rows'),
        ("comparison.get('payload_files') == 12", f"comparison.get('payload_files') == {payload_count}"),
        ("recipe['expected_test_count'] == 11", f"recipe['expected_test_count'] == {test_count}"),
        ('exact recipe and positive17 makepkg checks required', 'exact recipe and positive makepkg checks required'),
        ('actual17 check() controls', 'the exact named check() controls'),
        ('complete seventeen-file archive namespace required', 'complete source-bound archive namespace required'),
        ('count=12, verified=True', f'count={payload_count}, verified=True'),
        ('actual ALPM installed seventeen-file source-bound payload required', 'actual ALPM source-bound installed payload required'),
        ('all seventeen payload leaves', 'all payload leaves'),
        ("value['controls']==9", f"value['controls']=={controls}"),
        ("value['commands_covered']==6", f"value['commands_covered']=={commands}"),
        ('dict(files=12,payload=payload)', f'dict(files={payload_count},payload=payload)'),
        ('exact12 installed/moved payload identity', 'exact installed/moved payload identity'),
        ('len(source_commands)==9', f'len(source_commands)=={controls}'),
        ("native['page_bytes'] > 0", "native['page_bytes'] == 4096"),
        ("runner['page_size'] > 0", "runner['page_size'] == 4096"),
    ):
        source = _replace(source, old, new)
    return source.encode()
