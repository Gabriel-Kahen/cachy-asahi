# SPDX-License-Identifier: MIT
"""Finite Perl installed-lifecycle DATA contract; no qualification is inferred."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent
OPERATION = 'perl5423-installed-lifecycle-v1'
CANDIDATE = 'perl-5.42.3-1.3-aarch64.pkg.tar.zst'
BASELINE = 'perl-5.42.3-1-aarch64.pkg.tar.xz'
SOURCE = '25dc3e65bdb6137c87a9409067fe9b2cf6e9763f'
ARCHIVE = {'bytes': 22071176, 'sha256': '647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22'}
OLD = {'bytes': 16017184, 'sha256': 'f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f'}
OLD_SIG = {'bytes': 566, 'sha256': 'f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca'}
EXPECTED_SHA = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
LOCK_SHA = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
HELPERS = {'owned_child.py': 'eaf9a46630e4fe4ca0a8f94a6dc2de4a881a6ad7e8b4dd0810b3347c0d7038d5',
           'archive_stream.py': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, cap=64 * 1024**2):
    path = Path(path)
    need(not any(p.is_symlink() for p in path.parents), 'input ancestry alias refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
             'bounded single-link ordinary input required')
        raw = stream.read(cap + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
             == identity(path.lstat()), 'input changed during read')
        return raw


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda s: need(False, 'nonfinite JSON value'))


def load(name):
    path = HERE / 'helpers' / name
    raw = read(path)
    if name in HELPERS:
        need(pin(raw)['sha256'] == HELPERS[name], 'existing owned/decoder helper changed')
    spec = importlib.util.spec_from_file_location('perl_lifecycle_' + name.replace('.', '_'), path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def natural(row):
    return (row.get('natural_exit') is True and row.get('group_absent') is True
            and row.get('leader_held_until_group_inspection') is True
            and row.get('exit_observed_via_waitpid') is True and row.get('ownership_lost') is False
            and row.get('forced_cleanup') is False and row.get('retirement') == 'REAPED'
            and 'cleanup_error' not in row and type(row.get('exit')) is int)


def inventory(raw, version='5.42.3-1'):
    rows = raw.decode().splitlines()
    need(len(rows) == 349 and rows == sorted(set(rows)), 'exact sorted 349 package inventory required')
    result = dict(row.split(' ', 1) for row in rows)
    need(len(result) == 349 and result.get('perl') == version, 'exact baseline Perl package required')
    return result


def admission(a, source_sha):
    need(set(a) == {'schema', 'operation', 'run', 'source_map_sha256', 'image', 'container',
                   'inputs', 'test_fingerprint', 'baseline_fingerprint', 'root_qualification_sha256', 'base_labels'},
         'exact Root selector fields required')
    need(a['schema'] == 1 and a['operation'] == OPERATION, 'fixed installed-lifecycle operation')
    for key in ('source_map_sha256', 'root_qualification_sha256'):
        need(type(a[key]) is str and re.fullmatch('[0-9a-f]{64}', a[key]), 'concrete Root ' + key)
    need(a['source_map_sha256'] == source_sha, 'exact installed-lifecycle Source map')
    need(type(a['run']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{0,48}', a['run']), 'bounded Root run identity')
    need(a['container'] == 'cachy-perl-lifecycle-' + a['run'], 'fixed unique container selector')
    need(type(a['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}', a['image']), 'immutable Root baseline image')
    labels = a['base_labels']
    need(type(labels) is dict and len(labels) <= 32 and all(type(k) is str and 0 < len(k) <= 128
         and type(v) is str and len(v) <= 1024 and not k.startswith('cachy-asahi.perl-lifecycle.')
         for k, v in labels.items()), 'exact reviewed inherited labels; lifecycle namespace collision refused')
    p = Path(a['inputs']) if type(a['inputs']) is str else None
    need(p is not None and p.is_absolute() and str(p) == str(p.resolve())
         and not any(c in str(p) for c in ',:\n\r'), 'literal exact input bind selector')
    for key in ('test_fingerprint', 'baseline_fingerprint'):
        need(type(a[key]) is str and re.fullmatch('[0-9A-F]{40}', a[key]), 'exact public primary signer: ' + key)
    need(a['test_fingerprint'] != a['baseline_fingerprint'], 'fresh separate TEST signer required')


def source(root, expected):
    raw = read(root / 'source-map.json', 4 * 1024**2)
    need(pin(raw)['sha256'] == expected, 'externally supplied Source map checksum')
    value = decode(raw)
    need(value['schema'] == 1 and value['operation'] == OPERATION, 'fixed Source map role')
    found = set()
    for p in root.rglob('*'):
        if p.is_dir() and not p.is_symlink():
            continue
        name = p.relative_to(root).as_posix()
        need(name == 'source-map.json' or name in value['files'], 'unmapped input or secret refused')
        if name != 'source-map.json':
            need(pin(read(p)) == value['files'][name], 'exact Source input bytes: ' + name)
            found.add(name)
    need(found == set(value['files']), 'complete Source input set required')
    return value
