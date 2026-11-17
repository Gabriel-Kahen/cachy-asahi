#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure public cache DATA decoder/derivation caller; no phase or runtime API."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FAMILY = ROOT / 'scripts/integration/arm16k_perl_ldcache_semantic_transition'
BASELINE = dict(bytes=17551, sha256='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215')
INSTALLED = dict(bytes=17695, sha256='eeb01c0c2d393aa9bf526a673fedfa331173573722827ec2f68849ccf997412c')
HELPERS = {
    'cache.py': dict(bytes=5293, sha256='8b89b9d6139b2e8153835cbca3e3312125dc01885e4bb5cc80901788d800c7b0'),
    'providers.py': dict(bytes=2222, sha256='ec9968268f5135df822967f471c10cc562f7a640b17bc311c073a0ee82f5da12'),
    'transition.py': dict(bytes=4952, sha256='2798b614a7f992cc7d486d363638fc5525877d74bc65c77434ed9f08b50c1f3c'),
    'providers.DATA.json': dict(bytes=180225, sha256='654bfbc3adbcbc06780fe0e31c52b987eeb8ce14734297a4f0e1f319f5c76dda'),
}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity(info):
    return tuple(getattr(info, field) for field in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid',
                                                   'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def whole(path, expected):
    """Read one explicit whole-pinned regular DATA leaf; never discover inputs."""
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(), 'canonical nonaliased public DATA leaf')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o644 and before.st_size == expected['bytes'],
             'single-link exact0644 bounded DATA leaf')
        raw = stream.read(expected['bytes'] + 1)
        need(identity(before) == identity(os.fstat(stream.fileno()))
             == identity(path.stat(follow_symlinks=False)) and pin(raw) == expected, 'stable whole public DATA pin')
    return raw


def helpers():
    for name, expected in HELPERS.items(): whole(FAMILY / name, expected)
    spec = importlib.util.spec_from_file_location('public_baseline_transition', FAMILY / 'transition.py')
    transition = importlib.util.module_from_spec(spec); spec.loader.exec_module(transition)
    return transition.C, transition.P, transition


def analyze(baseline):
    need(type(baseline) is bytes and pin(baseline) == BASELINE, 'exact supplied public baseline bytes required')
    cache, providers, transition = helpers()
    decoded = cache.decode(baseline)
    need(len(decoded['entries']) == 358 and cache.encode(decoded['entries']) == baseline, 'canonical finite358 baseline')
    projection = transition.qualified_providers()
    manifest, installed = transition.derive(baseline, projection['baseline_nodes'], projection['db_nodes'],
                                          projection['db_elf_sonames'])
    need(pin(installed) == INSTALLED and manifest['baseline_entries'] == 358
         and manifest['installed_entries'] == 361 and manifest['restored'] == BASELINE,
         'independently derived three-provider DATA transition')
    need(all(manifest[key] is None for key in ('Root_acceptance', 'lifecycle_acceptance', 'VM', 'M2', 'release')),
         'DATA derivation cannot issue acceptance')
    return dict(kind='PUBLIC_CACHE_BASELINE_DECODE_AND_DERIVATION_DATA_ONLY', baseline=BASELINE,
                baseline_entries=358, installed=INSTALLED, installed_entries=361, restored=BASELINE,
                added_names=sorted(row['name'] for row in manifest['added_entries']),
                Root_acceptance=None, lifecycle_acceptance=None, VM=None, M2=None, release=None), installed


if __name__ == '__main__':
    report, _ = analyze(whole(HERE / 'baseline-cache.bin', BASELINE))
    print(json.dumps(report, sort_keys=True, indent=2))
