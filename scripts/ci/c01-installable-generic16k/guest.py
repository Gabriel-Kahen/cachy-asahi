#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite root-guest ALPM lifecycle of the exact accepted C01 package archives."""
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

ORIGIN = {'source': 'd33e595a10acf2d148752ea382ae607283fc0b73', 'run': 40468241048,
          'attempt': 1, 'artifact': 12717726584}
HELPER = 'bb9dee8f7b38fde2ca69b02d625f1117418f5090921f75461ce2a04d8eee0b29'
INVENTORY = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
RELEASE = '7.1.13-generic16k-managed-gui'
PASS = 'PASS_C01_INSTALLABLE_GENERIC16K_LIFECYCLE_ONLY'
PACKAGES = {
 'baseline-r1-1.pkg.tar.xz': {'bytes': 1730592, 'sha256': '30a5de643b71603d1158982163a0560841fda50c2bd68f7cbbfea81403451924'},
 'baseline-r1-2.pkg.tar.xz': {'bytes': 1730592, 'sha256': '30a5de643b71603d1158982163a0560841fda50c2bd68f7cbbfea81403451924'},
 'baseline-r2-1.pkg.tar.xz': {'bytes': 1730908, 'sha256': 'ed6279f5982b0d7e17f2faf6cbb45334daa332e0db83b6b22106c674c860e382'},
 'lto-r1-1.pkg.tar.xz': {'bytes': 2136328, 'sha256': '0bf11d89052f419546ea43d922b1d5eb36ca2f2e6612971750442f77ff57a084'},
 'lto-r1-2.pkg.tar.xz': {'bytes': 2136328, 'sha256': '0bf11d89052f419546ea43d922b1d5eb36ca2f2e6612971750442f77ff57a084'},
 'lto-r2-1.pkg.tar.xz': {'bytes': 2136452, 'sha256': 'ac0b922cdd99ab1ee7f17ffee855b2c4aab9b1982aedd38ac284cf9f0db1f5af'},
}
PHASES = [('install-baseline', {'baseline': 1}), ('coexist', {'baseline': 1, 'lto': 1}),
          ('upgrade', {'baseline': 2, 'lto': 2}), ('repeat', {'baseline': 2, 'lto': 2}),
          ('remove-baseline', {'lto': 2}), ('remove-lto', {}),
          ('reinstall', {'baseline': 2, 'lto': 2}), ('final-remove', {})]
BASE_SENTINELS = {'/etc/pacman.conf': '14d304eeb83baf1379279356c232580fd095c2d508b41c74677347801a0bafe7',
 '/usr/bin/pacman': 'dd3a8cbecc7f31a2e0f4f718e63aec1c66838b1ea30491ab1a10b8225d79a884',
 '/usr/lib/libc.so.6': '6ab264fb4e8df9942b0fb75b48fcd5c30b2f081d8dfaa6c25d7be1d3fce5b2ab',
 '/usr/lib/libz.so.1.3.2': 'f8d5729601ca8fb86a8d9d048eff241a0e349342da7a5cea11389d0e33ed0a43'}
SENTINELS = ('/usr/lib/libz.so.1', '/usr/lib/libc.so.6', '/usr/bin/pacman', '/etc/pacman.conf')


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pin(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def ordinary(path, cap=16 * 1024**2):
    path = Path(path); before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap
         and not any(p.is_symlink() for p in path.parents), 'bounded ordinary guest input')
    data = path.read_bytes(); after = path.lstat()
    identity = lambda i: (i.st_dev, i.st_ino, i.st_mode, i.st_size, i.st_mtime_ns, i.st_ctime_ns)
    need(len(data) <= cap and identity(before) == identity(after), 'guest input changed during read')
    return data


def selection(value):
    need(type(value) is dict and set(value) == {'schema', 'nonce', 'source_commit', 'accepted_origin',
         'host_page_size', 'helper_sha256', 'inventory_sha256', 'packages', 'base_sentinels'}, 'closed guest selection')
    need(type(value['schema']) is int and value['schema'] == 1 and
         re.fullmatch('[0-9a-f]{32}', value['nonce']) and
         re.fullmatch('[0-9a-f]{40}', value['source_commit']), 'source/nonce/schema selection')
    need(encoded(value['accepted_origin']) == encoded(ORIGIN), 'exact accepted native origin')
    need(type(value['host_page_size']) is int and value['host_page_size'] == 4096,
         'separately observed host4K required')
    need(value['helper_sha256'] == HELPER and value['inventory_sha256'] == INVENTORY and
         encoded(value['packages']) == encoded(PACKAGES) and encoded(value['base_sentinels']) == encoded(BASE_SENTINELS), 'accepted source/archive/inventory identity')
    return value


def actual_facts():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getauxval.argtypes = [ctypes.c_ulong]; libc.getauxval.restype = ctypes.c_ulong
    return {'sysname': os.uname().sysname, 'machine': os.uname().machine, 'kernel': os.uname().release,
            'page_size': os.sysconf('SC_PAGE_SIZE'), 'auxv_page_size': int(libc.getauxval(6)),
            'uid': os.getuid(), 'euid': os.geteuid(),
            'cmdline': ordinary('/proc/cmdline', 65536).decode().split(),
            'network': sorted(p.name for p in Path('/sys/class/net').iterdir())}


def require_facts(s, facts):
    expected = {'sysname': 'Linux', 'machine': 'aarch64', 'kernel': RELEASE,
                'page_size': 16384, 'auxv_page_size': 16384, 'uid': 0, 'euid': 0}
    need(all(type(facts[k]) is type(v) and facts[k] == v for k, v in expected.items()),
         'actual root Linux/aarch64/16384 sysconf+auxv and exact guest kernel required')
    tokens = [v for v in facts['cmdline'] if v.startswith('c01install16k')]
    need(tokens == ['c01install16k=' + s['nonce']] and facts['network'] == ['lo'],
         'one nonce-bound offline guest boot marker')
    return facts


def helper(c01):
    need(pin(ordinary(c01 / 'package_variants.py'))['sha256'] == HELPER, 'exact accepted helper before import')
    spec = importlib.util.spec_from_file_location('accepted_c01_package_variants', c01 / 'package_variants.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def archives(s, h, c01):
    need({p.name for p in (c01 / 'packages').iterdir()} == set(PACKAGES), 'closed six accepted archives')
    verified = {}; members = {}
    for filename, binding in PACKAGES.items():
        data = ordinary(c01 / 'packages' / filename)
        need(pin(data) == binding == s['packages'][filename], 'accepted archive bytes differ')
        variant = filename.split('-')[0]
        contents = h.package_members(data, variant)
        own = h.prefix(variant).relative_to('/').as_posix()
        material = h.source_material(contents[own + '/source/zlib-1.3.2.tar.gz'])
        need(contents['usr/share/licenses/' + h.name(variant) + '/LICENSE.zlib'] == material['LICENSE'],
             'corresponding upstream license differs')
        h.configured_flags(contents[own + '/build/Makefile'], variant)
        verified[filename] = pin(data); members[filename] = contents
    for v in h.VARIANTS:
        first, second = v + '-r1-1.pkg.tar.xz', v + '-r1-2.pkg.tar.xz'
        need(verified[first] == verified[second] and members[first] == members[second], 'accepted r1 pair differs')
    return members, verified


def log_bound(output):
    entries = list(output.iterdir())
    need(len(entries) <= 1024 and all(p.is_file() and not p.is_symlink() for p in entries), 'finite guest log namespace')
    sizes = [p.stat().st_size for p in entries]
    need(all(n <= 16 * 1024**2 for n in sizes) and sum(sizes) <= 64 * 1024**2, 'finite guest log bytes')


def lifecycle(s, h, runner, c01, root=Path('/'), report=None):
    """root is a test filesystem seam; the actual entrypoint always uses / only."""
    placed = lambda path: root / Path(path).relative_to('/')
    output = c01 / 'output'
    need(output.is_dir() and not output.is_symlink() and not any(output.iterdir()), 'fresh guest-local output directory')
    lock = ordinary(c01 / 'packages.lock', 65536)
    need(pin(lock)['sha256'] == INVENTORY, 'exact complete original341 lock')
    members, bindings = archives(s, h, c01)
    initial = h.inventory(runner, 'initial-inventory')
    need(len(initial) == 341 and ''.join(k + ' ' + v + '\n' for k, v in sorted(initial.items())).encode() == lock,
         'actual complete original341 inventory')
    need(not any(placed(h.prefix(v)).exists() or placed(h.prefix(v)).is_symlink() or h.name(v) in initial for v in h.VARIANTS),
         'experiment already installed')
    sentinel_paths = [placed(p).resolve(strict=True) for p in SENTINELS]
    sentinels = {str(p.relative_to(root)) if root != Path('/') else str(p): h.sha(h.read(p)) for p in sentinel_paths}
    canonical = {'/' + str(p.relative_to(root)): h.sha(h.read(p)) for p in sentinel_paths}
    need(canonical == s['base_sentinels'], 'guest baseline differs from accepted system sentinels')
    artifacts = {(v, r): c01 / 'packages' / f'{v}-r{r}-{2 if r == 1 else 1}.pkg.tar.xz'
                 for v in h.VARIANTS for r in (1, 2)}
    config = output / 'pacman-local.conf'
    need(placed('/builder-disabled-hooks').is_dir(), 'accepted masked-hook directory')
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Never\nLocalFileSigLevel = Never\nHookDir = /builder-disabled-hooks\n')
    phases = [] if report is None else report.setdefault('phases', [])
    transactions = [['-U', str(artifacts[('baseline', 1)])], ['-U', str(artifacts[('lto', 1)])],
                    ['-U', *[str(artifacts[(v, 2)]) for v in h.VARIANTS]],
                    ['-U', *[str(artifacts[(v, 2)]) for v in h.VARIANTS]],
                    ['-R', h.name('baseline')], ['-R', h.name('lto')],
                    ['-U', *[str(artifacts[(v, 2)]) for v in h.VARIANTS]],
                    ['-R', *[h.name(v) for v in h.VARIANTS]]]
    for (label, versions), transaction in zip(PHASES, transactions):
        runner.run('pacman-' + label, ['pacman', '--config', str(config), '--noconfirm', '--noscriptlet', *transaction], timeout=60)
        expected = {**initial, **{h.name(v): '1.3.2-' + str(r) for v, r in versions.items()}}
        need(h.inventory(runner, label + '-inventory') == expected, 'complete guest inventory changed')
        need({str(p.relative_to(root)) if root != Path('/') else str(p): h.sha(h.read(p)) for p in sentinel_paths} == sentinels,
             'protected system sentinel changed')
        for v in h.VARIANTS:
            need(not placed(h.prefix(v)).is_symlink() and placed(h.prefix(v)).exists() == (v in versions), 'guest installed/removed prefix differs')
            if v not in versions:
                need(not placed('/usr/share/licenses/' + h.name(v)).exists() and
                     not placed('/usr/share/licenses/' + h.name(v)).is_symlink(), 'removed package license remains')
        row = {'phase': label, 'versions': versions, 'inventory_preserved': True, 'system_sentinels_preserved': True}
        if versions:
            row['workload'] = h.workload(runner, tuple(versions), label)
            n = len(versions)
            need((row['workload']['encodes'], row['workload']['cross_decodes'], row['workload']['strict_rejections']) ==
                 (21 * n, 21 * n * n, 3 * n), 'complete original finite workload count')
            for v, release in versions.items():
                for path, data in members[artifacts[(v, release)].name].items():
                    if path not in h.META:
                        need(h.read(placed('/' + path)) == data, 'exact installed guest payload differs: ' + path)
        phases.append(row); log_bound(output)
    need(archives(s, h, c01)[1] == bindings, 'original accepted input preservation')
    return {'phases': phases, 'system_sentinels': sentinels, 'system_sentinels_preserved': True,
            'inventory_sha256': INVENTORY, 'original_packages_preserved': True, 'packages': bindings}


def emit(report):
    raw = encoded(report)
    frame = ('C01_INSTALL16K ' + report['nonce'] + ' ').encode() + base64.b64encode(raw) + b'\n'
    need(len(frame) <= 2 * 1024**2, 'bounded complete guest frame')
    sys.stdout.buffer.write(frame); sys.stdout.buffer.flush()


def main():
    c01 = Path('/c01')
    s = selection(json.loads(ordinary(c01 / 'selection.json', 65536)))
    report = {'status': 'FAIL', 'nonce': s['nonce'], 'source_commit': s['source_commit'], 'accepted_origin': ORIGIN,
              'host_page_size': s['host_page_size'], 'hardware_validation': 'NOT RUN',
              'performance_acceptance': 'NOT RUN', 'release_admission': False, 'independent_machine_reproduction': 'NOT RUN',
              'inner_budget_seconds': 1600, 'phases': [], 'commands': []}
    runner = None; previous = {}
    try:
        report['guest'] = actual_facts()
        require_facts(s, report['guest'])
        h = helper(c01)
        runner = h.Commands(c01 / 'output', seconds=1600)
        previous = {sig: signal.signal(sig, runner.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
        report.update(lifecycle(s, h, runner, c01, report=report))
        need(pin(ordinary(c01 / 'package_variants.py'))['sha256'] == HELPER, 'accepted helper preserved')
        need(len(runner.rows) == 645, 'exact eight-phase guest command count')
        report['status'] = PASS
    except BaseException as error:
        report.update(status='FAIL', error_kind=type(error).__name__, error=str(error)[:2048])
    finally:
        for sig in previous:
            signal.signal(sig, lambda *_: setattr(runner, 'cancelled', True))
        if runner is not None:
            report['commands'] = runner.rows
            report['command_count'] = len(runner.rows)
            if runner.cancelled or any(r.get('status') != 'PASS' or not r.get('group_absent') or
                                       not r.get('leader_held_until_group_inspection') for r in runner.rows):
                report['status'] = 'FAIL'
        report['phase_count'] = len(report['phases'])
        raw = encoded(report); need(len(raw) <= 1536 * 1024, 'bounded guest result JSON')
        (c01 / 'output/result.json').write_bytes(raw + b'\n')
        log_bound(c01 / 'output'); emit(report)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0 if report['status'] == PASS else 1


if __name__ == '__main__':
    sys.exit(main())
