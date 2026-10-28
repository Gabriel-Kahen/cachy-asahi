#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future native build. NULL selection blocks all actor imports."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import execution_selection, load, need, pin, read, save, verify_source

PACKAGE_ROOT = Path('packages/tools/cachy-asahi-support2')
EPOCH = 1793065600

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

def output_directory(path):
    need(path == Path('/out') and path.is_dir() and not path.is_symlink(), 'fixed ordinary output mount')
    need(set(p.name for p in path.iterdir()) <= {'inspect-before.json'}, 'fresh role output')
    if (path / 'inspect-before.json').exists(): load(path / 'inspect-before.json')

class Commands:
    def __init__(self, root, output, allowed_uids):
        self.owned = module(root / 'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py', '_support_owned_child')
        self.output, self.allowed_uids, self.rows = output, set(allowed_uids), []
        self.deadline = time.monotonic() + 1050
        (output / 'logs').mkdir(mode=0o755)

    def run(self, argv, *, cwd=None, env=None, timeout=120, expected=0):
        budget = min(timeout, self.deadline - time.monotonic())
        need(0 < budget <= 900, 'bounded remaining guest command budget')
        name = 'logs/' + str(len(self.rows)).zfill(3) + '.log'
        log, state = self.output / name, {}
        row = dict(argv=list(map(str, argv)), log=name, expected_exit=expected, status='FAIL')
        self.rows.append(row)
        try:
            with log.open('xb') as stream:
                result = self.owned.run(row['argv'], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=stream, stderr=subprocess.STDOUT, timeout=budget,
                    lifecycle=state, allowed_uids=self.allowed_uids)
            need(result.returncode == expected and state.get('exit') == expected, 'actual expected owned command exit')
            need(state.get('natural_exit') is True and state.get('group_absent') is True
                 and state.get('leader_held_until_group_inspection') is True
                 and state.get('exit_observed_via_waitpid') is True and state.get('ownership_lost') is False
                 and state.get('forced_cleanup') is False and state.get('retirement') == 'REAPED', 'direct natural owned retirement')
            row['status'] = 'PASS'
            return read(log).decode('utf-8')
        finally:
            row.update(supervision=state, log_pin=pin(read(log)))
            save(self.output / 'commands.json', self.rows)

def metadata(raw):
    value = {}
    for line in raw.decode('utf-8').splitlines():
        if line.strip() and not line.startswith('#'):
            key, item = line.strip().split(' = ', 1)
            value.setdefault(key, []).append(item)
    return value

def package_archive(path, root, selected, original):
    """Inspect a real uncompressed makepkg archive with stdlib tar only."""
    raw = read(path)
    payload, special = {}, {}
    expected = selected['payload']
    expected_dirs = {str(p) for name in expected for p in Path(name).parents if p != Path('.')}
    with tarfile.open(path, mode='r:') as archive:
        seen = set()
        for item in archive:
            name = item.name.removeprefix('./').rstrip('/')
            need(name and name not in seen and not Path(name).is_absolute() and '..' not in Path(name).parts, 'safe unique package member')
            seen.add(name)
            need(item.uid == item.gid == 0, 'root-owned package member')
            if item.isdir():
                need(name in expected_dirs and item.mode == 0o755, 'finite package directory')
                continue
            need(item.isfile() and 0 <= item.size <= 2 * 1024**2, 'ordinary bounded package member')
            body = archive.extractfile(item).read(2 * 1024**2 + 1)
            need(len(body) == item.size, 'complete package member')
            if name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                need(item.mode == 0o644, 'package metadata mode'); special[name] = body
            else:
                need(name in expected and pin(body) == {k: expected[name][k] for k in ('bytes', 'sha256')}
                     and item.mode == expected[name]['mode'], 'exact selected installed payload')
                payload[name] = dict(**pin(body), mode=item.mode)
    need(set(payload) == set(expected) and set(special) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete selected package namespace')
    info, build = metadata(special['.PKGINFO']), metadata(special['.BUILDINFO'])
    selected_info = metadata(read(root / PACKAGE_ROOT / '.SRCINFO'))
    name, version = selected['package']['name'], selected['package']['version']
    for key, values in dict(pkgname=[name], pkgbase=[name], pkgver=[version], arch=[selected['package']['arch']], license=selected['package']['license']).items():
        need(info.get(key) == values, 'selected package identity: ' + key)
    need(info.get('xdata') == ['pkgtype=pkg'] + selected_info.get('xdata', []), 'exact normal package type/extensions')
    for source, target in (('groups', 'group'), ('depends', 'depend'), ('optdepends', 'optdepend'), ('makedepends', 'makedepend'),
                           ('checkdepends', 'checkdepend'), ('provides', 'provides'), ('conflicts', 'conflict'),
                           ('replaces', 'replaces'), ('backup', 'backup')):
        need(sorted(info.get(target, [])) == sorted(selected_info.get(source, [])), 'complete package dependency metadata: ' + target)
    need(build.get('format') == ['2'] and build.get('pkgname') == [name]
         and build.get('pkgbase') == [name] and build.get('pkgver') == [version]
         and build.get('pkgarch') == [selected['package']['arch']]
         and build.get('pkgbuild_sha256sum') == [selected['recipe_sha256']], 'real format2 BUILDINFO recipe/identity')
    installed = load(root / 'native/policy.json')['installed341']
    need(type(installed) is list and len(installed) == 341 and all(type(row) is str for row in installed), 'full selected name-version-architecture build inventory')
    need(sorted(build.get('installed', [])) == installed, 'complete original341 BUILDINFO inventory')
    return dict(archive=pin(raw), PKGINFO=pin(special['.PKGINFO']), BUILDINFO=pin(special['.BUILDINFO']),
                payload=payload, metadata=info, buildinfo=build), special

def admission(root, output, checksum, *, root_user=False):
    verify_source(root, checksum)
    policy = execution_selection(root)
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() and (os.getuid() == 0 if root_user else os.getuid() != 0)
         and Path('/.dockerenv').is_file(), 'actual dedicated native ARM container and expected credentials')
    output_directory(output)
    original = read(root / 'native/original341.lock')
    need(read(Path('/builder-packages.lock')) == original and len(original.splitlines()) == 341, 'exact actual original341 inventory')
    return policy['selected_package'], original

def run(root, output, checksum):
    selected, original = admission(root, output, checksum)
    report = dict(schema=1, status='FAIL', source_map_sha256=checksum, architecture=platform.machine(),
        page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(), inventory=pin(original),
        package_identity=selected['package'], recipe_sha256=selected['recipe_sha256'],
        makepkg_check='EXTERNALIZED_EXACT_CHECK_FUNCTION_REQUIRED', makepkg_nocheck=True, SOURCE_DATE_EPOCH=EPOCH,
        native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', release='NOT_ADMITTED')
    commands = Commands(root, output, {os.getuid()})
    try:
        work = Path('/tmp/support-build')
        need(not work.exists(), 'fresh fixed build directory'); work.mkdir(mode=0o700)
        for name in selected['files']:
            path = Path(name)
            if path.parent == PACKAGE_ROOT: shutil.copyfile(root / path, work / path.name)
        config = read(Path('/etc/makepkg.conf')).decode()
        need(len(re.findall(r'^PKGEXT=.*$', config, re.M)) == 1, 'single makepkg package format setting')
        (work / 'makepkg-native.conf').write_text(re.sub(r'^PKGEXT=.*$', "PKGEXT='.pkg.tar'", config, flags=re.M))
        env = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', HOME='/tmp', SOURCE_DATE_EPOCH=str(EPOCH))
        commands.run(['/usr/bin/python3', '-I', '-B', str(work / 'check_package.py'), '--recipe-root', str(work)], env=env)
        commands.run(['/usr/bin/makepkg', '--config', str(work / 'makepkg-native.conf'), '--cleanbuild', '--force', '--nodeps', '--nocheck'],
                     cwd=work, env=env, timeout=900)
        matches = list(work.glob('*.pkg.tar')); need(len(matches) == 1, 'one actual uncompressed package archive')
        package, special = package_archive(matches[0], root, selected, original)
        shutil.copyfile(matches[0], output / 'package.pkg.tar')
        for name in ('.PKGINFO', '.BUILDINFO'): (output / name.removeprefix('.')).write_bytes(special[name])
        report.update(status='PASS_NATIVE_PACKAGE_BUILD', package=package)
    finally:
        report['commands'] = commands.rows
        save(output / 'result.json', report)
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-map-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(dict(status=run(Path('/source'), args.output, args.source_map_sha256)['status'])))
