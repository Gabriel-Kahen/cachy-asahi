#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Partition and verify one private DESTDIR, including directory modes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

PACKAGES=('networkmanager','libnm','nm-cloud-setup','networkmanager-docs')
SOURCE_SHA='843306ad54a3006ef7a60ba62932a3a2015cc87d46bd438fd5ac906d952c88d6'
OVS='usr/lib/systemd/system/NetworkManager.service.d/NetworkManager-ovs.conf'


def owner(path):
    if path==OVS:return 'networkmanager-docs','usr/share/doc/networkmanager/NetworkManager-ovs.conf.example'
    if 'nm-cloud-setup' in Path(path).name:return 'nm-cloud-setup',path
    if path.startswith('usr/share/gtk-doc/'):return 'networkmanager-docs',path
    if (path.startswith(('usr/include/libnm/','usr/lib/girepository-1.0/NM-','usr/share/gir-1.0/NM-','usr/share/vala/vapi/libnm.','usr/lib/libnm.'))
            or path in ('usr/lib/nm-libnm-helper','usr/lib/pkgconfig/libnm.pc')):return 'libnm',path
    return 'networkmanager',path


def node(path):
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    assert not mode & 0o6000, path
    if stat.S_ISDIR(info.st_mode):
        return {'kind': 'directory', 'mode': mode}
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        assert not Path(target).is_absolute(), path
        return {'kind': 'symlink', 'mode': mode, 'target': target}
    assert stat.S_ISREG(info.st_mode), path
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'kind': 'file', 'mode': mode, 'bytes': info.st_size, 'sha256': digest}


def directory(path):
    assert stat.S_ISDIR(path.lstat().st_mode), path
    return path.resolve(strict=True)


def inventory(root):
    root = directory(root)
    entries = {}
    pending = [root]
    while pending:
        for path in pending.pop().iterdir():
            details = node(path)
            if details['kind'] == 'directory':
                pending.append(path)
            elif details['kind'] == 'symlink':
                assert path.resolve().is_relative_to(root), path
            entries[path.relative_to(root).as_posix()] = details
    return dict(sorted(entries.items()))


def projection(stage):
    entries = inventory(stage)
    assert entries.get('usr', {}).get('kind') == 'directory', stage
    records = []
    expected = {name: {} for name in PACKAGES}
    for rel, details in entries.items():
        assert not rel.startswith(('etc/resolv.conf', 'usr/share/libalpm/hooks/', 'etc/pacman',
                                   'boot/', 'var/lib/pacman/')), rel
        is_dir = details['kind'] == 'directory'
        if not is_dir:
            assert not rel.startswith(('etc/NetworkManager/system-connections/', 'var/lib/NetworkManager/')), rel
        package, dest = owner(rel + '/' if is_dir else rel)
        dest = dest.rstrip('/')
        assert dest not in expected[package], (package, dest)
        expected[package][dest] = details
        records.append({'source': rel, 'package': package, 'destination': dest, **details})
    for paths in expected.values():
        for rel in tuple(paths):
            for parent in Path(rel).parents:
                if parent != Path('.'):
                    details = paths.setdefault(parent.as_posix(), {'kind': 'directory', 'mode': 0o755})
                    assert details['kind'] == 'directory', parent
    report = {'schema_version': 2, 'version': '1.58.1-2.1', 'source_sha256': SOURCE_SHA, 'records': records,
              'OVS_dropin_policy': 'retained as docs example; no new automatic OVS service dependency',
              'system_mutation': False, 'native_ARM': 'NOT RUN'}
    return report, expected


def partition(stage, output):
    stage = directory(stage)
    assert stage != Path('/'), stage
    assert not output.exists() and not output.is_symlink() and not output.resolve().is_relative_to(stage), output
    report, expected = projection(stage)
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    for name, paths in expected.items():
        package = output / name
        package.mkdir(mode=0o700)
        package.chmod(0o700)
        for rel, details in sorted(paths.items()):
            if details['kind'] == 'directory':
                (package / rel).mkdir(mode=0o700)
    for record in report['records']:
        target = output / record['package'] / record['destination']
        if record['kind'] == 'symlink':
            target.symlink_to(record['target'])
        elif record['kind'] == 'file':
            shutil.copyfile(stage / record['source'], target)
            target.chmod(record['mode'])
    for name, paths in expected.items():
        for rel, details in sorted(paths.items(), reverse=True):
            if details['kind'] == 'directory':
                (output / name / rel).chmod(details['mode'])
    (output / 'ownership.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    check_split(output, report, expected)
    return report

def require_layout(output):
    required={
      'networkmanager':['usr/bin/NetworkManager','usr/bin/nmcli','usr/bin/nmtui','usr/bin/nm-online','etc/NetworkManager/NetworkManager.conf','usr/lib/systemd/system/NetworkManager.service','usr/lib/NetworkManager/conf.d/20-connectivity.conf'],
      'libnm':['usr/lib/libnm.so','usr/lib/pkgconfig/libnm.pc','usr/include/libnm/NetworkManager.h','usr/lib/girepository-1.0/NM-1.0.typelib','usr/share/gir-1.0/NM-1.0.gir','usr/share/vala/vapi/libnm.vapi','usr/lib/nm-libnm-helper'],
      'nm-cloud-setup':['usr/lib/nm-cloud-setup','usr/lib/systemd/system/nm-cloud-setup.service','usr/lib/systemd/system/nm-cloud-setup.timer'],
      'networkmanager-docs':['usr/share/doc/networkmanager/NetworkManager-ovs.conf.example'],
    }
    for name,paths in required.items():
        for rel in paths:assert (output/name/rel).is_file(),(name,rel)
    assert any((output/'networkmanager-docs/usr/share/gtk-doc').rglob('*.html')),'built API documentation required'
    connections=output/'networkmanager/etc/NetworkManager/system-connections'
    assert connections.is_dir() and not connections.is_symlink() and stat.S_IMODE(connections.stat().st_mode)==0o700
    assert not list(connections.iterdir()),'no packaged connections'
    assert not (output/'networkmanager'/OVS).exists(),'no new OVS service dependency'
    for name in PACKAGES:
        assert not any((output/name/'usr/share/polkit-1/rules.d').glob('*'))


def check_split(output, report, expected):
    assert {path.name for path in output.iterdir()} == {*PACKAGES, 'ownership.json'}, output
    receipt = output / 'ownership.json'
    assert stat.S_ISREG(receipt.lstat().st_mode), receipt
    assert json.loads(receipt.read_text()) == report, 'current staged tree differs from split receipt'
    for name, paths in expected.items():
        package = output / name
        assert node(package) == {'kind': 'directory', 'mode': 0o700}, package
        assert inventory(package) == paths, package
    require_layout(output)


def verify(stage, output, package=None, destination=None):
    output = directory(output)
    report, expected = projection(stage)
    check_split(output, report, expected)
    if destination is not None:
        assert package in PACKAGES, package
        destination = directory(destination)
        assert not any(destination.iterdir()), destination
        shutil.copytree(output / package, destination, symlinks=True, dirs_exist_ok=True)
        assert node(destination) == {'kind': 'directory', 'mode': 0o700}, destination
        assert inventory(destination) == expected[package], destination
    return {'split_leaves': {name: sum(row['kind'] != 'directory' for row in paths.values())
                             for name, paths in expected.items()}, 'source_sha256': SOURCE_SHA}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--package', choices=PACKAGES)
    parser.add_argument('--copy-to', type=Path)
    args = parser.parse_args()
    if (args.package is None) != (args.copy_to is None) or (args.package is not None and not args.verify):
        parser.error('--package and --copy-to must be supplied together with --verify')
    result = (verify(args.stage, args.output, args.package, args.copy_to)
              if args.verify else partition(args.stage, args.output))
    print(json.dumps(result, sort_keys=True))
