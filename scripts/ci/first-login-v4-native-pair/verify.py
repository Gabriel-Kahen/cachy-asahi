# SPDX-License-Identifier: MIT
"""Check retained archives, inputs and isolation receipts from both native lanes."""
import argparse
from collections import defaultdict
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

SETUP = 'cachy-asahi-setup'
FIRST = 'cachy-asahi-first-login'
RECIPES = {
    SETUP: ('0.3.1-2', 'cachy-asahi-setup8-v3', 'setup', [29, 7], 13),
    FIRST: ('0.1.0-4', 'cachy-asahi-first-login-v4', 'first-login', [14, 6], 9),
}
METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(raw):
    data = defaultdict(list)
    for line in raw.decode().splitlines():
        key, separator, value = line.lstrip().partition(' = ')
        if separator:
            data[key].append(value)
    return data


def payload(package):
    files = {
        f'usr/bin/{package}': '@setup.py' if package == SETUP else package,
        f'usr/share/doc/{package}/README.md': 'README.md',
        f'usr/share/licenses/{package}/LICENSE': 'LICENSE',
        f'usr/share/licenses/{package}/NOTICE': 'NOTICE',
    }
    if package == SETUP:
        files.update({
            'usr/bin/cachy-asahi-config-migrate': 'cachy-asahi-config-migrate',
            'usr/bin/cachy-asahi-repository': 'cachy-asahi-repository',
            'usr/lib/cachy-asahi/setup8/setup.py': '@setup.py',
            'usr/lib/cachy-asahi/setup8/config_migrate.py': '@config_migrate.py',
            f'usr/share/doc/{package}/configuration-migrations.md': 'configuration-migrations.md',
            f'usr/share/doc/{package}/repository-enrollment.md': 'repository-enrollment.md',
        })
    else:
        files.update({
            'usr/lib/cachy-asahi/first-login/first_login.py': 'first_login.py',
            f'usr/share/doc/{package}/source-provenance.json': 'source-provenance.json',
        })
    return files


def archive_name(package):
    return f'{package}-{RECIPES[package][0]}-any.pkg.tar.xz'


def check_archive(raw, path, recipe, package, epoch, inventory):
    files = payload(package)
    dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents} - {'.'}
    prepared = {name: digest for digest, name in re.findall(
        r'^([0-9a-f]{64})  (\S+)$', (recipe / 'PKGBUILD').read_text(), re.M)}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        members = archive.getmembers()
        names = {row.name for row in members}
        need(len(names) == len(members) and names == set(files) | dirs | METADATA, f'{path}: payload paths')
        items = {}
        for row in members:
            name = row.name
            directory = name in dirs
            kind = row.isdir() if directory else row.isfile()
            mode = 0o755 if directory or name.startswith('usr/bin/') else 0o644
            need(kind and row.uid == row.gid == 0 and row.mode == mode, f'{path}: type, owner or mode of {name}')
            if directory:
                continue
            content = archive.extractfile(row).read()
            digest = sha(content)
            items[name] = {'sha256': digest, 'mode': f'{mode:04o}', 'bytes': len(content)}
            if name in files:
                filename = files[name]
                expected = prepared[filename[1:]] if filename.startswith('@') else sha((recipe / filename).read_bytes())
                need(digest == expected, f'{path}: source bytes of {name}')
        package_info = fields(archive.extractfile('.PKGINFO').read())
        build_info = fields(archive.extractfile('.BUILDINFO').read())
        mtree = gzip.decompress(archive.extractfile('.MTREE').read()).decode()
    mtree_hashes = dict(re.findall(r'^\./(usr/\S+) .+\bsha256digest=([0-9a-f]{64})\b', mtree, re.M))
    need(all(mtree_hashes.get(name) == items[name]['sha256'] for name in files), f'{path}: mtree SHA-256')
    source_info = fields((recipe / '.SRCINFO').read_bytes())
    for field in ('depend', 'optdepend', 'makedepend', 'checkdepend'):
        need(package_info[field] == source_info[field + 's'], f'{path}: {field}')
    need(package_info['pkgname'] == [package] and package_info['pkgver'] == [RECIPES[package][0]]
         and package_info['arch'] == ['any'] and package_info['builddate'] == [epoch], f'{path}: package identity')
    need(build_info['pkgbuild_sha256sum'] == [sha((recipe / 'PKGBUILD').read_bytes())]
         and build_info['builddate'] == [epoch] and {'check', '!sign'} <= set(build_info['buildenv']),
         f'{path}: build identity')
    installed = {item.rsplit('-', 1)[0] for item in build_info['installed']}
    expected = {line.replace(' ', '-', 1) for line in inventory.decode().splitlines()}
    need(installed == expected, f'{path}: build dependency inventory')
    return {'bytes': len(raw), 'sha256': sha(raw), 'files': items, 'dependencies': package_info['depend'],
            'check_dependencies': package_info['checkdepend']}


def check_pair(public, source):
    base = (public / 'base-packages.txt').read_bytes()
    first_inventory = b''.join(sorted(base.splitlines(keepends=True) + [b'cachy-asahi-setup 0.3.1-2\n']))
    epoch = (source / 'source-date-epoch').read_text().strip()
    image = (public / 'build-image.txt').read_text().strip()
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'build image identity')
    common_archives = {}
    containers = set()
    packages = {}
    for label in ('lane-1', 'lane-2'):
        lane = public / label
        container, build_image, network, privileged = (lane / 'container.txt').read_text().split()
        need(re.fullmatch(r'[0-9a-f]{64}', container) and container not in containers
             and (build_image, network, privileged) == (image, 'none', 'false'), f'{label}: container isolation')
        containers.add(container)
        need((lane / 'before-setup.txt').read_bytes() == base, f'{label}: original inventory')
        need((lane / 'before-first-login.txt').read_bytes() == first_inventory, f'{label}: Setup dependency inventory')
        need((lane / 'runtime.txt').read_text() == (
            f'architecture=aarch64\npage_size=4096\nbuilder_uid=2000\nsource_date_epoch={epoch}\n'), f'{label}: native runtime')
        need({entry.name for entry in (lane / 'packages').iterdir()} == {
            archive_name(package) for package in RECIPES}, f'{label}: archive set')
        need((lane / 'install-build-dependency.log').stat().st_size > 0, f'{label}: Setup dependency transaction')
        for package, inventory in ((SETUP, base), (FIRST, first_inventory)):
            _, dirname, prefix, counts, sources = RECIPES[package]
            log = (lane / f'{prefix}-build.log').read_text()
            need([int(n) for n in re.findall(r'^Ran (\d+) tests? ', log, re.M)] == counts
                 and log.count('\nOK\n') == len(counts)
                 and 'Checking runtime dependencies' in log and 'Checking buildtime dependencies' in log
                 and 'Skipping dependency checks' not in log, f'{label}: {package} checks')
            need((lane / f'{prefix}-source.log').read_text().count('... Passed') == sources, f'{label}: source hashes')
            path = lane / 'packages' / archive_name(package)
            need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024, f'{path}: archive size')
            raw = path.read_bytes()
            packages[package] = check_archive(raw, path, source / 'packages/tools' / dirname, package, epoch, inventory)
            need(common_archives.setdefault(package, raw) == raw, f'{package}: pair archive bytes differ')
        dependency = (lane / 'installed-build-dependency.sha256').read_text().split()
        need(dependency == [packages[SETUP]['sha256'], f'/work/result/packages/{archive_name(SETUP)}'],
             f'{label}: installed Setup archive hash')
    fixture = source / 'packages/tools' / RECIPES[FIRST][1] / 'setup8-fixture.py'
    need(sha(fixture.read_bytes()) == packages[SETUP]['files'][f'usr/bin/{SETUP}']['sha256'], 'cross-recipe Setup fixture')
    return {
        'native_build_pair': 'PASS', 'build_image': image, 'containers': sorted(containers),
        'source_date_epoch': int(epoch), 'base_inventory_sha256': sha(base), 'packages': packages,
        'signed_installation': 'NOT RUN', 'graphical_first_login': 'NOT RUN', 'hardware': 'NOT RUN',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('public', type=Path)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    result = check_pair(args.public, args.source)
    (args.public / 'pair.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print('PASS native AArch64/4 KiB build pair; both archives byte-identical.')
