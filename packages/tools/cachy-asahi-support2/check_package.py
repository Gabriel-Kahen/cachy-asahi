#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the finite source metadata, pinned runtime and exact staged payload."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat

NAME = 'cachy-asahi-support'
SOURCES = (NAME, 'support_bundle.py', 'doctor.py', 'session_probe.py', 'check_package.py',
           'test_package.py', 'collect_support.py', 'collect-support.md', 'fixtures.json', 'README.md', 'support-bundle.md',
           'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE')
RUNTIME = {'collect_support.py': '2116e931e91ceed87627eeeb1acec2da1158a523c7c2f71fc2f4b4b41936159e','support_bundle.py': '2fff76ad4df036f383927381b0b56c89904c3087f7ca151902ba80fb8c82bdc8',
           'doctor.py': 'ddd8c3cedc5ba1291dcdd2d1d7a188e5b4d4a4ac7323ffe6f7ee554f6687d41e',
           'session_probe.py': '9c5c41899cd991b0de4bf8d30bad6f5452b4592ea9440df0f0b4a7b54bc66984'}
PAYLOAD = {'usr/lib/cachy-asahi/support/scripts/support/collect_support.py': {'source': 'collect_support.py', 'mode': 0o644},
    f'usr/bin/{NAME}': {'source': NAME, 'mode': 0o755},
    'usr/lib/cachy-asahi/support/scripts/support/support_bundle.py': {'source': 'support_bundle.py', 'mode': 0o644},
    'usr/lib/cachy-asahi/support/scripts/hardware/session_probe.py': {'source': 'session_probe.py', 'mode': 0o644},
    'usr/lib/cachy-asahi/support/packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor': {'source': 'doctor.py', 'mode': 0o644}}
PAYLOAD.update({f'usr/share/doc/{NAME}/{f}': {'source': f, 'mode': 0o644}
                for f in ('README.md', 'support-bundle.md', 'collect-support.md', 'source-provenance.json', 'payload-map.json')})
PAYLOAD.update({f'usr/share/licenses/{NAME}/{f}': {'source': f, 'mode': 0o644} for f in ('NOTICE', 'LICENSE')})


def require(ok):
    if not ok:
        raise ValueError('package source, metadata or payload mismatch')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(raw):
    result = {}
    for line in raw.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.strip().split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def check_source(root):
    raw = (root / 'PKGBUILD').read_text()
    literal = {}
    for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)', raw, re.M):
        key, value = match.groups()
        require('$' not in value and '`' not in value and key not in literal)
        literal[key] = shlex.split(value[1:-1] if value.startswith('(') else value, comments=True)
    info = metadata((root / '.SRCINFO').read_text())
    require(info == dict(literal, pkgbase=[NAME]))
    for key, value in dict(pkgname=[NAME], pkgver=['0.2.0'], pkgrel=['1'], arch=['any'], license=['MIT'],
                           depends=['python>=3.11'], checkdepends=['bubblewrap'], options=['!strip', '!debug']).items():
        require(info.get(key) == value)
    require(not set(info) - {'pkgbase', 'pkgname', 'pkgver', 'pkgrel', 'pkgdesc', 'arch', 'url', 'license', 'depends', 'checkdepends', 'options', 'source', 'sha256sums'})
    require(info['source'] == list(SOURCES) and len(info['sha256sums']) == len(SOURCES))
    require(not list(root.glob('*.install')) and not list(root.glob('*.hook')))
    for name, checksum in zip(SOURCES, info['sha256sums']):
        path = root / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1)
        require(bool(re.fullmatch('[0-9a-f]{64}', checksum)) and sha(path) == checksum)
        if name.endswith('.py') or name == NAME:
            compile(path.read_bytes(), name, 'exec')
    require(json.loads((root / 'payload-map.json').read_bytes()) == PAYLOAD)
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    require(provenance['package'] == NAME and provenance['version'] == '0.2.0-1' and provenance['source_revision'] is None)
    require(set(provenance['runtime_closure']) == set(RUNTIME))
    require(provenance['dependencies']['required'] == ['python>=3.11'] and provenance['dependencies']['optional'] == [])
    require(provenance['license']['id'] == 'MIT' and provenance['license']['sha256'] == sha(root / 'LICENSE'))
    require(provenance['future_native_build_pair'] == dict(actual_binding=None, build1=None, build2=None))
    for name, checksum in RUNTIME.items():
        require(sha(root / name) == checksum and provenance['runtime_closure'][name]['sha256'] == checksum)
        require(checksum in (root / NAME).read_text() and provenance['runtime_closure'][name]['license'] == 'MIT')
    installs = {}
    for line in raw.splitlines():
        if line.strip().startswith('install -Dm'):
            command, mode, source, destination, *tail = shlex.split(line.strip())
            require(tail == ['||', 'return'] and source.startswith('$srcdir/') and destination.startswith('$pkgdir/'))
            installs[destination.removeprefix('$pkgdir/')] = dict(source=source.removeprefix('$srcdir/'), mode=int(mode[3:], 8))
    require(installs == PAYLOAD)
    # Keep the executable recipe finite: reject appended or hidden shell work.
    expected = ['# SPDX-License-Identifier: MIT', '# Original support collection CLI; no installation hooks or system mutation.']
    arrays = {'arch', 'license', 'depends', 'checkdepends', 'options', 'source', 'sha256sums'}
    for key, values in literal.items():
        value = ' '.join(shlex.quote(v) for v in values)
        expected.append(key + '=' + ('(' + value + ')' if key in arrays else value))
    expected += ['', 'check() {',
        '    python -I -B "$srcdir/check_package.py" --recipe-root "$startdir" || return',
        '    python -I -B -Werror::ResourceWarning "$srcdir/test_package.py" --recipe-root "$startdir"',
        '}', '', 'package() {', '    [[ -n ${pkgdir:-} && $pkgdir != / ]] || return 1']
    for destination, row in sorted(PAYLOAD.items()):
        expected.append('    install -Dm' + format(row['mode'], 'o') + ' "$srcdir/' + row['source'] + '" "$pkgdir/' + destination + '" || return')
    expected += ['}', '']
    require(raw == '\n'.join(expected))
    return info


def check_stage(root, stage):
    expected_dirs = {str(p) for name in PAYLOAD for p in Path(name).parents if str(p) != '.'}
    files, directories = set(), set()
    for path in stage.rglob('*'):
        require(not path.is_symlink())
        name = path.relative_to(stage).as_posix()
        if path.is_dir():
            directories.add(name)
            require(stat.S_IMODE(path.stat().st_mode) == 0o755)
        else:
            require(path.is_file() and path.stat().st_nlink == 1)
            files.add(name)
    require(files == set(PAYLOAD) and directories == expected_dirs)
    for name, row in PAYLOAD.items():
        path = stage / name
        require(path.read_bytes() == (root / row['source']).read_bytes() and stat.S_IMODE(path.stat().st_mode) == row['mode'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    try:
        check_source(args.recipe_root)
        if args.stage:
            check_stage(args.recipe_root, args.stage)
    except (OSError, ValueError, TypeError, KeyError, IndexError, SyntaxError):
        print('Support package validation failed.')
        return 2
    print(json.dumps(dict(status='PASS_SOURCE_AND_STAGE' if args.stage else 'PASS_SOURCE', sources=len(SOURCES),
                         payload_files=len(PAYLOAD), native_build='NOT RUN', ALPM='NOT RUN', physical_M2='NOT RUN')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
