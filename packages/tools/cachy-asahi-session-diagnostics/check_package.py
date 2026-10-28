#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Check this recipe's local pins and exact owned payload; no live probes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat

NAME = 'cachy-asahi-session-diagnostics'
SOURCES = (NAME, 'session_probe.py', 'test_session_probe.py', 'check_package.py',
           'test_package.py', 'README.md', 'session-probe.md', 'source-provenance.json', 'NOTICE', 'LICENSE')
FROZEN = {'session_probe.py': 'be8de7b2644585918336b629b2bf436b79c36e55ce160590003d592e62658e49',
          'test_session_probe.py': '4a60a874d0a1f2568ee37707dc6df64a948015c57a81f52eb43dcb4ea882284c',
          'session-probe.md': 'a861b60cd1417604207d8b7d0e8745150e218b5736003068f464b307f0fa6acd'}
CORRECTED = {'session_probe.py': '9c5c41899cd991b0de4bf8d30bad6f5452b4592ea9440df0f0b4a7b54bc66984', 'test_session_probe.py': 'b830ec828dd73e0b40ebc509c079f55a28b045d4a783e0090952ad696320f964', 'session-probe.md': '2d8125214150de5b6426692758525b0636fcbb53c45539a139d7fc5bf4f804e1'}
SOCKET_FIXTURE = {'test_session_probe.py': 'f598bf4ea38f753c1ffe31fb55e636d64722c32139230bd5485564d7f2332d2f'}
OPTIONAL = ['hyprland: current compositor version and display observations',
            'mesa-utils: current Wayland GLES client renderer observation',
            'pipewire: current sanitized audio graph observation',
            'systemd: current session, unit states and suspend capability queries']
PAYLOAD = {f'usr/bin/{NAME}': (NAME, 0o755),
           f'usr/lib/{NAME}/session_probe.py': ('session_probe.py', 0o644)}
PAYLOAD.update({f'usr/share/doc/{NAME}/{f}': (f, 0o644) for f in ('README.md', 'session-probe.md', 'source-provenance.json')})
PAYLOAD.update({f'usr/share/licenses/{NAME}/{f}': (f, 0o644) for f in ('NOTICE', 'LICENSE')})


def require(condition):
    if not condition:
        raise ValueError('package source or payload mismatch')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_source(root):
    recipe = (root / 'PKGBUILD').read_text()
    names = shlex.split(re.search(r'^source=\((.*?)\)', recipe, re.M | re.S)[1])
    pins = shlex.split(re.search(r'^sha256sums=\((.*?)\)', recipe, re.M | re.S)[1])
    require(names == list(SOURCES) and len(pins) == len(SOURCES))
    for name, digest in zip(names, pins):
        path = root / name
        require(not path.is_symlink() and path.is_file() and bool(re.fullmatch('[0-9a-f]{64}', digest)))
        require(sha(path) == digest)
        if name.endswith('.py') or name == NAME:
            compile(path.read_bytes(), name, 'exec')
    info = {}
    for line in (root / '.SRCINFO').read_text().splitlines():
        if line.strip():
            key, value = line.strip().split(' = ', 1)
            info.setdefault(key, []).append(value)
    for key, values in {'pkgbase': [NAME], 'pkgname': [NAME], 'pkgver': ['0.1.0'], 'pkgrel': ['3'],
                        'arch': ['any'], 'license': ['MIT'], 'depends': ['python>=3.11'],
                        'optdepends': OPTIONAL, 'source': names, 'sha256sums': pins}.items():
        require(info.get(key) == values)
    require(not any(key in info for key in ('install', 'backup', 'conflicts', 'replaces')))
    require(not list(root.glob('*.install')) and not list(root.glob('*.hook')))
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    require(provenance['frozen_sources'] == FROZEN and provenance['corrected_sources'] == CORRECTED)
    require(provenance['socket_fixture_sources'] == SOCKET_FIXTURE)
    require(provenance['package'] == NAME and provenance['version'] == '0.1.0-3')
    for name in ('session_probe.py', NAME):
        require(provenance['runtime_sources'][name] == {'bytes': (root / name).stat().st_size, 'sha256': sha(root / name)})
    require(all(sha(root / name) == digest for name, digest in (CORRECTED | SOCKET_FIXTURE).items()))
    require(CORRECTED['session_probe.py'] in (root / NAME).read_text())


def check_stage(root, stage, archive=False):
    expected_dirs = {str(parent) for name in PAYLOAD for parent in Path(name).parents if str(parent) != '.'}
    files, directories = set(), set()
    metadata = {'.PKGINFO', '.BUILDINFO', '.MTREE'} if archive else set()
    for path in stage.rglob('*'):
        require(not path.is_symlink())
        name = path.relative_to(stage).as_posix()
        if path.is_dir():
            directories.add(name)
            require(stat.S_IMODE(path.stat().st_mode) == 0o755)
        else:
            require(path.is_file())
            files.add(name)
    require(files == set(PAYLOAD) | metadata and directories == expected_dirs)
    for name, (source, mode) in PAYLOAD.items():
        path = stage / name
        require(stat.S_IMODE(path.stat().st_mode) == mode and path.read_bytes() == (root / source).read_bytes())
    for name in metadata:
        require(stat.S_IMODE((stage / name).stat().st_mode) == 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    stages = parser.add_mutually_exclusive_group()
    stages.add_argument('--stage', type=Path)
    stages.add_argument('--archive-stage', type=Path)
    args = parser.parse_args()
    try:
        check_source(args.recipe_root)
        stage = args.stage or args.archive_stage
        if stage:
            check_stage(args.recipe_root, stage, archive=args.archive_stage is not None)
    except (OSError, ValueError, TypeError, KeyError, IndexError, SyntaxError):
        print('Package source or payload validation failed.')
        return 2
    print(json.dumps({'status': 'PASS_SOURCE_AND_PAYLOAD' if stage else 'PASS_SOURCE', 'sources': len(SOURCES),
                      'payload_files': len(PAYLOAD), 'native_ARM': 'NOT RUN', 'ALPM': 'NOT RUN', 'M2': 'NOT RUN'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
