#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Verify recipe inputs, the exact private import closure, and an optional stage."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat

HERE = Path(__file__).absolute().parent
NAME = 'cachy-asahi-maintenance'
PRIVATE = 'usr/lib/cachy-asahi/maintenance/'
MODULES = {**{n + '.py': 'scripts/maintenance/' + n + '.py' for n in
             ('health', 'update_plan', 'rebuild_plan', 'signing_expiry', 'security_advisories')},
           **{n + '.py': 'scripts/release/' + n + '.py' for n in
              ('check_source_pins', 'compare_releases', 'release', 'source_delivery')}}
DOCS = ('README.md', 'health-inputs.md', 'source-provenance.json', 'payload-pins.json')


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def installed_map():
    files = {PRIVATE + relative: source for source, relative in MODULES.items()}
    files['usr/bin/' + NAME] = NAME
    files.update({'usr/share/doc/' + NAME + '/' + n: n for n in DOCS})
    files.update({'usr/share/licenses/' + NAME + '/' + n: n for n in ('NOTICE', 'LICENSE')})
    return files


def check(root, stage=None):
    root = Path(root).absolute()
    recipe = (root / 'PKGBUILD').read_text()
    def array(key):
        return shlex.split(re.search(r'^' + key + r'=\((.*?)\)', recipe, re.M | re.S)[1])
    sources, sums = array('source'), array('sha256sums')
    expected = set(MODULES) | set(DOCS) | {NAME, 'test_package.py', 'check_source.py', 'NOTICE', 'LICENSE'}
    need(len(sources) == len(sums) == len(set(sources)) and set(sources) == expected,
         'closed recipe source set required')
    for name, digest in zip(sources, sums):
        path = root / name
        need(Path(name).name == name and re.fullmatch('[0-9a-f]{64}', digest), 'literal source pin required')
        need(path.is_file() and not path.is_symlink(), 'ordinary source required: ' + name)
        raw = path.read_bytes()
        need(pin(raw)['sha256'] == digest, 'recipe checksum mismatch: ' + name)
        if name.endswith('.py') or name == NAME:
            compile(raw, name, 'exec')
    info = {}
    for line in (root / '.SRCINFO').read_text().splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.strip().split(' = ', 1)
            info.setdefault(key, []).append(value)
    for key, values in dict(source=sources, sha256sums=sums, pkgname=[NAME], pkgver=['0.1.0'],
                            pkgrel=['1'], arch=['any'], license=['MIT'],
                            depends=['python>=3.11', 'gnupg', 'libarchive', 'pacman']).items():
        need(info.get(key) == values, '.SRCINFO mismatch: ' + key)
    need(not any(info.get(n) for n in ('install', 'backup', 'replaces', 'conflicts', 'provides'))
         and not list(root.glob('*.install')), 'no hook, global config or package replacement')
    pins = json.loads((root / 'payload-pins.json').read_bytes())
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    payload = {PRIVATE + relative: dict(source=source, mode='0644', **pin((root / source).read_bytes()))
               for source, relative in MODULES.items()}
    payload['usr/bin/' + NAME] = dict(source=NAME, mode='0755', **pin((root / NAME).read_bytes()))
    need(pins == dict(schema_version=1, files=payload), 'exact private payload pins required')
    original = {relative: dict(source=source, **pin((root / source).read_bytes()))
                for source, relative in MODULES.items()}
    need(provenance['files'] == original and provenance['license'] == 'MIT', 'original module provenance mismatch')
    for source in MODULES:
        need(b'SPDX-License-Identifier: MIT' in (root / source).read_bytes()[:200], 'module license missing')
    need('Permission is hereby granted' in (root / 'LICENSE').read_text(), 'license text missing')
    if stage is not None:
        stage = Path(stage)
        need(not any(p.is_symlink() for p in stage.rglob('*')), 'stage symlinks refused')
        actual = {p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()}
        need(actual == set(installed_map()), 'unexpected or missing installed file')
        for relative, source in installed_map().items():
            path = stage / relative
            mode = 0o755 if relative == 'usr/bin/' + NAME else 0o644
            need(stat.S_ISREG(path.stat().st_mode) and stat.S_IMODE(path.stat().st_mode) == mode,
                 'installed file type/mode differs: ' + relative)
            need(path.read_bytes() == (root / source).read_bytes(), 'installed bytes differ: ' + relative)
    return dict(status='PASS_EXACT_PRIVATE_RUNTIME', module_files=len(MODULES),
                module_bytes=sum(row['bytes'] for row in original.values()),
                installed_files=len(installed_map()), stage='PASS' if stage else 'NOT_RUN',
                native_build='NOT_RUN', alpm_installed_lifecycle='NOT_RUN', physical_m2='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=HERE)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root, args.stage), sort_keys=True))
