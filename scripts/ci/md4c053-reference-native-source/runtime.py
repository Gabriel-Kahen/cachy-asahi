# SPDX-License-Identifier: MIT
"""Admitted md4c recipe/finisher seam; retain inherited container ownership labels.

Import/install is actor-free. Only the inherited post-bootstrap plans call stages
the source-bound bundle into its already-created quota work output. This hook
does not change admission, the all501 audit, resources, cleanup or retirement.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

BASE = 'held-source/scripts/ci/llhttp-reference-native-source/base'
ARCHIVE = 'md4c-472c417005c2c71b8617de4f7b8d6b30411d78f4.tar.gz'
FILES = frozenset(('recipe/PKGBUILD', 'recipe/.SRCINFO', 'recipe/smoke.sh',
    'recipe/smoke.c', 'recipe/'+ARCHIVE, 'finish_pair.py', 'recipe-pin.json',
    'reviewed-inputs.json', 'expected349.lock'))
MAX_BYTES = 1024**2


def need(value, why):
    if not value:
        raise ValueError(why)


def ordinary(path, directory=True):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and
         all(not p.is_symlink() for p in (path, *path.parents)),
         'canonical unaliased provider path')
    if directory:
        need(path.is_dir(), 'existing provider directory')
    return path


def decode_bundle(bundle):
    need(type(bundle) is dict and set(bundle) == FILES and len(bundle) <= 16,
         'exact bounded md4c bundle namespace')
    bodies = {}
    total = 0
    for name, row in bundle.items():
        path = PurePosixPath(name)
        need(str(path) == name and not path.is_absolute() and
             all(p not in ('', '.', '..') for p in path.parts), 'safe bundle name')
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'body_base64', 'mode'}
             and row['mode'] == 0o644 and type(row['bytes']) is int and
             0 < row['bytes'] <= MAX_BYTES and type(row['body_base64']) is str and
             len(row['body_base64']) <= 4*((MAX_BYTES+2)//3) and
             re.fullmatch('[0-9a-f]{64}', row['sha256'] or ''),
             'whole bounded bundle member frame')
        raw = base64.b64decode(row['body_base64'], validate=True)
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
             'whole bundle member hash')
        total += len(raw)
        need(total <= MAX_BYTES, 'finite complete md4c bundle')
        bodies[name] = raw
    return bodies


def verify_stage(stage, bodies):
    need(stage.is_dir() and not stage.is_symlink() and
         stat.S_IMODE(stage.stat().st_mode) == 0o700, 'ordinary private provider stage')
    found = set()
    for path in stage.rglob('*'):
        need(not path.is_symlink(), 'unaliasable staged member')
        if path.is_dir():
            need(stat.S_IMODE(path.stat().st_mode) == 0o700, 'private staged directory')
        else:
            need(path.is_file(), 'ordinary staged leaf')
            name = path.relative_to(stage).as_posix()
            need(name in bodies and stat.S_IMODE(path.stat().st_mode) == 0o644 and
                 path.stat().st_nlink == 1 and path.stat().st_size == len(bodies[name]) and
                 path.read_bytes() == bodies[name], 'whole staged body/mode')
            found.add(name)
    need(found == set(bodies), 'complete closed staged namespace')


def install(namespace, source_root, bundle):
    """Bind only plans and the one finisher import; do not execute a native actor."""
    root = ordinary(source_root)
    here = ordinary(namespace['HERE'])
    need(here == root/BASE and namespace.get('_md4c053_provider') is None,
         'one hook on the exact held entry namespace')
    bodies = decode_bundle(bundle)
    # The baseline lock remains authoritative. No package installation occurs.
    need((here/'expected349.lock').read_bytes() == bodies['expected349.lock'],
         'unchanged exact349 target lock')
    reviewed = json.loads(bodies['reviewed-inputs.json'])
    need(reviewed == {n[7:]: hashlib.sha256(raw).hexdigest()
                     for n, raw in bodies.items() if n.startswith('recipe/')},
         'whole independently reviewed recipe input map')
    contract = namespace['C']
    original_module = contract.module
    state = dict(consumed=False, stage=None)

    def plans(actual_here, output, image):
        need(Path(actual_here) == here and re.fullmatch('sha256:[0-9a-f]{64}', image or ''),
             'same held entry and immutable native image')
        output = ordinary(output)
        need(not output.is_relative_to(root) and not root.is_relative_to(output) and
             stat.S_IMODE(output.stat().st_mode) == 0o700 and not state['consumed'],
             'one private disjoint post-bootstrap provider staging')
        state['consumed'] = True
        stage = output/'md4c-provider-inputs'
        stage.mkdir(mode=0o700)
        for name, raw in sorted(bodies.items()):
            path = stage/name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(raw)
        verify_stage(stage, bodies)
        state['stage'] = stage
        common = ['--image', image, '--mode', 'native', '--network', 'none',
            '--source-date-epoch', '1776685420', '--timeout', '300',
            '--expected-packages', str(here/'expected349.lock'),
            '--reviewed-inputs', str(stage/'reviewed-inputs.json')]
        builds = [['/usr/bin/python3', '-I', '-B',
            str(here/'runtime/scripts/build/build_llhttp-reference.py'),
            str(stage/'recipe'), *common, '--output', str(output/('build-'+str(i)))]
            for i in (1, 2)]
        compare = ['/usr/bin/python3', '-I', '-B',
            str(here/'runtime/scripts/build/compare_llhttp.py'),
            str(output/'build-1'), str(output/'build-2'), '--require-bytes']
        return builds, compare

    def module(path, name):
        if Path(path) != here/'finish_pair.py':
            return original_module(path, name)
        stage = state['stage']
        need(stage is not None, 'finisher only after complete post-bootstrap plans')
        verify_stage(stage, bodies)
        spec = importlib.util.spec_from_file_location(name, stage/'finish_pair.py')
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    namespace['_md4c053_provider'] = state
    contract.plans = plans
    contract.module = module
