# SPDX-License-Identifier: MIT
"""Select exact source families for the repository development tests."""

from functools import cache
import hashlib
import json
import subprocess

HISTORICAL_COMMIT = 'bcf0cee981ee4b7f7b082f636922c859dc7e0abc'
ORIGINAL_LOCK = 'scripts/ci/integration.lock.json'
ORIGINAL_LOCK_SHA256 = 'd4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31'
RELEASE = 'scripts/release/release.py'
HISTORICAL_GRAPH_PATHS = {
    ORIGINAL_LOCK,
    'scripts/ci/development/repository_authority.py',
    'scripts/client/client.py',
    'scripts/port/repository-client-stage/adapter.py',
    'scripts/port/repository-client-stage/gate.py',
}
HISTORICAL_GRAPH_PREFIXES = (
    'scripts/port/repository-client-native/',
    'scripts/port/repository-client-phase-stage/',
)


def _git(project, *args):
    result = subprocess.run(
        ['git', '--no-replace-objects', '-C', str(project), *args],
        check=True, capture_output=True,
    )
    return result.stdout


@cache
def historical_modes(project):
    try:
        raw = _git(project, 'ls-tree', '-rz', HISTORICAL_COMMIT)
    except subprocess.CalledProcessError as error:
        raise ValueError(f'historical fixture requires Git commit {HISTORICAL_COMMIT}') from error
    modes = {}
    for row in raw.rstrip(b'\0').split(b'\0'):
        metadata, name = row.split(b'\t', 1)
        mode, kind, _ = metadata.split()
        if kind == b'blob' and mode in (b'100644', b'100755'):
            modes[name.decode()] = int(mode, 8) & 0o777
    return modes


@cache
def historical_input(project, name):
    mode = historical_modes(project)[name]
    raw = _git(project, 'cat-file', 'blob', f'{HISTORICAL_COMMIT}:{name}')
    return raw, mode


@cache
def original_lock(project):
    raw, mode = historical_input(project, ORIGINAL_LOCK)
    if mode != 0o644 or hashlib.sha256(raw).hexdigest() != ORIGINAL_LOCK_SHA256:
        raise ValueError('historical integration lock identity differs')
    lock = json.loads(raw)
    if len(lock['source_files']) != 159:
        raise ValueError('historical original source closure does not contain 159 files')
    return lock


def checkout_input(project, name):
    source = project / name
    return source.read_bytes(), source.stat().st_mode & 0o777


def historical_graph_input(project, name):
    original = original_lock(project)['source_files']
    if name in original or name in HISTORICAL_GRAPH_PATHS or name.startswith(HISTORICAL_GRAPH_PREFIXES):
        raw, mode = historical_input(project, name)
        if name in original:
            observed = {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode}
            if observed != original[name]:
                raise ValueError(f'historical original source identity differs: {name}')
        return raw, mode
    return checkout_input(project, name)
