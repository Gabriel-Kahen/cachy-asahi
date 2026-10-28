# SPDX-License-Identifier: MIT
"""Data-only closed source and exact frozen input contracts; no actor imports."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAP = 'native/source-map.json'
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
LOCK = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
LABEL = 'org.cachy-asahi.native-debugger'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-debugger-workflow.yml')


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, cap=16 * 1024**2):
    path = Path(path); info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= cap
         and not any(p.is_symlink() for p in path.parents), 'bounded ordinary path: ' + str(path))
    return path.read_bytes()


def load(path):
    return json.loads(read(path))


def source_bytes(root, name):
    return read(Path(root) / name)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def verify_source(root, checksum):
    root = Path(root).absolute()
    need(re.fullmatch('[0-9a-f]{64}', checksum or ''), 'explicit whole source-map hash required')
    raw = read(root / MAP); need(pin(raw)['sha256'] == checksum, 'whole source map differs')
    manifest = json.loads(raw)
    need(manifest['schema'] == 1 and manifest['actual'] == dict(source=None, ref=None, run=None), 'NULL unexecuted source selectors')
    rows = manifest['files']; need(MAP not in rows and len(rows) <= 200, 'finite nonrecursive source map')
    actual = set(); actual_dirs = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in tuple(dirs):
            need(not (base / name).is_symlink(), 'source directory alias')
            if base == root and name == '.git':
                dirs.remove(name)
            else:
                actual_dirs.add(str((base / name).relative_to(root)))
        for name in files:
            actual.add(str((base / name).relative_to(root)))
    need(actual == set(rows) | {MAP}, 'closed complete source namespace differs')
    expected_dirs = {str(p) for name in set(rows) | {MAP} for p in Path(name).parents if p != Path('.')}
    need(actual_dirs == expected_dirs, 'closed source directory namespace differs')
    for name, expected in rows.items():
        path = Path(name)
        need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name, 'source path')
        need(pin(source_bytes(root, name)) == {k: expected[k] for k in ('bytes', 'sha256')}
             and stat.S_IMODE((root / path).stat().st_mode) == expected['mode'], 'source bytes/mode differ: ' + name)
    return manifest


def input_contract(root):
    root = Path(root); profile = load(root / 'native/input-profile.json')
    raw = read(root / 'bootstrap/scripts/ci/inputs.lock.json')
    need(pin(raw)['sha256'] == INPUTS, 'original248 whole input pin')
    original = json.loads(raw)
    lock = read(root / 'native/original341.lock')
    need(pin(lock)['sha256'] == LOCK and len(lock.splitlines()) == 341, 'exact original341 inventory')
    versions = {r['name'][0]: r['version'][0] for r in original['rootfs_packages']}
    versions.update({r['name']: r['version'] for r in original['packages']})
    need(lock == ''.join(n + ' ' + v + '\n' for n, v in sorted(versions.items())).encode(), 'original inventory derivation differs')
    need(profile['schema'] == 1 and profile['actual'] == dict(source=None, ref=None, run=None)
         and profile['packages'] == 341 and profile['additions'] == [], 'original341 debugger input profile')
    need(profile['gdb_rows'] == [r for r in original['packages'] if r['name'] in ('gdb', 'gdb-common')],
         'exact original signed GDB rows')
    need({r['name']: r['version'] for r in profile['gdb_rows']} == {'gdb': '18.1-1', 'gdb-common': '18.1-1'}, 'fixed GDB versions')
    expected = lock
    return profile, original, expected


def binding(source, ref, run, env):
    need(re.fullmatch('[0-9a-f]{40}', source or '') and isinstance(ref, str)
         and ref.startswith('refs/heads/codex/') and re.fullmatch('[1-9][0-9]*', run or ''), 'Root publication/source/ref/run required')
    need(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == source
         and env.get('GITHUB_REF') == ref and env.get('GITHUB_RUN_ID') == run
         and env.get('GITHUB_RUN_ATTEMPT') == '1' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
         and env.get('GITHUB_WORKFLOW_REF') in {'Gabriel-Kahen/cachy-asahi/' + name + '@' + ref for name in ALIASES},
         'exact same-source first-attempt dedicated manual workflow binding')
    token = hashlib.sha256((source + ':' + ref + ':' + run).encode()).hexdigest()[:24]
    return dict(source=source, ref=ref, run=run, attempt=1, token=token)


def consumer_contract(row, own, image, root, output, uid, gid):
    h = row['HostConfig']; labels = row['Config']['Labels']
    need(row['Name'] == '/debugger-' + own['token'] and row['Image'] == image
         and labels.get(LABEL) == own['token'] and labels.get(LABEL + '.source') == own['source']
         and row['Config']['User'] == str(uid) + ':' + str(gid), 'exact owned consumer identity')
    need(h['NetworkMode'] == 'none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False
         and h['PidsLimit'] == 256 and h['Memory'] == 4*1024**3 and h['NanoCpus'] == 2_000_000_000
         and set(h['CapDrop']) == {'ALL'} and not h.get('CapAdd') and h['SecurityOpt'] == ['no-new-privileges']
         and h.get('PidMode', '') == '' and h.get('IpcMode') == 'private'
         and not h.get('Devices') and not h.get('DeviceRequests') and not h.get('VolumesFrom'), 'actual consumer resource/isolation limits')
    binds = {(m['Destination'], m['Source'], m['RW']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(binds == {('/source', str(root), False), ('/out', str(output), True)}
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(h['Tmpfs']) == {'/tmp'}
         and set(h['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=2g'}, 'exact source/output/tmpfs mounts')
