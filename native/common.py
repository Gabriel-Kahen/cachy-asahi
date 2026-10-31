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
DESKTOP = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
EXTRAS = {'cmake', 'cppdap', 'jsoncpp', 'libuv', 'rhash', 'meson', 'ninja', 'python-tqdm'}
LABEL = 'org.cachy-asahi.native-developer'
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')


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


def uv_policy(root):
    value = load(Path(root) / 'native/uv-inputs.json')
    need(value['schema'] == 1 and value['version'] == '0.11.28'
         and len(value['artifacts']) == 2 and {r['role'] for r in value['artifacts']} == {'frontend', 'backend'}, 'exact separate frontend/backend inputs')
    for row in value['artifacts']:
        name = Path(row['path'])
        need(name.parts[0] == 'inputs' and not name.is_absolute() and '..' not in name.parts
             and type(row['bytes']) is int and 0 < row['bytes'] <= 64*1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256']) and row['url'].startswith('https://'), 'fixed public tool archive pin')
    return value


def source_bytes(root, name):
    rows = {r['path']: r for r in uv_policy(root)['artifacts']}
    if name in rows:
        row = rows[name]
        body = read(Path(root) / name, cap=row['bytes'])
        need(pin(body) == {k: row[k] for k in ('bytes', 'sha256')}, 'exact pinned large tool input')
        return body
    return read(Path(root) / name)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def verify_source(root, checksum):
    root = Path(root).absolute()
    need(re.fullmatch('[0-9a-f]{64}', checksum or ''), 'explicit whole source-map hash required')
    raw = read(root / MAP); need(pin(raw)['sha256'] == checksum, 'whole source map differs')
    manifest = json.loads(raw)
    need(manifest['schema'] == 1 and manifest['actual'] == dict(source=None, ref=None, run=None), 'NULL unexecuted source selectors')
    rows = manifest['files']
    if manifest.get('source_profile') == 'image-tools202-source-v1':
        additions = {'native/image_tools_v1.py','native/image_alpm_v1.py','native/image_guest_v1.py',
                     'native/image_reader_v1.py','native/image_projection_v1.py','native/image_host_diagnostics_v1.py',
                     'native/image-contract-v1.json','native/image-makepkg-v1.conf','native/image-sources-v1.tar',
                     'native/image_synthetic_v1.py','native/image_readback_v1.py'}
        need(MAP not in rows and len(rows) == 201 and additions <= set(rows)
             and manifest.get('image_operation') == 'image-tools-alpm-v1'
             and manifest.get('image_genuine_parent') == '111f14d2b21b220d86912d5ead978848c7ef1cb0',
             'exact image-tools202 source-only profile')
    else:
        need(MAP not in rows and len(rows) <= 200, 'finite nonrecursive source map')
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
    extras = profile['additions']['rows']
    desktop_raw = read(root / 'native/desktop574-inputs.lock.json')
    need(pin(desktop_raw)['sha256'] == DESKTOP, 'whole retained574 supplementary input pin')
    desktop = json.loads(desktop_raw)
    need({r['name']: r for r in extras} == {r['name']: r for r in desktop['packages'] if r['name'] in EXTRAS}, 'exact retained8 rows and signatures differ')
    need(len(extras) == 8 and {r['name'] for r in extras} == EXTRAS and not EXTRAS & versions.keys(), 'fixed eight package additions')
    available = set(versions) | EXTRAS
    for row in extras:
        need(row['arch'] in ('aarch64', 'any') and row['filename'].endswith('.pkg.tar.xz'), 'original ARM archive format')
        for key in ('sha256', 'signature_sha256'):
            need(re.fullmatch('[0-9a-f]{64}', row[key] or ''), 'exact archive/signature hash')
        for key in ('size', 'signature_size'):
            need(type(row[key]) is int and 0 < row[key] <= 64 * 1024**2, 'finite archive/signature bytes')
        need(all(d in available for d in row['depends']), 'complete name-only retained dependency closure')
        versions[row['name']] = row['version']
    expected = ''.join(n + ' ' + v + '\n' for n, v in sorted(versions.items())).encode()
    need(read(root / 'native/expected349.lock') == expected and len(versions) == 349, 'exact augmented349 inventory')
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
    need(row['Name'] == '/developer-' + own['token'] and row['Image'] == image
         and labels.get(LABEL) == own['token'] and labels.get(LABEL + '.source') == own['source']
         and row['Config']['User'] == str(uid) + ':' + str(gid), 'exact owned consumer identity')
    need(h['NetworkMode'] == 'none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False
         and h['PidsLimit'] == 256 and h['Memory'] == 4*1024**3 and h['NanoCpus'] == 2_000_000_000
         and set(h['CapDrop']) == {'ALL'} and not h.get('CapAdd') and h['SecurityOpt'] == ['no-new-privileges']
         and not h.get('Devices') and not h.get('DeviceRequests') and not h.get('VolumesFrom'), 'actual consumer resource/isolation limits')
    binds = {(m['Destination'], m['Source'], m['RW']) for m in row['Mounts'] if m['Type'] == 'bind'}
    need(binds == {('/source', str(root), False), ('/out', str(output), True)}
         and all(m['Type'] == 'bind' or (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp') for m in row['Mounts'])
         and set(h['Tmpfs']) == {'/tmp'}
         and set(h['Tmpfs']['/tmp'].split(',')) == {'rw', 'nosuid', 'nodev', 'exec', 'size=2g'}, 'exact source/output/tmpfs mounts')
