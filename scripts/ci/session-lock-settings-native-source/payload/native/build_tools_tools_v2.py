# SPDX-License-Identifier: MIT
"""Pinned two-package native DATA policy; no actor is created on import."""
import base64

import hashlib

import importlib.util

import io

import json

import os

from pathlib import Path

import re

import stat

import tarfile

def need(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def data_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(path, maximum=2 * 1024**2):
    path = Path(path)
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'ordinary nonaliased path required')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'bounded ordinary source required')
        pieces, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            pieces.append(block); size += len(block)
            need(size <= maximum, 'ordinary byte cap exceeded')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid')
        need(all(getattr(before, key) == getattr(after, key) for key in keys) and size == after.st_size,
             'ordinary file changed while reading')
        return b''.join(pieces)
    finally:
        os.close(fd)

def pin(path):
    return data_pin(ordinary(path, MAX_FILE))

def _pin_row(item, maximum=1024**2):
    return (type(item) is dict and type(item.get('bytes')) is int and 0 < item['bytes'] <= maximum
            and type(item.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', item['sha256'])
            and type(item.get('mode')) is int and item['mode'] in (0o644, 0o755))

def expected_installed(root):
    """Derive all349 version AND architecture rows from the genuine held inputs."""
    root = Path(root)
    original = json.loads(ordinary(root / 'bootstrap/scripts/ci/inputs.lock.json'))
    additions = json.loads(ordinary(root / 'native/input-profile.json'))['additions']['rows']
    versions = {}
    for row in original['rootfs_packages']:
        need(all(type(row[key]) is list and len(row[key]) == 1 for key in ('name', 'version', 'arch')),
             'exact rootfs package metadata')
        versions[row['name'][0]] = (row['version'][0], row['arch'][0])
    for row in original['packages'] + additions:
        versions[row['name']] = (row['version'], row['arch'])
    need(len(versions) == 349 and all(arch in ('any', 'aarch64') for _, arch in versions.values()),
         'complete genuine349 architecture metadata')
    lock = ordinary(root / 'native/expected349.lock')
    need(lock == ''.join(name + ' ' + version + '\n' for name, (version, _) in sorted(versions.items())).encode(),
         'derived full349 version/architecture inventory differs')
    return sorted(name + '-' + version + '-' + arch for name, (version, arch) in versions.items())

def load_workflow(root, policy):
    row = policy['original_workflow']
    path = Path(root) / row['path']; raw = ordinary(path)
    need(data_pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'genuine owned Commands source bytes')
    spec = importlib.util.spec_from_file_location('_build_tools_owned_workflow_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module

def snapshot(root):
    """Bounded quiescent tree bytes/modes/ownership; never follow symlink nodes."""
    root = Path(root)
    need(not any(path.is_symlink() for path in root.parents), 'snapshot ancestry alias refused')
    if not os.path.lexists(root):
        return {}
    need(not root.is_symlink(), 'snapshot root alias refused')
    result, total, count = {}, 0, 0
    def visit(path, name, depth):
        nonlocal total, count
        count += 1
        need(count <= MAX_NODES and depth <= 64, 'snapshot node/depth budget exceeded')
        info = path.lstat()
        item = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        if stat.S_ISDIR(info.st_mode):
            item['kind'] = 'directory'; result[name] = item
            for child in sorted(path.iterdir()):
                visit(child, str(child.relative_to(root)), depth + 1)
        elif stat.S_ISREG(info.st_mode):
            raw = ordinary(path, min(MAX_FILE, MAX_TOTAL - total))
            total += len(raw); item.update(kind='file', **data_pin(raw)); result[name] = item
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            need(len(target.encode()) <= 4096, 'snapshot link byte cap')
            item.update(kind='symlink', target=target); result[name] = item
        else:
            raise ValueError('snapshot special file refused: ' + name)
    visit(root, '.', 0)
    return result

def snapshot_receipt(root):
    value = snapshot(root)
    return dict(files=len(value), **data_pin(encoded(value)))

def _metadata(raw):
    need(len(raw) <= 256 * 1024, 'metadata byte cap')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'canonical makepkg metadata field')
        key, value = line.split(' = ', 1)
        need(re.fullmatch('[a-z][a-z0-9_]*', key) and len(value) <= 8192, 'bounded makepkg metadata field')
        rows.setdefault(key, []).append(value)
    return rows

def _own_tree(root, uid, gid):
    root = Path(root)
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'fixture aliases/special nodes refused')
        os.chown(path, uid, gid, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):path.chmod(0o700)

OPERATION='session-lock-settings-alpm-v1'
PAIR='settings011-session-lock010'
PREFIX=Path('/opt/native-session-lock-settings-alpm-v1')
SOURCE=PREFIX/'source'
STORE=PREFIX/'evidence'
MAX_FILE=16*1024**2
MAX_TOTAL=128*1024**2
MAX_NODES=100000
KINDS=('helper','settings')
STAGES=('sign','build-a-helper','bootstrap-a-install','build-a-settings','bootstrap-a-remove','build-b-helper','bootstrap-b-install','build-b-settings','bootstrap-b-remove','compare','install','remove','reinstall','remove-again','restore','cleanup')


def source_policy(root):
    root=Path(root);policy=json.loads(ordinary(root/'native/build-tools-contract-v2.json'))
    need(policy['schema']==1 and policy['operation']==OPERATION and policy['pair']==PAIR
         and set(policy['actual'])=={'source','ref','run','job','artifact'} and all(v is None for v in policy['actual'].values()),'new unexecuted pair source contract')
    base=ordinary(root/'native/expected349.lock');versions=dict(line.decode().split(' ',1) for line in base.splitlines())
    need(data_pin(base)=={k:policy['expected349'][k] for k in ('bytes','sha256')} and len(versions)==349
         and all(versions.get(k)==v for k,v in policy['dependencies'].items()),'genuine349 exact available dependencies')
    installed=expected_installed(root)
    need(set(policy['recipes'])==set(KINDS),'exact helper/settings recipes')
    for kind,count in (('helper',4),('settings',9)):
        recipe=policy['recipes'][kind]
        need(recipe['name']==('cachy-asahi-session-lock' if kind=='helper' else 'cachy-asahi-hyprland-settings')
             and recipe['version']==('0.1.0-1' if kind=='helper' else '0.1.1-1') and len(recipe['payload_files'])==count,'finite exact recipe identity')
        expected=installed if kind=='helper' else sorted(installed+['cachy-asahi-session-lock-0.1.0-1-any'])
        need(recipe['buildinfo_installed']==expected,'349 helper/350 settings exact BUILDINFO inputs')
        for name,item in recipe['source_files'].items():need(Path(name).name==name and _pin_row(item),'flat exact source pin')
        for name,item in recipe['payload_files'].items():need(name.startswith('usr/') and '..' not in Path(name).parts and _pin_row(item),'finite payload pin')
    need(policy['recipes']['helper']['test_blocks']==[24,2] and policy['recipes']['settings']['test_blocks']==[5,2],'actual unchanged recipe test blocks')
    config=ordinary(root/policy['makepkg_config']['path'])
    need(data_pin(config)=={k:policy['makepkg_config'][k] for k in ('bytes','sha256')}
         and b' check ' in config and b'!check' not in config,'positive held makepkg configuration')
    return policy,base


def recipe_members(root,policy):
    row=policy['bundle'];raw=ordinary(Path(root)/row['path'],row['max_bytes'])
    need(data_pin(raw)=={k:row[k] for k in ('bytes','sha256')},'exact source bundle pin')
    expected={f'recipes/{kind}/{name}':item for kind,recipe in policy['recipes'].items() for name,item in recipe['source_files'].items()}
    expected.update(policy['verification']['files']);found={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            need(member.name in expected and member.name not in found and member.isfile() and not member.pax_headers
                 and member.uid==member.gid==member.mtime==0,'bounded ordinary exact bundle member')
            item=expected[member.name];body=archive.extractfile(member).read()
            need(member.mode==item['mode'] and data_pin(body)=={k:item[k] for k in ('bytes','sha256')},'bundle member body/mode pin')
            found[member.name]=body
    need(set(found)==set(expected) and len(found)==row['members'],'complete bundle namespace')
    return found


def extract_recipes(root,destination,policy):
    members=recipe_members(root,policy);destination=Path(destination);destination.mkdir(mode=0o755)
    for label in ('a','b'):
        for kind,recipe in policy['recipes'].items():
            target=destination/label/kind;target.mkdir(parents=True,mode=0o755)
            for name,item in recipe['source_files'].items():
                path=target/name;path.write_bytes(members[f'recipes/{kind}/{name}']);path.chmod(item['mode'])
    target=PREFIX/'verification';target.mkdir(mode=0o755)
    for name,item in policy['verification']['files'].items():
        path=target/Path(name).name;path.write_bytes(members[name]);path.chmod(item['mode'])
    return destination


def inventory_expected(base,kinds=()):
    rows=base.splitlines(keepends=True)
    need(len(rows)==349 and not any(b'cachy-asahi-session-lock ' in r or b'cachy-asahi-hyprland-settings ' in r for r in rows),'genuine untouched349 base')
    need(set(kinds)<=set(KINDS),'closed pair inventory')
    for kind in kinds:
        rows.append((('cachy-asahi-session-lock 0.1.0-1' if kind=='helper' else 'cachy-asahi-hyprland-settings 0.1.1-1')+'\n').encode())
    return b''.join(sorted(rows))


def archive_data(raw,recipe):
    need(type(raw)is bytes and 0<len(raw)<=1024**2,'bounded decoded archive DATA')
    expected=recipe['payload_files'];parents={str(p)for n in expected for p in Path(n).parents if str(p)!='.'}
    files={};dirs=set();seen=set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name.rstrip('/');need(name not in seen and not member.pax_headers and member.uid==member.gid==0,'unique ordinary root-owned member');seen.add(name)
            if member.isdir():need(name in parents and member.mode==0o755 and member.size==0,'exact parent directory');dirs.add(name);continue
            need(member.isfile() and member.size<=256*1024 and name in set(expected)|{'.PKGINFO','.BUILDINFO','.MTREE'},'finite regular package namespace')
            body=archive.extractfile(member).read();files[name]=body
            if name in expected:need(member.mode==expected[name]['mode'] and data_pin(body)=={k:expected[name][k]for k in ('bytes','sha256')},'exact source payload')
            else:need(member.mode==0o644,'ordinary metadata mode')
    need(set(files)==set(expected)|{'.PKGINFO','.BUILDINFO','.MTREE'} and dirs==parents,'complete package namespace')
    pkg=_metadata(files['.PKGINFO']);build=_metadata(files['.BUILDINFO'])
    static={k:v for k,v in pkg.items()if k not in ('builddate','packager','size')}
    need(static==recipe['metadata'],'exact declared static package metadata')
    for key,value in [('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])]:need(build.get(key)==[value],'exact BUILDINFO identity')
    need(sorted(build.get('installed',[]))==recipe['buildinfo_installed'] and len(set(build['installed']))==len(build['installed'])
         and 'check'in build.get('buildenv',[]) and '!check'not in build['buildenv'],'complete349/350 positive-check native provenance')
    return files


def compare_archives(run,archives,policy,map_hash):
    need(set(archives)=={'a','b'},'two clean iterations')
    result={}
    for kind in KINDS:
        decoded={};bodies={};rows={};recipe=policy['recipes'][kind]
        for label in ('a','b'):
            path=archives[label][kind];bodies[label]=ordinary(path,1024**2)
            decoded[label]=archive_data(run(f'archive-{label}-{kind}',['/usr/bin/zstd','-dc',str(path)]),recipe)
            rows[label]=dict(archive=data_pin(bodies[label]),metadata={n:data_pin(decoded[label][n])for n in ('.PKGINFO','.BUILDINFO','.MTREE')},payload={n:data_pin(decoded[label][n])for n in recipe['payload_files']})
        need(bodies['a']==bodies['b'] and decoded['a']==decoded['b'],'two exact native archives/payload/PKGINFO/BUILDINFO/MTREE')
        result[kind]=dict(status='PASS_EXACT_NATIVE_BUILD_PAIR',builds=rows,payload_files=len(recipe['payload_files']),buildinfo_count=len(recipe['buildinfo_installed']))
    return dict(status='PASS_EXACT_NATIVE_PAIR_OF_PACKAGES',source_map_sha256=map_hash,packages=result)


def verify_pair(run,archives,label,policy,payload_root=None):
    prefix=PREFIX/('verified-prefix-'+label);prefix.mkdir(mode=0o700)
    members=recipe_members(SOURCE,policy)
    for kind,recipe in policy['recipes'].items():
        for name,item in recipe['payload_files'].items():
            body=ordinary(Path(payload_root)/name) if payload_root is not None else members[f'recipes/{kind}/{Path(name).name}']
            path=prefix/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755);path.write_bytes(body);path.chmod(item['mode'])
    argv=['/usr/bin/python3','-I','-B',str(PREFIX/'verification/desktop_session_lock.py'),'--profile',str(PREFIX/'verification/desktop-session-lock011.json'),'--profile-sha256',policy['verification']['profile_sha256'],
          '--settings-package',str(archives['settings']),'--settings-sha256',pin(archives['settings'])['sha256'],'--session-lock-package',str(archives['helper']),'--session-lock-sha256',pin(archives['helper'])['sha256'],'--prefix',str(prefix)]
    value=json.loads(run('verify-prefix-'+label,argv))
    need(value.get('status')=='desktop-session-lock-prefix-pass' and value.get('payload_files')==13 and value.get('payload_executed')is False
         and value.get('profile_sha256')==policy['verification']['profile_sha256'],'actual exact pair source-prefix verifier')
    return value


def check_payload(root,policy,run,pacman):
    result={}
    for kind,recipe in policy['recipes'].items():
        for name,item in recipe['payload_files'].items():
            path=Path(root)/name;info=path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==item['mode'] and pin(path)=={k:item[k]for k in ('bytes','sha256')},'actual installed source payload')
            need(run('owner-'+recipe['name'],['/usr/bin/pacman',*pacman,'-Qoq',str(path)]).strip()==recipe['name'].encode(),'actual ALPM owner')
        listed=run('owned-files-'+recipe['name'],['/usr/bin/pacman',*pacman,'-Qlq',recipe['name']]).decode().splitlines()
        need(len(listed)==len(set(listed)) and {n.lstrip('/')for n in listed if not n.endswith('/')}==set(recipe['payload_files'])
             and {n.strip('/')for n in listed if n.endswith('/')}=={str(p)for n in recipe['payload_files']for p in Path(n).parents if str(p)!='.'},'complete ALPM package namespace')
        result[kind]=dict(name=recipe['name'],version=recipe['version'],files=recipe['payload_files'])
    return dict(count=13,verified=True,packages=result)
