#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact Source200 with genuine signed Security upgrade protocol; DATA only."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = '4e74176f2804b618c53a6ae1238fc93f132b52c45dcc71f1d359fb8542e98ad1'
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
MAX_FILE = 64*1024**2
MAX_SOURCE = 64*1024**2


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, maximum=MAX_FILE):
    path = Path(path).absolute()
    need(path == path.resolve(), 'source symlink ancestry')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'bounded ordinary single-link source')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum+1)
        need(len(raw) == before.st_size and all(getattr(before,key) == getattr(os.fstat(fd),key)
             == getattr(path.lstat(),key) for key in FIELDS), 'source changed during read')
        return raw
    finally:
        os.close(fd)


def name(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9._+/-]+',value)
         and not value.startswith('/') and all(part not in ('','.','..') for part in value.split('/')), 'relative source path')
    return value


def snapshot(root, *, checkout=False):
    root = Path(root).absolute()
    need(root == root.resolve() and root.is_dir(), 'ordinary source root')
    rows, bodies, directories = {}, {}, set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for leaf in tuple(dirs):
            path = base/leaf
            need(not path.is_symlink(), 'source directory alias')
            if checkout and base == root and leaf == '.git':
                dirs.remove(leaf)
            else:
                directories.add(path.relative_to(root).as_posix())
        for leaf in files:
            if checkout and base == root and leaf == '.git':
                continue
            path = base/leaf; relative = name(path.relative_to(root).as_posix())
            raw = read(path); mode = stat.S_IMODE(path.lstat().st_mode)
            need(mode in (0o644,0o755), 'source mode')
            rows[relative] = dict(**pin(raw),mode=mode); bodies[relative] = raw
            need(len(rows) <= 200 and sum(item['bytes'] for item in rows.values()) <= MAX_SOURCE, 'finite source bounds')
    expected_dirs = {str(p) for leaf in rows for p in Path(leaf).parents if p != Path('.')}
    need(directories == expected_dirs, 'source directory namespace')
    return rows, bodies


def object_id(kind, raw):
    return hashlib.sha1(kind+b' '+str(len(raw)).encode()+b'\0'+raw).digest()


def tree_id(bodies, modes):
    nodes = {}
    for leaf, raw in bodies.items():
        parts = name(leaf).split('/'); parent = nodes
        for part in parts[:-1]:
            parent = parent.setdefault(part,{})
            need(type(parent) is dict, 'file/directory overlap')
        need(parts[-1] not in parent, 'duplicate source path')
        parent[parts[-1]] = (raw,modes[leaf])
    def digest(directory):
        result = b''
        for leaf,value in sorted(directory.items(),key=lambda row:row[0].encode()+(b'/' if type(row[1]) is dict else b'')):
            if type(value) is dict:
                mode,body = b'40000',digest(value)
            else:
                raw,source_mode = value; mode = b'100755' if source_mode == 0o755 else b'100644'; body = object_id(b'blob',raw)
            result += mode+b' '+leaf.encode()+b'\0'+body
        return object_id(b'tree',result)
    return digest(nodes).hex()



PRODUCER_BEFORE = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28318, 'sha256': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'}, 'native/failure_retention.py': {'bytes': 13639, 'sha256': '20f9f6fb153d3be98e41c343e63f5994aa3708ccbd4299e1f551a38b697ffbe3'}}
PRODUCER_AFTER = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28877, 'sha256': '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba', 'mode': 420}, 'native/failure_retention.py': {'bytes': 13639, 'sha256': 'cdb50b755f3e76d0229278bb89476752702544f3c31947e74676c82b213a8dc7', 'mode': 420}}


def retired_producer(bodies):
    """Two authenticated producer/cleanup replacements; operands never execute."""
    need({name: dict(bytes=len(bodies[name]), sha256=hashlib.sha256(bodies[name]).hexdigest()) for name in PRODUCER_BEFORE} == PRODUCER_BEFORE,
         'strict frozen producer/observer inputs differ')
    overlay_rows, overlay = snapshot(HERE / 'producer-overlay')
    need(overlay_rows == PRODUCER_AFTER, 'fixed producer retirement overlay differs')
    result = dict(bodies)
    result.update(overlay)
    return result

CONCURRENCY_GROUP = 'native-arm-security-maintenance'
WORKFLOW_ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')


def scheduled_workflows(bodies):
    """Change only the authenticated legacy scheduling block, never job behavior."""
    before = b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
    after = ('concurrency:\n  group: ' + CONCURRENCY_GROUP + '\n  cancel-in-progress: false\n  queue: max\njobs:\n').encode()
    need(bodies[WORKFLOW_ALIASES[0]] == bodies[WORKFLOW_ALIASES[1]], 'workflow aliases differ before scheduling')
    result = dict(bodies)
    for name in WORKFLOW_ALIASES:
        raw = bodies[name]
        need(raw.count(before) == 1 and raw.count(b'\nconcurrency:\n') == 1, 'exact unqueued legacy concurrency block required')
        result[name] = raw.replace(before, after, 1)
    return result


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def profile():
    raw=read(HERE/'profile.json',1024**2)
    need(pin(raw)['sha256']==PROFILE_SHA256,'whole fixed Security factory profile')
    value=json.loads(raw)
    need(value['schema']==1 and value['kind']=='security-maintenance-native-source-v1'
         and value['operation']=='security-alpm-v1' and value['upgrade_protocol']=='signed-prior-to-current-v1'
         and value['observation_protocol']=='first-real-upgrade-zero-observation-v1'
         and value['target_base']=='main' and value['parent']['source']=='b6a02f11648738ded90084f7dcdcd4ea77c194fa'
         and len(value['parent']['files'])==len(value['expected']['files'])==200
         and len(value['payload'])==3 and value['producer_overlay']==PRODUCER_AFTER
         and value['actual']==dict(source=None,ref=None,run=None,job=None,artifact=None,runtime=None),
         'exact unexecuted Security Source200 profile')
    return value


def render(parent):
    value=profile();before,bodies=snapshot(parent,checkout=True)
    need(before==value['parent']['files'] and tree_id(bodies,{n:r['mode']for n,r in before.items()})==value['parent']['tree'],
         'complete exact genuine Source200 parent bodies/modes/tree')
    raw=read(HERE/'parent-commit.raw');need(pin(raw)==value['parent']['raw_commit']
         and object_id(b'commit',raw).hex()==value['parent']['source'],'genuine raw native predecessor')
    headers=raw.split(b'\n\n',1)[0].splitlines()
    need([r[5:].decode()for r in headers if r.startswith(b'tree ')]==[value['parent']['tree']]
         and len([r for r in headers if r.startswith(b'parent ')])==1,'genuine raw parent tree and sole-parent shape')
    payload,replacements=snapshot(HERE/'overlay');need(payload==value['payload'],'whole fixed upgrade overlay')
    original_mapping=json.loads(bodies['native/source-map.json'])
    need(original_mapping['files']=={n:r for n,r in before.items()if n!='native/source-map.json'},'closed parent map199')
    bodies.update(replacements);bodies=retired_producer(scheduled_workflows(bodies))
    modes={n:r['mode']for n,r in value['expected']['files'].items()}
    mapping=dict(value['source_map_metadata'])
    mapping['files']={n:dict(**pin(raw),mode=modes[n])for n,raw in sorted(bodies.items())if n!='native/source-map.json'}
    need(mapping['actual']==dict(source=None,ref=None,run=None) and len(mapping['files'])==199,'unchanged default map bound')
    bodies['native/source-map.json']=encoded(mapping)
    after={n:dict(**pin(raw),mode=modes[n])for n,raw in bodies.items()}
    need(after==value['expected']['files'] and tree_id(bodies,modes)==value['expected']['tree'],
         'complete exact emitted Source200 bodies/modes/map/tree')
    need(bodies['native/common.py']==read(Path(parent)/'native/common.py'), 'default unnamed Source guard held byte-for-byte')
    for alias in WORKFLOW_ALIASES:
        declarations=re.findall(rb"'([0-9a-f]{64})' native/common.py \| sha256sum --check",bodies[alias])
        need(declarations==[hashlib.sha256(bodies['native/common.py']).hexdigest().encode()],'workflow common binding')
    for name in ('native/security_native_v1.py','native/security_reader_v1.py'):
        compile(bodies[name],name,'exec')
    return value,before,bodies,modes


def assemble(parent,output):
    parent,output=Path(parent).absolute(),Path(output).absolute()
    need(not os.path.lexists(output) and output.parent.is_dir() and output.parent==output.parent.resolve(), 'fresh nonaliased output')
    need(output.parent.stat().st_uid==os.geteuid() and stat.S_IMODE(output.parent.stat().st_mode)==0o700,'caller-owned0700 output parent')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)for root in (parent,HERE)),'disjoint input/output')
    value,before,bodies,modes=render(parent)
    stage=dict(status='PREPARED_SECURITY_UPGRADE_CHECKPOINT_OBSERVATION_SOURCE_ONLY',operation=value['operation'],upgrade_protocol=value['upgrade_protocol'],
               files=200,source_map_rows=199,parent=value['parent']['source'],parent_tree=value['parent']['tree'],
               prospective_tree=value['expected']['tree'],source_map_sha256=pin(bodies['native/source-map.json'])['sha256'],
               proposed_ref=value['proposed_ref'],workflow_id=381664314,target_base='main',main_checkpoint=value['main_checkpoint'],actual=value['actual'],
               native='NOT_RUN',GPG='NOT_RUN',ALPM_upgrade='NOT_RUN',ALPM_observation='NOT_RUN',
               ALPM_interruption='NOT_RUN',ALPM_recovery='NOT_RUN',M2='NOT_RUN',release='NOT_ADMITTED')
    after=value['expected']['files'];changed={n:dict(before=before[n],after=after[n])for n in after if before[n]!=after[n]}
    operands={
        'stage.json':encoded(stage),
        'source-authorization.json':encoded({n:{k:r[k]for k in('bytes','sha256')}for n,r in after.items()}),
        'source-modes.json':encoded(modes),
        'git-blobs.json':encoded({n:dict(blob=object_id(b'blob',raw).hex(),**after[n])for n,raw in bodies.items()}),
        'change-map.json':encoded(changed),
        'parent-raw-commit.txt':read(HERE/'parent-commit.raw'),
        'actual-binding-template.json':encoded(dict(source=None,ref=None,run=None,map_sha256=stage['source_map_sha256'])),
        'dispatch-template.json':encoded(dict(ref=stage['proposed_ref'],inputs=dict(source_sha=None,source_map_sha256=stage['source_map_sha256'],operation=value['operation']))),
        'reader-operands.json':encoded(dict(status='PINNED_MATCHING_READER_ACTUAL_BINDING_PENDING_ROOT',API='reader.validate(capsule_path, actual_binding)',
             pins={n:after[n]for n in('native/reader.py','native/security_reader_v1.py','native/common.py','native/capsule.py')},
             actual_binding=dict(source=None,ref=None,run=None,map_sha256=stage['source_map_sha256']),Root_acceptance=None)),
    }
    with tempfile.TemporaryDirectory(prefix='.security-native-source-',dir=output.parent)as temp:
        staging=Path(temp)/'stage';staging.mkdir(mode=0o700)
        for name,raw in sorted(bodies.items()):
            p=staging/'source'/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with p.open('xb')as stream:stream.write(raw)
            p.chmod(modes[name])
        for name,raw in operands.items():
            with(staging/name).open('xb')as stream:stream.write(raw)
            (staging/name).chmod(0o644)
        for name in changed:
            p=staging/'inverse/originals'/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with p.open('xb')as stream:stream.write(read(parent/name))
            p.chmod(before[name]['mode'])
        emitted,_=snapshot(staging/'source');need(emitted==after,'complete emitted Source check')
        rename=ctypes.CDLL(None,use_errno=True).renameat2
        rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
        if rename(-100,os.fsencode(staging),-100,os.fsencode(output),1):
            code=ctypes.get_errno();raise OSError(code,os.strerror(code))
    return stage


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    print(json.dumps(assemble(args.parent,args.output),sort_keys=True))


if __name__=='__main__':main()
