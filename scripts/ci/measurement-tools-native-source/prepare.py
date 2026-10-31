#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the exact measurement native Source as DATA; never execute actors."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = '1f5c4675f3b5c75206bb38004bb7799f3ba2d7b14d7b88a974d71a59df1e4823'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 96 * 1024**2, 200


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw, mode):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=mode)


def relative(name):
    need(type(name) is str and 0 < len(name) <= 512, 'bounded source name required')
    path = PurePosixPath(name)
    need(path.as_posix() == name and not path.is_absolute() and len(path.parts) <= 24
         and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', part) and part not in ('.', '..', '.git')
                 for part in path.parts), 'safe canonical relative source name required')
    return path


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute nonaliased path required')
    return path


def read(path, limit=MAX_FILE):
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'bounded ordinary single-link source required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
            need(size <= limit, 'source byte bound exceeded')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(size == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
             'source changed during read')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(fd)


def tree(root, checkout=False):
    root = absolute(root); need(root.is_dir(), 'ordinary source root required')
    result, directories, total = {}, set(), 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        current = Path(directory)
        if checkout and current == root:
            dirs[:] = [n for n in dirs if n != '.git']
            names = [n for n in names if n != '.git']
        for name in dirs:
            child = current / name
            need(stat.S_ISDIR(child.lstat().st_mode), 'source directory alias or special node refused')
            directories.add(child.relative_to(root).as_posix())
        for name in names:
            child = current / name; leaf = child.relative_to(root).as_posix(); relative(leaf)
            need(len(result) < MAX_FILES, 'source member count exceeded')
            raw, mode = read(child); total += len(raw)
            need(total <= MAX_TOTAL and mode in (0o644, 0o755), 'source total/mode bound exceeded')
            result[leaf] = (raw, mode)
    wanted = {p.as_posix() for name in result for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    need(directories == wanted, 'empty or unexpected source directory refused')
    return result


def rows(files):
    return {name: pin(raw, mode) for name, (raw, mode) in files.items()}


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def git_tree(files):
    nested = {}
    for name, (raw, mode) in files.items():
        parts = relative(name).parts; node = nested
        for part in parts[:-1]:
            need(not isinstance(node.get(part), tuple), 'source file/directory collision')
            node = node.setdefault(part, {})
        need(parts[-1] not in node, 'duplicate source leaf'); node[parts[-1]] = (raw, mode)
    def visit(node):
        body = bytearray()
        for name, value in sorted(node.items(), key=lambda pair: pair[0].encode() + (b'/' if isinstance(pair[1], dict) else b'')):
            directory = isinstance(value, dict)
            mode = b'40000' if directory else b'100755' if value[1] == 0o755 else b'100644'
            body.extend(mode + b' ' + name.encode() + b'\0' + (visit(value) if directory else oid(b'blob', value[0])))
        return oid(b'tree', body)
    return visit(nested).hex()


def profile():
    raw,_=read(HERE/'profile.json',1024**2)
    need(hashlib.sha256(raw).hexdigest()==PROFILE_SHA256,'whole fixed profile differs')
    value=json.loads(raw)
    need(value['kind']=='measurement-tools-native-source-profile-v1' and len(value['basis'])==191
         and len(value['after'])==199 and value['group_admission']=='NOT_ADMITTED'
         and all(x is None for x in value['actual'].values()),'unexecuted finite native profile required')
    return value

def render(basis):
    value=profile();before=tree(basis,checkout=True)
    need(rows(before)==value['basis'] and git_tree(before)==value['parent_tree'],'whole genuine191 basis differs')
    raw,mode=read(HERE/'parent-commit.raw')
    need(pin(raw,mode)==value['parent_raw'] and oid(b'commit',raw).hex()==value['genuine_parent'],'genuine raw parent differs')
    need([r[5:].decode() for r in raw.split(b'\n\n',1)[0].splitlines() if r.startswith(b'tree ')]==[value['parent_tree']],'raw parent tree differs')
    payload=tree(HERE/'payload');need(rows(payload)==value['payload'],'closed fixed payload differs')
    after=dict(before);after.update(payload)
    need(rows(after)==value['after'] and git_tree(after)==value['source_tree'],'whole proposed199 Source differs')
    manifest=json.loads(after['native/source-map.json'][0])
    need(manifest['actual']==dict(source=None,ref=None,run=None)
         and manifest['files']=={n:r for n,r in rows(after).items() if n!='native/source-map.json'}
         and hashlib.sha256(after['native/source-map.json'][0]).hexdigest()==value['source_map_sha256'],'closed198 map differs')
    for name,(raw,_) in after.items():
        if name.endswith('.py'):compile(raw,name,'exec')
    return value,before,after

def emit(basis,output):
    basis,output=absolute(basis),absolute(output)
    for source in (basis,HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output),'disjoint output required')
    info=output.parent.stat()
    need(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700 and not os.path.lexists(output),'fresh output in owned0700 parent required')
    value,before,after=render(basis)
    stage=dict(status='SOURCE_ONLY_EXACT_MEASUREMENT_NATIVE199',operation='measurement-tools-alpm-v1',parent=value['genuine_parent'],
      parent_tree=value['parent_tree'],prospective_tree=value['source_tree'],source_map_sha256=value['source_map_sha256'],source_files=199,source_map_rows=198,
      actual=value['actual'],native='NOT_RUN',namespace_support='UNKNOWN',group_admission='NOT_ADMITTED',physical_M2='NOT_RUN',native_16K='NOT_QUALIFIED',performance='NOT_MEASURED',release='NOT_ADMITTED')
    delta={n:dict(before=rows(before).get(n),after=rows(after).get(n)) for n in value['payload']}
    restored=dict(after)
    for name,row in delta.items():
        if row['before'] is None:del restored[name]
        else:restored[name]=before[name]
    need(rows(restored)==rows(before) and git_tree(restored)==value['parent_tree'],'full191 inverse differs')
    bodies={'source/'+n:item for n,item in after.items()}
    bodies.update({'stage.json':(encoded(stage),420),'source-authorization.json':(encoded({n:{k:r[k] for k in ('bytes','sha256')} for n,r in rows(after).items()}),420),
      'source-modes.json':(encoded({n:m for n,(_,m) in after.items()}),420),'git-blobs.json':(encoded({n:dict(blob=oid(b'blob',b).hex()) for n,(b,_) in after.items()}),420),
      'delta191.json':(encoded(dict(parent=value['genuine_parent'],changes=delta,full_inverse='PASS_EXACT191')),420),'parent-commit.raw':(read(HERE/'parent-commit.raw')[0],420)})
    for n in delta:
        if n in before:bodies['before191/'+n]=before[n]
    with tempfile.TemporaryDirectory(prefix='.measurement-source-',dir=output.parent) as temporary:
        staged=Path(temporary)/'output';staged.mkdir(mode=0o700)
        for name,(raw,mode) in sorted(bodies.items()):
            target=staged/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with target.open('xb') as stream:stream.write(raw)
            target.chmod(mode)
        need(rows(tree(staged/'source'))==value['after'],'emitted whole source differs')
        rename=ctypes.CDLL(None,use_errno=True).renameat2
        rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
        if rename(-100,os.fsencode(staged),-100,os.fsencode(output),1):
            code=ctypes.get_errno();raise OSError(code,os.strerror(code))
    return stage

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--basis',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    try:result=emit(args.basis.absolute(),args.output.absolute())
    except (OSError,ValueError,KeyError,TypeError,UnicodeError) as error:parser.exit(1,'measurement native Source refused: '+str(error)+'\n')
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
