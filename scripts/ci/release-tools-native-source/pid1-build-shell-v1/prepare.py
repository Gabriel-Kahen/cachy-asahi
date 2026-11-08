#!/usr/bin/env python3
"""Explicit PID1-shell Source201 DATA variant; never imports emitted code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
HERE=Path(__file__).resolve().parent
PARENT='d9708daa75083f85f1a182cb3aa97a728d04d695'
MAP='native/source-map.json'
CHANGED={'native/release_alpm_v1.py','native/release_projection_v1.py','native/release_reader_v1.py'}

def need(ok,why):
    if not ok: raise ValueError(why)
def pin(raw): return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def oid(kind,raw): return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def read(path,cap=32*1024**2):
    path=Path(path); info=path.lstat()
    need(path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)) and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<=info.st_size<=cap,'ordinary bounded DATA input')
    raw=path.read_bytes(); after=path.stat()
    need(len(raw)==info.st_size and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'unchanged DATA input')
    return raw

def tree(rows):
    root={}
    for name,row in rows.items():
        path=Path(name); need(not path.is_absolute() and '..' not in path.parts and path.as_posix()==name,'canonical Source path')
        at=root
        for part in path.parts[:-1]: at=at.setdefault(part,{})
        at[path.name]=(row['mode'],row['oid'])
    def walk(at):
        raw=b''
        for name,row in sorted(at.items(),key=lambda x:(x[0]+('/' if isinstance(x[1],dict) else '')).encode()):
            mode,blob=('40000',walk(row)) if isinstance(row,dict) else row
            raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(blob)
        return oid('tree',raw)
    return walk(root)

def construct(parent,output,profile_sha256):
    parent=Path(parent).absolute(); output=Path(output).absolute()
    raw=read(HERE/'profile.json',1024**2); need(pin(raw)['sha256']==profile_sha256,'externally reviewed variant profile')
    profile=json.loads(raw); need(profile['variant']=='pid1-build-shell-v1' and profile['parent_source']==PARENT and profile['actual']==dict(source=None,ref=None,run=None),'explicit unexecuted variant identity')
    rows_raw=read(HERE/'parent-files.json',1024**2); need(pin(rows_raw)==profile['parent_files'],'pinned Source201 parent map'); rows=json.loads(rows_raw)
    parent_raw=read(HERE/'parent.raw-commit',1024**2); need(pin(parent_raw)==profile['parent_raw'] and oid('commit',parent_raw)==PARENT and parent_raw.startswith(('tree '+profile['parent_tree']+'\n').encode()) and tree(rows)==profile['parent_tree'],'actual D970 raw commit and complete tree')
    need(parent==parent.resolve() and parent.is_dir() and not any(p.is_symlink() for p in (parent,*parent.parents)),'ordinary closed parent Source')
    names=set(); directories=set()
    for directory,dirs,files in os.walk(parent,followlinks=False):
        base=Path(directory)
        if base==parent and '.git' in dirs: dirs.remove('.git')
        for name in dirs:
            need(not (base/name).is_symlink(),'no Source directory alias');directories.add((base/name).relative_to(parent).as_posix())
        for name in files:
            if base==parent and name=='.git': continue
            names.add((base/name).relative_to(parent).as_posix())
    need(len(rows)==201 and names==set(rows) and directories=={p.as_posix() for n in rows for p in Path(n).parents if p!=Path('.')},'exact201 parent namespace')
    bodies={}
    for name,row in rows.items():
        body=read(parent/name); need(pin(body)=={k:row[k] for k in ('bytes','sha256')} and oid('blob',body)==row['oid'] and stat.S_IMODE((parent/name).stat().st_mode)==int(row['mode'],8)&0o777,'complete parent body/mode/OID')
        bodies[name]=body
    manifest=json.loads(bodies[MAP]); need(manifest['actual']==dict(source=None,ref=None,run=None) and len(manifest['files'])==200 and set(manifest['files'])==names-{MAP},'unexecuted parent map200')
    need(set(profile['payload'])==CHANGED,'exact three code replacements')
    for name,row in profile['payload'].items():
        body=read(HERE/'payload'/name); need(pin(body)==row and rows[name]['mode']=='100644','exact variant payload pin/mode'); bodies[name]=body
        manifest['files'][name]=dict(pin(body),mode=0o644)
    fixture=profile['privacy_fixture']; fixture_body=read(HERE/fixture['path']);need(pin(fixture_body)=={k:fixture[k] for k in ('bytes','sha256')} and fixture_body==bodies['native/release_projection_v1.py'],'variant privacy fixture matches emitted projection')
    need(profile['matching_reader']==dict(target='native/release_reader_v1.py',**pin(bodies['native/release_reader_v1.py'])),'variant matching reader pin')
    manifest['release_prior_build_retirement_parent']=PARENT
    bodies[MAP]=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    after={name:dict(pin(body),mode=rows[name]['mode'],oid=oid('blob',body)) for name,body in bodies.items()}
    need({name for name in rows if rows[name]!=after[name]}==CHANGED|{MAP} and tree(after)==profile['source_tree'] and pin(bodies[MAP])==profile['source_map'],'exact four delta/197held Source201 result')
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir() and output.parent==output.parent.resolve() and not output.is_relative_to(parent) and not parent.is_relative_to(output) and not output.is_relative_to(HERE),'fresh separate DATA output')
    output.mkdir(mode=0o700)
    for name,body in bodies.items():
        target=output/name; target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream: stream.write(body)
        target.chmod(int(after[name]['mode'],8)&0o777)
    return {'status':'PREPARED_CLOSED_SOURCE201_DATA_ONLY','parent':PARENT,'source':None,'tree':tree(after),'map_sha256':pin(bodies[MAP])['sha256'],'files':201,'changed':4,'held':197,'actual':dict(source=None,ref=None,run=None),'native':'NOT_RUN','reader_executed':False}

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--parent-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-sha256',required=True);a=p.parse_args()
    print(json.dumps(construct(a.parent_source,a.output,a.profile_sha256),sort_keys=True))
if __name__=='__main__': main()
