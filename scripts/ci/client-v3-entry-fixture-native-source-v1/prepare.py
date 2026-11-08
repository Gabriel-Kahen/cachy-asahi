# SPDX-License-Identifier: MIT
"""Exact closed-entry fixture DATA successor; actual Source construction is Root-only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
LANE='scripts/ci/client-v3-native'
MANIFEST=LANE+'/source-manifest.json'
WORKFLOW='.github/workflows/native-arm-build.yml'

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def row(raw):return dict(mode='100644',oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),**pin(raw))
def wire(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ordinary(path):
    path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary ancestry')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and a.st_size<=16*1024**2,'owned bounded ordinary file')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(a.st_size+1)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'whole stable descriptor/path');return raw
    finally:os.close(fd)
def profile():return json.loads(ordinary(HERE/'profile.json'))
def trusted(root):
    p=profile()
    for n,w in p['trusted_inputs'].items():need(pin(ordinary(root/n))==w,'held trusted maintained input '+n)
    return p

def project(base,fixture):
    """Only bytes are projected; Source/artifact code is never imported."""
    p=profile();need(set(base)==set(p['base_Source'])and len(base)==82,'exact Source15b82 namespace')
    for n,raw in base.items():need(type(raw)is bytes and row(raw)==p['base_Source'][n],'exact Source15b body/mode/blob '+n)
    need(type(fixture)is bytes and pin(fixture)==p['fixture_after'],'exact reviewed entry fixture')
    n=p['fixture_path'];need(pin(base[n])==p['fixture_before'],'exact old closed-entry fixture')
    policy=json.loads(base[LANE+'/input-policy.json']);need(policy['candidate_source']==p['recipe_source'],'held strict438 runtime policy')
    need(all(policy[k]is None for k in('native_source','actual_run','native_authority','resource_authority')),'no Native selector authority')
    out=dict(base);out[n]=fixture
    manifest=json.loads(base[MANIFEST]);need(set(manifest['files'])==set(base)-{MANIFEST,WORKFLOW},'full80 prior manifest')
    for name,w in manifest['files'].items():need(pin(base[name])==w,'prior manifest hash '+name)
    manifest['files'][n]=pin(fixture);out[MANIFEST]=wire(manifest)
    before=pin(base[MANIFEST])['sha256'].encode();after=pin(out[MANIFEST])['sha256'].encode();need(base[WORKFLOW].count(before)==1,'one literal manifest hash');out[WORKFLOW]=base[WORKFLOW].replace(before,after,1)
    delta={n:dict(before=row(base[n]),after=row(raw))for n,raw in out.items()if raw!=base[n]};need(set(delta)=={p['fixture_path'],MANIFEST,WORKFLOW},'exact3 fixture/manifest/workflow delta')
    return out,dict(status='EXACT_SOURCE15B_ENTRY_FIXTURE_DATA_SUCCESSOR_NOT_ACTUAL_SOURCE',physical_parent=p['physical_parent'],files=82,manifest_rows=80,delta=delta,held=79,actual_source=None,run=None,native='NOT_RUN',actual_Reader_calls=0)

def stage_controls(root,target,old=False):
    # Trusted maintained files only: this is not a Source constructor.
    p=trusted(root);need(not os.path.lexists(target),'fresh DATA-control stage');os.umask(0o077);target.mkdir(mode=0o700)
    base=root/LANE
    for n in json.loads(ordinary(root/'scripts/ci/client-v3-makepkg-native-source-v1/profile.json'))['base_producer']:
        (target/n).write_bytes(ordinary(base/n))
    for n in('prepare.py','test_source.py'):(target/n).write_bytes(ordinary(root/'scripts/ci/client-v3-makepkg-native-source-v1/producer'/n))
    body=ordinary(base/'test_entry_failures.py')if old else ordinary(HERE/'producer/test_entry_failures.py')
    need(pin(body)==p['fixture_before'if old else'fixture_after'],'exact selected maintained fixture');(target/'test_entry_failures.py').write_bytes(body)

if __name__=='__main__':
    a=argparse.ArgumentParser(description='Stage trusted entry DATA controls; no actual Source/Reader/native capability');a.add_argument('--root',type=Path,required=True);a.add_argument('--stage-entry-controls',type=Path,required=True);a.add_argument('--old-fixture',action='store_true');v=a.parse_args();stage_controls(v.root.resolve(),v.stage_entry_controls.absolute(),v.old_fixture)
