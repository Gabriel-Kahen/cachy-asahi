# SPDX-License-Identifier: MIT
"""Exact Source82/PR411 DATA successor. Actual construction is Root-only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

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
        need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'whole stable descriptor/path')
        return raw
    finally:os.close(fd)

def profile():return json.loads(ordinary(HERE/'profile.json'))

def project(base,recipe,overrides):
    """Pure DATA projection; no Source imports, filesystem writes or actors."""
    p=profile();need(set(base)==set(p['base_Source'])and len(base)==82,'exact parent82 namespace')
    for n,raw in base.items():need(type(raw)is bytes and row(raw)==p['base_Source'][n],'parent body/mode/blob '+n)
    need(set(recipe)==set(p['recipe_files']),'exact24 recipe input namespace')
    for n,raw in recipe.items():need(type(raw)is bytes and pin(raw)==p['recipe_files'][n],'actual438 recipe bytes '+n)
    changed=sorted(n for n in recipe if recipe[n]!=base[n]);need(changed==p['approved_recipe_delta']and len(changed)==3,'only genuine three recipe leaf deltas')
    need(set(overrides)==set(p['producer_overrides'])=={'prepare.py','test_source.py'},'two explicit producer overrides')
    for n,raw in overrides.items():need(pin(raw)==p['producer_overrides'][n],'trusted producer override '+n)
    out=dict(base);out.update(recipe)
    for n,raw in overrides.items():out[LANE+'/'+n]=raw
    policy=json.loads(base[LANE+'/input-policy.json']);need(policy['candidate_source']=='2dbe7fe5623fae9ed5940a26385400958c3ffb42'and policy['retained_input_carrier']=='3856733787d10820ab73f842e9f2bbf4fdb84181','exact old logical source/physical14 provenance')
    need(all(policy[k]is None for k in('native_source','actual_run','native_authority','resource_authority')),'no actual Native authority')
    policy['candidate_source']=p['recipe_source']
    for role,product in policy['products'].items():
        product['source_sha']=p['recipe_source'];product['recipe_sha256']=pin(recipe[product['recipe_directory']+'/PKGBUILD'])['sha256']
        product['source_files']={n:pin(recipe[product['recipe_directory']+'/'+n])for n in product['source_files']}
        if role=='client':
            need(product['check_markers'].count('Ran 6 tests')==1,'exact old six marker');product['check_markers']=[('Ran 8 tests'if n=='Ran 6 tests'else n)for n in product['check_markers']]
    out[LANE+'/input-policy.json']=wire(policy)
    manifest=json.loads(base[MANIFEST]);manifest['files']={n:pin(raw)for n,raw in out.items()if n not in(MANIFEST,WORKFLOW)};need(len(manifest['files'])==80,'held full80 manifest rows');out[MANIFEST]=wire(manifest)
    before=pin(base[MANIFEST])['sha256'].encode();after=pin(out[MANIFEST])['sha256'].encode();need(base[WORKFLOW].count(before)==1,'exact manifest-only native workflow seam');out[WORKFLOW]=base[WORKFLOW].replace(before,after,1)
    delta={n:dict(before=row(base[n]),after=row(raw))for n,raw in out.items()if raw!=base[n]};need(len(out)==82 and len(delta)==8,'exact82 rows/eight deltas/74held')
    return out,dict(status='EXACT_DATA_SUCCESSOR_NOT_ACTUAL_SOURCE',physical_parent=p['physical_parent'],recipe_source=p['recipe_source'],files=82,manifest_rows=80,delta=delta,held=74,actual_source=None,run=None,native='NOT_RUN',actual_Reader_calls=0)

def construct(args):
    # Root invokes only after the genuine ordinary411 merge. Nothing dispatches.
    need(args.Root_construct and args.merge_proof and args.merge_sha256,'explicit Root constructor and genuine411 merge pin required')
    raw=ordinary(args.merge_proof);need(pin(raw)['sha256']==args.merge_sha256,'actual Root411 merge receipt pin');m=json.loads(raw);p=profile()
    need(m['status']=='PASS_EXACT_THREE_PATH_CLIENT_MAKEPKG_FIXTURE_MERGE'and m['tested_head']==p['recipe_source']and m['merge_PUTs']==1 and m['all_unlisted_objects_modes_preserved']is m['inverse_restores_actual_premerge_main']is True,'genuine Root411 green exact3 merge')
    repo=args.repository.resolve()
    def git(*a):return subprocess.check_output(['git','--no-replace-objects',*a],cwd=repo,timeout=30)
    live=git('rev-parse','HEAD').decode().strip();need(git('symbolic-ref','--short','HEAD').decode().strip()=='main'and not git('status','--porcelain','--untracked-files=no'),'clean Main for Root source construction');git('merge-base','--is-ancestor',m['main'],live)
    base={n:ordinary(args.Source82/n)for n in p['base_Source']};need({n.relative_to(args.Source82).as_posix()for n in args.Source82.rglob('*')if n.is_file()or n.is_symlink()}==set(base),'closed ordinary Source82 namespace')
    recipe={n:git('show',p['recipe_source']+':'+n)for n in p['recipe_files']};overrides={n:ordinary(HERE/'producer'/n)for n in p['producer_overrides']};out,proof=project(base,recipe,overrides)
    target=args.output.absolute();need(not os.path.lexists(target)and target.parent.is_dir()and not any(q.is_symlink()for q in(target,*target.parents))and not target.is_relative_to(args.Source82),'fresh disjoint Root output')
    report=target.parent/(target.name+'-construction.json');need(not os.path.lexists(report),'fresh construction receipt')
    os.umask(0o077);target.mkdir(mode=0o700)
    for n,body in sorted(out.items()):
        q=target/n;q.parent.mkdir(mode=0o700,parents=True,exist_ok=True);q.write_bytes(body);q.chmod(0o644)
    proof.update(Main=live,merge=m['main'],whole_map={n:row(raw)for n,raw in out.items()})
    with report.open('xb')as stream:stream.write(wire(proof));stream.flush();os.fsync(stream.fileno())
    print(proof['status'])

if __name__=='__main__':
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--Root-construct',dest='Root_construct',action='store_true');a.add_argument('--merge-proof',type=Path);a.add_argument('--merge-sha256');a.add_argument('--repository',type=Path,required=True);a.add_argument('--Source82',type=Path,required=True);a.add_argument('--output',type=Path,required=True);construct(a.parse_args())
