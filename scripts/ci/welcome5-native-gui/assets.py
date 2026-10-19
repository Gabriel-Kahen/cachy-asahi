# SPDX-License-Identifier: MIT
"""Assemble GUI inputs only from selected public native data; never import it."""
import json,shutil,subprocess
from pathlib import Path
import candidates as C

PUBLIC='77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90'

def revision(root,expected):
    result=subprocess.run(['git','-C',str(root),'rev-parse','HEAD'],capture_output=True,timeout=10)
    C.need(result.returncode==0 and result.stdout.decode().strip()==expected and len(result.stdout)+len(result.stderr)<=4096,'exact real public carrier checkout required')
    result=subprocess.run(['git','-C',str(root),'status','--porcelain','--untracked-files=all'],capture_output=True,timeout=10)
    C.need(result.returncode==0 and not result.stdout and len(result.stderr)<=4096,'clean public carrier required')

def prepare(source,public,carrier,out,renewal=None):
    policy=C.selection(source);C.need(not out.exists(),'fresh assets required')
    selected=list(policy['inputs'].values());C.need(len({(r['carrier_source'],r['carrier_ref'],r['index_path'],r['index_pin']['sha256'])for r in selected})==1,'one explicit new carrier required')
    R=C.load('welcome5_gui_renewal_public',source/C.ROLE/'renewal.py');R.selection(source)
    C.need(renewal is not None,'explicit genuine renewal checkout required');revision(renewal,R.CARRIER)
    revision(public,PUBLIC);revision(carrier,selected[0]['carrier_source'])
    value=assemble_data(source,public/'payload',carrier/'payload',out,policy,renewal)
    return dict(value,status='PREPARED_PUBLIC_NATIVE_INPUTS_ONLY',new_carrier=selected[0]['carrier_source'])

def assemble_data(source,public,packet,out,policy,renewal=None):
    """Pure local data/source proof; never attests a public carrier revision."""
    C.need(not out.exists(),'fresh source-control assets required')
    selected=list(policy['inputs'].values())
    inspect=C.load('held_public_native_GUI_inputs',source/'scripts/ci/current604-public-gui-assets/assets.py')
    facts=inspect.inspect(source,public)
    # No GUI component authorization is used: these archives are native INPUTS.
    index=C.read(public/'index.json');refs={r['path']:r for r in index['evidence']['files']}
    out.mkdir(mode=0o700);held=out/'held';held.mkdir(mode=0o700)
    files={}
    for row in facts['products'].values():
        for name in (row['archive'],row['archive']+'.sig'):files[name]='signed/'+name
    files.update({'TEST-public.asc':'signed/TEST-public.asc','control.json':'signed/control.json'})
    for name,relative in files.items():
        ref=refs[relative];path=C.pinned(public,relative,{k:ref[k]for k in ('bytes','sha256')});shutil.copyfile(path,held/name)
    (held/'products.json').write_text(json.dumps(facts['products'],sort_keys=True,indent=2)+'\n')
    index=C.read(C.pinned(packet,selected[0]['index_path'],selected[0]['index_pin'],1024**2))
    for name,row in index['files'].items():C.pinned(packet,name,row)
    actual={str(p.relative_to(packet))for p in packet.rglob('*')if p.is_file()}
    C.need(actual==set(index['files'])|{selected[0]['index_path']}and all(not p.is_symlink()for p in packet.rglob('*')),'closed project native carrier required')
    for role in ('welcome5','dns2'):shutil.copytree(packet,out/role)
    # Full new pair/metadata/payload/Root joins also run before any secrets.
    C.stage_data(source,out,out/'checked-candidates',policy)
    if renewal is not None:
        R=C.load('welcome5_gui_renewal_data',source/C.ROLE/'renewal.py');R.inspect(renewal,packet,public)
        destination=out/'renewal';destination.mkdir(mode=0o700)
        for name in R.overlay(renewal)['files']|{'index.json':R.INDEX}:
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(renewal/name,target)
    return dict(status='PREPARED_NATIVE_DATA_ONLY_PUBLICATION_NOT_ATTESTED',held_carrier=PUBLIC,new_carrier=None,native_GUI='NOT_RUN',historical_GUI_authority='NOT_CONSUMED')
