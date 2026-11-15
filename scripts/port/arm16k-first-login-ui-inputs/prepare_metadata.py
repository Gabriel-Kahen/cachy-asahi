#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private existing libalpm prepare over an explicit finite ARM proposal; no commit."""
import importlib.util,json,os,resource,stat,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_AS,(96*1024**2,96*1024**2))
ROOT=Path(__file__).resolve().parents[3]
def run(path):
    spec=importlib.util.spec_from_file_location('ARM_UI_existing_prepare',ROOT/'scripts/platform/transaction.py');T=importlib.util.module_from_spec(spec);sys.modules[spec.name]=T;spec.loader.exec_module(T)
    assert path.is_absolute()and path.name=='proposal.json'and path.parent.parent==Path('/tmp')and path.parent.name.startswith('private-ARM111-UI-metadata-')and not path.is_symlink()
    assert path.parent.stat().st_uid==os.getuid()and stat.S_IMODE(path.parent.stat().st_mode)==0o700
    assert path.is_file()and path.stat().st_size<=2*1024**2
    value=T.tuple_audit.load_json(path.read_bytes());assert set(value)=={'image','catalogs','targets'};image=value['image'];catalogs=value['catalogs'];targets=value['targets'];protected={k:v['VERSION'][0]for k,v in image.items()};assert len(image)==111 and len(targets)<=256
    assert set(catalogs)<= {'core','extra','project'}
    for rows in [image,*catalogs.values()]:
        for name,row in rows.items():T.clean(row);assert row['NAME']==[name]
    work=path.parent
    for name in ['root','gpg','cache','hooks']:(work/name).mkdir()
    (work/'db/sync').mkdir(parents=True)
    T.preview.write_local(work/'db/local',image)
    for repo,rows in catalogs.items():T.write_catalog(work/'db/sync'/(repo+'.db'),rows)
    result=T.prepare(work,image,protected,catalogs,targets)
    final=dict(image)
    for row in result['add']:final[row['name']]=catalogs[row['repo']][row['name']]
    assert not result['remove']and all(final[n]['VERSION']==image[n]['VERSION']for n in image),'baseline drift refused'
    audit=work/'final-audit';(audit/'root').mkdir(parents=True);T.preview.write_local(audit/'db/local',final);dependencies,conflicts=T.preview.alpm_audit(audit,final)
    return {'prepare':result,'dependencies':dependencies,'conflicts':conflicts,'final_count':len(final),'baseline_preserved':111,'proc_memory':{k:int(v.split()[0])*1024 for k,v in(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if line.startswith(('VmPeak:','VmHWM:')))},'scope':'explicit proposed package metadata only; no archives/install/signature/hardware acceptance'}
if __name__=='__main__':
    try:result=run(Path(sys.argv[1]));print(json.dumps(result,sort_keys=True))
    except Exception as error:print(json.dumps({'status':'HOLD_PREPARE_REFUSAL','category':type(error).__name__,'message':str(error)[:512]}));raise SystemExit(1)
