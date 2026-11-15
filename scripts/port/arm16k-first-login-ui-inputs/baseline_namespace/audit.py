#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact ARM111 installed desc/FILES and fixed namespace read-only DATA join."""
import argparse,hashlib,importlib.util,json,os,re,resource,shutil,signal,stat,subprocess,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('baseline_namespace_held_plan',HERE.parent/'plan.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
R=P.load('baseline_namespace_held_fields',P.ROOT/'scripts/port/platform-residual-closure/resolve.py')
def pin(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':P.sha(path)}
def canonical(value):
    name=value.rstrip('/');assert name and not name.startswith('/')and all(part not in ['','.','..']for part in name.split('/'))and not re.search(r'[\x00-\x20\x7f]',name);return name

def join_rows(selection,index,prepared):
    wanted={r['name']:r['version']for r in prepared['base_packages']};assert len(wanted)==111 and {r['name']:r['version']for r in selection['packages']}==wanted
    rows={};directories={r['name']:r['directory']for r in prepared['base_packages']}
    for package in selection['packages']:
        name=package['name'];directory=package['directory'];assert directory==directories[name],'prepared package directory differs';assert re.fullmatch(r'[A-Za-z0-9_+.:@-]+',directory);source=index['packages'][directory];assert source['desc']==package['desc']and source['desc']['NAME']==[name]and source['desc']['VERSION']==[wanted[name]]
        files=[canonical(p)for p in source['files'].get('FILES',[])];assert len(files)==len(set(files))and set(files)<=set(selection['paths'])
        rows[name]={'version':wanted[name],'directory':directory,'provides':source['desc'].get('PROVIDES',[]),'files':files}
    return rows

def dump(raw,path,target,maximum):
    canonical(path);assert re.fullmatch(r'[A-Za-z0-9_+./:@-]+',path)
    result=subprocess.run(['/usr/bin/debugfs','-R','dump /'+path+' '+str(target),str(raw)],capture_output=True,timeout=5,env={'PATH':'/usr/bin','LC_ALL':'C','HOME':str(target.parent)})
    assert result.returncode==0 and target.is_file()and not target.is_symlink()and target.stat().st_size<=maximum,'bounded read-only filesystem DATA refused'
    data=target.read_bytes();target.chmod(0o600);return data

def actual_stat(raw,path):
    result=subprocess.run(['/usr/bin/debugfs','-R','stat /'+path,str(raw)],capture_output=True,text=True,timeout=5,env={'PATH':'/usr/bin','LC_ALL':'C'})
    assert result.returncode==0 and len(result.stdout)<65536
    text=result.stdout;shape=re.search(r'Type: +regular +Mode: +([0-7]+)',text);owner=re.search(r'User: +(\d+) +Group: +(\d+)',text);size=re.search(r'Size: +(\d+)',text)
    assert shape and owner and size,'actual fixed leaf stat refused'
    return {'type':'0','mode':int(shape[1],8),'uid':int(owner[1]),'gid':int(owner[2]),'bytes':int(size[1]),'link':''}

def run(output):
    started=time.monotonic();output.mkdir(mode=0o700,exist_ok=False);c=json.loads((HERE/'inputs.json').read_text());refs=c['references'];selection=json.loads(P.bound(refs['selection.json']));index=json.loads(P.bound(refs['rootfs-index.json']));prepared=json.loads(P.bound(refs['prepared.json']));rows=join_rows(selection,index,prepared);raw=Path(c['raw']['path']);before=raw.stat();assert stat.S_ISREG(before.st_mode)and not raw.is_symlink()and before.st_uid==os.getuid()and before.st_size==c['raw']['bytes'];assert prepared['files']['guest.raw']=={k:c['raw'][k]for k in ['bytes','sha256']};assert P.sha(raw)==c['raw']['sha256'],'original raw checksum differs'
    assert shutil.disk_usage(output).free>=2*1024**3+16*1024**2
    installed=[];required={};original_pins={}
    with tempfile.TemporaryDirectory(prefix='public-baseline-metadata-',dir=output)as tmp:
        work=Path(tmp)
        for name,row in sorted(rows.items()):
            directory=row['directory'];expected=index['packages'][directory];record={'name':name,'version':row['version'],'directory':directory}
            for kind in ['desc','files']:
                data=dump(raw,'var/lib/pacman/local/'+directory+'/'+kind,work/'metadata.DATA',1024**2);assert R.fields(data)==expected[kind],'actual raw installed '+kind+' differs from retained index';record[kind+'_bytes']=len(data);record[kind+'_sha256']=hashlib.sha256(data).hexdigest();(work/'metadata.DATA').unlink()
            installed.append(record)
        for path in c['fixed_paths']:
            canonical(path);node=index['nodes'][path];assert node['type']=='0'and node['bytes']<=2*1024**2 and path in selection['paths'];owners=[name for name,row in rows.items()if path in row['files']];assert len(owners)==1,'fixed namespace owner ambiguous/missing'
            actual=actual_stat(raw,path);assert actual=={k:node[k]for k in ['type','mode','uid','gid','bytes','link']},'raw namespace numeric metadata differs';data=dump(raw,path,work/'fixed.DATA',2*1024**2);assert len(data)==node['bytes'];digest=hashlib.sha256(data).hexdigest();required[path]={'owner':owners[0],'payload':actual|{'sha256':digest}};original_pins['/'+path]=digest;(work/'fixed.DATA').unlink()
    assert P.sha(raw)==c['raw']['sha256'],'original raw changed';after=raw.stat();assert all(getattr(before,k)==getattr(after,k)for k in ['st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])
    return {'schema_version':1,'status':'PASS_ARM111_BASELINE_METADATA_NAMESPACE_DATA_ONLY','baseline_metadata':rows,'baseline_metadata_provenance':{'method':'all111 raw installed desc/FILES parsed and exactly compared to pinned selected rootfs-index; each fixed leaf read only from the same hash-verified raw','prepared':refs['prepared.json'],'raw':c['raw'],'rootfs_index':refs['rootfs-index.json'],'selection':refs['selection.json'],'raw_SHA256_verified_before_and_after':True,'fixed_leaf_numeric_metadata_independently_read_from_raw':True,'installed_metadata_records':installed,'empty_FILES_metapackages':[n for n,r in rows.items()if not r['files']]},'original_file_pins':original_pins,'required_namespace':required,'counts':{'packages':len(rows),'distinct_provides':len({p for row in rows.values()for p in row['provides']}),'package_owned_paths':len({p for row in rows.values()for p in row['files']}),'selected_paths':len(selection['paths']),'actual_raw_metadata_files':len(installed)*2,'fixed_namespace_leaves':len(required)},'limits':{'address_space_bytes':256*1024**2,'wall_seconds':180,'new_export_bound_bytes':16*1024**2},'no_archive44_authentication_guest_policy_install_execution':True,'source_native_M2_release':'HOLD','seconds':time.monotonic()-started}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not __debug__:p.error('assertions required')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(90,90));signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('180s bounded baseline DATA audit')));signal.alarm(180)
    try:report=run(a.output)
    except Exception as error:report={'status':'HOLD_BASELINE_DATA_REFUSAL','category':type(error).__name__,'reason':str(error)[:512]}
    finally:signal.alarm(0)
    if a.output.exists():(a.output/'baseline-namespace.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report.get(k)for k in ['status','counts','seconds','category','reason']}));raise SystemExit(0 if report['status'].startswith('PASS')else 2)
