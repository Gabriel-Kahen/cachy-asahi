#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent published LLVM256 passive Reader; Root authority remains external."""
import argparse,hashlib,importlib.util,json,resource,sys,time,os,struct,tarfile,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('llvm_v4_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);v=B.v
MIB,GIB=v.MIB,v.GIB
P253=dict(source=None,ref=None,files=253,bytes=40862047,map_sha256='5c19a2699856e081712d159c551ce496919938bd456f2182c0c905f03cbd2ef0',tree='2f90eaaaa532d14574c0ce1f1c93b02310f44d91')
VOLUME='hosted/volume.py';SAVED_VOLUME='previous-v3/hosted-volume.py';SAVED_MAP='previous-v3/source-map.json';META='successor-v4.json'
OLD="h['CapAdd']==['CHOWN']";NEW="h['CapAdd']in(['CHOWN'],['CAP_CHOWN'])"
ACTUAL=dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))

def binding(value,pins):
 v.need(value['scope']=='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V4','new published256 Reader scope')
 projected=dict(value,scope='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V2');v.check_binding(projected,pins)
 v.need(value['actual']==projected['actual'],'actual Source/ref/run/job/map unchanged');return value

def descriptor(row):return dict(bytes=len(row[0]),sha256=hashlib.sha256(row[0]).hexdigest(),mode=row[1])
def git_tree(found):
 def tree(prefix=''):
  children={}
  for name,row in found.items():
   if name.startswith(prefix):
    part=name[len(prefix):].split('/',1)[0];children[part]=None if prefix+part!=name else row
  raw=bytearray()
  for name,row in sorted(children.items(),key=lambda x:(x[0]+('/'if x[1]is None else '')).encode()):
   mode,oid=('40000',tree(prefix+name+'/'))if row is None else('100755'if row['mode']==0o755 else'100644',row['blob']);raw.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid))
  return v.git_oid('tree',raw)
 return tree()

def namespace_rows(rows,pins):
 """Verify reconstructed historical DATA without writing or importing any leaf."""
 v.need(len(rows)==pins['source_files']and sum(len(b)for b,_ in rows.values())==pins['source_bytes'],'complete historical membership/count/bytes')
 raw,mode=rows['source-map.json'];manifest=v.decode(raw)
 v.need(mode==0o644 and hashlib.sha256(raw).hexdigest()==pins['source_map_sha256']and set(manifest)=={'schema','scope','actual','files'}and type(manifest['schema'])is int and manifest['schema']==1 and manifest['actual']==ACTUAL,'whole historical map/schema/NULL author selectors')
 found={}
 for name,row in rows.items():
  v.safe_name(name);v.need(row[1]in(0o644,0o755),'historical ordinary byte/mode')
  found[name]=dict(**descriptor(row),blob=v.git_oid('blob',row[0]))
 v.need(manifest['files']=={n:descriptor(row)for n,row in rows.items()if n!='source-map.json'}and git_tree(found)==pins['source_tree'],'closed historical map/mode/blob/tree')
 return found

def inverse253_rows(rows,pins,found,parent,ancestor):
 """Exact256→253, followed by unchanged independent253→251→248 guards."""
 v.need(namespace_rows(rows,pins)==found,'actual256 rows match independently checked physical namespace')
 result=dict(rows);result.pop('source-map.json');raw,mode=result.pop(META);meta=v.decode(raw)
 v.need(mode==0o644 and set(meta)=={'schema','scope','parent','outer_operation','inner_operation','changed','saved_parent_map','saved_parent_volume','all_other_parent_leaves_unchanged','actual'}and type(meta['schema'])is int and meta['schema']==1 and meta['scope']=='INITIALIZER_CAPABILITY_SPELLING_SOURCE_ONLY_NOT_REPLAY'and meta['parent']==P253 and meta['outer_operation']==pins['operation']and meta['inner_operation']==pins['inner_operation']and meta['actual']==ACTUAL and meta['saved_parent_map']==SAVED_MAP and meta['saved_parent_volume']==SAVED_VOLUME and meta['all_other_parent_leaves_unchanged']is True and set(meta['changed'])=={VOLUME},'exact unadmitted256 correction lineage')
 saved=result.pop(SAVED_VOLUME);saved_map=result.pop(SAVED_MAP);before=B.old_pins['files'][VOLUME];after=pins['files'][VOLUME]
 v.need(descriptor(saved)==before and descriptor(result[VOLUME])==after and saved_map[1]==0o644 and len(saved_map[0])==49842 and hashlib.sha256(saved_map[0]).hexdigest()==P253['map_sha256'],'whole saved253 volume/map and corrected volume')
 v.need(meta['changed'][VOLUME]==dict(before=before,after=after,inverse=dict(old=OLD,new=NEW,count=1))and saved[0].count(OLD.encode())==1 and NEW.encode()not in saved[0]and result[VOLUME]==(saved[0].replace(OLD.encode(),NEW.encode()),saved[1]),'only exact raw singleton capability spelling predicate changed')
 result[VOLUME]=saved;result['source-map.json']=saved_map
 historical=namespace_rows(result,B.old_pins)
 v.need(set(rows)-set(result)=={META,SAVED_MAP,SAVED_VOLUME}and set(result)<=set(rows),'exact three additions with no dropped historical leaf')
 for name in set(result)-{VOLUME,'source-map.json'}:v.need(found[name]==historical[name],'unmodified253 leaf differs')
 restored251=B.historical253(result,parent,B.old_pins,ancestor)
 v.need(len(restored251)==251,'complete historical251 then248 verified');return historical,restored251

def inverse253(source,pins,found,parent,ancestor):
 rows={n:(v.read(source/n,64*MIB),row['mode'])for n,row in found.items()}
 return inverse253_rows(rows,pins,found,parent,ancestor)

def admitted_provider(provider,approval,b,pins):
 actual=b['actual']
 v.need(approval['status']=='ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT'and approval['authority']==actual['authority']and approval['source_reviewed']is approval['holds_preserved']is True and approval['operation']==pins['operation']and approval['source']==actual['source']and approval['ref']==actual['ref']and approval['source_map_sha256']==pins['source_map_sha256']and approval['resources']==pins['policy'],'actual published256 Root approval preserved')
 run,job,artifact=(provider[n]for n in('run','job','artifact'))
 v.need(str(run['id'])==actual['run']and run['run_attempt']==1 and run['event']=='workflow_dispatch'and run['head_sha']==actual['source']and run['head_branch']==actual['ref'].removeprefix('refs/heads/')and run['repository']['full_name']=='Gabriel-Kahen/cachy-asahi'and run['status']=='completed'and run['conclusion']=='success','genuine actual published256 successful run')
 v.need(str(job['id'])==actual['job']and str(job['run_id'])==actual['run']and job['head_sha']==actual['source']and job['name']=='llvm23-native-v2'and job['status']=='completed'and job['conclusion']=='success','actual job/head remains new Source')
 v.need(str(artifact['id'])==actual['artifact']and artifact['expired']is False and artifact['name']=='llvm23-native-v2-'+actual['run']+'-1'and str(artifact['workflow_run']['id'])==actual['run']and artifact['workflow_run']['head_sha']==actual['source'],'actual Original/new Source identity')

def proof_join(readback,found,actual,pins):
 v.need(readback['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK'and readback['files']==found and all(readback['binding'][k]==actual[k]for k in('source','ref','run','approval'))and readback['binding']['source_map_sha256']==pins['source_map_sha256'],'whole actual256 proof; never substitute253/251 members, volume, map or head')

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in('binding','source','parent-source','ancestor-source','original','provider','approval','source-commit','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--binding-sha256',required=True);a=parser.parse_args()
 resource.setrlimit(resource.RLIMIT_AS,(256*MIB,256*MIB));resource.setrlimit(resource.RLIMIT_CORE,(0,0));v.END=time.monotonic()+1800
 v.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Root Reader')
 raw=v.read(v.path(a.binding));v.need(hashlib.sha256(raw).hexdigest()==a.binding_sha256,'external Root binding SHA');pins=v.load(HERE/'pins.json');b=binding(v.decode(raw),pins);actual=b['actual']
 v.need(v.hashed(HERE/'reader.py')['sha256']==b['reader_sha256']and v.hashed(HERE/'pins.json')['sha256']==b['pins_sha256']and v.hashed(HERE/'base.py')['sha256']==pins['base_sha256'],'whole new Reader/pins/dependency selection')
 source=v.path(a.source);output=v.path(a.output);parent=v.path(a.parent_source);ancestor=v.path(a.ancestor_source)
 v.need(output.parent.stat().st_uid==os.geteuid()and not output.parent.stat().st_mode&0o022 and not output.exists()and output.parent.is_dir(),'fresh owned private Reader output')
 v.need(all(output!=p and output not in p.parents and p not in output.parents for p in(source,parent,ancestor)),'disjoint Source/parent/ancestor/output')
 space=os.statvfs(output.parent);v.need(space.f_bavail*space.f_frsize>=20*GIB and space.f_favail>=10000,'Reader DATA reserve')
 v.need(v.hashed(a.original)==b['original_archive']and v.hashed(a.provider)['sha256']==b['provider_sha256']and v.hashed(a.approval)['sha256']==actual['approval']and v.hashed(a.source_commit)['sha256']==b['source_commit_sha256'],'whole actual Original/provider/approval/commit bindings')
 admitted_provider(v.load(a.provider),v.load(a.approval),b,pins)
 commit=v.read(a.source_commit,MIB);v.need([s for s in commit.split(b'\n\n',1)[0].splitlines()if s.startswith(b'parent ')]==[('parent '+pins['published_git_parent']).encode()],'exact independently published251 Git parent;253 remains unpublished DATA')
 found=v.source_tree(source,pins,commit,actual['source']);inverse253(source,pins,found,parent,ancestor)
 output.mkdir(mode=0o700);evidence=output/'full-original';v.full_zip(a.original,evidence,b['full_original_decode']);readback=v.load(evidence/'source-readback.json');proof_join(readback,found,actual,pins)
 result=v.replay(b,source,evidence,output)
 report=dict(schema=1,status='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_PUBLISHED256_DATA_ONLY',binding_sha256=a.binding_sha256,actual=actual,source_tree=pins['source_tree'],source_files=256,verified_historical_inverse=[253,251,248],**result,native_acceptance=False,Root_authentication=False,Root_acceptance=None,holds='native16K/M2/performance/release remain held')
 (output/'reader.json').write_bytes(v.canonical(report));print(json.dumps(report,sort_keys=True))
if __name__=='__main__':
 try:main()
 except(ValueError,KeyError,TypeError,OSError,MemoryError,RuntimeError,struct.error,zipfile.BadZipFile,tarfile.TarError)as error:print('REFUSED: '+str(error),file=sys.stderr);raise SystemExit(2)
