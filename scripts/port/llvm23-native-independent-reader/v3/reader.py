#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Passive corrected253 DATA Reader; Root authentication/authority remain external."""
import argparse,hashlib,importlib.util,json,resource,sys,time,os,struct,tarfile,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('llvm_v3_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);v=B.v
MIB,GIB=v.MIB,v.GIB
PARENT=dict(source='6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0',files=251,bytes=40807998,map_sha256='809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2',tree='87f5aa3537474c2dd33a02c50e869ea5fb25e7b4')
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-llvm23-source-reference-v2.yml');OLD_ALIAS='.github/workflows/native-arm-llvm23-source-reference-v1.yml'

def binding(value,pins):
 v.need(value['scope']=='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V3','new corrected253 Reader scope')
 # Only the Reader-version scope literal changes. Every actual observation stays exact.
 projected=dict(value,scope='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V2');v.check_binding(projected,pins)
 v.need(value['actual']==projected['actual'],'no actual Source/ref/run/job/map projection');return value

def inverse251(source,pins,found,parent):
 """Reverse only the exact common alias and embedded workflow hash operands."""
 before=v.source_namespace(parent,B.old_pins);meta=v.load(source/'successor-v3.json')
 v.need(meta['parent']==PARENT and meta['actual']==dict.fromkeys(('source','ref','run','job','reader','authority','approval','artifact','image'))and meta['outer_operation']==pins['operation']and meta['inner_operation']==pins['inner_operation']and meta['saved_parent_map']=='previous-v2/source-map.json'and meta['candidate_original_actor_policy_unchanged']is True,'exact unadmitted correction lineage')
 v.need(set(meta['changed'])=={'hosted/common.py',*ALIASES},'only three existing leaves may change')
 names=set(found);v.need(names-set(before)=={'previous-v2/source-map.json','successor-v3.json'}and set(before)<=names,'exact253 additions, no dropped parent file')
 old_common=v.read(parent/'hosted/common.py');new_common=v.read(source/'hosted/common.py');old_hash=hashlib.sha256(old_common).hexdigest();new_hash=hashlib.sha256(new_common).hexdigest()
 expected={'hosted/common.py':dict(old=OLD_ALIAS,new=ALIASES[1],count=1),**{n:dict(old=old_hash,new=new_hash,count=1)for n in ALIASES}}
 describe=lambda row:{k:row[k]for k in ('bytes','sha256','mode')}
 restored={n:(v.read(source/n,64*MIB),found[n]['mode'])for n in names if n not in ('source-map.json','successor-v3.json','previous-v2/source-map.json')}
 for name,row in meta['changed'].items():
  v.need(row['before']==describe(before[name])and row['after']==describe(found[name])and row['inverse']==expected[name],'exact actual correction operands and counted inverse')
  raw,mode=restored[name];old,new=row['inverse']['old'].encode(),row['inverse']['new'].encode();v.need(raw.count(new)==1 and old not in raw,'one unambiguous corrected literal')
  restored[name]=(raw.replace(new,old),row['before']['mode'])
 restored['source-map.json']=(v.read(source/'previous-v2/source-map.json'),0o644)
 def rows(leaves):return{n:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=mode,blob=v.git_oid('blob',raw))for n,(raw,mode)in leaves.items()}
 restored_rows=rows(restored);v.need(restored_rows==before,'every restored251 body/mode/blob matches the independently retained parent')
 for name in set(before)-set(meta['changed'])-{'source-map.json'}:v.need(found[name]==before[name],'uncorrected parent leaf differs')
 frozen={'actor/container_mode.py','actor/entry.py','actor/runtime.py','actor/work_check.py'}
 v.need(meta['frozen_python']=={n:describe(before[n])for n in frozen}and meta['frozen_entry']==describe(before['hosted/entry.py']),'unchanged four Python actors and hosted entry')
 failure=meta['closed_failure'];v.need(failure['source']==PARENT['source']and failure['run']=='43720263251'and failure['job']=='132830512686'and failure['artifact']is None and failure['secret_input_bootstrap_native_started']is False and failure['permission_for_replay']is False,'closed pre-bootstrap failed Source remains unaccepted; no artifact reuse')
 fn,_=B.historical_successor();fn(restored,Path(pins['_ancestor_path']),B.old_pins,restored_rows)
 return restored_rows

def admitted_provider(provider,approval,b,pins):
 actual=b['actual']
 v.need(approval['status']=='ROOT_ADMITTED_SINGLE_NATIVE_LLVM23_ATTEMPT'and approval['authority']==actual['authority']and approval['source_reviewed']is approval['holds_preserved']is True and approval['operation']==pins['operation']and approval['source']==actual['source']and approval['ref']==actual['ref']and approval['source_map_sha256']==pins['source_map_sha256']and approval['resources']==pins['policy'],'actual corrected253 Root approval preserved')
 run,job,artifact=(provider[n]for n in ('run','job','artifact'))
 v.need(str(run['id'])==actual['run']and run['run_attempt']==1 and run['event']=='workflow_dispatch'and run['head_sha']==actual['source']and run['head_branch']==actual['ref'].removeprefix('refs/heads/')and run['repository']['full_name']=='Gabriel-Kahen/cachy-asahi'and run['status']=='completed'and run['conclusion']=='success','genuine actual corrected253 successful run')
 v.need(str(job['id'])==actual['job']and str(job['run_id'])==actual['run']and job['head_sha']==actual['source']and job['name']=='llvm23-native-v2'and job['status']=='completed'and job['conclusion']=='success','actual job/head remains new Source')
 v.need(str(artifact['id'])==actual['artifact']and artifact['expired']is False and artifact['name']=='llvm23-native-v2-'+actual['run']+'-1'and str(artifact['workflow_run']['id'])==actual['run']and artifact['workflow_run']['head_sha']==actual['source'],'actual Original/new Source identity')

def proof_join(readback,found,actual,pins):
 v.need(readback['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK'and readback['files']==found and all(readback['binding'][k]==actual[k]for k in ('source','ref','run','approval'))and readback['binding']['source_map_sha256']==pins['source_map_sha256'],'whole actual253 proof: never substitute historical6d head/common/map')

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('binding','source','parent-source','ancestor-source','original','provider','approval','source-commit','output'):parser.add_argument('--'+name,type=Path,required=True)
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
 commit=v.read(a.source_commit,MIB);v.need([s for s in commit.split(b'\n\n',1)[0].splitlines()if s.startswith(b'parent ')]==[('parent '+PARENT['source']).encode()],'exact sole251 Git parent')
 found=v.source_tree(source,pins,commit,actual['source']);inverse251(source,dict(pins,_ancestor_path=str(ancestor)),found,parent)
 output.mkdir(mode=0o700);evidence=output/'full-original';v.full_zip(a.original,evidence,b['full_original_decode']);readback=v.load(evidence/'source-readback.json')
 proof_join(readback,found,actual,pins)
 result=v.replay(b,source,evidence,output)
 report=dict(schema=1,status='PASS_INDEPENDENT_ROOT_BOUND_LLVM23_CORRECTED253_DATA_ONLY',binding_sha256=a.binding_sha256,actual=actual,source_tree=pins['source_tree'],source_files=253,verified_historical_inverse=[251,248],**result,native_acceptance=False,Root_authentication=False,Root_acceptance=None,holds='native16K/M2/performance/release remain held')
 (output/'reader.json').write_bytes(v.canonical(report));print(json.dumps(report,sort_keys=True))
if __name__=='__main__':
 try:main()
 except(ValueError,KeyError,TypeError,OSError,MemoryError,RuntimeError,struct.error,zipfile.BadZipFile,tarfile.TarError)as error:print('REFUSED: '+str(error),file=sys.stderr);raise SystemExit(2)
