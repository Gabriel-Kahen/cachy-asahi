#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original source/cleanup ownership, with a small project-only result export."""
import argparse,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def save(path,v):
 with path.open('xb')as f:f.write(C.encoded(v))
def original(source):return C.load('_original_parser_cleanup',source/'scripts/ci/tools-native/job.py')
def proof(source,output):
 m=C.verify_source(source);h=C.load('_original_parser_source_proof',source/'scripts/ci/welcome-native/ci/caller.py');v=h.prove(source,m,os.environ);v['consumer_token']=__import__('hashlib').sha256(('tools-consumer:'+v['run_id']+':'+v['run_attempt']+':'+v['source_sha']).encode()).hexdigest()[:32];save(output,v)
 with open(os.environ['GITHUB_OUTPUT'],'a')as f:f.write('job_token='+v['job_token']+'\nconsumer_token='+v['consumer_token']+'\n')
 return v

def retain(source,base,runtime,proof_path,cleanup_path,output):
 C.verify_source(source);C.need(not output.exists()and not output.is_symlink(),'fresh project-only export');output.mkdir(mode=0o700);result=dict(status='INCOMPLETE_BENCHMARK_EXPORT',files={},hardware='NOT_RUN',performance_gain='NOT_EVALUATED',release='NOT_ADMITTED')
 try:
  s=C.obj(C.read(proof_path));cleanup=C.obj(C.read(cleanup_path));b=C.obj(C.read(base/'report.json'));r=C.obj(C.read(runtime/'report.json'));m=C.metrics(C.obj(C.read(runtime/'measurement.json')))
  C.need(s['status']=='SOURCE_PROOF_PASS'and s['job_token']==b['ownership']['token']and r['status']=='COMPLETED_PARSER_EXPERIMENT_NOT_GAIN_ACCEPTANCE'and r['measurement']==C.pin(C.encoded(m))and cleanup['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'and cleanup['consumer']['status']=='PASS_CONSUMERS_RETIRED'and len(cleanup['consumer']['containers'])==1 and cleanup['producer']==b['owned_cleanup']and b['owned_cleanup']['status']=='PASS'and b['owned_cleanup']['image']==dict(id=b['image'],absence_verified=True)and b['owned_cleanup']['probe']['absence_verified']is True,'complete owned experiment and ordered retirement')
  owner=C.obj(C.read(runtime/'owner.json'));C.need(owner['token']==s['consumer_token']and owner['image']==b['image']and owner['label']==C.LABEL and len(owner['containers'])==1 and cleanup['consumer']['containers'][0]==dict(container=owner['containers'][0],status='PASS',absence_verified=True),'exact one-consumer then producer absence')
  values={'measurement.json':m,'source.json':{k:s[k]for k in('status','source_sha','workflow_sha','run_id','run_attempt','source_files')},'retirement.json':dict(status='PASS_ONE_CONSUMER_BEFORE_ORIGINAL574_PRODUCER',consumer_absence_verified=True,producer_absence_verified=True,original_private_cleanup=C.pin(C.read(cleanup_path)),dataset_image_sha256=b['image'].split(':')[1])}
  for n,v in values.items():raw=C.encoded(v);C.need(len(raw)<=65536,'bounded project-only artifact');save(output/n,v);result['files'][n]=C.pin(raw)
  result['status']='COMPLETED_NATIVE_PARSER_EXPERIMENT_NOT_GAIN_ACCEPTANCE'
 except BaseException as e:result['error_kind']=type(e).__name__
 save(output/'retention.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('preflight','proof','cleanup','retain'))
 for n in('source','base','runtime','proof','cleanup','output'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();source=a.source.absolute()
 if a.mode=='preflight':
  import worker
  m=C.verify_source(source,bound=False);profile=worker.production_profile({r:C.read(C.HERE/v['operand'])for r,v in C.policy(False)['sources'].items()});v=dict(status='SOURCE_ONLY_PREFLIGHT_PASS',source_files=len(m['files']),protocol=profile,actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',M2='NOT_RUN')
 elif a.mode=='proof':v=proof(source,a.proof)
 elif a.mode=='cleanup':C.verify_source(source);v=original(source).cleanup(source,C.obj(C.read(source/C.LANE/'source-manifest.json')),C.obj(C.read(a.proof)),a.base,a.runtime,a.output)
 else:v=retain(source,a.base,a.runtime,a.proof,a.cleanup,a.output)
 print(json.dumps(dict(status=v['status']),sort_keys=True));raise SystemExit(int(v['status']not in('SOURCE_ONLY_PREFLIGHT_PASS','SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','COMPLETED_NATIVE_PARSER_EXPERIMENT_NOT_GAIN_ACCEPTANCE')))
