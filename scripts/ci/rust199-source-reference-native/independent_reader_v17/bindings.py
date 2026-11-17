# SPDX-License-Identifier: MIT
"""Independent predicates for retained Root/provider/transfer DATA."""
import copy,hashlib,re
S=None
OP='rust199-source-reference-native-v1';REPO='Gabriel-Kahen/cachy-asahi';REPO_ID=1414857795
WORKFLOW=381664314;WF='.github/workflows/native-arm-build.yml'
POLICY=dict(member='hosted/phase-transfer-provider-policy.json',bytes=1261,sha256='ac64464206b2e9e4165bfd6916395ea0873cbfbb25937011a8ae4ba301d94116')
CLAIMS=dict(hardware_acceptance=False,native_acceptance=False,release_acceptance=False,root_authenticated=False)
CARRIERS=('llvm_original','root_proof_carrier','stage0_carrier')
def without_local(v):
 if isinstance(v,dict):return{k:None if k=='local_path'else without_local(x)for k,x in v.items()}
 if isinstance(v,list):return[without_local(x)for x in v]
 return v
def dispatch(raw,shape,source,selected):
 v=S.decode(raw);S.need(raw==( __import__('json').dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()and 0<len(raw)<=16384,'DISPATCH_CANONICAL_WHOLE_BYTES')
 S.need(set(v)==set(shape)and v['schema']==5 and v['status']=='ROOT_ADMITTED_RUST199_PHASE_TRANSFER_ONCE'and v['once']is True and v['retry']is False and v['holds_preserved']is True and v['claims']==CLAIMS,'DISPATCH_SCHEMA_CLAIMS_HOLDS')
 expected=copy.deepcopy(shape);expected.update(schema=5,status=v['status'],once=True,retry=False,source=dict(sha=selected['source'],ref=selected['ref'],map_sha256=S.SOURCE['map_sha256'],approval=selected['source_review_sha256'],run=None,job=None),resources=S.decode(source['resource-policy.json'][0]),reviews=dict.fromkeys(shape['reviews'],True))
 expected['bootstrap'].update(provider_policy_reviewed=True,qualification_allowed=True,network_during_qualification=False)
 expected['delivery']['status']='ROOT_ADMITTED_FINITE_RUST_MATERIAL_DELIVERY'
 for role in CARRIERS:
  hosts=selected['initial_redirect_hosts'][role];S.need(type(hosts)is list and len(hosts)==1 and re.fullmatch(r'productionresultssa[1-9][0-9]{0,2}\.blob\.core\.windows\.net',hosts[0]),'INITIAL_CARRIER_EXPLICIT_HOST')
  expected['delivery'][role].update(accepted_by_root=True,redirect_hosts=hosts)
 S.need(without_local(v)==without_local(expected),'DISPATCH_EXACT_REVIEWED_DECLARATIONS')
 S.need(v['bootstrap']['transfer_provider_policy']==POLICY and v['bootstrap']['transfer_redirect_hosts']is None,'V8_CONDITIONAL_POLICY_NOT_GUESSED_HOST')
 return v

def initial_carriers(grant,objects,raws):
 out={}
 for role in CARRIERS:
  row=grant['delivery'][role];artifact,job=objects[role+'_artifact'],objects[role+'_job'];workflow=artifact['workflow_run']
  S.need(S.pin(raws[role+'_artifact'])['sha256']==row['metadata_sha256']and S.pin(raws[role+'_job'])['sha256']==row['job_metadata_sha256'],'INITIAL_METADATA_WHOLE_PIN')
  S.need(type(artifact['id'])is int and str(artifact['id'])==row['id']and artifact['expired']is False and artifact['size_in_bytes']==row['bytes']and str(workflow['id'])==row['run']and workflow['head_sha']==row['source'],'INITIAL_ARTIFACT_PROVIDER_JOIN')
  S.need(str(job['id'])==row['job']and str(job['run_id'])==row['run']and job['head_sha']==row['source']and job['status']=='completed'and job['conclusion']=='success','INITIAL_TERMINAL_JOB_JOIN')
  S.need(artifact.get('digest')in(None,'sha256:'+row['sha256']),'INITIAL_ARTIFACT_DIGEST')
  out[role]=dict(artifact=row['id'],run=row['run'],job=row['job'],source=row['source'],input_provider_only=True)
 return out

def provider(value,phase,grant,selected,jobs_raw):
 S.need(value['schema']==4 and value['status']=='ACTUAL_PROVIDER_BINDING_ONLY'and value['phase']==phase and type(value['run_attempt'])is int and value['run_attempt']==1 and value['manual_dispatch']is True and value['readback_required']is True and value['native_acceptance']is False,'PHASE_PROVIDER_SCOPE')
 expected=dict(grant['source'],run=selected['run'],job=selected[phase+'_job']);S.need(value['source']==expected and value['dispatch_sha256']==selected['dispatch_sha256']and value['job_metadata_sha256']==S.pin(jobs_raw)['sha256'],'PHASE_PROVIDER_WHOLE_BINDING')
 jobs=S.decode(jobs_raw);rows=jobs['jobs'];S.need(type(rows)is list and jobs['total_count']==len(rows)and 1<=len(rows)<=2 and len({r['id']for r in rows})==len(rows)and len({r['name']for r in rows})==len(rows),'START_JOB_NAMESPACE')
 for row in rows:S.need(row['name']in('rust199-bootstrap-v4','rust199-build-v4')and str(row['run_id'])==selected['run']and row['head_sha']==selected['source']and type(row.get('run_attempt',1))is int and row.get('run_attempt',1)==1,'START_JOB_SOURCE_RUN')
 own=[r for r in rows if r['name']=='rust199-'+phase+'-v4'];S.need(len(own)==1 and str(own[0]['id'])==selected[phase+'_job']and own[0]['status']=='in_progress'and own[0]['conclusion']is None,'ACTUAL_RUNNING_PHASE_BINDING')
 return expected

def terminal(run,jobs,selected):
 S.need(str(run['id'])==selected['run']and type(run['run_attempt'])is int and run['run_attempt']==1 and run['head_sha']==selected['source']and run['head_branch']==selected['ref'].removeprefix('refs/heads/')and run['event']=='workflow_dispatch'and run['workflow_id']==WORKFLOW and run['path']==WF and run['status']=='completed'and run['conclusion']=='success','TERMINAL_RUN_EXACT_TWO_JOB_WORKFLOW')
 for key in('repository','head_repository'):S.need(run[key]['id']==REPO_ID and run[key]['full_name']==REPO,'TERMINAL_RUN_REPOSITORIES')
 rows=jobs['jobs'];S.need(jobs['total_count']==len(rows)==2 and {r['name']for r in rows}=={'rust199-bootstrap-v4','rust199-build-v4'},'TERMINAL_EXACT_JOB_NAMESPACE')
 for phase in('bootstrap','build'):
  row=next(r for r in rows if r['name']=='rust199-'+phase+'-v4');S.need(str(row['id'])==selected[phase+'_job']and str(row['run_id'])==selected['run']and row['head_sha']==selected['source']and type(row.get('run_attempt',1))is int and row.get('run_attempt',1)==1 and row['status']=='completed'and row['conclusion']=='success','TERMINAL_PHASE_JOB')
 S.need(selected['bootstrap_job']!=selected['build_job'],'DISTINCT_PHASE_JOBS')

def transfer(grant,selected,policy,artifact,job,run,observation,acquisition,manifest,manifest_raw,bootstrap):
 t=selected['transfer'];binding=dict(source=selected['source'],ref=selected['ref'],map_sha256=S.SOURCE['map_sha256'],run=selected['run'],attempt=1,bootstrap_job=selected['bootstrap_job'],build_job=selected['build_job'],artifact_id=t['artifact_id'],artifact_sha256=t['artifact']['sha256'],manifest_sha256=t['manifest_sha256'],image_id=t['image_id'],image_pin=t['image'])
 S.need(S.pin(S.canonical(policy))=={k:POLICY[k]for k in('bytes','sha256')}and policy['schema']==8 and all(v is None for v in policy['actual'].values())and policy['Root_review']is policy['accepted']is None,'V8_WHOLE_UNISSUED_PROVIDER_POLICY')
 S.need(observation['schema']==8 and observation['kind']=='POSTSTART_PHASE_TRANSFER_STORAGE_OBSERVATION_V8'and observation['policy_pin']==POLICY and observation['binding']==binding and observation['credentials_forwarded']is False and observation['Root_acceptance']is None and observation['native_acceptance']is False,'V8_PROVIDER_HOST_OBSERVATION')
 host=observation['storage_host'];S.need(host==t['storage_host']and type(host)is str and re.fullmatch(r'productionresultssa[1-9][0-9]{0,2}\.blob\.core\.windows\.net',host),'V8_EXACT_OBSERVED_STORAGE_HOST')
 S.need(str(run['id'])==selected['run']and run['head_sha']==selected['source']and run['head_branch']==selected['ref'].removeprefix('refs/heads/')and run['workflow_id']==WORKFLOW and run['path']==WF and run['event']=='workflow_dispatch'and type(run['run_attempt'])is int and run['run_attempt']==1 and run['status']=='in_progress'and run['conclusion']is None,'V8_PREIMPORT_RUNNING_RUN')
 for key in('repository','head_repository'):S.need(run[key]['id']==REPO_ID and run[key]['full_name']==REPO,'V8_PREIMPORT_REPOSITORIES')
 wr=artifact['workflow_run'];S.need(str(artifact['id'])==t['artifact_id']and artifact['expired']is False and artifact['size_in_bytes']==t['artifact']['bytes']and artifact['digest']=='sha256:'+t['artifact']['sha256']and artifact['name']=='rust199-qualified-transfer-v4-'+selected['run']+'-1'and str(wr['id'])==selected['run']and wr['head_sha']==selected['source']and wr['head_branch']==selected['ref'].removeprefix('refs/heads/')and wr['repository_id']==wr['head_repository_id']==REPO_ID,'V8_TRANSFER_ARTIFACT_TUPLE')
 S.need(str(job['id'])==selected['bootstrap_job']and str(job['run_id'])==selected['run']and job['head_sha']==selected['source']and job['head_branch']==selected['ref'].removeprefix('refs/heads/')and type(job['run_attempt'])is int and job['run_attempt']==1 and job['name']=='rust199-bootstrap-v4'and job['status']=='completed'and job['conclusion']=='success','V8_NEEDS_BOOTSTRAP_JOB')
 rows=acquisition['requests'];endpoint='/repos/'+REPO+'/actions/artifacts/'+t['artifact_id']+'/zip';S.need(acquisition['schema']==4 and acquisition['status']=='FINITE_PHASE_TRANSFER_GET_DATA_ONLY'and acquisition['native_acceptance']is False and 4<=len(rows)<=7,'V8_REQUEST_COUNT')
 first=['/repos/'+REPO+'/actions/artifacts/'+t['artifact_id'],'/repos/'+REPO+'/actions/jobs/'+selected['bootstrap_job'],'/repos/'+REPO+'/actions/runs/'+selected['run']]
 for row,path in zip(rows[:3],first):S.need(set(row)=={'host','path','status','bytes'}and row['host']=='api.github.com'and row['path']==path and row['status']==200 and type(row['bytes'])is int and row['bytes']>0,'V8_FIXED_METADATA_REQUESTS')
 chain=rows[3:];S.need(chain[0]['host']=='api.github.com'and chain[0]['path']==endpoint and len(chain)>=2 and all(row['host']==host for row in chain[1:]),'V8_AUTHENTICATED_ENDPOINT_SINGLE_SELECTED_HOST')
 for index,row in enumerate(chain):S.need(set(row)=={'host','path','status','bytes'}and type(row['path'])is str and row['path'].startswith('/')and '?'not in row['path']and '#'not in row['path']and row['status']in((200,)if index==len(chain)-1 else(301,302,303,307,308))and type(row['bytes'])is int and row['bytes']>=0,'V8_REDIRECT_OR_QUERY_LEAK')
 S.need(chain[-1]['bytes']==t['artifact']['bytes'],'V8_COMPLETE_ARCHIVE_RESPONSE_BYTES')
 S.need(S.pin(manifest_raw)['sha256']==t['manifest_sha256']and manifest['schema']==4 and manifest['status']=='QUALIFIED_BOOTSTRAP_PHASE_TRANSFER_DATA_ONLY'and manifest['bootstrap_provider']==bootstrap and manifest['source']==bootstrap['source']and manifest['dispatch_sha256']==selected['dispatch_sha256']and manifest['dispatch_raw'].encode()==selected['dispatch_raw']and manifest['image_id']==t['image_id']and manifest['native_acceptance']is False and manifest['holds_preserved']is True,'V8_WHOLE_MANIFEST_PROVIDER_DISPATCH')
 S.need({k:manifest['files']['image.tar'][k]for k in('bytes','sha256')}==t['image']and 0<t['image']['bytes']<=12*S.GIB,'V8_NEEDS_MANIFEST_IMAGE_PIN')
 return binding
