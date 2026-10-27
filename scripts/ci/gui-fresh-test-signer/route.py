#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-dispatched native TEST signer; all private/public GPG work stays in containers."""
import argparse,contextlib,importlib.util,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import plan as P
HERE=Path(__file__).resolve().parent
PASS='PASS_FRESH_TEST_SIGNATURES_ONLY_NO_GUI_OR_BUILD_ACCEPTANCE'
VERIFY='PASS_INDEPENDENT_PUBLIC_ONLY_TEST_SIGNATURE_VERIFICATION'
def save(path,value):
 raw=P.enc(value);P.need(len(raw)<=4*1024**2,'bounded public provenance')
 with path.open('xb')as stream:stream.write(raw)
 path.chmod(0o600)
def write(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb')as stream:stream.write(raw)
 path.chmod(0o644)
def source_check(source,manifest_path,manifest_sha,inputs_root=None):
 source=P.ordinary(source);slice_root=source/P.SLICE;table=P.obj(P.read(slice_root/'source-manifest.json'));P.need(table['schema_version']==1 and table['actual_source']is table['actual_ref']is table['actual_run']is table['Root_acceptance']is None,'unbound source candidate')
 for name,w in table['files'].items():P.need(P.pin(P.read(source/P.relative(name)))==w,'exact signer/workflow source pin')
 own=P.rows(slice_root);P.need(set(own)=={name[len(P.SLICE)+1:]for name in table['files']if name.startswith(P.SLICE+'/')}|{'source-manifest.json'},'complete source-only route namespace')
 for name,w in P.BASE_PINS.items():P.need(table['files'][P.BASE_PATHS[name]]==w,'unchanged legitimate signer machinery')
 raw=P.read(manifest_path,1024**2);P.need(P.pin(raw)==P.PLAN_PIN and manifest_sha==P.PLAN_PIN['sha256'],'reviewed fixed GUI input plan');manifest,docs=P.manifest(raw)
 if inputs_root is not None:
  inputs_root=P.ordinary(inputs_root);P.need({p.name for p in inputs_root.iterdir()}==set(manifest['carriers']),'exact three explicit public carriers')
  for alias,row in manifest['carriers'].items():P.need(P.rows(inputs_root/alias)==row['files'],'complete exact public carrier file map')
  core=load_core(source);P.PACKAGE_CHECK=core.package
  for row in docs:P.validate_body(inputs_root/row['carrier']/row['path'],row)
 return dict(status='PASS_GUI_FRESH_SIGNER_SOURCE_ONLY',source_files=table['files'],input_plan=P.PLAN_PIN,carrier_closures='PASS'if inputs_root is not None else'NOT_RUN',native='NOT_RUN',crypto='NOT_RUN',Root_acceptance=None)
def load_core(source=None,root=None):
 if root is None:
  path=source/'scripts/ci/sign_fixture.py';directory=source/'scripts/ci'
 else:path=root/'runner/sign_fixture.py';directory=root/'runner';sys.path.insert(0,str(root/'scripts/checks'))
 P.need(P.pin(P.read(path))==P.BASE_PINS['runner/sign_fixture.py'],'original signer module bytes before import');sys.path.insert(0,str(directory))
 spec=importlib.util.spec_from_file_location('_exact_gui_signer_core',path);core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core);P.PACKAGE_CHECK=core.package;return core
@contextlib.contextmanager
def docker_scope(environment,home):
 config=P.ordinary(environment/'docker-config');P.need(config.is_dir()and stat.S_IMODE(config.stat().st_mode)==0o700 and list(config.iterdir())==[],'fresh empty credential-free Docker configuration');home.mkdir(mode=0o700)
 previous=dict(os.environ)
 try:
  os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',HOME=str(home),DOCKER_CONFIG=str(config),DOCKER_CONTEXT='default',DOCKER_HOST='unix:///var/run/docker.sock',PYTHONDONTWRITEBYTECODE='1');yield
 finally:os.environ.clear();os.environ.update(previous)
def snapshot(args,source,proof,out,image,image_raw):
 inputs=out/'inputs';inputs.mkdir(mode=0o700);files={}
 for name in sorted(P.CODE_PATHS):
  original=source/P.BASE_PATHS[name]if name in P.BASE_PATHS else source/P.SLICE/Path(name).name;raw=P.read(original);files[name]=P.pin(raw);write(inputs/name,raw)
 write(inputs/'manifest.json',P.read(args.plan));write(inputs/'image-contract.json',image_raw);manifest,docs=P.manifest(P.read(args.plan))
 for row in docs:
  path=args.inputs_root/row['carrier']/row['path'];P.validate_body(path,row);write(P.body_path(inputs,row),P.read(path,8*1024**2));P.validate_body(P.body_path(inputs,row),row)
 nonce=os.urandom(16).hex();baseline=dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce=nonce,image_id=image['image_id'],manifest_sha256=P.PLAN_PIN['sha256'],entry_sha256=P.BASE_PINS['runner/sign_fixture.py']['sha256'],helpers_sha256={n:P.BASE_PINS[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')})
 contract=dict(schema_version=1,purpose=P.PURPOSE,nonce=nonce,source_sha=image['source_sha'],image_id=image['image_id'],image_contract_sha256=args.image_contract_sha256,manifest_pin=P.PLAN_PIN,files=files,baseline=baseline);write(inputs/'contract.json',P.enc(contract));return inputs,contract,manifest,docs
def retire(core,name,token,image):
 query=['docker','container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}'];before=core.command_result(query,10);P.need(before.returncode==0,'successful owned actor absence query')
 if not before.stdout.strip():return dict(status='PASS',container_absent=True,already_absent=True)
 inspected=core.command_result(['docker','container','inspect',name],10);P.need(inspected.returncode==0,'successful owned actor identity query');rows=P.obj(b'{"rows":'+inspected.stdout+b'}')['rows'];P.need(type(rows)is list and len(rows)==1,'one owned actor identity');row=rows[0];cid=row['Id'];P.need(re.fullmatch('[a-f0-9]{64}',cid)and row['Name']=='/'+name and row['Image']==image and row['Config']['Labels'].get('org.cachy-asahi.gui-fresh-signer')==token,'exact owned ID/image/nonce before cleanup')
 removed=core.command_result(['docker','rm','-f',cid],10);after=core.command_result(['docker','container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}'],10);P.need(removed.returncode==after.returncode==0 and not after.stdout.strip(),'owned exact container ID absent');return dict(status='PASS',container_absent=True,id=cid)
def actor(core,inputs,output,contract,mode,record):
 output.mkdir(mode=0o700);token=os.urandom(16).hex();name='cachy-asahi-test-signer-'+token;prior=core.command_result(['docker','container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}'],10);P.need(prior.returncode==0 and not prior.stdout.strip(),'fresh owned actor name before creation');command=['docker','run','--rm','--name',name,'--label','org.cachy-asahi.gui-fresh-signer='+token,'--pull=never','--platform=linux/arm64','--user',str(os.getuid())+':'+str(os.getgid()),'--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--cgroupns=private','--pids-limit=128','--memory=512m','--cpus=2','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m,mode=0700,uid='+str(os.getuid())+',gid='+str(os.getgid()),'--env','CACHY_ASAHI_TEST_SIGNER='+contract['nonce'],'--env','CACHY_ASAHI_SIGNER_CONTRACT_SHA256='+P.pin(P.enc(contract))['sha256'],'--mount','type=bind,src='+str(inputs)+',dst=/inputs,readonly','--mount','type=bind,src='+str(output)+',dst=/out','--entrypoint=/usr/bin/python3',contract['image_id'],'-I','-B','/inputs/route/route.py',mode]
 receipt=dict(name=name,image=contract['image_id'],mode=mode,command=command,cleanup=None)
 record['actors'].append(receipt)
 try:core.run(command,timeout=300 if mode=='inside-sign'else 180)
 finally:
  previous=[signal.getsignal(n)for n in(signal.SIGTERM,signal.SIGINT)]
  try:
   for n in(signal.SIGTERM,signal.SIGINT):signal.signal(n,signal.SIG_IGN)
   receipt['cleanup']=retire(core,name,token,contract['image_id'])
  finally:
   for n,handler in zip((signal.SIGTERM,signal.SIGINT),previous):signal.signal(n,handler)
def sign(args):
 source=P.ordinary(args.source);proof=source_check(source,args.plan,args.plan_sha256,args.inputs_root);image_raw=P.read(args.image_contract,65536);P.need(P.pin(image_raw)['sha256']==args.image_contract_sha256,'exact reviewed image contract');image=P.obj(image_raw);P.need(type(image.get('source_sha'))is str and re.fullmatch('[a-f0-9]{40}',image['source_sha'])and image['source_sha']==os.environ.get('SOURCE_SHA'),'current exact workflow source before any image query or actor')
 production=None
 if image.get('oci_ref')is None:
  spec=importlib.util.spec_from_file_location('_gui_source_built_image',HERE/'provision.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);validated=B.validate_environment(args.environment,image['source_sha']);P.need(P.enc(validated)==P.enc(image),'actual source-built image contract and retained production receipt');production=P.obj(P.read(args.environment/'production.json'))
 else:
  spec=importlib.util.spec_from_file_location('_gui_image_contract',HERE/'environment.py');E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E);E.validate(image)
 receipt=P.obj(P.read(args.environment/'environment.json'));P.need(receipt['status']=='PASS'and receipt['source_sha']==image['source_sha']==os.environ.get('SOURCE_SHA')and receipt['image_id']==image['image_id']and receipt['contract_sha256']==args.image_contract_sha256 and receipt['container_cleanup']['status']=='PASS'and receipt['container_cleanup']['container_absent']is True,'actual qualified native image/source/tool receipt required');P.need((receipt['uid'],receipt['gid'])==(os.getuid(),os.getgid())==(image['alarm_uid'],image['alarm_gid']),'same qualified nonroot alarm mapping')
 out=P.ordinary(args.output);P.need(out.parent.is_dir()and not out.exists()and all(not out.is_relative_to(p)and not p.is_relative_to(out)for p in(source,P.ordinary(args.environment),P.ordinary(args.inputs_root)))and not any(','in str(p)or'\n'in str(p)for p in(out,args.environment,args.inputs_root)),'fresh disjoint safe signer workspace');out.mkdir(mode=0o700);record=dict(schema_version=1,purpose=P.PURPOSE,status='FAIL',source_sha=image['source_sha'],image_id=image['image_id'],image_contract_sha256=args.image_contract_sha256,environment=str(args.environment),input_plan=P.PLAN_PIN,actors=[],crypto='NOT_RUN',GUI='NOT_RUN',native_build='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)
 try:
  core=load_core(source)
  if production is not None:record['image_production']=production
  with core.cancellation_scope(),docker_scope(args.environment,out/'private-home'):
   core.host_probe(out);inputs,contract,manifest,docs=snapshot(args,source,proof,out,image,image_raw);before=P.rows(inputs);record['contract']=contract
   actor(core,inputs,out/'public',contract,'inside-sign',record);report=P.obj(P.read(out/'public/result.json',4*1024**2));P.need(report['status']==PASS and report['private_home_retired']is True and P.enc(report['contract'])==P.enc(contract),'genuine new signer result and private home retirement')
   public_before=P.rows(out/'public');P.need(P.rows(inputs)==before and set(public_before)==P.public_names(docs),'whole inputs and closed public signing outputs')
   verify_inputs=out/'verify-inputs';verify_inputs.mkdir(mode=0o700)
   for name,w in before.items():write(verify_inputs/name,P.read(inputs/name))
   for name in sorted(P.public_names(docs)):write(verify_inputs/'public'/name,P.read(out/'public'/name,4*1024**2))
   verify_before=P.rows(verify_inputs);actor(core,verify_inputs,out/'verify-output',contract,'inside-verify',record);verified=P.obj(P.read(out/'verify-output/verify-result.json',4*1024**2));P.need(verified['status']==VERIFY and verified['public_only_home_retired']is True and verified['fingerprint']==report['fingerprint']and verified['expiry']==report['expiry']and P.enc(verified['contract'])==P.enc(contract)and verified['Root_acceptance']is None,'fresh independent public-only image verification')
   P.need(P.rows(verify_inputs)==verify_before and P.rows(inputs)==before and P.rows(out/'public')==public_before,'all immutable snapshots and original public outputs unchanged through independent verification');P.need({k:v['signature_pin']for k,v in verified['signatures'].items()}=={k:v['signature_pin']for k,v in report['signatures'].items()},'independent six signature byte joins')
   P.need(verified['public_catalog']['body_pin']==report['public_catalog']['body_pin']and verified['public_catalog']['signature_pin']==report['public_catalog']['signature_pin'],'independent new catalog signature/body join');source_check(source,args.plan,args.plan_sha256,args.inputs_root);record.update(status=PASS,crypto='PASS_FRESH_TEST_ONLY',fingerprint=report['fingerprint'],created=report['created'],expiry=report['expiry'],public_outputs=public_before,verification_pin=P.pin(P.read(out/'verify-output/verify-result.json')))
 except BaseException as error:record['error_type']=type(error).__name__;raise
 finally:save(out/'provenance.json',record)
 return record
def export(run,output):
 run=P.ordinary(run);output=P.ordinary(output);P.need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(run)and not run.is_relative_to(output),'fresh disjoint public export');record=P.obj(P.read(run/'provenance.json'));P.need(record['status']==PASS and record['crypto']=='PASS_FRESH_TEST_ONLY'and record['Root_acceptance']is None and len(record['actors'])==2 and all(r['cleanup']['status']=='PASS'and r['cleanup']['container_absent']is True for r in record['actors']),'complete signing/public verification and actor retirement')
 P.need(type(record['fingerprint'])is str and re.fullmatch('[0-9A-F]{40}',record['fingerprint'])and type(record['created'])is int and type(record['expiry'])is int and record['created']>0 and record['expiry']-record['created']==86400,'typed new one-day TEST signer identity')
 environment=Path(record['environment']);cleanup=P.obj(P.read(environment/'cleanup.json'));P.need(cleanup['status']=='PASS'and cleanup['image_id']==record['image_id']and cleanup['contract_sha256']==record['image_contract_sha256'],'qualified image cleanup/preservation required before export');manifest,docs=P.manifest(P.read(run/'inputs/manifest.json'));files=P.rows(run/'public');P.need(files==record['public_outputs']and set(files)==P.public_names(docs),'exact successful allowlist, no key homes or archive bodies');P.need(P.pin(P.read(run/'verify-output/verify-result.json'))==record['verification_pin'],'whole independent verification receipt')
 payloads={}
 for name in sorted(files):
  raw=P.read(run/'public'/name,4*1024**2);P.need(b'PRIVATE KEY'not in raw and b'export-secret'not in raw,'no private material in public output');payloads[name]=raw
 public_provenance=dict(schema_version=1,purpose=P.PURPOSE,status=PASS,source_sha=record['source_sha'],image_id=record['image_id'],image_contract_sha256=record['image_contract_sha256'],image_production=record.get('image_production'),input_plan=manifest,signer={k:record[k]for k in('fingerprint','created','expiry')},independent_verification=P.obj(P.read(run/'verify-output/verify-result.json')),signer_retirement=[r['cleanup']for r in record['actors']],image_retirement=cleanup,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)
 payloads['provenance.json']=P.enc(public_provenance);index=dict(schema_version=1,kind='NEW_GUI_FRESH_TEST_SIGNING_OUTPUTS_REQUIRES_NEW_VERSIONED_SOURCE_REFERENCES',files={n:P.pin(raw)for n,raw in payloads.items()},input_plan=P.PLAN_PIN,signer=record['fingerprint'],created=record['created'],expires=record['expiry'],actual_GUI='NOT_RUN',Root_acceptance=None);payloads['index.json']=P.enc(index);P.need(sum(map(len,payloads.values()))<=4*1024**2,'bounded public certificate/signature/provenance bundle')
 with tempfile.TemporaryDirectory(prefix='gui-fresh-public-',dir=output.parent)as td:
  stage=Path(td)/'public';stage.mkdir(mode=0o700)
  for name,raw in payloads.items():write(stage/name,raw)
  P.need(P.rows(stage)=={n:P.pin(raw)for n,raw in payloads.items()}and not output.exists(),'entire public namespace before atomic publication');os.rename(stage,output)
 return index
def main():
 parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
 proof=sub.add_parser('source-check');signer=sub.add_parser('sign')
 for p in(proof,signer):p.add_argument('--source',type=Path,required=True);p.add_argument('--plan',type=Path,required=True);p.add_argument('--plan-sha256',required=True);p.add_argument('--inputs-root',type=Path,required=p is signer)
 for name in('image-contract','environment','output'):signer.add_argument('--'+name,type=Path,required=True)
 signer.add_argument('--image-contract-sha256',required=True);public=sub.add_parser('export');public.add_argument('--run',type=Path,required=True);public.add_argument('--output',type=Path,required=True);sub.add_parser('inside-sign');sub.add_parser('inside-verify');args=parser.parse_args()
 if args.command=='source-check':result=source_check(args.source,args.plan,args.plan_sha256,args.inputs_root)
 elif args.command=='sign':result=sign(args)
 elif args.command=='export':result=export(args.run,args.output)
 else:
  root=Path('/inputs');P.need(Path(__file__)==root/'route/route.py','fixed container entry');contract=P.obj(P.read(root/'contract.json'));P.need(P.pin(P.enc(contract))['sha256']==os.environ.get('CACHY_ASAHI_SIGNER_CONTRACT_SHA256'),'explicit actual contract hash');core=load_core(root=root);import inside;return inside.run(root,Path('/out'),contract,core,P)if args.command=='inside-sign'else inside.verify(root,Path('/out'),contract,core,P)
 print(json.dumps(dict(status=result['status']if'status'in result else'EXPORTED_NEW_TEST_SIGNATURE_INPUTS',Root_acceptance=None),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
