# SPDX-License-Identifier: MIT
"""Fresh genuine607 provisioning followed by normal Core PID1 two-boot622."""
import argparse,contextlib,hashlib,json,os,re,shutil,stat,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,adapter,desktop622 as X,ownership622,export622
ROOT=Path(__file__).resolve().parent

@contextlib.contextmanager
def namespace(root,bindings=None):
 """Exact source-owned import roles, restored across the two real libraries."""
 root=Path(root);names={p.stem for p in root.glob('*.py')};bindings={}if bindings is None else bindings;C.need(set(bindings)<=names,'only declared source module roles');missing=object();prior={n:sys.modules.get(n,missing)for n in names};paths=sys.path[:]
 try:
  for n in names:sys.modules.pop(n,None)
  sys.modules.update(bindings);sys.path.insert(0,str(root));yield
 finally:
  sys.path[:]=paths
  for n,old in prior.items():
   if old is missing:sys.modules.pop(n,None)
   else:sys.modules[n]=old

def public_rows(root):
 rows={};total=0
 for p in Path(root).rglob('*'):
  C.need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary complete original public namespace')
  if p.is_file():
   raw=C.read(p,128*1024**2);total+=len(raw);C.need(total<=768*1024**2 and len(rows)<4096,'original whole public transport limits');rows[p.relative_to(root).as_posix()]=C.pin(raw)
 return rows

def declared_context_inventory(public,owner,claim,selected,kernel,export):
 """Budget only the already-retained Source declarations, never observed sizes."""
 C.selection(selected);C.need(type(public)is dict and public and type(claim)is dict and len(owner)<=16384 and owner==C.encoded(claim)and C.decode(owner)==claim and claim['schema']==1 and claim['status']=='OWNED_PRE_CORE_INPUT_CONTEXT_NO_CORE_ACTOR'and claim['Core_actor']=='NOT_STARTED'and claim['actual']==selected['actual']and claim['nonce']==selected['nonce'],'same original tracked context identity and Source/run/nonce');parent=Path(claim['path']);C.need(parent.parent==Path('/tmp')and parent.name.endswith('-context')and parent==parent.absolute()and all(type(v)is int for v in claim['root'])and len(claim['root'])==5 and claim['root'][2]==0o700 and len(claim['parent'])==2,'literal original private context role')
 def checked(name,row,cap=128*1024**2):
  C.need(type(name)is str and name==Path(name).as_posix()and not Path(name).is_absolute()and all(v not in('','.','..')for v in name.split('/'))and type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=cap and type(row['sha256'])is str and re.fullmatch('[a-f0-9]{64}',row['sha256']),'finite declared context role pin');return dict(row)
 public={n:checked(n,r)for n,r in public.items()};record=C.decode(export);C.need(len(export)<=4*1024**2 and type(record)is dict and type(record.get('files'))is dict and set(public)==set(record['files'])|{'export.json'}and public['export.json']==C.pin(export)and all(public[n]==r for n,r in record['files'].items())and type(record['bytes'])is int and record['bytes']==sum(r['bytes']for r in record['files'].values()),'exact original private public-retainer export closure');C.need(sum(r['bytes']for r in public.values())<=768*1024**2 and len(public)<=4096,'unchanged complete public capacity');fixed={'source-proof.json':'source-proof.json','ordered-cleanup.json':'ordered-cleanup.json','original800-ordered-cleanup.json':'original800-ordered-cleanup.json',**{'retained/'+n:n for n in('fresh607-manifest.json','fresh607-producer.json','fresh607-base-build.json','fresh607-owner.json','fresh607-tooling-seed.json')}};C.need(set(fixed)<=set(public)and'export.json'in public,'all original fixed post-Core retained declarations');parts={'public':{'public/'+n:r for n,r in public.items()},'inputs':{n:r for n,r in public.items()if n.startswith('current607-inputs/')},'kernel':{'kernel-inputs/'+n:r for n,r in public.items()if n.startswith('kernel/')},'fixed':{n:public[k]for k,n in fixed.items()}};parts['fixed']['context-owner.json']=C.pin(owner)
 inputs=parts['inputs'];archives={n:r for n,r in inputs.items()if n.startswith('current607-inputs/packages/')};C.need(set(inputs)==set(archives)|{'current607-inputs/capture.json','current607-inputs/current607-inputs.json.gz'}and len(archives)==270 and all(n=='current607-inputs/packages/'+Path(n).name for n in archives)and sum(r['bytes']for r in archives.values())<=647070676 and inputs['current607-inputs/capture.json']['bytes']<=1024**2 and inputs['current607-inputs/current607-inputs.json.gz']['bytes']<=2*1024**2,'unchanged exact270 exported input roles and declared retention capacities');expected={}
 for n,r in kernel.items():
  C.need(n.startswith('payload/')and'/'not in n[len('payload/'):],'flat pinned kernel payload role');expected['kernel-inputs/kernel/'+n[len('payload/'):]]=checked(n,r,256*1024**2)
 C.need(parts['kernel']==expected,'entire original pinned kernel projection');files={}
 for name,rows in parts.items():
  for n,r in rows.items():C.need(n not in files,'disjoint private inventory roles');files[n]=r
 directories={p.as_posix()for n in files for p in Path(n).parents if p.as_posix()!='.'};C.need(len(files)+len(directories)<=2048,'unchanged private context node capacity');summary=dict(schema=1,status='EXACT_SOURCE_DECLARED_POST_CORE_CONTEXT_BYTES_DATA_ONLY',identity=selected['actual'],nonce=selected['nonce'],context_path_sha256=hashlib.sha256(str(parent).encode('utf-8','surrogateescape')).hexdigest(),root_identity_sha256=hashlib.sha256(C.encoded(dict(root=claim['root'],parent=claim['parent']))).hexdigest(),context_owner=C.pin(owner),public_export=C.pin(export),public_files_sha256=hashlib.sha256(C.encoded(public)).hexdigest(),kernel_files_sha256=hashlib.sha256(C.encoded(kernel)).hexdigest(),files_sha256=hashlib.sha256(C.encoded(files)).hexdigest(),files=len(files),directories=len(directories),components={n:dict(files=len(rows),bytes=sum(r['bytes']for r in rows.values()))for n,rows in parts.items()},bytes=sum(r['bytes']for r in files.values()),acceptance=False);return dict(public=public,owner=owner,claim=claim,selected=selected,kernel=kernel,export=export,files=files,directories=sorted(directories),summary=summary)

def context_inventory_stat(observed,path,value):
 observed.setdefault(path,[]).append(value);return value

def validate_context_inventory(value,parent,entries,selected,observed):
 """Use only the original entries list, after every original guard conjunct."""
 C.need(type(value)is dict and set(value)=={'public','owner','claim','selected','kernel','export','files','directories','summary'}and value['selected']==selected,'required exact cached context inventory');C.need(value==declared_context_inventory(value['public'],value['owner'],value['claim'],selected,value['kernel'],value['export']),'whole unchanged declared inventory before retirement');claim=value['claim'];parent=Path(parent);C.need(str(parent)==claim['path']and parent.parent==Path('/tmp'),'same exact owned private context scope');s=parent.lstat();grand=parent.parent.stat();C.need([s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]==claim['root']and[grand.st_dev,grand.st_ino]==claim['parent']and stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid(),'same original private context inode and parent marker');files={};directories=set()
 for p in entries:
  name=p.relative_to(parent).as_posix();C.need(name and name==Path(name).as_posix()and all(v not in('','.','..')for v in name.split('/')),'literal same-scan context role');snapshots=observed.get(p,[]);C.need(bool(snapshots),'only actually evaluated original stat operands');st=snapshots[0];identity=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));C.need(all(identity(v)==identity(st)for v in snapshots)and st.st_dev==s.st_dev and st.st_uid==os.getuid(),'stable same-device original stat operands')
  if stat.S_ISDIR(st.st_mode):C.need(name not in directories,'unique declared context directory');directories.add(name)
  else:C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and name not in files and name in value['files']and st.st_size==value['files'][name]['bytes'],'exact declared ordinary private context file size');files[name]=value['files'][name]
 C.need(files==value['files']and directories==set(value['directories']),'complete exact same-scan private namespace');return True

def derive(text):
 edits=(
 ("            vm.host(SimpleNamespace(","            Y.core_host(SimpleNamespace("),
 ("receipt['status']=='PASS' and all(receipt[k]=='PASS' for k in ('container_cleanup','image_cleanup','private_cleanup'))","receipt['status']=='PASS_CORE622_CURRENT607_NORMAL_CORE_TWO_BOOT' and receipt['all_original_cleanup']=='PASS'"),
 ("safe=vm_retired(vm_output)","safe=Y.core_retired(vm_output)"),
 ("cleanup=producer.cleanup(producer_output)","cleanup=Y.cleanup(producer,producer_output,vm_output)"),
 ("    except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])","    except BaseException as error:\n        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])\n        try:Y.outer_exception(error)\n        except BaseException:pass # Original caught error/result remains primary.\n        try:Y.desktop_failure(result)\n        except BaseException:pass # Optional DATA cannot replace original failure/cleanup."),
 ("'GENERIC4K_LATEST607_FRESH_INSTALLER_SOFTWARE_ONLY'",repr(X.SCOPE)),
 )
 before=text
 for old,new in edits:C.need(text.count(old)==1,'one complete original fresh607 bridge seam');text=text.replace(old,new)
 inverse=text
 for old,new in reversed(edits):C.need(inverse.count(new)==1,'one whole fresh607 inverse seam');inverse=inverse.replace(new,old)
 C.need(inverse==before,'entire fresh607 producer/materializer/cleanup body inverse');return text

def inputs(root,fresh):
 import entry,source622
 fact=source622.verify(ROOT);p=C.decode(C.read(ROOT/'profile.json',4*1024**2));v=C.decode(C.read(ROOT/'composition.json',4*1024**2));body=adapter.core(root/'core-source');end=time.monotonic()+180;git={}
 roles={'core800':root/'core-source','ksm637':root/'vm-source','core7_carrier':root/'core7-inputs','kernel_carrier':root/'kernel-inputs'}
 for name,path in roles.items():git[name]=body.C.S.prove(path,path/'.git',p['source_profiles'][name],end)
 for role,name,path in(('fresh607','latest607-fresh-tooling-inputs-trial-root-20261025',fresh),('accepted_core','core7-two-boot-accepted-decision-root-20261026',root/'core622-core-record'),('accepted_fresh','latest607-fresh-tooling-accepted-decision-root-20261025',root/'core622-fresh-record')):
  git[role]=body.C.S.prove(path,path/'.git',v['public'][name],end)
 git['core64']=body.C.S.prove(root/'core64-inputs',root/'core64-inputs/.git',body.C.profile()['retained64'],end);body.C.packet(root/'core7-inputs')
 s=os.environ.get('GITHUB_SHA');run=os.environ.get('GITHUB_RUN_ID');ref=os.environ.get('GITHUB_REF_NAME');C.need(s==os.environ.get('SOURCE_SHA')==os.environ.get('WORKFLOW_SHA')and re.fullmatch('[0-9a-f]{40}',s or'')and re.fullmatch('codex/[a-z0-9-]+',ref or'')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and os.environ.get('GITHUB_RUN_ATTEMPT')=='1'and os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and os.environ.get('RUNNER_ARCH')=='ARM64','genuine first native622 workflow binding')
 git['current']=body.C.S.prove(ROOT,ROOT/'.git',dict(source=s,ref=ref,files=adapter.source_rows(ROOT)),end)
 core_decision=C.decode(C.read(root/'core622-core-record/decision.json'));fresh_decision=C.decode(C.read(root/'core622-fresh-record/decision.json'))
 C.need(core_decision['status']=='ROOT_ACCEPTED_CORE7_AUTOMATIC_HOOKS_AND_CANDIDATE_PID1_TWO_BOOT_GENERIC16K'and core_decision['source']=='11b3cfb59663e42b34247facb9f30f042e891444'and core_decision['run']==40238067402 and core_decision['component']['boots']==2 and core_decision['component']['installed']==589 and core_decision['component']['different_boot_ids']is True and core_decision['component']['root_persistent']is True,'entire prior Core finite scope retained, no607 transfer')
 C.need(fresh_decision['status']=='ROOT_ACCEPTED_SIGNED_LATEST607_FRESH_INSTALLER'and fresh_decision['source_sha']=='b9976eea34eaed4b6e56af3be21d4d652fa971d6'and fresh_decision['run_id']==40223603945 and fresh_decision['package_count']==607 and fresh_decision['expected607_sha256']==v['fresh607']['sha256']and len(fresh_decision['ordinary_and_root_flags'])==15 and all(flag is True for flag in fresh_decision['ordinary_and_root_flags'].values())and fresh_decision['cleanup']=='PASS_SOURCE_BOUND_RETAINED_RECEIPTS'and fresh_decision['root_observation']['complete']is True and fresh_decision['hooks_scriptlets']=='NOT_ACCEPTED'and fresh_decision['target_boot']=='NOT_RUN'and type(fresh_decision['limits'])is list and len(fresh_decision['limits'])==4,'whole fresh607 decision with original flags/readback/cleanup/limits, no new authority')
 actual=dict(source=s,ref=ref,run=int(run),attempt=1);nonce=hashlib.sha256(('current607-core622:'+s+':'+run).encode()).hexdigest()[:32];selected=dict(schema=1,scope=X.SCOPE,actual=actual,nonce=nonce,kernel=p['kernel'],source_profiles={n:p['source_profiles'][n]for n in('core800','ksm637','core7_carrier')},budgets=C.BUDGET);C.selection(selected);return dict(status='PASS_GENUINE_CORE622_SOURCE_INPUTS_BEFORE_ACTORS',source_sha=s,run_id=run,attempt=1,selection=selected,consumer_token=nonce,git=git,source_preflight=fact)

class Context:
 def __init__(self,workspace,fresh,proof,end,*,job_clock=None,native_phase=None):self.workspace,self.fresh,self.proof,self.end=workspace,fresh,proof,end;self.producer=None;self.current=None;self.cleanup_end=None;self.tooling_seed=None;self.desktop_build_failure=None;self.dependency_failure=None;self.verification=[];self.verification_error=None;self.context_lease=None;self.context_failure=None;self.job_clock=job_clock;self.native_phase=native_phase;self.context_inventory=None
 def capture_desktop_build(self,value):
  ownership622.validate_desktop_note(value)
  if self.desktop_build_failure is None:self.desktop_build_failure=value
 def capture_dependency(self,value):
  ownership622.validate_dependency_note(value)
  if self.dependency_failure is None:self.dependency_failure=value

 def desktop_failure(self,result):
  if result.get('status')=='FAIL'and self.context_lease is not None and self.current is None:
   if self.context_failure is None:self.context_failure=__import__('provision622').context_failure(self.context_lease,result.get('error_type','UNKNOWN_PRIMARY_ERROR'))
   result['current607_input_context_failure_data']=self.context_failure
  if result.get('status')=='FAIL'and self.verification_error is not None:result['current607_verification_failure_data']=dict(status='INCOMPLETE_ORIGINAL607_VERIFICATION_DATA_ONLY',selection=self.proof['selection'],completed=self.verification,error=self.verification_error,acceptance=False)
  if result.get('status')=='FAIL'and self.desktop_build_failure is not None:
   value=ownership622.validate_desktop_note(self.desktop_build_failure);result['desktop574_first_build_failure_data']=json.loads(json.dumps(value,sort_keys=True,allow_nan=False))
  if result.get('status')=='FAIL'and self.dependency_failure is not None:
   value=ownership622.validate_dependency_note(self.dependency_failure);result['dependency_failure_data']=json.loads(json.dumps(value,sort_keys=True,allow_nan=False))
 def host(self,a):
  with namespace(ROOT,dict(case=C,adapter=adapter,desktop622=X,ownership622=ownership622)):return self._host(a)
 def _host(self,a):
  import controller,evidence,entry
  export622.telemetry_phase('CORE_HOST_PREPARE')
  w=self.workspace;producer=self.producer;C.need(producer is not None and a.output.parent==Path('/tmp')and not a.output.exists(),'same original fresh607 producer and fresh sibling Core owner');base=producer/'private/desktop574';base_report=C.decode(C.read(base/'report.json'));marker=C.read(base/'image-id',128).decode().strip();C.need(base_report['image']==marker and base_report['ownership']['token']and marker not in base_report['ownership']['before_images'],'actual base token/image-id equality before Core actor')
  record=C.decode(C.read(a.ready/'manifest.json',4*1024**2));X.manifest(C.decode(C.read(ROOT/'composition.json',4*1024**2)),record);C.need(record['status']=='READY_SIGNED_EXPANDED607'and record['preparation']['base_receipt']['image']==marker and record['preparation']['base_receipt']['ownership']['token']==base_report['ownership']['token']and record['preparation']['package_signatures']=='verified-each-exact-signer','actual full fresh607 preparation/base/signer binding');C.need(self.tooling_seed is not None and self.tooling_seed['status']=='EXACT35_TOOLING_INPUT_CACHE_PREPARED_NOT_AUTHENTICATION','actual unchanged retained35 seed result')
  parent=a.output.with_name(a.output.name+'-context');C.need(not parent.exists(),'fresh independent Core context');parent.mkdir(mode=0o700);self.context_lease=__import__('provision622').claim_input_context(parent,self.proof['selection']);__import__('provision622').record_input_context(self.context_lease)
  for name,raw in(('fresh607-manifest.json',C.read(a.ready/'manifest.json',4*1024**2)),('fresh607-producer.json',C.read(producer/'public/producer.json',4*1024**2)),('fresh607-base-build.json',C.read(base/'report.json',4*1024**2)),('fresh607-owner.json',C.read(producer/'producer-owner.json',4*1024**2)),('fresh607-tooling-seed.json',C.encoded(self.tooling_seed))):(parent/name).write_bytes(raw)
  proof=dict(self.proof,producer_token=base_report['ownership']['token']);(parent/'source-proof.json').write_bytes(C.encoded(proof))
  try:__import__('provision622').retain_input_evidence(parent,a.ready,record,dict(proof,export_phase_end=self.end),self.verification)
  except BaseException as primary:
   self.context_failure=__import__('provision622').context_failure(self.context_lease,type(primary).__name__)
   try:__import__('provision622').retain_input_failure(parent,producer.with_name(producer.name.removesuffix('-producer'))/'core622-public',self.context_failure)
   except BaseException as retention:self.context_failure['retention_error_type']=type(retention).__name__;primary.add_note('pre-Core input retention failed: '+type(retention).__name__)
   raise
  kernel=entry.kernel_inputs(types.SimpleNamespace(proof=parent/'source-proof.json',kernel_carrier=w/'kernel-inputs'),C.decode(C.read(ROOT/'profile.json',4*1024**2)))
  args=types.SimpleNamespace(core_source=w/'core-source',vm_source=w/'vm-source',core7=w/'core7-inputs',core64=w/'core64-inputs',kernel_inputs=kernel,base=base,proof=parent/'source-proof.json',output=a.output,receipt=parent/'ordered-cleanup.json',public=parent/'public',source=w/'core-source',case_source=ROOT,workspace=w/'core-source/runtime/runtime-vm',selected=proof['selection'],current607_inputs=a.ready,fresh607_source=self.fresh,current607_code=a.code,outer_deadline=self.end);self.current=args
  code=1
  try:export622.telemetry_phase('CORE_EXECUTION');code=controller.execute(args)
  finally:
   export622.telemetry_phase('CORE_EVIDENCE_CLEANUP');cleanup=evidence.cleanup(args);export622.telemetry_phase('CORE_EVIDENCE_RETENTION');retained=evidence.retain(args)
   C.need(not(ROOT/'actual.json').exists(),'no source-owned acceptance slot created')
   clean=C.decode(C.read(args.receipt));status='PASS_CORE622_CURRENT607_NORMAL_CORE_TWO_BOOT'if code==cleanup==retained==0 else'FAIL';result=dict(status=status,scope=X.SCOPE,provisioning=X.PROVISIONING,normal_fresh607_installation='NOT_RUN',all_original_cleanup='PASS'if cleanup==0 else'FAIL',whole_graph_and_two_boots='PASS'if retained==0 else'UNQUALIFIED',fit='NOT_ESTABLISHED',hardware='NOT_RUN',core_public=public_rows(parent/'public'));(a.output/'result.json').write_bytes(C.encoded(result))
   # Copy original complete public Core evidence before the unchanged outer
   # owner retires its private VM sibling. No old result is reused.
   target=producer.with_name(producer.name.removesuffix('-producer'))/'core622-public';C.need(not target.exists(),'fresh bounded full Core evidence destination');shutil.copytree(parent/'public',target);C.need(public_rows(target)==result['core_public'],'all current Core public bytes retained exactly')
   try:self.context_inventory=declared_context_inventory(result['core_public'],C.read(parent/'context-owner.json',16384),self.context_lease,args.selected,C.decode(C.read(ROOT/'profile.json',4*1024**2))['source_profiles']['kernel_carrier']['files'],C.read(parent/'public/export.json',4*1024**2))
   except BaseException:pass # Missing authority refuses retirement; original result/exception remains primary.
  export622.telemetry_phase('CORE_HOST_RETURN');C.need(code==cleanup==retained==0,'complete actual607 formation and normal Core twoBoot result')
 def retired(self,path):
  if self.current is None:return not path.exists()
  a=self.current
  try:
   clean=C.decode(C.read(a.receipt));C.need(clean['status']=='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT'and clean['original_cleanup']==0 and not(a.output/'data/current607').exists()and not(a.output/'media').exists()and not(a.output/'vm-work').exists(),'all new owned root/media and original Core consumers/producer retired');return True
  except (OSError,KeyError,ValueError):return False
 def handoff(self,producer,path):
  C.need(self.current is not None and producer==self.producer and path==self.current.output and self.retired(path),'same current complete Core retirement before fresh original cleanup');a=self.current;report=C.decode(C.read(a.output/'owner.json',16*1024**2));adapter.core(a.core_source);old=C.load('_core622_original_cleanup_command',a.core_source/'scripts/ci/core-native-lifecycle/owner.py');command=old.command_api(a.workspace,a.output,report);C.need(self.cleanup_end is not None,'shared cleanup clock begins before handoff')
  proof=dict(self.proof_with_producer(),producer_path=str(producer));captured=ownership622.handoff_capture(command,report,path,proof,self.cleanup_end);fact=None
  try:fact=ownership622.handoff(producer,path,proof,C.decode(C.read(a.receipt)),captured,self.cleanup_end)
  finally:ownership622.retain_handoff_query(path,producer.with_name(producer.name.removesuffix('-producer'))/'core622-public',fact is not None)
  target=producer.with_name(producer.name.removesuffix('-producer'))/'core622-public/image-retirement';shutil.copytree(path/'image-retirement',target);public=target.parent;export=C.decode(C.read(public/'export.json',4*1024**2));newrows=public_rows(target);C.need(set(newrows)=={'original-desktop574-image-id','retirement.json'},'exact two declared current retirement DATA roles')
  for n,row in newrows.items():export['files']['image-retirement/'+n]=row;export['bytes']+=row['bytes']
  C.need(export['bytes']<=768*1024**2,'original complete transport cap after exact retirement DATA');(public/'export.json').write_bytes(C.encoded(export));result=C.decode(C.read(path/'result.json',4*1024**2));result['core_public']=public_rows(public);(path/'result.json').write_bytes(C.encoded(result));return fact
 def cleanup(self,original,producer,path):
  with namespace(ROOT,dict(case=C,adapter=adapter,desktop622=X,ownership622=ownership622)):return self._cleanup(original,producer,path)
 def _cleanup(self,original,producer,path):
  export622.telemetry_phase('ORIGINAL_PRODUCER_CLEANUP')
  # The original cleanup body remains exact. Only its real subprocess timeout
  # arguments are clamped to the remaining same240s handoff/retirement clock.
  self.cleanup_end=min(time.monotonic()+240,self.native_phase['phase_end'])if self.native_phase is not None else ownership622.remaining_deadline(240,'cleanup',clock=self.job_clock)if self.job_clock is not None else time.monotonic()+240
  if self.current is not None:self.handoff(producer,path)
  import subprocess
  def run(*args,**kw):
   remaining=self.cleanup_end-time.monotonic();C.need(remaining>0,'unchanged shared240 producer cleanup allowance');kw=dict(kw);kw['timeout']=min(kw.get('timeout',remaining),remaining);return subprocess.run(*args,**kw)
  shim=types.SimpleNamespace(**{n:getattr(subprocess,n)for n in dir(subprocess)if not n.startswith('__')});shim.run=run;scoped=X.clone(original,subprocess=shim);C.need(scoped.cleanup.__code__ is original.cleanup.__code__ and scoped.cleanup.__globals__['subprocess'].run is run,'actual whole original cleanup executing shared remaining clock');result=scoped.cleanup(producer)
  if self.current is not None:
   export622.telemetry_phase('CURRENT_CONTEXT_RETIREMENT');parent=self.current.proof.parent;entries=list(parent.rglob('*'));C.need(self.context_inventory is not None,'required declared private context retirement inventory');limit=self.context_inventory['summary']['bytes'];inventory_nodes={};observation=export622.context_retirement_observations(parent,self.cleanup_end,self.context_inventory['summary'])
   try:
    bounded=observation.record('entry_count',len(entries))<=2048 and observation.record('file_bytes_total',sum(observation.record('file_bytes',context_inventory_stat(inventory_nodes,p,p.stat()).st_size,p)for p in entries if observation.record('byte_is_file',p.is_file(),p)))<=limit and observation.record('owner_type_alias_all',all(not observation.record('alias',p.is_symlink(),p)and observation.record('owner_matches_current',context_inventory_stat(inventory_nodes,p,p.stat()).st_uid==os.getuid(),p)and(observation.record('type_is_file',p.is_file(),p)or observation.record('type_is_dir',p.is_dir(),p))for p in entries))and observation.inventory_check(lambda:validate_context_inventory(self.context_inventory,parent,entries,self.current.selected,inventory_nodes))and observation.record('monotonic',time.monotonic())<self.cleanup_end
   except BaseException as error:observation.emit(operand_error=type(error).__name__);raise
   observation.emit(predicate=bounded);C.need(bounded,'bounded exact owned current context retirement');C.need(shutil.rmtree.avoids_symlink_attacks,'descriptor-safe private context retirement');shutil.rmtree(parent);C.need(not parent.exists(),'current context retired')
  if self.current is None and self.context_lease is not None:
   if self.context_failure is None:self.context_failure=__import__('provision622').context_failure(self.context_lease,'UNKNOWN_PRE_CORE_PRIMARY')
   public=producer.with_name(producer.name.removesuffix('-producer'))/'core622-public'
   try:__import__('provision622').retire_input_context(self.context_lease,self.proof['selection'],self.workspace/'core-source',public,(self.cleanup_end if self.job_clock is not None else min(self.end,self.cleanup_end)),self.context_failure);self.context_lease=None
   except BaseException as error:
    self.context_failure.update(retirement='FAIL_PRESERVED_IDENTIFIED_PRE_CORE_CONTEXT',retirement_error_type=type(error).__name__)
    result=dict(result,status='FAIL_PRE_CORE_CONTEXT_PRESERVED_IDENTIFIED',current607_input_context_failure_data=self.context_failure)
    try:__import__('provision622').publish_context_failure(public,self.context_failure)
    except BaseException as retention:self.context_failure['failure_transport_error_type']=type(retention).__name__
  return result
 def proof_with_producer(self):return C.decode(C.read(self.current.proof,4*1024**2))

def main(argv=None):
 import source622
 argv=list(sys.argv[1:]if argv is None else argv)
 if argv==['--source-preflight']:print(C.encoded(source622.verify(ROOT)).decode(),end='');return 0
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--fresh607-source',type=Path,required=True);n,rest=p.parse_known_args(argv);fresh=n.fresh607_source.absolute();workspace=Path(os.environ.get('GITHUB_WORKSPACE','')).absolute();C.need(ROOT==workspace/'core622-code'and fresh==workspace/'fresh607-code','literal current622 and pinned607 checkout roles');phase=ownership622.native_phase();proof=inputs(workspace,fresh);clock=ownership622.job_clock();C.need(ownership622.native_phase()==phase,'one immutable native phase through original proof');end=phase['work_end'];context=Context(workspace,fresh,proof,end,job_clock=clock,native_phase=phase)
 with namespace(fresh/'implementation'):
  F=C.load('_core622_exact_fresh1197_run',fresh/'implementation/run.py');old_integration=F.Integration
  class Integration(old_integration):
   def bind(self,original,producer):return ownership622.verifier_capture(old_integration.bind,F,context,self,original,producer)
   def producer(self,original,args):
    export622.telemetry_phase('PRODUCER_PREPARE');context.producer=args.output;return ownership622.prepare_owned(original,args,super().producer,F.producer_diagnostic.CALLER_PIN,context.workspace/'core-source',context.proof['git']['core800'],F.producer_diagnostic.command,context.capture_desktop_build,context.end,context.capture_dependency)
   def seed_tooling(self,*a):
    export622.telemetry_phase('TOOLING_SEED');fact=super().seed_tooling(*a);context.tooling_seed=fact;return fact
   def outer_exception(self,error):return export622.outer_exception(error,'child')
   def desktop_failure(self,result):return context.desktop_failure(result)
   def core_host(self,args):return context.host(args)
   def core_retired(self,path):return context.retired(path)
   def cleanup(self,original,producer,path):return context.cleanup(original,producer,path)
   def __init__(self,*a,**kw):super().__init__(*a,**kw);self.source=proof['source_sha']
  oldderive=F.derive;selected=X.clone(F,Integration=Integration,derive=lambda raw:derive(oldderive(raw)))
  return export622.outer_delegate(lambda:selected.main(rest))
if __name__=='__main__':raise SystemExit(main())
