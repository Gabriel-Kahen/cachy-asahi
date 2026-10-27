# SPDX-License-Identifier: MIT
"""Real held fresh587 -> owned temporary604 -> signed607 production API.

No actors run on import. prepare() is for the future owned native job. A real
Prepared607 retains backing data until outer consumer/provider absence, then
close() runs original cleanup. No __exit__ or destructor can delete live inputs.
"""
import argparse,ast,contextlib,importlib.util,os,platform,re,shutil,stat,sys,tarfile,tempfile,types
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import route607 as R
need,read,decode,encoded,pin=R.need,R.read,R.decode,R.encoded,R.pin
SOURCE='b9976eea34eaed4b6e56af3be21d4d652fa971d6'
LIBRARY='bd0cf1891083d011b70edab10501c317d3720b78'
LANE='scripts/ci/expanded604-apps6-public-pair-installer'
PURPOSE='latest607-fresh-installer'
PRODUCER_PATHS=('preparation_source','product','updater','desktop','updater_v2_source','native','fdk','cache','setup4_pair')
CARRIERS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source','apps6_source','apps6_authority_source')
DECISIONS=('fresh600_decisions','native604_decisions')
PATH_ARGS=tuple(dict.fromkeys(('fresh_source','fresh_authorization','six_record','six_public','tooling_inputs','implementation',*PRODUCER_PATHS,*CARRIERS,*DECISIONS,'audio_inputs','output')))
VERSIONS={'cachy-asahi-apps':'0.1.0-16','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2','cachy-asahi-repository-runtime':'0.1.0-1'}

@contextlib.contextmanager
def aliases(values):
 missing=object();old={k:sys.modules.get(k,missing)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in old.items():
   if v is missing:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def load(name,path,bindings=()):
 with aliases(dict(bindings)):
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def body(raw,name):return ast.get_source_segment(raw,next(n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name==name))+'\n'

class OwnedSourceStage:
 """Explicit lifetime only; GC/process exit never removes actor backing source."""
 def __init__(self):self.name=tempfile.mkdtemp(prefix='fresh607-owned-source-');self.inode=R.identity(Path(self.name).lstat())[:2]
 def cleanup(self):
  root=R.canonical(self.name)
  if root.exists():
   need(R.identity(root.lstat())[:2]==self.inode and root.stat().st_uid==os.geteuid()and stat.S_IMODE(root.stat().st_mode)==0o700,'same explicitly owned source stage');shutil.rmtree(root)

def stage_source(args):
 """Authenticate all1197 files; root .git is staging metadata, never executed here."""
 root=R.canonical(args.fresh_source);raw=read(args.fresh_authorization);need(pin(raw)==R.PROVIDERS['fresh4k']['authorization'],'exact1197 authorization');wanted=decode(raw);names=set();directories=set()
 for parent,dirs,files in os.walk(root,followlinks=False):
  folder=Path(parent)
  if folder==root and '.git'in dirs:need(not(root/'.git').is_symlink(),'ordinary root git metadata');dirs.remove('.git')
  for n in files:
   if folder==root and n=='.git':need(not(root/n).is_symlink(),'ordinary root git pointer');continue
   names.add((folder/n).relative_to(root).as_posix())
  need(not any((folder/n).is_symlink()for n in dirs),'source directory alias');directories.update((folder/n).relative_to(root).as_posix()for n in dirs)
 need(names==set(wanted)and len(wanted)==1197 and directories=={q.as_posix()for n in wanted for q in Path(n).parents if str(q)!='.'},'entire1197 checkout source namespace')
 temporary=OwnedSourceStage();clean=Path(temporary.name)/'source';clean.mkdir(mode=0o700)
 try:
  for n,w in wanted.items():
   raw=read(root/n);need(pin(raw)==w,'exact1197 source byte '+n);p=clean/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o444)
  proof=R.source_contract(clean,args.fresh_authorization,'fresh4k');return temporary,clean,proof
 except BaseException:temporary.cleanup();raise

def runtime(args):
 need(args.fresh_source_revision==SOURCE and args.implementation_revision==LIBRARY,'exact607/604 revisions');temporary,fresh,proof=stage_source(args)
 try:
  base=R.runtime_modules(fresh,args.fresh_authorization,'fresh4k');common=base.common
  def held(n,extra=()):return load('_producer607_'+n[:-3],fresh/'implementation'/n,dict(common=common,**dict(extra)).items())
  loaders=held('loaders.py');adapter=held('adapter.py');diagnostic=held('producer_diagnostic.py');context=held('runtime_context.py');tooling=held('tooling_inputs.py',{'loaders':loaders}.items())
  rows=decode(read(fresh/'source-manifest.json'))['parents']['installer604'];root=R.canonical(args.implementation);names={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()and'.git'not in p.relative_to(root).parts};need(len(rows)==274 and names==set(rows),'whole qualified274 installer checkout')
  for n,w in rows.items():need(pin(read(root/n))==w,'exact274 installer byte '+n)
  C=load('_producer607_original_contract',root/LANE/'contract.py');oldadapter=C.scoped_load('_producer607_original_adapter',root/LANE/'adapter.py',{'contract':C});ci=C.scoped_load('_producer607_original_ci',root/LANE/'ci.py',{'contract':C,'adapter':oldadapter});ci.PURPOSE=PURPOSE
  scope=dict(C=common,Path=Path,types=types,adapter=adapter,materialize=base.materializer,producer_diagnostic=diagnostic,runtime_context=context,tooling_inputs=tooling,load=loaders.load);exec(compile(body(read(fresh/'implementation/run.py').decode(),'Integration'),'<exact-held607-Integration>','exec'),scope)
  return types.SimpleNamespace(C=C,ci=ci,Integration=scope['Integration'],common=common,accepted=base.accepted,tooling=tooling,loaders=loaders,checks=base.checks,temporary=temporary,source=fresh,proof=proof)
 except BaseException:temporary.cleanup();raise

def preflight(args,r):
 C=r.C;policy=C.policy()
 for n in PATH_ARGS:setattr(args,n,C.safe(Path(getattr(args,n)).absolute()))
 need(getattr(args,'page_mode','generic4k')=='generic4k'and getattr(args,'kernel_input',None)is None,'explicit native4K producer only')
 for p,s in((args.fresh_source,SOURCE),(args.implementation,LIBRARY),(args.six_record,r.common.profile()['accepted_record_source']),(args.tooling_inputs,r.tooling.SOURCE)):r.loaders.revision(p,s)
 C.verify_source(args.implementation);C.legacy(args.legacy_source);args.code=args.implementation;decision,unused=r.accepted.public(args.six_record,args.six_public);r.tooling.preflight(args.tooling_inputs,args.legacy_source);composition,summary,accepted=C.inputs(args,policy)
 need(platform.machine()=='aarch64'and os.getuid()==os.geteuid()>0 and os.sysconf('SC_PAGE_SIZE')==4096,'actual ordinary native ARM4K coordinator')
 need(args.output.parent==Path('/tmp')and not any(os.path.lexists(args.output.with_name(args.output.name+s))for s in('','-producer','-vm')),'fresh original /tmp output and siblings')
 return composition,decision

class PreparationFailure(RuntimeError):
 def __init__(self,error,prepared):super().__init__(str(error));self.prepared=prepared

class Prepared607:
 def __init__(self,args,r,owner):
  self.args,self.runtime,self.owner=args,r,owner;self.output=args.output;self.producer_output=Path(owner['producer']);self.bundle607=self.bundle=self.output/'ready604';self.candidate=self.output/'candidate';self.token=owner['token'];self.closed=False;self.repair_inputs=None;self.source_stage_record=None;self.installer_code=Path(args.legacy_source);self.installer_source=Path(args.implementation);self.fresh_source=self.runtime.source;self.tooling_cache=self.output/'tooling-cache'
 def finish(self):
  self.producer_owner=decode(read(self.producer_output/'producer-owner.json'));need(re.fullmatch('[0-9a-f]{32}',self.producer_owner['token']),'actual fresh producer identity');self.manifest_path=self.bundle607/'manifest.json';self.manifest=pin(read(self.manifest_path));self.value=decode(read(self.manifest_path));need(self.value['status']=='READY_SIGNED_EXPANDED607'and len(self.value['packages'])==607,'actual ready607 result')
  self.expected_lock_path=self.bundle607/'expected-installed.lock';self.expected_lock=pin(read(self.expected_lock_path));R.lock_map(read(self.expected_lock_path));self.image=self.value['preparation']['image_id'];need(re.fullmatch('sha256:[0-9a-f]{64}',self.image),'actual prepared image')
  need(Path(self.value['preparation']['image_id_path'])==self.producer_output/'private/desktop574/image-id'and read(Path(self.value['preparation']['image_id_path'])).decode().strip()==self.image,'prepared image receipt join');self.signing_home=self.producer_output/'private/test-signing';self.signer=self.value['preparation']['signer_roles']['ephemeral_TEST'];need(re.fullmatch('[0-9A-F]{40}',self.signer),'actual fresh TEST signer')
  self.runner_files={p.name:pin(read(p))for p in self.candidate.iterdir()};need(set(self.runner_files)=={'profile.py','run.py','prepare.py','guest.py','installer.py','numeric_vm.py','adapter.json'},'whole emitted607 runner');return self
 def public_files(self):
  files={'owner':self.output/'owner.json','producer':self.producer_output/'public/producer.json','producer-cleanup':self.producer_output/'public/producer-cleanup.json','signed607-manifest':self.bundle607/'manifest.json','expected607':self.bundle607/'expected-installed.lock','adapter':self.candidate/'adapter.json'}
  if self.repair_inputs is not None:
   files.update({'repair-inputs/'+p.relative_to(self.repair_inputs).as_posix():p for p in self.repair_inputs.rglob('*')if p.is_file()and not p.is_symlink()})
  return {n:p for n,p in files.items()if p.is_file()and not p.is_symlink()and len(read(p))<=16*1024**2}
 def close(self):
  """Only after outer all-actor/provider/consumer/source/work absence checks."""
  if self.closed:return self.cleanup_receipt
  need(decode(read(self.output/'owner.json'))==self.owner,'same exact original producer owner');need(not any(os.path.lexists(self.producer_output/'private'/n)for n in('expanded604-verifier','latest607-verifier')),'original verifier absence required')
  if self.repair_inputs is not None and self.repair_inputs.exists():
   need(len(list(self.repair_inputs.rglob('*')))<=2048,'bounded owned repair input closure');shutil.rmtree(self.repair_inputs)
  if self.tooling_cache.exists():
   need(len(list(self.tooling_cache.iterdir()))<=64 and all(p.is_file()and not p.is_symlink()for p in self.tooling_cache.iterdir()),'closed original tooling cache');shutil.rmtree(self.tooling_cache)
  self.runtime.ci.cleanup_ready(self.bundle607,self.owner);cleanup=self.producer.cleanup(self.producer_output)if(self.producer_output/'producer-owner.json').is_file()else None;need(cleanup is None or cleanup['status']=='PASS','original producer cleanup')
  if self.candidate.exists():
   if hasattr(self,'runner_files'):need({p.name:pin(read(p))for p in self.candidate.iterdir()}==self.runner_files,'emitted source held until retirement')
   shutil.rmtree(self.candidate)
  need(not self.bundle607.exists()and not(self.producer_output/'private').exists()and not self.candidate.exists(),'observed producer backing absence');retire_source_stage(self);self.runtime.temporary.cleanup();self.cleanup_receipt=dict(status='PASS_FRESH607_PRODUCER_BACKING_ABSENCE',producer=cleanup,bundle_absent=True,candidate_absent=True,token=self.token,consumer_absence='OUTER_PRECONDITION_NOT_OWNED_HERE');self.closed=True;return self.cleanup_receipt

def prepare(args):
 r=runtime(args)
 try:composition,decision=preflight(args,r)
 except BaseException:r.temporary.cleanup();raise
 C=r.C;output=args.output;output.mkdir(mode=0o700);owner=dict(schema_version=1,purpose=PURPOSE,token=os.urandom(16).hex(),output=str(output),producer=str(output.with_name(output.name+'-producer')),vm=str(output.with_name(output.name+'-vm')),legacy_source=C.LEGACY)
 fd=os.open(output/'owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(encoded(owner));stream.flush();os.fsync(stream.fileno())
 p=Prepared607(args,r,owner);p.source_stage_record=dict(schema_version=1,token=owner['token'],root=r.temporary.name,source=str(r.source),identity=R.identity(Path(r.temporary.name).lstat()),authorization=R.PROVIDERS['fresh4k']['authorization']);(output/'producer607-source-stage.json').write_bytes(encoded(p.source_stage_record))
 try:
  p.producer=C.load('_producer607_actual_original_producer',args.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
  integration=r.Integration(args.six_record,args.six_public,args.legacy_source,C,args.fresh_source_revision,decision,args.tooling_inputs);original=types.SimpleNamespace(**{n:getattr(args,n)for n in PRODUCER_PATHS},code=args.legacy_source,code_revision=C.LEGACY,output=p.producer_output);ready=integration.producer(p.producer,original)
  materializer=C.scoped_load('_producer607_actual_original_materializer',C.HERE.parent/'expanded604-apps6-public-pairs/materializer.py',{'contract':C.COMPOSITION})
  integration.bind(materializer,p.producer_output).prepare(ready,p.producer_output,args.eight_source,args.seven_source,args.audio_inputs,args.legacy_source,p.bundle607,composition,args.management_source,args.setup_source,args.welcome_source,args.implementation,args.apps6_source,args.apps6_authority_source);integration.candidate(p.candidate)
  old_ci=C.load('_producer607_held_tooling_selector',args.legacy_source/'scripts/ci/full-composition-installer-vm/ci.py');preparation=C.load('_producer607_emitted_preparation',p.candidate/'prepare.py');auditor=integration.tooling();lock=C.read(args.legacy_source/'scripts/virtual/tooling.lock.json');auditor.validate_lock(lock);downloads=old_ci.selected_tooling_inputs(p.bundle607,lock,preparation,auditor);need(len(downloads)<=64 and len({row['filename']for row in downloads})==len(downloads),'held finite tooling selection');p.tooling_cache.mkdir(mode=0o700);integration.seed_tooling(auditor,downloads,p.tooling_cache,owner)
  p.finish();p.stage_repair_inputs();return p
 except BaseException as error:raise PreparationFailure(error,p)from error

def resume(args):
 r=runtime(args);args.output=R.canonical(args.output);owner=decode(read(args.output/'owner.json'));need(owner['schema_version']==1 and owner['purpose']==PURPOSE and re.fullmatch('[0-9a-f]{32}',owner['token'])and owner['output']==str(args.output)and owner['producer']==str(args.output.with_name(args.output.name+'-producer'))and owner['vm']==str(args.output.with_name(args.output.name+'-vm'))and owner['legacy_source']==r.C.LEGACY and args.output.parent==Path('/tmp'),'exact original ownership on resume');p=Prepared607(args,r,owner);p.source_stage_record=decode(read(args.output/'producer607-source-stage.json'));p.producer=r.C.load('_producer607_resume_original_producer',Path(args.legacy_source)/'scripts/ci/full-composition-installer-vm/producer.py')
 if(args.output/'repair-inputs').is_dir():p.repair_inputs=args.output/'repair-inputs'
 if p.candidate.is_dir():p.runner_files={q.name:pin(read(q))for q in p.candidate.iterdir()}
 return p

def retire_source_stage(prepared):
 record=prepared.source_stage_record
 if record is None:return
 root=R.canonical(record['root']);source=R.canonical(record['source']);need(record['schema_version']==1 and record['token']==prepared.token and root.parent==Path('/tmp')and root.name.startswith('fresh607-owned-source-')and source==root/'source'and record['authorization']==R.PROVIDERS['fresh4k']['authorization'],'exact owned source-stage receipt')
 if root.exists():
  need(R.identity(root.lstat())==record['identity']and root.stat().st_uid==os.geteuid()and stat.S_IMODE(root.stat().st_mode)==0o700 and set(root.iterdir())=={source},'same private closed source stage');R.source_contract(source,prepared.args.fresh_authorization,'fresh4k');shutil.rmtree(root)
 need(not root.exists(),'source stage absence')

def cleanup(args):return resume(args).close()

FROZEN_CAPSULE='0acbf48f82736ded95fae19c8ea250eda4d2386093cb26b2f9e0f33ba2b7013c'

def recovery_source(root):
 root=R.canonical(root);raw=read(root/'capsule.json');need(pin(raw)['sha256']==FROZEN_CAPSULE,'exact held259 recovery capsule');rows=decode(raw)['files'];need(len(rows)==258,'whole held258 nonself recovery source')
 names={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()};need(names==set(rows)|{'capsule.json'},'whole held259 source namespace')
 for n,w in rows.items():need(pin(read(root/n))==w,'held recovery source byte '+n)
 return root/'repair-source'

def stage_repair_inputs(prepared):
 """Only authenticated current four archives supply normal runtime/Apps code."""
 directory=prepared.output/'repair-inputs';need(not directory.exists(),'fresh repair inputs');directory.mkdir(mode=0o755);candidate=directory/'candidate';candidate.mkdir();selected={r['name']:r for r in prepared.value['packages']if r['name']in VERSIONS};need(set(selected)==set(VERSIONS)and all(r['version']==VERSIONS[n]for n,r in selected.items()),'exact four current607 candidates')
 for n,row in selected.items():
  path=prepared.bundle607/row['archive'];need(pin(read(path,256*1024**2))==dict(bytes=row['size'],sha256=row['sha256']),'signed607 candidate body held');report=prepared.runtime.checks.package(path);need(not report['errors'],'original package inspection gate')
  if n==R.APPS:need(row['sha256']=='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af','exact Apps16 archive')
  with tarfile.open(path,'r:*')as archive:
   for member in archive.getmembers():
    name=member.name.rstrip('/')
    if name.startswith('.')or member.isdir():continue
    need(member.isfile()and name.startswith('usr/')and all(p not in('','..','.')for p in name.split('/')),'ordinary bounded current candidate payload')
    target=candidate/name;need(not target.exists()and not any(p.is_symlink()for p in(target,*target.parents)),'unique ordinary candidate output');target.parent.mkdir(parents=True,exist_ok=True);raw=archive.extractfile(member).read(2*1024**2+1);need(len(raw)==member.size<=2*1024**2,'bounded complete candidate leaf');target.write_bytes(raw);target.chmod(member.mode&0o777)
 apps=directory/'apps-source';apps.mkdir()
 for name,relative in{'apps.py':'usr/lib/cachy-asahi-apps/apps.py','inventory.py':'usr/lib/cachy-asahi-apps/inventory.py','helper-pins.json':'usr/lib/cachy-asahi-apps/helper-pins.json','cachy-asahi-apps':'usr/bin/cachy-asahi-apps','source-provenance.json':'usr/share/doc/cachy-asahi-apps/source-provenance.json'}.items():shutil.copyfile(candidate/relative,apps/name)
 prepared.repair_inputs=directory;return directory

def base603(inventory,lock):
 expected=R.lock_map(lock);rows=inventory['packages'];need(len(rows)==607 and len({p['name']for p in rows})==607 and{p['name']:p['version']for p in rows}==expected,'actual current607 metadata before release603 projection')
 base={k:v for k,v in inventory.items()if k!='observation'};base.update(schema_version=1,target_arch='aarch64',kind='complete-target-transaction',snapshot_id='fresh607-minus-four-'+pin(encoded(inventory))['sha256'][:40],packages=[p for p in rows if p['name']not in VERSIONS]);need(len(base['packages'])==603,'exact other603 release base');return base

def signing_spec(prepared,inventory_path,recovery_root,current_source):
 need(re.fullmatch('[0-9a-f]{40}',current_source),'explicit current recovery source');inventory_path=R.canonical(inventory_path);raw=read(inventory_path,16*1024**2);base603(decode(raw),read(prepared.expected_lock_path));recovery_source(recovery_root)
 spec=dict(schema_version=1,purpose='FRESH607_CURRENT_FOUR_NORMAL_REPAIR_TEST_RELEASE',source_sha=current_source,owner=prepared.owner,producer_owner=prepared.producer_owner,bundle=str(prepared.bundle607),manifest=prepared.manifest,signing_home=str(prepared.signing_home),signer=prepared.signer,inputs=str(prepared.repair_inputs),inventory=str(inventory_path),inventory_pin=pin(raw),fresh_source=str(prepared.runtime.source),fresh_authorization=str(prepared.args.fresh_authorization),recovery_source=str(R.canonical(recovery_root)))
 path=prepared.output/'repair-signing-spec.json';need(not path.exists(),'fresh signing actor spec');path.write_bytes(encoded(spec));path.chmod(0o600);return path,pin(read(path))

def sign_from_spec(path,sha256):
 """Dedicated source-owned offline native signer; same fresh TEST key, no rebuild."""
 need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64'and os.sysconf('SC_PAGE_SIZE')==4096 and Path('/.dockerenv').is_file()and{p.name for p in Path('/sys/class/net').iterdir()}=={'lo'}and os.environ.get('FRESH607_SIGNER')=='1','dedicated offline native4K signing actor')
 output_ids=[os.environ.get(n,'')for n in('OUTPUT_UID','OUTPUT_GID')];need(all(v.isdecimal()and 0<int(v)<2**31 for v in output_ids),'ordinary output identities for signer publication');output_uid,output_gid=map(int,output_ids)
 raw=read(path);need(pin(raw)['sha256']==sha256,'exact outer-owned signer spec');s=decode(raw);need(s['schema_version']==1 and s['purpose']=='FRESH607_CURRENT_FOUR_NORMAL_REPAIR_TEST_RELEASE','closed native release purpose');bundle=R.canonical(s['bundle']);manifest=decode(read(bundle/'manifest.json'));need(pin(read(bundle/'manifest.json'))==s['manifest']and manifest['status']=='READY_SIGNED_EXPANDED607','same actual signed607 bundle');home=R.canonical(s['signing_home']);need(home==Path(s['owner']['producer'])/'private/test-signing'and manifest['preparation']['signer_roles']['ephemeral_TEST']==s['signer'],'same fresh607 TEST signing custody')
 root=recovery_source(s['recovery_source']);r=load('_producer607_held_release',root/'scripts/release/release.py');rt=R.runtime_modules(s['fresh_source'],s['fresh_authorization'],'fresh4k');inputs=R.canonical(s['inputs']);directory=inputs/'release';need(not directory.exists(),'fresh normal release directory');inventory_raw=read(s['inventory'],16*1024**2);need(pin(inventory_raw)==s['inventory_pin'],'actual native inventory raw join');base=base603(decode(inventory_raw),read(bundle/'expected-installed.lock'));directory.mkdir(mode=0o755);assembly=inputs/'release-assembly';repository=inputs/'release-repository';assembly.mkdir(mode=0o700);repository.mkdir(mode=0o700);(assembly/'base.json').write_bytes(encoded(base));shutil.copyfile(root/'LICENSE',assembly/'LICENSE');products=[]
 fixture=read(root/'scripts/ci/apps-full574-native/fixture.py').decode();before=body(fixture,'specification');old="len(base['packages'])==574";new="len(base['packages'])==603";need(before.count(old)==1,'one original fixture base-count seam');derived=before.replace(old,new,1);need(derived.replace(new,old,1)==before,'whole fixture specification inverse');scope=dict(C=types.SimpleNamespace(need=need,VERSIONS=VERSIONS,sha=lambda raw:pin(raw)['sha256'],encoded=encoded));exec(compile(derived,'<held-fixture-specification603>','exec'),scope)
 env=r.gpg_env(home,repository);signer=s['signer']
 try:
  listing=r.run(['gpg','--batch','--no-options','--homedir',str(home),'--with-colons','--list-secret-keys'],env=env).decode();need([line.split(':')[9]for line in listing.splitlines()if line.startswith('fpr:')]==[signer],'one same fresh producer TEST secret signer')
  for row in manifest['packages']:
   if row['name']not in VERSIONS:continue
   archive=bundle/row['archive'];need(pin(read(archive,256*1024**2))==dict(bytes=row['size'],sha256=row['sha256'])and row['signer']==signer,'exact four current archive/fresh signer');r.verify_signature(archive,signer,env);report=rt.checks.package(archive);need(not report['errors'],'original package gate');pkg=report['metadata']['.PKGINFO'];recipe=report['metadata']['.BUILDINFO']['pkgbuild_sha256sum'];need(len(recipe)==1 and re.fullmatch('[0-9a-f]{64}',recipe[0]),'actual BUILDINFO recipe provenance')
   if row['name']==R.APPS:need(row['sha256']=='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af','same exact Apps16')
   dest=assembly/archive.name;shutil.copyfile(archive,dest);provenance=dict(schema_version=1,artifact_sha256=row['sha256'],package=dict(name=row['name'],version=row['version'],arch=pkg['arch'][0]),source_commit=s['source_sha'],recipe_sha256=recipe[0],licenses=pkg['license'],sources=[dict(url='https://github.com/Gabriel-Kahen/cachy-asahi',commit=SOURCE)],build=dict(execution='synthetic',architecture='aarch64',environment='TEST_FRESH607_RELEASE_ASSEMBLY_NO_REBUILD',snapshot_id=base['snapshot_id']),fresh607_origin=dict(manifest=s['manifest'],provider_source=SOURCE,archive_sha256=row['sha256']))
   record=assembly/(row['name']+'.json');record.write_bytes(encoded(provenance));products.append(dict(artifact=dict(path=dest.name,sha256=row['sha256']),provenance=dict(path=record.name,sha256=pin(read(record))['sha256'])))
  need(len(products)==4,'all four current signed catalog candidates');spec=scope['specification'](base,products,s['source_sha']);spec['project_license']['sha256']=pin(read(assembly/'LICENSE'))['sha256'];(assembly/'spec.json').write_bytes(encoded(spec));result=r.stage(argparse.Namespace(spec=str(assembly/'spec.json')),repository,signer,env);release=Path(result['path']);r.verify_release(release,signer,env);shutil.copytree(release,directory/'bundle',symlinks=True)
  catalog=dict(schema_version=1,kind='development-application-catalog',target_arch='aarch64',release_sha256=r.sha(directory/'bundle/release.json'),repository=spec['repo_name'],applications=[dict(id=role,title=role,description='Current signed607 candidate in TEST owned-root recovery only',packages=[name])for role,name in(('apps',R.APPS),('cache','cachy-asahi-cache'),('orphans','cachy-asahi-orphans'),('runtime','cachy-asahi-repository-runtime'))]);catalog_path=directory/'catalog.json';catalog_path.write_bytes(encoded(catalog));r.sign(catalog_path,signer,env);(directory/'public.gpg').write_bytes(r.run(['gpg','--batch','--no-options','--homedir',str(home),'--export',signer],env=env));(directory/'control.json').write_bytes(encoded(dict(signer=signer,release_sha256=catalog['release_sha256'],catalog_sha256=r.sha(catalog_path),synthetic=True,production_trust='NOT_ESTABLISHED',archive_origins='FRESH_SIGNED607_SOURCE_BOUND_ARCHIVES_NO_REBUILD',base='ACTUAL607_METADATA_MINUS_CURRENT_FOUR603')))
  (inputs/'fixture-specification-derivation.json').write_bytes(encoded(dict(before=pin(before.encode()),after=pin(derived.encode()),old=old,new=new,whole_inverse=True,signer='SAME_FRESH607_TEST_KEY_NOT_A_NEW_OR_BORROWED_KEY',native_pair_claim='NOT_CREATED')))
  files={};links={};directories=[]
  for top in('candidate','apps-source','release'):
   for p in(inputs/top,*sorted((inputs/top).rglob('*'))):
    name=p.relative_to(inputs).as_posix()
    if p.is_symlink():
     target=os.readlink(p);need(not os.path.isabs(target)and'..'not in Path(target).parts,'internal signed-release link');links[name]=target
    elif p.is_dir():directories.append(name)
    else:files[name]=pin(read(p,16*1024**2))
  receipt=dict(schema_version=1,status='FRESH607_FOUR_SIGNED_NORMAL_REPAIR_INPUTS',files=files,links=links,directories=directories,signer=signer,source_sha=s['source_sha'],signed607_manifest=s['manifest'],observed607_inventory=s['inventory_pin'],base603=pin(read(assembly/'base.json')),synthetic=True,native_pair_claim='NOT_CREATED',hardware='NOT_RUN',production_trust='NOT_ESTABLISHED');(inputs/'repair-inputs.json').write_bytes(encoded(receipt));return receipt
 finally:
  try:r.run(['gpgconf','--homedir',str(home),'--kill','all'],env=env)
  finally:
   for top in(directory,assembly,repository):
    if top.exists():
     for leaf in(top,*top.rglob('*')):
      if leaf.is_symlink():os.lchown(leaf,output_uid,output_gid)
      else:os.chmod(leaf,0o755 if leaf.is_dir()else 0o644);os.chown(leaf,output_uid,output_gid)
   for name in('repair-inputs.json','fixture-specification-derivation.json'):
    if(inputs/name).is_file():os.chown(inputs/name,output_uid,output_gid)

Prepared607.stage_repair_inputs=stage_repair_inputs
Prepared607.signing_spec=signing_spec
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['sign']);parser.add_argument('--spec',type=Path,required=True);parser.add_argument('--spec-sha256',required=True);a=parser.parse_args();sign_from_spec(a.spec,a.spec_sha256)
