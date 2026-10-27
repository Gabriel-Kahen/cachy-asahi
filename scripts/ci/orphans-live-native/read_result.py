#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline replay of once-collected Orphans0.3 originals. No acquisition API.

Publication authorization and original identity are independent trusted Root inputs;
this reader never promotes artifact summaries into identity or release authority.
"""
import argparse,hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path,PurePosixPath
LANE='scripts/ci/orphans-live-native';RECIPE='packages/tools/cachy-asahi-orphans03';PRODUCT='cachy-asahi-orphans'
WORKFLOWS=('.github/workflows/native-arm-orphans-live.yml','.github/workflows/native-arm-build.yml')
RETENTION='PASS_NATIVE_ORPHANS03_PRIVATE_REMOVAL_AND_ORDERED_CLEANUP';RUNTIME='PASS_NATIVE_ORPHANS03_PAIR_AND_REAL_PRIVATE_REMOVAL';SCOPE='PRIVATE_EXPLICIT_LIVE_CLI_FIXTURE_ONLY'
PRODUCT_FILES={'.SRCINFO','PKGBUILD','LICENSE','NOTICE','README.md','READONLY.md','cachy-asahi-orphans','check_source.py','live.py','live_policy.py','orphans3','protection-floor.json','remove.py','source-provenance.json','test_live.py','test_live_policy.py','test_live_supervision.py','test_orphans.py','test_remove.py','test_retirement.py'}
SHA=re.compile('[0-9a-f]{64}\\Z');OID=re.compile('[0-9a-f]{40}\\Z');DECIMAL=re.compile('[1-9][0-9]{0,19}\\Z');MAX_TOTAL=384*1024**2;MAX_FILE=128*1024**2

def need(value,message):
 if not value:raise ValueError(message)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ordinary(name):
 need(type(name) is str and 0<len(name)<=512 and '\\' not in name and not any(c in name for c in '\0\r\n'),'ordinary relative name required')
 path=PurePosixPath(name);need(bool(path.parts) and name!='.' and not path.is_absolute() and '..' not in path.parts and str(path)==name and '.git' not in path.parts,'ordinary relative name required');return path

def raw(path,cap=MAX_FILE):
 path=Path(path).absolute();need(path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary canonical evidence path required')
 before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link evidence required');data=path.read_bytes();after=path.lstat()
 need(len(data)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'evidence changed during read');return data

def digest(path):return hashlib.sha256(raw(path)).hexdigest()
def json_bytes(data):
 def pairs(rows):
  result={}
  for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
  return result
 return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
def read(path,cap=16*1024**2):return json_bytes(raw(path,cap))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def source_path(directory,name):return directory/'source'/('source-manifest.json' if name==LANE+'/source-manifest.json' else name)

def git_tree(files,read_file):
 tree={}
 for name,row in files.items():
  parts=ordinary(name).parts;node=tree
  for part in parts[:-1]:
   node=node.setdefault(part,{});need(type(node) is dict,'source file/directory collision')
  need(parts[-1] not in node and row['mode'] in ('100644','100755'),'ordinary unique Git source mode required');data=read_file(name);node[parts[-1]]=(row['mode'],hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).digest())
 def build(node):
  entries=[]
  for name,item in node.items():
   mode,oid=('40000',build(item)) if type(item) is dict else item
   entries.append((name.encode()+(b'/' if mode=='40000' else b''),mode.encode()+b' '+name.encode()+b'\0'+oid))
  body=b''.join(value for _,value in sorted(entries));return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).digest()
 return build(tree).hex()

def verify_index(directory):
 directory=Path(directory).absolute();need(directory==directory.resolve() and directory.is_dir(),'ordinary originals directory required');index=read(directory/'retention.json')
 need(index.get('status')==RETENTION and index.get('scope')==SCOPE and index.get('errors')==[],'complete scoped0.3 retained success required')
 need(index.get('hardware')=='NOT_RUN' and index.get('release')=='NOT_ADMITTED' and all(index.get(k) is None for k in ('actual_source','actual_ref','actual_run')),'retention grants no future identity/release authority')
 files=index.get('files');need(type(files) is dict and 1<=len(files)<=1024,'bounded retained file map required');total=0
 for name,row in files.items():
  ordinary(name);need(name!='retention.json' and type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=MAX_FILE and type(row['sha256']) is str and SHA.fullmatch(row['sha256']),'exact retained hash row required')
  data=raw(directory/name);need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'retained hash differs: '+name);total+=len(data);need(total<=MAX_TOTAL,'retained total byte limit')
 actual=set();directories=set()
 for parent,dirs,names in os.walk(directory,followlinks=False):
  for name in dirs:
   child=Path(parent)/name;need(not child.is_symlink(),'retained directory alias');directories.add(child.relative_to(directory).as_posix())
  for name in names:actual.add((Path(parent)/name).relative_to(directory).as_posix())
 need(actual==set(files)|{'retention.json'} and index.get('total_bytes')==total,'whole retained evidence closure differs')
 parents={str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent)!='.'};need(directories<=parents,'undeclared retained directory');return index

def verify_source(directory,authorization,source_sha):
 need(type(authorization) is dict and authorization.get('source_sha')==source_sha and OID.fullmatch(authorization.get('tree','')),'trusted exact source/tree authorization required')
 files=authorization.get('files');need(type(files) is dict and 20<len(files)<=128,'trusted finite source map required')
 for name,row in files.items():
  ordinary(name);need(type(row) is dict and {'bytes','sha256','mode'}<=set(row) and type(row['bytes']) is int and 0<=row['bytes']<=16*1024**2 and SHA.fullmatch(row.get('sha256','')) and row.get('mode') in ('100644','100755'),'trusted source byte/mode row required')
  data=raw(source_path(directory,name),16*1024**2);need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'reviewed source differs: '+name)
 product={name.removeprefix(RECIPE+'/') for name in files if name.startswith(RECIPE+'/')};need(product==PRODUCT_FILES,'all20 selected version0.3 product files required')
 need(not any(name.startswith('packages/tools/cachy-asahi-orphans/') for name in files),'old recipe path cannot select0.3 source')
 manifest=read(directory/'source/source-manifest.json');excluded={LANE+'/source-manifest.json',*WORKFLOWS};need(set(manifest['files'])==set(files)-excluded,'whole manifest/authorized leaf set differs')
 for name,row in manifest['files'].items():need(row['bytes']==files[name]['bytes'] and row['sha256']==files[name]['sha256'],'manifest/authorized source differs')
 need(all(manifest.get(k) is None for k in ('actual_source','actual_ref','actual_run')),'source construction grants no future identities')
 template=raw(source_path(directory,LANE+'/workflow.yml')).decode();rendered=template.replace('@JOB_SHA256@',files[LANE+'/job.py']['sha256']).replace('@MANIFEST_SHA256@',files[LANE+'/source-manifest.json']['sha256'])
 need(all(raw(source_path(directory,n)).decode()==rendered for n in WORKFLOWS),'rendered source workflow aliases differ')
 need(read(directory/'source-mode-map.json')=={n:r['mode'] for n,r in files.items()},'original source modes differ from publication')
 tree=git_tree(files,lambda n:raw(source_path(directory,n),16*1024**2));need(tree==authorization['tree'],'computed complete source Git tree differs')
 receipt=read(directory/'source-tree.json');need(receipt.get('tree')==tree and receipt.get('files')==len(files) and receipt.get('source_map_sha256')==hashlib.sha256(encoded(files)).hexdigest(),'retained source tree/map/count differs')
 return manifest,files

def verify_reviewed_source(root,files):
 root=Path(root).absolute();need(root==root.resolve(),'canonical trusted reviewed source required')
 for name,row in files.items():
  data=raw(root/name,16*1024**2);need(len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256'],'reader helper source differs from publication: '+name)
  mode='100755' if (root/name).stat().st_mode&0o111 else '100644';need(mode==row['mode'],'reviewed helper executable mode differs')
 actual=set()
 for parent,dirs,names in os.walk(root,followlinks=False):
  if Path(parent)==root:
   if 'retained574-data' in dirs:need(not(root/'retained574-data').is_symlink(),'external DATA directory alias')
   dirs[:]=[n for n in dirs if n not in ('.git','retained574-data')];names=[n for n in names if n!='.git']
  for name in dirs:need(not(Path(parent)/name).is_symlink(),'reviewed source directory alias')
  actual.update((Path(parent)/n).relative_to(root).as_posix() for n in names)
 need(actual==set(files),'whole local reviewed helper closure differs')
 return root

def _helpers(root):
 sys.path[:0]=[str(root/'scripts/build'),str(root/'scripts/checks'),str(root/LANE)]
 contract=load('orphans03_reader_contract',root/LANE/'contract.py');sys.modules['contract']=contract;checks=load('package_checks',root/'scripts/checks/package_checks.py');binding=load('build',root/'scripts/build/build.py');comparison=load('orphans03_reader_compare',root/'scripts/build/compare.py');actor=load('orphans03_reader_lifecycle',root/LANE/'lifecycle.py');transport=load('orphans03_reader_transport',root/LANE/'closed.py')
 return contract,checks,binding,comparison,actor,transport

def check_log(path):
 text=raw(path,16*1024**2).decode(errors='replace');counts=re.findall(r'^Ran (\d+) tests in [0-9.]+s$',text,re.M)
 need('Starting check()' in text and counts==['20','25','8','24','25','7'] and len(re.findall('^OK$',text,re.M))==6 and not re.search(r'\bskipped=|\bOK \(|\bFAILED\b|^ERROR',text,re.M),'exact109 selected package checks without skips required');return dict(count=109,status='PASS_109_NATIVE_PACKAGE_CHECKS_NO_SKIPS')

def verify_builds(directory,source,files,base,runtime,life,helpers):
 C,checks,bind,comparison,_,_=helpers;recipe=C.recipe(source,PRODUCT);inputs={n.removeprefix(RECIPE+'/'):r['sha256'] for n,r in files.items() if n.startswith(RECIPE+'/')}
 need(set(inputs)==PRODUCT_FILES and recipe['input_sha256']==inputs,'exact20 selected0.3 inputs required');metadata=recipe['metadata']
 need(metadata.get('pkgname')==[PRODUCT] and metadata.get('pkgver')==['0.3.0'] and metadata.get('pkgrel')==['2'] and metadata.get('arch')==['any'] and len(metadata.get('source',[]))==18,'selected recipe is not0.3/18 sources')
 B=load('orphans03_reader_full574',source/LANE/'buildinfo_supplement.py');lock=read(source/B.LOCK);full_inputs=dict(body={B.LOCK:raw(source/B.LOCK)},base={r['name']:r['version'] for r in lock['packages']});buildinfo=[]
 archives=[];containers=[]
 for side in ('a','b'):
  root=directory/'runtime'/(PRODUCT+'-'+side);record=read(root/'provenance.json')
  need(record.get('status')=='built-package-static-pass' and record.get('mode')=='native' and record.get('image')==record.get('image_id')==base['image'],'native clean build provenance differs')
  need(record.get('recipe_inputs')==inputs and record.get('recipe_metadata')==metadata,'build selected wrong source/metadata')
  container=record.get('clean_environment_id');need(type(container) is str and re.fullmatch('cachy-asahi-product-[0-9a-f]{32}',container),'owned clean builder identity required');containers.append(container)
  command=record.get('command',[]);need(command[:2]==['docker','run'] and all(flag in command for flag in ('--network=none','--pull=never','--platform=linux/arm64','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges')),'isolated native builder command missing')
  need('--name' in command and command[command.index('--name')+1]==container and '--user' in command and re.fullmatch('[1-9][0-9]*:[0-9]+',command[command.index('--user')+1]),'build owner/user command differs')
  command_row=runtime['commands'][0 if side=='a' else 1];need(command_row.get('argv')==command and command_row.get('log')==PRODUCT+'-'+side+'/build.log','actual command/build provenance differs')
  actual_inputs={p.relative_to(root/'inputs').as_posix() for p in (root/'inputs').rglob('*') if p.is_file()};need(actual_inputs==PRODUCT_FILES,'whole20-file build input closure differs')
  need(record.get('expected_packages_sha256')==C.BASE==digest(root/'expected-packages.lock')==digest(root/'artifacts/packages.lock'),'build base lock differs')
  need(record.get('entry_script_sha256')==files['scripts/build/container-entry.sh']['sha256'],'build entry source differs')
  env=raw(root/'artifacts/environment.txt').decode().splitlines();need(len(env)>=3 and 'aarch64' in env[0].split() and env[1]==str(life['page_size']),'actual build uname/page size absent')
  check_log(root/'build.log');need(C.check_log(root/'build.log',PRODUCT)['count']==109,'contract test gate differs')
  items=record.get('artifacts',{});need(type(items) is dict and len(items)==1,'one0.3 archive required');name=next(iter(items));need(name in {PRODUCT+'-0.3.0-2-any.pkg.tar.'+s for s in ('xz','zst')},'old or wrong archive basename')
  package=checks.package(root/'artifacts'/name);need(package['sha256']==items[name] and not package['errors'] and not package['elf'],'actual script archive differs')
  need(not bind.bind_artifact(metadata,package,inputs['PKGBUILD']),'actual archive metadata/source differs');buildinfo.append(B.verify(package['metadata']['.BUILDINFO'],raw(source/RECIPE/'PKGBUILD'),full_inputs));payload=C.payload(package,source,PRODUCT);need(len(payload)==12,'all12 version0.3 payload files required')
  validation=read(root/'validation.json');need(validation.get('package')==package and validation.get('payload')==payload and validation.get('tests',{}).get('count')==109 and validation.get('errors')==[],'retained validation differs from archive')
  for name_in,pin in inputs.items():need(digest(root/'inputs'/name_in)==pin,'retained recipe snapshot differs')
  archives.append((name,package['sha256']))
 need(len(set(containers))==2,'distinct clean build containers required')
 actual=comparison.compare(directory/'runtime'/(PRODUCT+'-a'),directory/'runtime'/(PRODUCT+'-b'));C.pair_gate(actual)
 need(actual==read(directory/'runtime/comparison.json')==runtime['pair']['comparison'],'independent archive pair replay differs')
 need(len(runtime['pair']['builds'])==2 and [(r['archive'],r['sha256']) for r in runtime['pair']['builds']]==archives and all(r['tests']['count']==109 for r in runtime['pair']['builds']),'pair archive/test identities differ')
 return dict(containers=containers,archives=archives,comparison=actual,full574_buildinfo=buildinfo)

def verify_fixtures(directory,source,files,runtime,control,helpers):
 C,checks,_,_,_,_=helpers;root=directory/'runtime/fixtures';fixtures=control['fixtures']
 need(runtime.get('fixtures')==fixtures==read(root/'fixture-packages.json'),'actual fixture/control/builder joins differ')
 need(digest(root/'expected-packages.lock')==digest(root/'artifacts/packages.lock')==C.BASE,'fixture builder base lock differs')
 for name in ('PKGBUILD','LICENSE'):need(digest(root/'inputs'/name)==files[LANE+'/fixture/'+name]['sha256'],'fixture recipe/license source differs')
 actual={p.name for p in (root/'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')};need(actual=={r['archive'] for r in fixtures.values()},'whole eight built fixture archive set differs')
 for name,row in fixtures.items():
  path=root/'artifacts'/row['archive'];need(digest(path)==row['sha256']==digest(directory/'runtime/lifecycle-inputs'/row['archive']),'built/installed fixture archive differs')
  package=checks.package(path);metadata=package.get('metadata',{}).get('.PKGINFO',{});need(not package['errors'] and not package['elf'] and metadata.get('pkgname')==[name] and metadata.get('pkgver')==['1-1'] and metadata.get('arch')==['any'],'actual inert fixture archive metadata differs')
  members={n:r for n,r in package['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')};need(set(members)=={'usr/share/orphans3-fixture/'+name+'.txt','usr/share/licenses/'+name+'/LICENSE'} and all(r['type']=='0' and r['mode']==0o644 and r['uid']==r['gid']==0 for r in members.values()),'actual fixed inert fixture payload differs')
  need(members['usr/share/licenses/'+name+'/LICENSE']['sha256']==files[LANE+'/fixture/LICENSE']['sha256'],'inert fixture license source differs')
 return True

def verify_target_map(rows):
 need(type(rows) is dict and 0<len(rows)<=32768 and rows.get('.',{}).get('kind')=='directory','complete finite target map required')
 spent=0
 for name,row in rows.items():
  if name!='.':ordinary(name)
  need(type(row) is dict and row.get('kind') in ('file','directory','symlink'),'actual target node kind required')
  for key in ('dev','ino','mode','uid','gid','links','bytes','mtime_ns','ctime_ns'):need(type(row.get(key)) is int and row[key]>=0,'complete target node metadata required')
  need(row['ino']>0 and row['links']>0 and row['mode']<=0o7777,'actual target identity/mode required')
  if row['kind']=='file':
   spent+=row['bytes'];need(row['links']==1 and spent<=MAX_FILE,'bounded single-link target files required')
   if name!='var/lib/pacman/db.lck':need(SHA.fullmatch(row.get('sha256','')),'actual target file hash required')
  if row['kind']=='symlink':need(type(row.get('target')) is str and 0<len(row['target'])<=4096 and '\0' not in row['target'],'actual alias target required')
 return rows

def verify_lifecycle(directory,life,actor):
 actor.validate_lifecycle(life);need(life.get('architecture')=='aarch64' and type(life.get('page_size')) is int and life['page_size']>0 and life.get('version')=='0.3.0-2','native0.3 lifecycle identity required')
 root=directory/'runtime/lifecycle-output';maps={}
 for name,row in life['maps'].items():
  path=ordinary(row['path']);need(path.parts[0]=='maps','fixed lifecycle map path required');p=root/str(path);need(digest(p)==row['sha256'],'target map hash differs');maps[name]=verify_target_map(read(p,MAX_FILE));need(len(maps[name])==row['nodes'],'target map count differs')
 for name in actor.UNCHANGED_CASES:actor.preservation(maps[name+'-before'],maps[name+'-after'])
 removed=actor.positive_removed(maps['positive-before']);actor.preservation(maps['positive-before'],maps['positive-after'],removed)
 need(removed and removed<=set(maps['positive-before'])-set(maps['positive-after']),'complete selected payload/database removal absent')
 for rows in maps.values():need(rows.get('etc/operator-owned.conf')==life['configuration_before'],'authored configuration map identity differs')
 policy=life['policy_contract'];need(digest(root/policy['path'])==policy['sha256'] and read(root/policy['path'])==policy['value'],'retained exact reviewed policy differs')
 need('var/lib/pacman/db.lck' not in maps['final-target'],'final target lock remains')
 for event in life['events']:
  if event['durable_result'] is not None:
   path=ordinary(event['durable_result']);need(path.parts[0]=='reports','fixed durable result path required');need(read(root/str(path))==event['result'],'durable product receipt differs')
  elif event['result'] is not None:need(event['result'].get('commit_started') is False,'missing durable receipt cannot assert commit')
 before_row,after_row=life['base_before'],life['base_after'];need(before_row['path']=='base-before.json' and after_row['path']=='base-after.json','fixed complete base map paths required')
 before=read(root/before_row['path'],MAX_FILE);after=read(root/after_row['path'],MAX_FILE)
 need(digest(root/before_row['path'])==before_row['sha256'] and digest(root/after_row['path'])==after_row['sha256'] and before==after,'actual base preservation differs')
 need(len(before['packages'])==574 and len(before['nodes'])==before_row['nodes']==after_row['nodes'] and hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()==life['base_preservation_sha256'],'complete original574 replay absent')
 expected=dict(line.split() for line in raw(directory/'base/installed-packages.lock').decode().splitlines());need({r['name']:r['version'] for r in before['packages']}==expected==read(directory/'runtime/lifecycle-inputs/base.json'),'base map/installed/input lock identities differ');return maps

def validate(directory,*,authorization,identity,source_sha,run_id,job_id,run_attempt,reviewed_source=None):
 need(type(source_sha) is str and OID.fullmatch(source_sha) and all(type(x) is str and DECIMAL.fullmatch(x) for x in (run_id,job_id,run_attempt)),'explicit source/run/job/attempt identity required')
 expected=dict(source_sha=source_sha,run_id=run_id,job_id=job_id,run_attempt=run_attempt,artifact_name='orphans03-explicit-target-'+run_id+'-'+run_attempt)
 need(type(identity) is dict and all(identity.get(k)==v for k,v in expected.items()),'trusted original collection identity differs')
 need(all(identity.get(key)=='success' for key in ('run_conclusion','job_conclusion')),'complete terminal run/job success metadata required')
 directory=Path(directory).absolute();index=verify_index(directory);manifest,files=verify_source(directory,authorization,source_sha)
 reviewed_source=Path(reviewed_source) if reviewed_source is not None else Path(__file__).resolve().parents[3];reviewed_source=verify_reviewed_source(reviewed_source,files);helpers=_helpers(reviewed_source);C,_,_,_,actor,transport=helpers
 proof=read(directory/'source-proof.json');need(proof.get('status')=='SOURCE_PROOF_PASS' and proof.get('source_sha')==proof.get('workflow_sha')==source_sha and proof.get('run_id')==run_id and proof.get('run_attempt')==run_attempt and proof.get('source_files')==len(manifest['files']) and proof.get('source_total_files')==len(files) and proof.get('source_tree')==authorization['tree'] and proof.get('source_map_sha256')==hashlib.sha256(encoded(files)).hexdigest() and proof.get('artifact_name')==expected['artifact_name'] and proof.get('manifest_sha256')==digest(directory/'source/source-manifest.json'),'actual source/workflow/run/attempt/tree proof differs')
 job_token=hashlib.sha256(('product-build-pair:'+run_id+':'+run_attempt+':'+source_sha).encode()).hexdigest()[:16];need(proof.get('job_token')==job_token,'producer token differs')
 base=read(directory/'base/report.json');runtime=read(directory/'runtime/report.json');owner=read(directory/'runtime/owner.json');ordered=read(directory/'ordered-cleanup.json');life=read(directory/'runtime/lifecycle-output/lifecycle.json')
 need(base.get('status')=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base.get('acquired')==1153 and base.get('failures')==[] and base['ownership']['token']==job_token,'complete original574 producer result missing')
 need(type(base.get('image')) is str and base['image'].startswith('sha256:') and SHA.fullmatch(base['image'][7:]),'exact base image required')
 prefix=getattr(C,'CONSUMER_TOKEN_PREFIX','orphans03-consumer:');consumer=hashlib.sha256((prefix+run_id+':'+run_attempt+':'+source_sha).encode()).hexdigest()[:32]
 need(proof.get('consumer_token')==consumer and runtime.get('status')==RUNTIME and runtime.get('lifecycle')==life and runtime.get('base_image')==base['image']==owner['image'] and runtime.get('ownership_token')==owner.get('token')==consumer and owner.get('label')==C.LABEL and runtime.get('base_count')==574,'runtime/source/base/ownership differs')
 need(runtime.get('base_lock_sha256')==digest(directory/'base/installed-packages.lock')==C.BASE,'base lock differs')
 commands=runtime.get('commands',[]);need(len(commands)==4 and all(row.get('exitcode')==0 and row.get('retirement',{}).get('ownership')=='RETIRED' and row['retirement'].get('leader_reaped') is True and row['retirement'].get('observed_returncode')==0 and row['retirement'].get('log_drained') is True and row['retirement'].get('log_error') is None and row['retirement'].get('error') is None for row in commands),'all four command leaders/logs require observed owned retirement')
 need(life.get('installed_backend',{}).get('sha256')==files[RECIPE+'/live.py']['sha256'],'installed live backend differs from reviewed0.3 payload')
 transport_result=transport.validate_transport(reviewed_source,read(directory/'base/retained-inputs.json'))
 maps=verify_lifecycle(directory,life,actor);builds=verify_builds(directory,reviewed_source,files,base,runtime,life,helpers)
 need(ordered.get('status')=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and ordered.get('authority')=='PASS_ABSENT_AFTER_ACTORS_AND_PRODUCER' and ordered.get('producer')==base.get('owned_cleanup') and base['owned_cleanup'].get('status')=='PASS','ordered producer/TEST authority cleanup incomplete')
 need(set(owner)=={'schema_version','token','image','label','containers'} and owner['schema_version']==1 and ordered['consumer'].get('status')=='PASS_CONSUMERS_RETIRED','exact owned consumer cleanup schema required')
 producer=base['owned_cleanup'];need(producer.get('build')=='COMPLETED' and producer.get('image')==dict(id=base['image'],absence_verified=True) and producer.get('probe',{}).get('name')=='cachy-asahi-574-probe-'+job_token and producer['probe'].get('absence_verified') is True and SHA.fullmatch(producer['probe'].get('cid','')),'owned base image/probe absence missing')
 actors=owner.get('containers',[]);removed=ordered['consumer']['containers'];need(len(actors)==len(set(actors))==len(removed)==4 and {r['container'] for r in removed}==set(actors) and all(r.get('status')=='PASS' and r.get('absence_verified') is True for r in removed) and set(builds['containers'])<=set(actors),'all exact owned consumer absences required')
 control=read(directory/'runtime/lifecycle-inputs/control.json');need(set(control['fixtures'])==set(C.FIXTURES) and re.fullmatch('[0-9A-F]{40}',control['signer']),'exact TEST-signed inert inputs required')
 need(control['candidate']['archive']==builds['archives'][0][0] and control['candidate']['sha256']==builds['archives'][0][1],'installed candidate differs from0.3 build')
 for row in [control['candidate'],*control['fixtures'].values()]:
  name=row['archive'];need(type(name) is str and Path(name).name==name and digest(directory/'runtime/lifecycle-inputs'/name)==row['sha256'],'installed archive missing or changed')
  signature=raw(directory/'runtime/lifecycle-inputs'/(name+'.sig'),16384);need(0<len(signature)<=16384,'retained detached TEST signature absent')
 verify_fixtures(directory,reviewed_source,files,runtime,control,helpers)
 authority=read(directory/'runtime/authority.json');need(authority.get('directory')=='test-signing' and authority.get('mode')==0o700 and authority.get('signer')==control['signer'],'recorded TEST authority custody differs')
 return dict(status='PASS_OFFLINE_ORPHANS03_NATIVE_COMPONENT_REPLAY',scope=SCOPE,identities=expected,source_files=len(files),product_files=20,package_version='0.3.0-2',package_checks_per_build=109,payload_files=12,architecture='aarch64',page_size=life['page_size'],maps=len(maps),full574_buildinfo=builds['full574_buildinfo'],retained_files=len(index['files']),transport=transport_result,hardware='NOT_RUN',release='NOT_ADMITTED',host_live_target_removal='NOT_PROVEN',identity_authority='ROOT_SUPPLIED_PUBLICATION_AND_ONCE_COLLECTED_ORIGINAL_METADATA')

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--originals',type=Path,required=True);parser.add_argument('--source-authorization',type=Path,required=True);parser.add_argument('--original-identity',type=Path,required=True);parser.add_argument('--reviewed-source',type=Path)
 for name in ('source-sha','run-id','job-id','run-attempt'):parser.add_argument('--'+name,required=True)
 args=parser.parse_args(argv)
 try:result=validate(args.originals,authorization=read(args.source_authorization),identity=read(args.original_identity),source_sha=args.source_sha,run_id=args.run_id,job_id=args.job_id,run_attempt=args.run_attempt,reviewed_source=args.reviewed_source)
 except Exception as error:print(json.dumps(dict(status='REFUSED_OR_INCOMPLETE',error_type=type(error).__name__,error=str(error)[:1000]),sort_keys=True));return 1
 print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
