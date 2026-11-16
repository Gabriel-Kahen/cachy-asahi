#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Portable inert MODEL/adversarial controls. No actor, Source execution or network."""
import ast,base64,copy,gzip,hashlib,importlib.util,io,json,os,stat,struct,tempfile,unittest,zipfile,tarfile,runpy,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.')) or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('portable v15 MODEL forbids process/network/authority operations: '+event)
sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('independent_rust_reader_v15_under_test',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
S,B,E,A=R.S,R.B,R.E,R.A
mspec=importlib.util.spec_from_file_location('reader13_actor_mount_model',HERE/'test_mounts.py');M=importlib.util.module_from_spec(mspec);mspec.loader.exec_module(M);M.S=S;M.E=E
bspec=importlib.util.spec_from_file_location('reader15_reader_owned_bind_model',HERE/'test_owned_bind.py');W=importlib.util.module_from_spec(bspec);bspec.loader.exec_module(W);W.S=S;W.E=E
ACTUAL_FAILURE_PIN={'bytes': 2454, 'sha256': 'ab80b4456df882aea34b2e8c6317ab60623fb4ad0b1d6c1d087410cc64100b97'}

def life():return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=0)
def selected():
 return dict(source='1'*40,ref='refs/heads/codex/rust199-source361-native-v15-MODEL',run='100',bootstrap_job='101',build_job='102',bootstrap_artifact_id='104',build_artifact_id='105',source_review_sha256='2'*64,dispatch_sha256='3'*64)
def shape():return S.decode((HERE.parent/'successor_v8/Root-admission.TEMPLATE.json').read_bytes())
def model_dispatch():
 v=shape();sel=selected();sel['initial_redirect_hosts']=dict.fromkeys(B.CARRIERS,['productionresultssa1.blob.core.windows.net']);resources={'MODEL_limit':1};v['resources']=resources;source={'resource-policy.json':(S.canonical(resources),0o644)}
 v.update(schema=5,status='ROOT_ADMITTED_RUST199_PHASE_TRANSFER_ONCE',once=True,retry=False,holds_preserved=True,source=dict(sha=sel['source'],ref=sel['ref'],map_sha256=S.SOURCE['map_sha256'],approval=sel['source_review_sha256'],run=None,job=None),reviews=dict.fromkeys(v['reviews'],True))
 v['bootstrap'].update(provider_policy_reviewed=True,qualification_allowed=True,network_during_qualification=False);v['delivery']['status']='ROOT_ADMITTED_FINITE_RUST_MATERIAL_DELIVERY'
 for role in B.CARRIERS:v['delivery'][role].update(accepted_by_root=True,redirect_hosts=sel['initial_redirect_hosts'][role])
 return v,sel,source

def compact(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def jobs(sel,status='completed'):
 return dict(total_count=2,jobs=[dict(id=int(sel[p+'_job']),run_id=int(sel['run']),head_sha=sel['source'],run_attempt=1,name='rust199-'+p+'-v4',status=status,conclusion='success'if status=='completed'else None)for p in('bootstrap','build')])
def run(sel,status='completed'):
 return dict(id=int(sel['run']),run_attempt=1,head_sha=sel['source'],head_branch=sel['ref'].removeprefix('refs/heads/'),event='workflow_dispatch',workflow_id=B.WORKFLOW,path=B.WF,status=status,conclusion='success'if status=='completed'else None,repository=dict(id=B.REPO_ID,full_name=B.REPO),head_repository=dict(id=B.REPO_ID,full_name=B.REPO))
def transfer_model():
 grant,sel,_=model_dispatch();raw=compact(grant);sel['dispatch_raw']=raw;sel['dispatch_sha256']=S.pin(raw)['sha256']
 bootstrap=dict(source=dict(grant['source'],run=sel['run'],job=sel['bootstrap_job']))
 image=dict(bytes=120,sha256='a'*64);artifact_pin=dict(bytes=456,sha256='b'*64)
 t=dict(artifact_id='103',artifact=artifact_pin,image=image,image_id='sha256:'+'c'*64,storage_host='productionresultssa2.blob.core.windows.net');sel['transfer']=t
 manifest=dict(schema=4,status='QUALIFIED_BOOTSTRAP_PHASE_TRANSFER_DATA_ONLY',source=bootstrap['source'],bootstrap_provider=bootstrap,dispatch_sha256=sel['dispatch_sha256'],dispatch_raw=raw.decode(),image_id=t['image_id'],files={'image.tar':dict(image,mode=0o444)},native_acceptance=False,holds_preserved=True)
 manifest_raw=S.canonical(manifest);t['manifest_sha256']=S.pin(manifest_raw)['sha256']
 binding=dict(source=sel['source'],ref=sel['ref'],map_sha256=S.SOURCE['map_sha256'],run=sel['run'],attempt=1,bootstrap_job=sel['bootstrap_job'],build_job=sel['build_job'],artifact_id=t['artifact_id'],artifact_sha256=t['artifact']['sha256'],manifest_sha256=t['manifest_sha256'],image_id=t['image_id'],image_pin=t['image'])
 policy=S.decode((HERE.parent/'successor_v8/payload/hosted/phase-transfer-provider-policy.json').read_bytes())
 observation=dict(schema=8,kind='POSTSTART_PHASE_TRANSFER_STORAGE_OBSERVATION_V8',policy_pin=B.POLICY,binding=binding,credentials_forwarded=False,Root_acceptance=None,native_acceptance=False,storage_host=t['storage_host'])
 artifact=dict(id=103,expired=False,size_in_bytes=456,digest='sha256:'+'b'*64,name='rust199-qualified-transfer-v4-100-1',workflow_run=dict(id=100,head_sha=sel['source'],head_branch=sel['ref'].removeprefix('refs/heads/'),repository_id=B.REPO_ID,head_repository_id=B.REPO_ID))
 job=dict(id=101,run_id=100,head_sha=sel['source'],head_branch=sel['ref'].removeprefix('refs/heads/'),run_attempt=1,name='rust199-bootstrap-v4',status='completed',conclusion='success')
 paths=['/repos/'+B.REPO+'/actions/artifacts/103','/repos/'+B.REPO+'/actions/jobs/101','/repos/'+B.REPO+'/actions/runs/100']
 rows=[dict(host='api.github.com',path=p,status=200,bytes=20)for p in paths]+[dict(host='api.github.com',path=paths[0]+'/zip',status=302,bytes=0),dict(host=t['storage_host'],path='/public/MODEL.zip',status=200,bytes=456)]
 acquisition=dict(schema=4,status='FINITE_PHASE_TRANSFER_GET_DATA_ONLY',native_acceptance=False,requests=rows)
 return [grant,sel,policy,artifact,job,run(sel,'in_progress'),observation,acquisition,manifest,manifest_raw,bootstrap]

def elf_bytes(machine=183,alignment=4096,rpath=None):
 header=bytearray(64);header[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',header,16,3,machine);struct.pack_into('<Q',header,32,64);struct.pack_into('<HH',header,54,56,2 if rpath else 1)
 if not rpath:return bytes(header)+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,alignment)
 strings=b'\0'+rpath.encode()+b'\0';offset=240;total=offset+len(strings)
 return bytes(header)+struct.pack('<IIQQQQQQ',1,5,0,0,0,total,total,alignment)+struct.pack('<IIQQQQQQ',2,4,176,176,176,64,64,8)+b''.join(struct.pack('<qQ',*r)for r in[(5,offset),(10,len(strings)),(29,1),(0,0)])+strings

def tar_bytes(files):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT)as archive:
  for name,value in files.items():
   kind,mode,body=value;row=tarfile.TarInfo(name);row.mode=mode;row.uid=row.gid=0
   if kind=='dir':row.type=tarfile.DIRTYPE;archive.addfile(row)
   elif kind=='link':row.type=tarfile.SYMTYPE;row.linkname=body;archive.addfile(row)
   else:row.size=len(body);archive.addfile(row,io.BytesIO(body))
 return out.getvalue()

def package_model(change=None):
 prefix=A.PREFIX;notice=A.NOTICES;body=b'MODEL exact notice\n';digest=S.pin(body)['sha256'];grant=b'MODEL upstream grant\n';gd=S.pin(grant)['sha256'];scope='EXACT_SOURCE_FILES_CONTAINING_CATALOGUED_NOTICE_CONTEXTS_ONLY_NO_LEGAL_ACCEPTANCE'
 catalogue=dict(scope=scope,grant_scope='MODEL retained grant evidence only',source_archive=S.pin(b'MODEL archive'),files={'LICENSE':S.pin(body)},retained_upstream_grant_bodies={gd:dict(S.pin(grant),text=grant.decode(),path='MODEL-retained.txt',context='MODEL')},components=[dict(component='MODEL-component',retained_exact_upstream_grant_bodies=[gd])]);raw=S.canonical(catalogue)
 row=catalogue['retained_upstream_grant_bodies'][gd]
 index=dict(scope=scope,holds_preserved=True,source_archive=catalogue['source_archive'],catalogue_sha256=S.pin(raw)['sha256'],copyright_ownership_inferred=False,manifest_authors_are_owners=False,paths={'LICENSE':dict(S.pin(body),body='bodies/'+digest+'.txt')},retained_grants={gd:dict(S.pin(grant),retained_evidence_path=row['path'],retained_evidence={k:v for k,v in row.items()if k!='text'},body='bodies/'+gd+'.txt',components=['MODEL-component'],scope=catalogue['grant_scope'])})
 deps=['bash','curl','gcc','glibc','libgcc','libstdc++','libgit2','libssh2','openssl','sqlite','zlib','cachy-asahi-llvm23-source-reference=23.1.1'];inventory=b'MODEL 1-1\n'
 files={'.PKGINFO':('file',0o644,('pkgname = cachy-asahi-rust199-source-reference\npkgver = 1.99.0-1\narch = aarch64\n'+''.join('depend = '+n+'\n'for n in deps)).encode()),'.BUILDINFO':('file',0o644,b'pkgname = cachy-asahi-rust199-source-reference\npkgver = 1.99.0-1\npkgarch = aarch64\ninstalled = MODEL-1-1\n')}
 for tool in('bin/rustc','bin/cargo','bin/rustdoc','bin/rustfmt','bin/clippy-driver','libexec/rust-analyzer-proc-macro-srv'):files[prefix+'/'+tool]=('file',0o755,elf_bytes())
 files[prefix+'/lib/rustlib/src/rust/library/Cargo.toml']=('file',0o644,b'[workspace]\n');files[notice+'catalogue.DATA.json']=('file',0o644,raw);files[notice+'index.json']=('file',0o644,S.canonical(index));files[notice+'bodies/'+digest+'.txt']=('file',0o644,body);files[notice+'bodies/'+gd+'.txt']=('file',0o644,grant)
 if change:change(files,index,catalogue)
 lines=[]
 for name,(kind,mode,body)in files.items():
  line='./'+name+' type='+kind+' uid=0 gid=0 mode='+oct(mode)[2:]
  if kind=='file':line+=' size='+str(len(body))+' sha256digest='+S.pin(body)['sha256']
  elif kind=='link':line+=' link='+body
  lines.append(line)
 files['.MTREE']=('file',0o644,gzip.compress(('\n'.join(lines)+'\n').encode(),mtime=0))
 return tar_bytes(files),{'packages/port/rust199-source-reference/notice-catalogue.DATA.json':(raw,0o644)},inventory,files

def actor_model():
 materials={name:dict(role='stage0'if name.startswith(('cargo','rust-std','rustc-1.98'))else'source')for name in('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz','llvm-project-23.1.1.src.tar.xz','rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.99.0-src.tar.xz')}
 source={n:(body,0o644)for n,body in {'contract.json':b'MODEL contract','actor/mount_proof.py':b'MODEL independent mount helper','packages/port/rust199-source-reference/reference.py':b'MODEL code DATA only','packages/port/rust199-source-reference/bootstrap.toml':b'MODEL configuration DATA only','packages/port/rust199-source-reference/inputs.json':S.canonical(dict(archives=materials))}.items()}
 sel=selected();binding=dict(sha=sel['source'],ref=sel['ref'],map_sha256=S.SOURCE['map_sha256'],approval=sel['source_review_sha256'],run=sel['run'],job=sel['build_job']);a=dict(candidate_admission=dict(sha256='a'*64),source=binding,image=dict(id='sha256:'+'f'*64),authorization=dict(dispatch=dict(sha256=sel['dispatch_sha256'])));q=dict(stage0_tree_sha256='b'*64);volume='c'*64;root=S.pin(S.canonical(a))['sha256'];data={};pkg=dict(file=A.PACKAGE,bytes=4,sha256=S.pin(b'MODEL')['sha256']);prepared=dict(admission_sha256='a'*64,config_sha256=S.pin(source['packages/port/rust199-source-reference/bootstrap.toml'][0])['sha256']);built=dict(prepared,staged_tree_sha256='d'*64)
 data.update({'prepared.json':S.canonical(prepared),'built.json':S.canonical(built),'actual-packages.txt':b'MODEL 1-1\n'})
 for i,phase in enumerate(('prepare','build','package','makepkg')):
  receipt=dict(schema=1,status='COMPLETED_ACTOR_ACTION_DATA',action=phase,root_admission_sha256=root,native_acceptance=False,holds_preserved=True)
  if phase=='makepkg':
   receipt.update(command=0,package=pkg,inventory=dict(file='actual-packages.txt',**S.pin(data['actual-packages.txt'])))
   for leaf in('prepared.json','built.json'):receipt[leaf]=dict(file=leaf,**S.pin(data[leaf]))
  else:
   counts=dict(extract=5,probe=0,build=0,project=0)if phase=='prepare'else dict(extract=0,probe=9,build=1,project=2)if phase=='build'else dict(extract=0,probe=0,build=0,project=0)
   receipt['phase']=dict(status='COMPLETED_NATIVE_PHASE_DATA',phase=phase,candidate_sha256=S.pin(source['packages/port/rust199-source-reference/reference.py'][0])['sha256'],candidate_admission_sha256='a'*64,stage0_tree_sha256='b'*64,native_acceptance=False,holds_preserved=True,commands=counts)
  context=dict(source=binding,dispatch_sha256=sel['dispatch_sha256'],input_admission_sha256=root,image_id=a['image']['id'],volume_token=S.pin(S.canonical(binding))['sha256'][:24],phase=phase)
  envelope,bodies,*_=M.proof_model(phase,context=context,helper_sha256=S.pin(source['actor/mount_proof.py'][0])['sha256'],invocation='10-'+str(i)*32)
  data.update(bodies);receipt['kernel_mount_proof']=envelope
  data['phase-'+phase+'-10-'+str(i)*32+'.json']=S.canonical(receipt)
 env=dict(PATH=f'/stage0/bin:{E.LLVM}/bin:/usr/bin:/bin',HOME='/work/build/home',CARGO_HOME='/work/build/cargo-home',LIBGIT2_NO_VENDOR='1',LIBSSH2_SYS_USE_PKG_CONFIG='1',LIBSQLITE3_SYS_USE_PKG_CONFIG='1',CARGO_NET_OFFLINE='true',CACHY_ASAHI_RUST199_STAGE0_SHA256='b'*64,CACHY_ASAHI_RUST199_BUILD='1',CACHY_ASAHI_RUST199_ADMISSION='/inputs/candidate-admission.json',CACHY_ASAHI_RUST199_ADMISSION_SHA256='a'*64,LC_ALL='C',TZ='UTC',DESTDIR='/work/build/dest',MAKEFLAGS='-j2',ROOT_ADMISSION_SHA256=root,SOURCE_MAP_SHA256=S.SOURCE['map_sha256'],CONTRACT_SHA256=S.pin(source['contract.json'][0])['sha256'],WORK_VOLUME_ADMISSION_SHA256=volume,PYTHONDONTWRITEBYTECODE='1')
 extracts=[['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf','/work/build/verified-materials/'+name,'-C','/work/build/stage0-unpack'if row['role']=='stage0'else'/work/build']for name,row in materials.items()]
 vectors=[('prepare',v)for v in extracts]+[('build',v)for v in E.PROBES+[E.BUILD]]+[('makepkg',['/usr/bin/pacman','-Q']),('makepkg',E.MAKEPKG)]
 for i,(phase,argv)in enumerate(vectors):
  name='cmd-10-'+format(i,'032x');stdout=b'MODEL stdout';stderr=b'';data[name+'.stdout']=stdout;data[name+'.stderr']=stderr
  row=dict(schema=1,phase=phase,argv=argv,cwd='/work/recipe'if phase=='makepkg'else'/work/build'if phase=='prepare'else'/work/build/rustc-1.99.0-src',environment_sha256=S.pin(S.canonical(env))['sha256'],capture=argv in E.PROBES or argv==['/usr/bin/pacman','-Q'],lifecycle=life(),returncode=0,kernel_mount_proof_sha256=S.decode(next(v for k,v in data.items()if k.startswith('phase-'+phase+'-')))['kernel_mount_proof']['receipt']['sha256'],stdout=dict(file=name+'.stdout',**S.pin(stdout)),stderr=dict(file=name+'.stderr',**S.pin(stderr)));data[name+'.json']=S.canonical(row)
 return data,pkg,a,source,q,volume

def qualification_model():
 sel=selected();bootstrap=dict(source=dict(sha=sel['source'],ref=sel['ref'],map_sha256=S.SOURCE['map_sha256'],approval=sel['source_review_sha256'],run=sel['run'],job=sel['bootstrap_job']),dispatch_sha256=sel['dispatch_sha256']);ro=dict(paths=['/stage0','/work/build/stage0'],readonly=True,namespace_permissions_verified=True,write_attempts_denied=True,alias_write_attempts_denied=True,attempts=[dict(path=p,errno=30,denied=True)for p in('/stage0','/work/build/stage0')]);q=dict(schema=4,status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY',binding=bootstrap['source'],dispatch_sha256=bootstrap['dispatch_sha256'],provider_phase_sha256=S.pin(S.canonical(bootstrap))['sha256'],image_id='sha256:'+'a'*64,native_acceptance=False,holds_preserved=True,readonly_stage0=ro,probe_receipts=[dict(argv=v,returncode=0,lifecycle=life())for v in E.PROBES])
 q.update(dict.fromkeys(('rootfs_tree_sha256','qualified_llvm_tree_sha256','stage0_tree_sha256','library_cargo_config_sha256','source_tree_sha256'),'b'*64));return q,bootstrap,q['image_id']

def transferred_qualification_model():
 q,bootstrap,image=qualification_model();sel=selected();sel['transfer']=dict(image_id=image)
 binding=dict(source=sel['source'],ref=sel['ref'],run=sel['run'],job=sel['bootstrap_job'],source_map_sha256=S.SOURCE['map_sha256'],approval=sel['source_review_sha256']);token=S.pin(S.canonical(binding))['sha256'][:24]
 owner=dict(source=sel['source'],run=sel['run'],job=sel['bootstrap_job'],token=token,base_tag='rust199-base:'+token,tag='rust199-qualified:'+token)
 fields={};members={};bodies={}
 def retain(name,body):
  member='proofs/'+name;key='retained/'+name;members[member]=key;bodies[key]=body
  return dict(local_path={'__rust_phase_file__':member},**S.pin(body))
 outputs=(b'release: 1.98.0\n',b'host: aarch64-unknown-linux-gnu\n',b'/stage0\n',b'cargo 1.98.0 MODEL\n',b'rustdoc 1.98.0 MODEL\n',b'23.1.1\n',b'AArch64\n',b'aarch64-model-linux-gnu\n',b'MODEL gcc 23.1.1\n')
 for i,(receipt,stdout)in enumerate(zip(q['probe_receipts'],outputs)):
  receipt.update(stdout='probe-'+str(i)+'.stdout',stderr='probe-'+str(i)+'.stderr')
  fields['qualification_'+receipt['stdout']]=retain(receipt['stdout'],stdout);fields['qualification_'+receipt['stderr']]=retain(receipt['stderr'],b'')
 custody=dict(init='1'*64,data='2'*64,probe='3'*64);work_bind,*_=W.model('bootstrap',bootstrap['source']);controller=dict(container_ids=custody,status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY',errors=[],owned_resources_absent=True,result=dict(q,owned_work_bind=work_bind),owned_work_bind=work_bind)
 fields['qualification_controller']=retain('controller.json',S.canonical(controller))
 extraction=dict(files=17,logical_bytes=4096,rootfs_tree_sha256=q['rootfs_tree_sha256'],digest_timing='PRIVATE_READABLE_STAGING_BEFORE_EXACT_MODE_FINALIZATION',final_modes_verified=True)
 boot=dict(owner=owner,provider_binding=bootstrap,status='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA',errors=[],native_acceptance=False,image=image,rootfs_tree_sha256=q['rootfs_tree_sha256'],extraction=extraction)
 manifest=dict(owner=owner,metadata=dict(boot=boot,qual=dict(q,files=fields,owned_work_bind=work_bind)))
 return manifest,SimpleNamespace(bodies=bodies,member=lambda name,cap:bodies[name]),members,q,bootstrap,sel,custody

def producer_model():
 sel=selected();binding=dict(sha=sel['source'],ref=sel['ref'],run=sel['run'],job=sel['build_job'],map_sha256=S.SOURCE['map_sha256'],approval=sel['source_review_sha256']);image='sha256:'+'f'*64;a=dict(source=binding,image=dict(id=image));root=S.pin(S.canonical(a))['sha256'];token=S.pin(S.canonical(binding))['sha256'][:24];base='rust199-'+token;owner=dict(source=binding,image=image,root_admission_sha256=root,token=token,init=base+'-init',prepare=base+'-prepare',makepkg=base+'-makepkg',volume=base+'-work',operation=B.OP)
 p=dict(schema=1,status='COMPLETED_EXPORTED_RETIRED',operation=B.OP,source=binding,image=image,prepare_completed=True,makepkg_completed=True,owned_resources_absent=True,errors=[],root_admission_sha256=root,native_acceptance=False,hardware_acceptance=False,release_acceptance=False,export=dict(lifecycle=life()),volume_binding=owner,actors={k:owner[k]for k in('init','prepare','makepkg')},volume=owner['volume']);finished={}
 for i,role in enumerate(('init','prepare','makepkg')):
  labels={'cachy-asahi.'+k:v for k,v in dict(source=sel['source'],run=sel['run'],job=sel['build_job'],role=role,token=token,operation=B.OP).items()};finished[role]=dict(Id=str(i+1)*64,Name='/'+owner[role],Image=image,State=dict(Status='exited',ExitCode=0,Running=False,OOMKilled=False,Restarting=False,Error=''),Config=dict(Labels=labels))
 return p,a,sel,finished

class Controls(unittest.TestCase):
 def setUp(self):S.END=None
 def refuses(self,code,fn,*args):
  with self.assertRaisesRegex(S.Hold,code):fn(*args)
 def test_unissued_refuses_before_any_input_read(self):
  with patch.object(R,'Corpus',side_effect=AssertionError('must not read')):self.assertEqual(R.evaluate({},None,None,None)['reason'],'ROOT_READER_SELECTION_UNISSUED')
 def test_selector_exact_current_source_jobs(self):
  v=dict(schema=15,kind='ROOT_SELECTED_RUST361_RETAINED_EVIDENCE_READER_V15',issuer='Root',approved=True,selected=selected(),resources=R.MAX);self.assertEqual(R.selector(v)['run'],'100')
  v['selected']['build_job']='101';self.refuses('ROOT_EXACT_SOURCE_RUN_JOB',R.selector,v)
 def test_no_source_or_producer_execution(self):
  for leaf in('storage.py','bindings.py','evidence.py','archives.py','reader.py'):
   tree=ast.parse((HERE/leaf).read_text());imports=[n for n in ast.walk(tree)if isinstance(n,(ast.Import,ast.ImportFrom))]
   self.assertFalse(any(any(k in ast.unparse(n)for k in('subprocess','socket','ctypes','urllib','requests'))for n in imports))
  self.assertIn('INDEPENDENT_TAR_ELF_HELPER_PIN',(HERE/'archives.py').read_text());self.assertNotIn('exec(', (HERE/'storage.py').read_text())
 def test_json_duplicate_nonfinite_deep_refusal(self):
  self.refuses('DUPLICATE',S.decode,b'{"x":1,"x":2}');self.refuses('NONFINITE',S.decode,b'{"x":NaN}')
  with patch.object(R,'read',side_effect=RecursionError):self.assertEqual(R.evaluate({},None,None,None)['reason'],'MALFORMED_OR_UNSUPPORTED_RETAINED_RECURSIONERROR')
 def test_relative_paths(self):
  for value in('../x','/x','a//b','a/./b','a\\b','a\nx','.git/config'):
   if value.startswith('.git'):continue
   self.refuses('UNSAFE',S.relative,value)
 def test_stable_read_and_hardlink_symlink_refusal(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);p=root/'data';p.write_bytes(b'MODEL');self.assertEqual(S.read(p),b'MODEL');self.assertEqual(S.hashed(p,5),S.pin(b'MODEL'))
   os.link(p,root/'hard');self.refuses('INPUT_KIND',S.read,p);(root/'hard').unlink();(root/'alias').symlink_to(p);self.refuses('ALIAS',S.read,root/'alias')
 def test_atime_only_projection_and_content_metadata(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'data';p.write_bytes(b'MODEL');before=p.stat();row=SimpleNamespace(**{k:getattr(before,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')},st_atime_ns=before.st_atime_ns+1)
   self.assertEqual(S.identity(before),S.identity(row));row.st_mtime_ns+=1;self.assertNotEqual(S.identity(before),S.identity(row))
   with patch.object(S.os,'fstat',side_effect=[before,row]):self.refuses('INPUT_CHANGED',S.read,p)
 def test_namespace_extra_empty_directory_refused(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp);(p/'file').write_bytes(b'1');self.assertEqual(S.namespace(p),{'file'});(p/'extra').mkdir();self.refuses('EMPTY_OR_UNLISTED',S.namespace,p)
 def test_external_source_contract_fixed(self):
  code='SOURCE15_CONTRACT_UNPINNED'if S.SOURCE['files']is None else'EXTERNAL_SOURCE_PROFILE'
  self.refuses(code,S.source,None,b'{}',dict(S.SOURCE,files=344))
  self.assertIn(S.SOURCE['files'],(None,361))
 def test_dispatch_exact_reviewed_shape(self):
  v,sel,source=model_dispatch();self.assertEqual(B.dispatch(compact(v),shape(),source,sel),v)
  for mutate in(lambda x:x['claims'].update(native_acceptance=True),lambda x:x['reviews'].update(stage0=False),lambda x:x.update(retry=True),lambda x:x['resources'].update(extra=1)):
   other=copy.deepcopy(v);mutate(other)
   with self.assertRaises(S.Hold):B.dispatch(compact(other),shape(),source,sel)
 def test_dispatch_noncanonical_bytes(self):
  v,sel,source=model_dispatch();self.refuses('CANONICAL',B.dispatch,S.canonical(v),shape(),source,sel)
 def test_initial_three_provider_tuples(self):
  grant={'delivery':{}};objects={};raws={}
  for i,role in enumerate(B.CARRIERS):
   art=dict(id=i+1,expired=False,size_in_bytes=20,workflow_run=dict(id=10+i,head_sha='1'*40),digest=None);job=dict(id=100+i,run_id=10+i,head_sha='1'*40,status='completed',conclusion='success')
   objects.update({role+'_artifact':art,role+'_job':job});raws.update({role+'_artifact':S.canonical(art),role+'_job':S.canonical(job)})
   grant['delivery'][role]=dict(id=str(i+1),bytes=20,sha256='a'*64,run=str(10+i),job=str(100+i),source='1'*40,metadata_sha256=S.pin(raws[role+'_artifact'])['sha256'],job_metadata_sha256=S.pin(raws[role+'_job'])['sha256'])
  self.assertEqual(len(B.initial_carriers(grant,objects,raws)),3);objects[B.CARRIERS[0]+'_job']['conclusion']='failure';self.refuses('TERMINAL_JOB',B.initial_carriers,grant,objects,raws)
 def test_two_terminal_jobs_and_retries(self):
  sel=selected();B.terminal(run(sel),jobs(sel),sel)
  for key,value in(('run_attempt',2),('event','push'),('head_sha','f'*40),('workflow_id',1)):
   bad=run(sel);bad[key]=value;self.refuses('TERMINAL_RUN',B.terminal,bad,jobs(sel),sel)
  bad=jobs(sel);bad['jobs'][1]['id']=101;self.refuses('TERMINAL_PHASE_JOB',B.terminal,run(sel),bad,sel)
 def test_start_provider_binding(self):
  grant,sel,_=model_dispatch();j=S.canonical(jobs(sel,'in_progress'));p=dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase='build',source=dict(grant['source'],run='100',job='102'),run_attempt=1,manual_dispatch=True,readback_required=True,native_acceptance=False,dispatch_sha256=sel['dispatch_sha256'],job_metadata_sha256=S.pin(j)['sha256']);B.provider(p,'build',grant,sel,j);p['source']['job']='101';self.refuses('WHOLE_BINDING',B.provider,p,'build',grant,sel,j)
 def test_v8_selected_storage_and_whole_needs_join(self):
  args=transfer_model();self.assertEqual(B.transfer(*args)['artifact_id'],'103')
  for index,key,value,reason in((6,'storage_host','productionresultssa3.blob.core.windows.net','EXACT_OBSERVED'),(3,'digest','sha256:'+'d'*64,'ARTIFACT_TUPLE'),(4,'id',102,'NEEDS_BOOTSTRAP'),(5,'run_attempt',2,'PREIMPORT_RUNNING')):
   other=copy.deepcopy(args);other[index][key]=value;self.refuses(reason,B.transfer,*other)
 def test_v8_token_query_credential_or_policy_mutation(self):
  for mutation in('query','credentials','policy','manifest','requests'):
   args=transfer_model()
   if mutation=='query':args[7]['requests'][-1]['path']+='?sig=MODEL'
   elif mutation=='credentials':args[6]['credentials_forwarded']=True
   elif mutation=='policy':args[2]['accepted']=True
   elif mutation=='manifest':args[8]['dispatch_raw']='different\n'
   else:args[7]['requests']*=2
   with self.assertRaises(S.Hold):B.transfer(*args)
 def test_phase_operations_log_is_from_own_artifact(self):
  raw=b'MODEL';pin=S.pin(raw);row=dict(argv=['MODEL'],returncode=0,lifecycle=life(),stdout=dict(pin,file='operations/000.stdout'),stderr=dict(pin,file='operations/000.stderr'));c=SimpleNamespace(rows={'build/operations/000.stdout':pin,'build/operations/000.stderr':pin});members={'operations/000.stdout':'build/operations/000.stdout','operations/000.stderr':'build/operations/000.stderr'}
  self.assertEqual(E.operations([row],c,'build',members),1);self.refuses('COMPLETE_CAPTURE',E.operations,[row],c,'build',{})
 def test_forced_nonzero_or_missing_retirement_refused(self):
  E.natural(life())
  for key,value in(('forced_cleanup',True),('exit',134),('group_absent',False),('ownership_lost',True),('cleanup_error','MODEL')):
   row=life();row[key]=value;self.refuses('NATURAL_RETIREMENT',E.natural,row)
 def test_zip_whole_members_and_alias_refusal(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'artifact.zip'
   with zipfile.ZipFile(p,'w')as z:z.writestr('proof.json',b'MODEL')
   c=SimpleNamespace(rows={'retained/proof':S.pin(b'MODEL')});self.assertEqual(A.zip_members(p,S.pin(p.read_bytes()),{'proof.json':'retained/proof'},c,100000)['files'],1)
   c.rows['retained/proof']=S.pin(b'other');self.refuses('WHOLE_MEMBER_PIN',A.zip_members,p,S.pin(p.read_bytes()),{'proof.json':'retained/proof'},c,100000)
   with zipfile.ZipFile(p,'w')as z:z.writestr('../escape',b'MODEL')
   self.refuses('UNSAFE_RELATIVE',A.zip_members,p,S.pin(p.read_bytes()),{'../escape':'retained/proof'},c,100000)
 def test_zip_symlink_refused(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'artifact.zip';row=zipfile.ZipInfo('alias');row.create_system=3;row.external_attr=(stat.S_IFLNK|0o777)<<16
   with zipfile.ZipFile(p,'w')as z:z.writestr(row,b'target')
   self.refuses('ZIP_SPECIAL',A.zip_members,p,S.pin(p.read_bytes()),{'alias':'body'},SimpleNamespace(rows={'body':S.pin(b'target')}),100000)
 def test_independent_elf_projection_and_machine_rejection(self):
  A.helper();model=elf_bytes(rpath='$ORIGIN/../lib:'+E.LLVM+'/lib');result=A.ELF(io.BytesIO(model),len(model),A.PREFIX+'/bin/rustc');self.assertIn('/'+A.PREFIX+'/lib',result['rpaths'])
  for bad in(elf_bytes(machine=62),elf_bytes(alignment=1024),elf_bytes(rpath='/tmp/private')):
   with self.assertRaises(ValueError):A.ELF(io.BytesIO(bad),len(bad),A.PREFIX+'/bin/rustc')
 def test_package_model_elf_inventory_notice_and_mtree(self):
  raw,source,inventory,_=package_model()
  with tempfile.TemporaryDirectory()as temp:result=A.package_tar(io.BytesIO(raw),source,inventory,Path(temp))
  self.assertEqual(result['elf_files'],6);self.assertEqual(result['new_tool_runtime'],'NOT_EMITTED_NOT_QUALIFIED');self.assertFalse(result['legal_acceptance'])
 def test_package_library_node_not_a_file(self):
  raw,source,inventory,_=package_model(lambda f,i,c:f.update({A.PREFIX+'/lib/rustlib/src/rust/library/Cargo.toml':('dir',0o755,b'')}))
  with tempfile.TemporaryDirectory()as temp:self.refuses('LIBRARY_SOURCE',A.package_tar,io.BytesIO(raw),source,inventory,Path(temp))
 def test_notice_grant_context_tamper(self):
  def change(files,index,catalogue):
   row=next(iter(index['retained_grants'].values()));row['retained_evidence']['context']='forged';files[A.NOTICES+'index.json']=('file',0o644,S.canonical(index))
  raw,source,inventory,_=package_model(change)
  with tempfile.TemporaryDirectory()as temp:self.refuses('EXACT_RETAINED_GRANT',A.package_tar,io.BytesIO(raw),source,inventory,Path(temp))
 def test_package_wrong_arch_and_escape(self):
  for mutation in('arch','escape','setid','notice'):
   def change(f,i,c):
    if mutation=='arch':f['.PKGINFO']=('file',0o644,f['.PKGINFO'][2].replace(b'arch = aarch64',b'arch = x86_64'))
    elif mutation=='escape':f['usr/bin/rustc']=('file',0o755,elf_bytes())
    elif mutation=='setid':f[A.PREFIX+'/bin/rustc']=('file',0o4755,elf_bytes())
    else:f[A.NOTICES+'bodies/'+next(iter(c['files'].values()))['sha256']+'.txt']=('file',0o644,b'changed')
   raw,source,inventory,_=package_model(change)
   with tempfile.TemporaryDirectory()as temp:
    with self.assertRaises(S.Hold):A.package_tar(io.BytesIO(raw),source,inventory,Path(temp))
 def test_mtree_incomplete_and_mismatched_body(self):
  rows={'file':dict(kind='file',mode=0o644,bytes=1,sha256=S.pin(b'x')['sha256']),'.MTREE':{}}
  A.mtree(gzip.compress(('./file type=file uid=0 gid=0 mode=644 size=1 sha256digest='+S.pin(b'x')['sha256']+'\n').encode()),rows)
  self.refuses('COMPLETE_PACKAGE',A.mtree,gzip.compress(b''),rows);self.refuses('WHOLE_FILE',A.mtree,gzip.compress(b'./file type=file uid=0 gid=0 mode=644 size=2 sha256digest=wrong\n'),rows)
 def test_image_model_config_layer_identity(self):
  with tempfile.TemporaryDirectory()as temp:
   owner=dict(token='MODEL-token',source='1'*40,tag='rust199-qualified:MODEL-token');layer=b'MODEL layer bytes';config=dict(architecture='arm64',os='linux',config=dict(Labels={'cachy-asahi.rust199-bootstrap':owner['token'],'cachy-asahi.rust199-bootstrap.source':owner['source']}),rootfs=dict(type='layers',diff_ids=['sha256:'+S.pin(layer)['sha256']]));raw=S.canonical(config);image='sha256:'+S.pin(raw)['sha256'];cn=image[7:]+'.json';manifest=[dict(Config=cn,RepoTags=[owner['tag']],Layers=['layer.tar'])];files={cn:('file',0o644,raw),'manifest.json':('file',0o644,S.canonical(manifest)),'layer.tar':('file',0o644,layer)};p=Path(temp)/'image.tar';p.write_bytes(tar_bytes(files));self.assertEqual(A.image_tar(p,S.pin(p.read_bytes()),image,owner)['layers'],1)
   files['layer.tar']=('file',0o644,b'changed');p.write_bytes(tar_bytes(files));self.refuses('DIFFID_MISMATCH',A.image_tar,p,S.pin(p.read_bytes()),image,owner)
 def test_transfer_namespace_descriptor_pin(self):
  row=dict(S.pin(b'MODEL'),mode=0o444);m=dict(files={'inputs/data':row},metadata=dict(proof=dict(local_path={'__rust_phase_file__':'inputs/data'},bytes=5,sha256=row['sha256'])));c=SimpleNamespace(rows={'retained/data':S.pin(b'MODEL')});members={'inputs/data':'retained/data','manifest.json':'retained/manifest'};R.manifest_data(m,c,members);m['metadata']['proof']['bytes']=6;self.refuses('DESCRIPTOR_WHOLE_JOIN',R.manifest_data,m,c,members)
 def test_qualification_envelope_path_projection_does_not_drop_bodies(self):
  a=dict(proof_path='/retained/a',files={'proof':dict(local_path='/retained/a',bytes=3,sha256='a'*64)},schema=4);b=copy.deepcopy(a);b['proof_path']={'__rust_phase_file__':'inputs/a'};b['files']['proof']['local_path']={'__rust_phase_file__':'inputs/a'};self.assertEqual(R.relocated(a),R.relocated(b));b['files']['proof']['sha256']='b'*64;self.assertNotEqual(R.relocated(a),R.relocated(b))
  args=transferred_qualification_model();self.assertEqual(R.transferred_qualification(*args),args[0]['owner'])
  # Counts are bounded receipt provenance, never an exact retained-tree reread.
  for files,size in ((1,0),(600000,16*S.GIB)):
   manifest=copy.deepcopy(args[0]);manifest['metadata']['boot']['extraction'].update(files=files,logical_bytes=size)
   self.assertEqual(R.transferred_qualification(manifest,*args[1:]),manifest['owner'])
  mutations=[lambda boot:boot.pop('extraction'),lambda boot:boot['extraction'].update(digest_timing='POSTMODE_CONTENT_REHASH'),
   lambda boot:boot['extraction'].update(final_modes_verified=False),lambda boot:boot['extraction'].update(final_modes_verified=1),
   lambda boot:boot['extraction'].update(files=True),lambda boot:boot['extraction'].update(files=0),lambda boot:boot['extraction'].update(files=600001),
   lambda boot:boot['extraction'].update(logical_bytes=True),lambda boot:boot['extraction'].update(logical_bytes=-1),lambda boot:boot['extraction'].update(logical_bytes=16*S.GIB+1),
   lambda boot:boot['extraction'].update(rootfs_tree_sha256='f'*64),lambda boot:boot['extraction'].update(postmode_content_rehashed=True)]
  for index,mutate in enumerate(mutations):
   manifest=copy.deepcopy(args[0]);mutate(manifest['metadata']['boot'])
   with self.subTest(staging_receipt=index):self.refuses('EXACT_PRE_FINALIZATION_ROOTFS_STAGING_RECEIPT',R.transferred_qualification,manifest,*args[1:])
  malformed=list(transferred_qualification_model());malformed[0]['metadata']['boot']['extraction']['rootfs_tree_sha256']='MODEL-invalid';malformed[0]['metadata']['boot']['rootfs_tree_sha256']='MODEL-invalid';malformed[3]['rootfs_tree_sha256']='MODEL-invalid'
  self.refuses('EXACT_PRE_FINALIZATION_ROOTFS_STAGING_RECEIPT',R.transferred_qualification,*malformed)

 def test_owned_bind_is_hosted_evidence_outside_raw_actor_qualification(self):
  args=transferred_qualification_model();manifest,corpus,members,q,*_=args
  self.assertNotIn('owned_work_bind',q)
  hosted=manifest['metadata']['qual'];self.assertEqual(hosted['owned_work_bind']['schema'],15)
  self.assertEqual(R.transferred_qualification(*args),manifest['owner'])
  for mutation in('missing_envelope','missing_controller','different_controller','missing_result','different_result','raw_actor'):
   args=list(transferred_qualification_model());manifest,corpus,members,q,*_=args;hosted=manifest['metadata']['qual'];descriptor=hosted['files']['qualification_controller'];member=members[descriptor['local_path']['__rust_phase_file__']];controller=S.decode(corpus.bodies[member])
   if mutation=='missing_envelope':hosted.pop('owned_work_bind')
   elif mutation=='missing_controller':controller.pop('owned_work_bind')
   elif mutation=='different_controller':controller['owned_work_bind']['work_source']='/MODEL/foreign'
   elif mutation=='missing_result':controller['result'].pop('owned_work_bind')
   elif mutation=='different_result':controller['result']['owned_work_bind']['work_source']='/MODEL/foreign'
   else:q['owned_work_bind']=copy.deepcopy(hosted['owned_work_bind']);controller['result']=q
   raw=S.canonical(controller);corpus.bodies[member]=raw;descriptor.update(S.pin(raw))
   with self.subTest(mutation=mutation):self.refuses('OWNED_BIND_HOSTED_CONTROLLER_ENVELOPE_JOIN|TRANSFERRED_QUALIFICATION_EXACT_PROOF|NATIVE_QUALIFICATION_NATURAL_CLEANUP',R.transferred_qualification,*args)

 def test_actor_model_exact_seventeen_commands_and_provenance(self):
  result=E.actor_output(*actor_model());self.assertEqual(result['actor_actions'],4);self.assertEqual(result['commands'],17);self.assertEqual(result['command_order'],'NOT_EMITTED');self.assertEqual(result['new_tool_runtime'],'NOT_EMITTED_NOT_QUALIFIED')
 def test_actor_model_rejects_log_change(self):
  args=actor_model();name=next(n for n in args[0]if n.endswith('.stdout'));args[0][name]=b'changed';self.refuses('COMPLETE_LOG_PIN',E.actor_output,*args)
 def test_actor_model_rejects_extra_or_changed_command(self):
  for what in('prepare','build','makepkg','cwd','environment','forced'):
   args=actor_model();name=next(n for n in args[0]if n.startswith('cmd-')and n.endswith('.json')and S.decode(args[0][n])['phase']==('prepare'if what in('prepare','cwd','environment','forced')else what));row=S.decode(args[0][name])
   if what in('prepare','build','makepkg'):row['argv'].append('--MODEL-EXTRA')
   elif what=='cwd':row['cwd']='/tmp'
   elif what=='environment':row['environment_sha256']='f'*64
   else:row['lifecycle']['forced_cleanup']=True
   args[0][name]=S.canonical(row)
   with self.assertRaises(S.Hold):E.actor_output(*args)
 def test_actor_model_rejects_forged_phase_counts_and_package_pin(self):
  for action in('prepare','makepkg'):
   args=actor_model();name=next(n for n in args[0]if n.startswith('phase-'+action));row=S.decode(args[0][name])
   if action=='prepare':row['phase']['commands']['extract']=4
   else:row['package']['sha256']='e'*64
   args[0][name]=S.canonical(row)
   with self.assertRaises(S.Hold):E.actor_output(*args)
 def test_actor_every_command_requires_its_own_phase_kernel_proof(self):
  initial=actor_model();names=[n for n in initial[0]if n.startswith('cmd-')and n.endswith('.json')]
  self.assertEqual(len(names),17)
  for name in names:
   args=actor_model();row=S.decode(args[0][name]);row['kernel_mount_proof_sha256']='f'*64;args[0][name]=S.canonical(row)
   with self.subTest(command=name):self.refuses('MOUNTINFO_EVERY_ACTOR_COMMAND_PROOF_JOIN',E.actor_output,*args)
 def test_actor_all_four_phase_envelopes_required(self):
  for phase in('prepare','makepkg','build','package'):
   args=actor_model();name=next(n for n in args[0]if n.startswith('phase-'+phase+'-'));row=S.decode(args[0][name]);row.pop('kernel_mount_proof');args[0][name]=S.canonical(row)
   with self.subTest(phase=phase):self.refuses('MOUNTINFO_ACTOR_PHASE_PROOF_REQUIRED',E.actor_output,*args)
 def test_actor_proof_raw_cannot_be_omitted_or_replaced(self):
  for phase in('prepare','makepkg','build','package'):
   args=actor_model();name=next(n for n in args[0]if n.startswith('kernel-mountinfo-'+phase+'-'));args[0].pop(name)
   with self.subTest(phase=phase):self.refuses('MOUNTINFO_RETAINED_FILE_MISSING',E.actor_output,*args)
 def test_actor_phase_and_kernel_invocation_suffix_must_match(self):
  args=actor_model();name=next(n for n in args[0]if n.startswith('phase-build-'));args[0][name.replace('-10-','-999-')]=args[0].pop(name)
  self.refuses('MOUNTINFO_SAME_PHASE_RECEIPT_INVOCATION',E.actor_output,*args)
 def test_actor_extra_kernel_output_not_silently_ignored(self):
  args=actor_model();args[0]['kernel-mountinfo-build-999-'+'f'*32+'.raw']=b'MODEL_UNUSED\n'
  self.refuses('MOUNTINFO_EXACT_ACTOR_PROOF_NAMESPACE',E.actor_output,*args)
 def test_qualification_model_readonly_aliases_and_nine_probes(self):
  E.qualification(*qualification_model())
  for what in('errno','denied','argv','exit','binding'):
   args=qualification_model();q=args[0]
   if what=='errno':q['readonly_stage0']['attempts'][1]['errno']=13
   elif what=='denied':q['readonly_stage0']['attempts'][1]['denied']=False
   elif what=='argv':q['probe_receipts'][0]['argv']=['/usr/bin/true']
   elif what=='exit':q['probe_receipts'][0]['lifecycle']['exit']=134
   else:q['binding']=dict(q['binding'],job='999')
   with self.assertRaises(S.Hold):E.qualification(*args)
 def test_export_model_stdlib_zstd_or_specific_python312_hold(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);raw,source,inventory,_=package_model()
   if R.sys.version_info>=(3,14):
    import compression.zstd
    compressed=compression.zstd.compress(raw)
   else:compressed=b'MODEL zstd bytes are never decoded on3.12'
   data={'output/'+A.PACKAGE:('file',0o644,compressed),'output/actual-packages.txt':('file',0o644,inventory),'output/cachy-asahi-rust199-source-reference-1.99.0-1-aarch64-build.log':('file',0o644,b'MODEL log')};export=root/'export.tar';export.write_bytes(tar_bytes(data));expected=S.pin(export.read_bytes())
   if R.sys.version_info>=(3,14):
    result,pin,package=A.export(export,expected,source,inventory,root);self.assertEqual(result['actual-packages.txt'],inventory);self.assertEqual(pin['file'],A.PACKAGE);self.assertEqual(package['elf_files'],6)
   else:self.refuses('PYTHON_STDLIB_ZSTD_UNAVAILABLE',A.export,export,expected,source,inventory,root)
 def test_export_unknown_member_refused(self):
  with tempfile.TemporaryDirectory()as temp:
   p=Path(temp)/'export.tar';p.write_bytes(tar_bytes({'output/unselected.py':('file',0o644,b'MODEL')}));self.refuses('UNKNOWN_PRODUCER_MEMBER',A.export,p,S.pin(p.read_bytes()),{},b'',Path(temp))
 def test_export_kernel_basename_and_size_bounds(self):
  for name,body,code in [('kernel-mountinfo-unknown-1-'+'a'*32+'.raw',b'MODEL','UNKNOWN_PRODUCER_MEMBER'),
                         ('kernel-mount-proof-build-01-'+'a'*32+'.json',b'MODEL','UNKNOWN_PRODUCER_MEMBER'),
                         ('kernel-mountinfo-build-1-'+'a'*32+'.raw',b'x'*(S.MIB+1),'KERNEL_PROOF_MEMBER_BOUND')]:
   with tempfile.TemporaryDirectory()as temp:
    path=Path(temp)/'export.tar';path.write_bytes(tar_bytes({'output/'+name:('file',0o644,body)}))
    self.refuses(code,A.export,path,S.pin(path.read_bytes()),{},b'',Path(temp))
 def test_malformed_is_fixed_hold_without_message_dump(self):
  with patch.object(R,'read',side_effect=ValueError('MODEL private path/token must not appear')):result=R.evaluate(None,None,None,None)
  self.assertEqual(result['reason'],'MALFORMED_OR_UNSUPPORTED_RETAINED_VALUEERROR');self.assertNotIn('private',str(result))

 def test_producer_model_identity_natural_and_claims(self):
  E.producer(*producer_model())
  for what in('owner','oom','exit','forced','credit','absent'):
   args=producer_model();p,a,sel,finished=args
   if what=='owner':p['volume_binding']['token']='forged'
   elif what=='oom':finished['makepkg']['State']['OOMKilled']=True
   elif what=='exit':finished['makepkg']['State']['ExitCode']=134
   elif what=='forced':p['export']['lifecycle']['forced_cleanup']=True
   elif what=='credit':p['native_acceptance']=True
   else:p['owned_resources_absent']=False
   with self.assertRaises(S.Hold):E.producer(*args)
 def test_initializer_exact_private_work_bind_no_caps(self):
  p,a,sel,finished=producer_model();code=(HERE/'fixtures/initializer-code.DATA.txt').read_text()
  work_bind,*_=W.model('build',a['source']);work=work_bind['work_source'];configured,actual=W.observed('/work',work,False)
  config=dict(User='1001:1001',Entrypoint=['/usr/bin/python'],WorkingDir='/',Cmd=['-I','-B','-c',code,S.canonical(p['volume_binding']).decode()]);host=dict(Memory=128*S.MIB,MemorySwap=128*S.MIB,PidsLimit=32,NanoCpus=2000000000,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,SecurityOpt=['no-new-privileges'],Init=True,IpcMode='private',CgroupnsMode='private',RestartPolicy=dict(Name='no'),LogConfig=dict(Type='none',Config={}),Ulimits=[dict(Name='nofile',Soft=1024,Hard=1024),dict(Name='core',Soft=0,Hard=0)],Mounts=[configured]);row=dict(Id=finished['init']['Id'],Name=finished['init']['Name'],Image=p['image'],State=dict(Status='created',Running=False),Config=config,HostConfig=host,Mounts=[actual]);E.inspected(row,finished['init'],'init',p,a,{},work)
  for what in('code','volume','source','propagation','access','cap','net'):
   bad=copy.deepcopy(row)
   if what=='code':bad['Config']['Cmd'][3]+='\nprint("MODEL extra action")'
   elif what=='volume':bad['HostConfig']['Mounts'][0].update(Type='volume',VolumeOptions=dict(NoCopy=True))
   elif what=='source':bad['Mounts'][0]['Source']='/MODEL/foreign'
   elif what=='propagation':bad['HostConfig']['Mounts'][0]['BindOptions']['Propagation']='rslave'
   elif what=='access':bad['Mounts'][0]['RW']=False
   elif what=='cap':bad['HostConfig']['CapAdd']=['CHOWN','FOWNER']
   else:bad['HostConfig']['NetworkMode']='host'
   with self.subTest(mutation=what):
    with self.assertRaises(S.Hold):E.inspected(bad,finished['init'],'init',p,a,{},work)
 def test_template_is_unissued_and_whole_reader_pinned(self):
  v=S.decode((HERE/'request.TEMPLATE.json').read_bytes());self.assertIsNone(v['issuer']);self.assertIsNone(v['approved']);self.assertTrue(all(v is None for v in v['resources'].values()));self.assertEqual(set(v['roles']),R.CORE);self.assertEqual(set(v['reader_files']),set(R.PROGRAMS))
  for name,pin in v['reader_files'].items():self.assertEqual(S.pin((HERE/name).read_bytes()),pin)
  self.refuses('UNISSUED',R.selector,v)
 def test_corpus_exact_ledger_and_whole_pin(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);(root/'public').write_bytes(b'MODEL');req=dict(files={'public':S.pin(b'MODEL')},roles=dict.fromkeys(R.CORE,'public'));c=R.Corpus(root,req);self.assertEqual(c.raw('dispatch'),b'MODEL');(root/'extra').write_bytes(b'1');self.refuses('COMPLETE_RETAINED_NAMESPACE',R.Corpus,root,req);(root/'extra').unlink();(root/'public').write_bytes(b'other');self.refuses('WHOLE_PIN',R.Corpus,root,req)

 def unissued_cli(self,args):
  stdout,stderr=io.StringIO(),io.StringIO()
  with patch.object(sys,'argv',[str(HERE/'reader.py'),*args]),patch.object(sys,'stdout',stdout),patch.object(sys,'stderr',stderr):
   with self.assertRaises(SystemExit)as stopped:runpy.run_path(str(HERE/'reader.py'),run_name='__main__')
  return SimpleNamespace(returncode=stopped.exception.code,stdout=stdout.getvalue().encode(),stderr=stderr.getvalue().encode())
 def test_unissued_cli_outputs_hold_without_source_or_scratch(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);request=root/'request.json';request.write_bytes((HERE/'request.TEMPLATE.json').read_bytes());output=root/'result.json';missing=root/'must-remain-absent';args=['--request',str(request),'--request-sha256',S.pin(request.read_bytes())['sha256'],'--source-root',str(missing),'--evidence-root',str(missing),'--scratch',str(missing),'--output',str(output)];done=self.unissued_cli(args)
   self.assertEqual(done.returncode,2);self.assertFalse(missing.exists());self.assertEqual(S.decode(output.read_bytes())['reason'],'ROOT_READER_SELECTION_UNISSUED');self.assertEqual(done.stderr,b'')
 def test_unissued_cli_whole_request_pin_refusal(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);request=root/'request.json';request.write_bytes(b'null\n');output=root/'result.json';args=['--request',str(request),'--request-sha256','0'*64,'--source-root',str(root/'absent'),'--evidence-root',str(root/'absent'),'--scratch',str(root/'absent'),'--output',str(output)];done=self.unissued_cli(args);self.assertEqual(done.returncode,2);self.assertEqual(S.decode(output.read_bytes())['reason'],'EXTERNAL_REQUEST_WHOLE_PIN')

 def test_full_program_inverse_preserves_v14(self):
  proof=S.decode((HERE/'inverse.DATA.json').read_bytes());self.assertEqual(proof['predecessor_commit'],'8b76a72d9b4808d5b8599a455e1cbf8163d86c5f');self.assertEqual(proof['schema'],15);self.assertIsNone(proof['Root_acceptance']);self.assertEqual(set(proof['files']),set(R.PROGRAMS))
  for name,row in proof['files'].items():
   raw=(HERE/name).read_bytes();self.assertEqual(S.pin(raw),row['after'])
   restored=base64.b64decode(row['inverse_body_base64'],validate=True)if row['inverse_body_base64']is not None else raw
   self.assertEqual(S.pin(restored),row['before']);self.assertEqual(restored,(HERE.parent/'independent_reader_v14'/name).read_bytes())
   if name in('bindings.py','elf.py'):self.assertIsNone(row['inverse_body_base64'])
 def test_source361_profile_exact_and_authority_unissued(self):
  raw=(HERE/'source-profile.DATA.json').read_bytes();profile=S.decode(raw)
  if S.SOURCE['profile_sha256']is None:self.assertTrue(all(v is None for v in S.SOURCE.values()))
  else:
   self.assertEqual(S.SOURCE['profile_sha256'],S.pin(raw)['sha256'])
   self.assertEqual({k:profile[k]for k in('files','bytes','tree','map_sha256')},{k:S.SOURCE[k]for k in('files','bytes','tree','map_sha256')})
  self.assertEqual(profile['schema'],15);self.assertIsNone(profile['Root_review']);self.assertIsNone(profile['accepted']);self.assertTrue(all(v is None for v in profile['actual'].values()));self.assertTrue(profile['unadmitted'])
 def test_old351_contract_ref_and_request_refused(self):
  spec=importlib.util.spec_from_file_location('unchanged_Source351_reader',HERE.parent/'independent_reader_v13/reader.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
  with patch.object(S,'namespace',side_effect=AssertionError('must refuse before input')):self.refuses('SOURCE15_CONTRACT_UNPINNED'if S.SOURCE['files']is None else'EXTERNAL_SOURCE_PROFILE_PIN',S.source,None,(HERE/'source-profile.DATA.json').read_bytes(),old.S.SOURCE)
  req=dict(schema=15,kind='ROOT_SELECTED_RUST361_RETAINED_EVIDENCE_READER_V15',issuer='Root',approved=True,selected=selected(),resources=R.MAX)
  with self.assertRaises(old.S.Hold):old.selector(req)
  wrong=copy.deepcopy(req);wrong['schema']=13;wrong['kind']='ROOT_SELECTED_RUST351_RETAINED_EVIDENCE_READER_V13';self.refuses('ROOT_READER_SELECTION_UNISSUED',R.selector,wrong)
  wrong=copy.deepcopy(req);wrong['selected']['ref']='refs/heads/codex/rust199-source351-native-v13-MODEL';self.refuses('ROOT_EXACT_SOURCE_RUN_JOB_SELECTORS',R.selector,wrong)
 def test_producer_report_and_finished_cannot_replace_acknowledged_custody(self):
  p,a,sel,finished=producer_model();custody={k:v['Id']for k,v in finished.items()};p['container_ids']=dict(custody);R.producer_custody(p,finished,custody)
  for mutant in (None,{},dict(custody,prepare='f'*64)):
   bad=copy.deepcopy(p);bad['container_ids']=mutant;self.refuses('PRODUCER_ACKNOWLEDGED_CID_REPORT_FINISH_JOIN',R.producer_custody,bad,finished,custody)
  finished['prepare']['Id']='e'*64;self.refuses('PRODUCER_ACKNOWLEDGED_CID_REPORT_FINISH_JOIN',R.producer_custody,p,finished,custody)
 def test_qualification_report_cannot_replace_acknowledged_custody(self):
  for mutant in (None,{},dict(init='f'*64,data='2'*64,probe='3'*64)):
   args=list(transferred_qualification_model());args[-1]=mutant
   self.refuses('QUALIFICATION_ACKNOWLEDGED_CID_REPORT_JOIN',R.transferred_qualification,*args)
 def test_actual_source340_failure_record_is_data_without_credit(self):
  raw=(HERE/'actual-failure.DATA.json').read_bytes();v=S.decode(raw)
  self.assertEqual(S.pin(raw),ACTUAL_FAILURE_PIN);self.assertEqual(v['scope'],'PUBLIC_SOURCE340_FAILURE_DATA_ONLY_NO_RUNTIME_CREDIT');self.assertEqual(v['hosted']['status'],'FAIL');self.assertEqual(v['hosted']['phase'],'bootstrap');self.assertFalse(v['hosted']['native_acceptance']);self.assertIsNone(v['accepted']);self.assertIsNone(v['Root_acceptance']);self.assertEqual(v['native'],'NOT RUN')
  self.assertEqual(v['container_id'],'16aa9ada533b4d6f5938b7b6cedf8571ba2a059d636c7a2c80f6762a0128513e');self.assertEqual(v['create_ack']['bytes'],65);self.assertEqual(v['configured_work_volume']['VolumeOptions'],dict(NoCopy=True,DriverConfig={}))
  self.assertEqual(v['files']['operations/287.stdout'],dict(bytes=14206,sha256='3049a973c26c02fbfdec6ea0300b518addd10b48e5b3de76c204b6c61e53189d'))
 def test_incomplete_retained_roles_produce_specific_hold_without_credit(self):
  req=dict(schema=15,kind='ROOT_SELECTED_RUST361_RETAINED_EVIDENCE_READER_V15',issuer='Root',approved=True,selected=selected(),resources=R.MAX,reader_files={n:S.pin((HERE/n).read_bytes())for n in R.PROGRAMS},files={},roles={})
  out=R.evaluate(req,HERE,HERE,HERE);self.assertEqual(out['status'],'HOLD');self.assertEqual(out['reason'],'EXACT_READER_ROLE_SCHEMA');self.assertFalse(out['native_acceptance']);self.assertIsNone(out['Root_acceptance']);self.assertEqual(out['M2'],'NOT_TESTED');self.assertFalse(out['release_acceptance'])

if __name__=='__main__':unittest.main()
