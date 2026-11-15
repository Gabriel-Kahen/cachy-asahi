#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small fenced DATA controls; no operational Reader, Source code or actors."""
import argparse,ast,copy,ctypes,hashlib,importlib.util,json,os,socket,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llvm_reader5_controls',HERE/'reader.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r);v=r.v
PARENT_SOURCE=HISTORICAL_SOURCE=ANCESTOR_SOURCE=SUCCESSOR_SOURCE=None

def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','fcntl.lockf','os.unshare','os.setns'):raise RuntimeError('Reader5 DATA controls forbid '+event)
sys.addaudithook(fence)
def save(path,value):path.write_bytes(v.canonical(value))
def runtime_model():
 raw=(HERE.parent/'v2/test_reader.py').read_bytes();assert hashlib.sha256(raw).hexdigest()=='d4f335235248694aac24ad0dd25dcdd22d76b585ae7f86daec6ab8352dfbf825';tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='modeled_runtime'];assert len(nodes)==1
 ns=dict(copy=copy);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<held inert modeled runtime>','exec'),ns);return ns['modeled_runtime']()
def life():return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=0,cleanup_error=None)

def modeled_namespace(root,specification=None):
 spec=dict(command_receipts={n:'command-'+n+'.json'for n in r.COMMANDS},command_logs={n:n+'.log'for n in r.COMMANDS},facts=dict(runtime='runtime.json',tools='tools.json'),fixed_output=['packages.txt'])
 if specification is not None:spec=copy.deepcopy(specification)
 for name in spec['fixed_output']:(root/name).write_bytes(b'MODELED_FIXED_DATA')
 facts=dict(schema=1,admission_sha256='a'*64,operation='llvm23-source-reference-native-v1',**runtime_model());save(root/'runtime.json',facts);save(root/'tools.json',dict(schema=1,tools=[],command_receipt=spec['command_receipts']['tool-owners'],expected349_sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453',scope='ACTUAL_PATH_BYTES_AND_ALPM_OWNERSHIP_ONLY_NOT_COMPILER_RUNTIME_QUALIFICATION'))
 (root/'packages.txt').write_bytes(b'MODEL\n');(root/r.PACKAGE).write_bytes(b'MODELED_NOT_A_PACKAGE')
 for name,maximum in r.COMMANDS.items():
  log=root/spec['command_logs'][name];log.write_bytes(('MODELED '+name+'\n').encode());save(root/spec['command_receipts'][name],dict(lifecycle=life(),success=True,returncode=0,timeout_seconds=maximum,requested_seconds=maximum,log=log.name,log_pin=v.hashed(log),argv=['/usr/bin/bash','/inputs/packages/port/llvm23-source-reference/build.sh',name]if name in('probe','tools','runtimes','check')else['MODELED_COMMAND']))
 result=dict(output_files={p.name:dict(**v.hashed(p),mode=0o644)for p in root.iterdir()});save(root/'actor-result.json',result);return result,spec

class NamespaceControls(unittest.TestCase):
 def setUp(self):
  v.END=time.monotonic()+60;self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.result,self.spec=modeled_namespace(self.root)
 def test_complete_stage_receipts_and_initial_facts(self):
  q=r.namespace(self.root,self.result,self.spec);self.assertEqual(q['command_receipts']['tools'],'command-tools.json');self.assertTrue(q['runtime_and_build_success_separate'])
 def test_same_fact_and_command_filename_refused(self):
  for stage,fact in(('tools','tools'),('runtimes','runtime')):
   spec=copy.deepcopy(self.spec);spec['command_receipts'][stage]=spec['facts'][fact]
   with self.assertRaises(ValueError):r.namespace(self.root,self.result,spec)
 def test_missing_extra_and_changed_whole_output(self):
  for kind in('missing','extra','hash'):
   with tempfile.TemporaryDirectory()as d:
    root=Path(d);result,spec=modeled_namespace(root)
    if kind=='missing':(root/'command-runtimes.json').unlink()
    elif kind=='extra':(root/'unexpected.DATA').write_bytes(b'unknown')
    else:(root/'tools.log').write_bytes(b'changed')
    with self.subTest(kind=kind),self.assertRaises((ValueError,OSError)):r.namespace(root,result,spec)
 def test_stage_argv_success_lifecycle_and_log_refused(self):
  for key,value in(('argv',['other']),('success',False),('returncode',False),('requested_seconds',1801),('lifecycle',{**life(),'forced_cleanup':True}),('log','tools.log')):
   with tempfile.TemporaryDirectory()as d:
    root=Path(d);result,spec=modeled_namespace(root);p=root/'command-runtimes.json';row=v.load(p);row[key]=value;save(p,row);result['output_files'][p.name]=dict(**v.hashed(p),mode=0o644)
    with self.subTest(key=key),self.assertRaises(ValueError):r.namespace(root,result,spec)
 def test_inventory_cannot_masquerade_as_runtime_facts(self):
  p=self.root/'runtime.json';save(p,v.load(self.root/'tools.json'));self.result['output_files'][p.name]=dict(**v.hashed(p),mode=0o644)
  with self.assertRaises(ValueError):r.namespace(self.root,self.result,self.spec)
 def test_runtime_resource_domain_unchanged(self):
  p=self.root/'runtime.json';row=v.load(p);row['entry']['uid']=0;save(p,row);self.result['output_files'][p.name]=dict(**v.hashed(p),mode=0o644)
  with self.assertRaises(ValueError):r.namespace(self.root,self.result,self.spec)
 def test_initial_tools_must_bind_actual_owner_receipt(self):
  p=self.root/'tools.json';row=v.load(p);row['command_receipt']='tool-owners.json';save(p,row);self.result['output_files'][p.name]=dict(**v.hashed(p),mode=0o644)
  with self.assertRaises(ValueError):r.namespace(self.root,self.result,self.spec)
 def test_trusted_projection_uses_cloned_new_guards(self):
  before=r.B.old.v.commands;proof=r.B.install(self.spec,lambda *_:None);self.assertIs(r.B.old.v.commands,before);self.assertIs(v.commands.__globals__,v.__dict__);self.assertIs(v.replay.__globals__,v.__dict__);self.assertEqual(proof['commands']['seams'],5);self.assertFalse(proof['actual_tuple_projection'])

class StorageControls(unittest.TestCase):
 def model(self):
  identity=dict(issued_by='Root',query_root='/home/gabe',identity_domains_distinct=True,fstat_device=54,kernel_mount_device='0:33',mount_id=62,mountinfo='62 40 0:33 /@home /home rw,noatime shared:169 - btrfs /dev/ROOT_DATA rw,subvolid=257,subvol=/@home')
  profile=dict(kind='ROOT_REVIEWED_LLVM_READER5_BTRFS_STORAGE_V1',issued_by='Root',accepted=True,observed_epoch=time.time(),output_parent='/home/gabe/model',uid=1000,inode_accounting='UNREPORTED_ALL_ZERO',reservation=False)
  live=dict(fd_device=54,fd_mount_id=62,fd_path_stable=True,mountinfo=identity['mountinfo'],available_bytes=21*r.GIB,files=0,ffree=0,favail=0)
  return profile,identity,live
 def check(self,p,i,l):return r.storage.validate(p,i,Path('/home/gabe/model'),1000,l,time.time())
 def test_btrfs_fstat_and_kernel_domains_are_explicitly_distinct(self):
  p,i,l=self.model();q=self.check(p,i,l);self.assertEqual(q['fstat_device'],54);self.assertEqual(q['kernel_mount_device'],'0:33');self.assertEqual(q['inode_accounting'],'UNREPORTED');self.assertFalse(q['reservation']);self.assertIsNone(q['quota_claim'])
 def test_unknown_nonbtrfs_wrong_mount_and_low_reported_inodes_refuse(self):
  for key,value in(('mountinfo','62 40 0:33 /@home /home rw - ext4 /dev/ROOT_DATA rw,subvolid=257,subvol=/@home'),('fd_device',33),('fd_mount_id',63),('fd_path_stable',False),('favail',1),('available_bytes',19*r.GIB),('files','0')):
   p,i,l=self.model();l[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(p,i,l)
 def test_profile_freshness_review_and_semantics_refuse(self):
  for key,value in(('accepted',False),('observed_epoch',time.time()-121),('uid',1000.0),('inode_accounting','UNLIMITED'),('reservation',True)):
   p,i,l=self.model();p[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(p,i,l)
 def test_eperm_open_does_not_turn_into_unreported_inodes(self):
  p,i,l=self.model();profile=v.canonical(dict(p,mount_identity=dict(path='/model/identity.json',**r.storage.IDENTITY)));identity=v.canonical(i)
  # Pin mismatch must refuse before a caller can fake a grant; exact live open error also propagates.
  class V:
   path=staticmethod(Path)
   decode=staticmethod(v.decode)
   @staticmethod
   def read(path,*_):return profile if str(path)=='/model/profile.json'else identity
  ref=dict(path='/model/profile.json',bytes=len(profile),sha256=hashlib.sha256(profile).hexdigest())
  with self.assertRaises(ValueError):r.storage.check(Path('/home/gabe/model'),ref,V)
  identity_pin=dict(bytes=len(identity),sha256=hashlib.sha256(identity).hexdigest());p['mount_identity']=dict(path='/model/identity.json',**identity_pin);profile=v.canonical(p);ref.update(bytes=len(profile),sha256=hashlib.sha256(profile).hexdigest())
  with patch.object(r.storage,'IDENTITY',identity_pin),patch.object(r.storage.os,'open',side_effect=PermissionError(1,'MODELED EPERM')),self.assertRaises(PermissionError):r.storage.check(Path('/home/gabe/model'),ref,V)
 def test_permanent_actor_network_ffi_lease_fence(self):
  for event in('subprocess.Popen','socket.__new__','ctypes.dlopen','os.fork','fcntl.flock'):
   with self.subTest(event=event),self.assertRaises(RuntimeError):sys.audit(event)


class LineageControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  v.END=time.monotonic()+120;cls.found=v.source_namespace(PARENT_SOURCE,r.B.parent_pins);cls.rows={n:(v.read(PARENT_SOURCE/n,64*r.MIB),x['mode'])for n,x in cls.found.items()}
 def rebind(self,rows):
  m=v.decode(rows['source-map.json'][0]);m['files']={n:r.B.old.descriptor(row)for n,row in rows.items()if n!='source-map.json'};rows['source-map.json']=(v.canonical(m),0o644)
  found={n:dict(**r.B.old.descriptor(row),blob=v.git_oid('blob',row[0]))for n,row in rows.items()};pins=copy.deepcopy(r.B.parent_pins);pins.update(source=None,ref=None,source_files=len(rows),source_bytes=sum(len(b)for b,_ in rows.values()),source_map_sha256=hashlib.sha256(rows['source-map.json'][0]).hexdigest(),source_tree=r.B.old.git_tree(found),correction_files=['actor/container_mode.py']);return rows,pins
 def model(self):
  rows=dict(self.rows);name='actor/container_mode.py';saved='previous-v4/actor-container_mode.py';savedmap='previous-v4/source-map.json';meta='successor-v5.json';old="path = OUT/(name+'.json')";new="path = OUT/('command-'+name+'.json')";before=rows[name];after=(before[0].replace(old.encode(),new.encode()),before[1]);rows[saved]=before;rows[savedmap]=rows['source-map.json'];rows[name]=after
  value=dict(schema=1,scope='MODELED_INERT_LITERAL_SOURCE_NOT_RUN',parent=r.PARENT,actual=r.B.old.ACTUAL)
  rows[meta]=(v.canonical(value),0o644);frame=dict(parent=r.PARENT,actual=r.B.old.ACTUAL,saved_parent_map=savedmap,metadata=meta,metadata_value=value,replacements={name:dict(saved=saved,before=r.B.old.descriptor(before),after=r.B.old.descriptor(after),inverse=dict(kind='LITERAL_SEAMS',seams=[dict(before=old,after=new,count=1)]))})
  rows,pins=self.rebind(rows);return rows,pins,frame
 def check(self,rows,pins,frame):return r.inverse256_rows(rows,pins,frame,HISTORICAL_SOURCE,ANCESTOR_SOURCE)
 def test_complete_append_only_then256_253_251_248(self):
  rows,pins,frame=self.model();restored=self.check(rows,pins,frame);self.assertEqual(len(restored),256);self.assertEqual(restored,self.found)
 def test_bad_archived_map_or_body_refused(self):
  for name in('previous-v4/source-map.json','previous-v4/actor-container_mode.py'):
   rows,pins,frame=self.model();rows[name]=(rows[name][0]+b'\n',0o644);rows,pins=self.rebind(rows)
   with self.subTest(name=name),self.assertRaises(ValueError):self.check(rows,pins,frame)
 def test_unprofiled_actor_candidate_mode_or_membership_refused(self):
  for kind in('actor','candidate','mode','extra'):
   rows,pins,frame=self.model()
   if kind=='extra':rows['unreviewed.DATA']=(b'unknown',0o644)
   else:
    name='actor/entry.py'if kind=='actor'else'packages/port/llvm23-source-reference/build.sh'if kind=='candidate'else'actor/container_mode.py';rows[name]=(rows[name][0]+(b'\n'if kind!='mode'else b''),0o755 if kind=='mode'else rows[name][1])
   rows,pins=self.rebind(rows)
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.check(rows,pins,frame)
 def test_extra_source_edit_even_rebound_after_descriptor_refused(self):
  rows,pins,frame=self.model();name='actor/container_mode.py';rows[name]=(rows[name][0]+b'\n# unprofiled\n',0o644);frame['replacements'][name]['after']=r.B.old.descriptor(rows[name]);rows,pins=self.rebind(rows)
  with self.assertRaises(ValueError):self.check(rows,pins,frame)
 def test_metadata_parent_typed_seam_and_future_claim_refused(self):
  for kind in('parent','count','actual'):
   rows,pins,frame=self.model()
   if kind=='parent':frame['parent']={**frame['parent'],'source':'0'*40}
   elif kind=='count':frame['replacements']['actor/container_mode.py']['inverse']['seams'][0]['count']=True
   else:frame['actual']={**frame['actual'],'run':'11'}
   with self.subTest(kind=kind),self.assertRaises(ValueError):self.check(rows,pins,frame)


class Exact260Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  v.END=time.monotonic()+120;cls.pins=v.load(HERE/'pins.json');cls.frame=v.load(HERE/'inverse-frame.json');cls.found=v.source_namespace(SUCCESSOR_SOURCE,cls.pins);cls.rows={n:(v.read(SUCCESSOR_SOURCE/n,64*r.MIB),x['mode'])for n,x in cls.found.items()}
 def test_actual260_data_inverse_and_exact_native_actor_revision(self):
  q=r.inverse256_rows(self.rows,self.pins,self.frame,HISTORICAL_SOURCE,ANCESTOR_SOURCE);self.assertEqual(len(q),256);self.assertFalse(v.decode(self.rows['contract.json'][0])['outer_delegation']['frozen_python_actor']);self.assertTrue(v.decode(self.rows['previous-v4/contract.json'][0])['outer_delegation']['frozen_python_actor'])
  self.assertEqual(self.pins['source_files'],260);self.assertIsNone(self.pins['source']);self.assertIsNone(self.pins['ref'])
 def test_actual_stage_profile_preserves_initial_facts_and_all_argv(self):
  spec=self.pins['output_namespace'];self.assertEqual(spec['facts'],dict(runtime='runtime.json',tools='tools.json'))
  for stage in('probe','tools','runtimes','check'):
   self.assertEqual(spec['command_receipts'][stage],'stage-'+stage+'.json');self.assertEqual(spec['command_logs'][stage],'stage-'+stage+'.log')
  self.assertEqual(spec['command_receipts']['tool-owners'],'tool-owners.json');self.assertEqual(len(set(spec['fixed_output'])|set(spec['facts'].values())|set(spec['command_receipts'].values())|set(spec['command_logs'].values())|{r.PACKAGE}),43)
 def test_actual_revised_contract_cannot_claim_frozen_actor(self):
  rows=dict(self.rows);frame=copy.deepcopy(self.frame);contract=v.decode(rows['contract.json'][0]);contract['outer_delegation']['frozen_python_actor']=True;rows['contract.json']=(v.canonical(contract),0o644);frame['replacements']['contract.json']['after']=r.B.old.descriptor(rows['contract.json'])
  m=v.decode(rows['source-map.json'][0]);m['files']={n:r.B.old.descriptor(row)for n,row in rows.items()if n!='source-map.json'};rows['source-map.json']=(v.canonical(m),0o644);found={n:dict(**r.B.old.descriptor(row),blob=v.git_oid('blob',row[0]))for n,row in rows.items()};pins=dict(self.pins,source_map_sha256=hashlib.sha256(rows['source-map.json'][0]).hexdigest(),source_tree=r.B.old.git_tree(found),source_bytes=sum(len(b)for b,_ in rows.values()))
  with self.assertRaises(ValueError):r.inverse256_rows(rows,pins,frame,HISTORICAL_SOURCE,ANCESTOR_SOURCE)
 def modeled_binding(self,root):
  b=v.load(HERE/'binding.TEMPLATE.json');b['actual']=dict(source='e'*40,ref='refs/heads/codex/MODELED_LLVM260',run='11',job='22',attempt=1,approval='a'*64,authority='MODELED_NOT_ISSUED',image='sha256:'+'b'*64,artifact='33',reader='MODELED_NOT_ENTERED')
  for k in('provider_sha256','source_commit_sha256','export_sha256','package_sha256','reader_sha256','pins_sha256'):b[k]='c'*64
  b['original_archive']=dict(bytes=1,sha256='d'*64);b['full_original_decode']=dict(bytes=1,files=1,map_sha256='f'*64)
  pub=dict(issuer='Root',status='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY',source=b['actual']['source'],ref=b['actual']['ref'],tree=self.pins['source_tree'],source_map_sha256=self.pins['source_map_sha256'],files=260,bytes=self.pins['source_bytes']);path=root/'publication.json';save(path,pub);b['publication']=dict(path=str(path),**v.hashed(path));return b,pub,path
 def test_future_actual_binding_and_publication_tuple_models(self):
  with tempfile.TemporaryDirectory()as d:
   b,pub,path=self.modeled_binding(Path(d));selected=r.binding(b,self.pins);self.assertEqual(selected['source'],b['actual']['source']);self.assertEqual(selected['ref'],b['actual']['ref']);self.assertEqual(b['actual']['source'],'e'*40)
   for key,value in(('source',r.PARENT['source']),('source_map_sha256',r.PARENT['map_sha256']),('files',256)):
    bad={**pub,key:value};save(path,bad);b['publication']=dict(path=str(path),**v.hashed(path))
    with self.subTest(key=key),self.assertRaises(ValueError):r.binding(b,self.pins)

 def test_actual_profile_full_namespace_and_projected_command_joins(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);result,spec=modeled_namespace(root,self.pins['output_namespace']);names=('bash','uname','grep','gcc','g++','gcc-ar','gcc-ranlib','ld','as','cmake','ninja','python','bsdtar','make','perl','pkg-config','fakeroot','pacman','zstd','env','sort','cp','timeout');lock=v.read(SUCCESSOR_SOURCE/'expected349.lock');baseline=dict(line.split(' ',1)for line in lock.decode().splitlines());(root/'packages.txt').write_bytes(lock)
   toolrows=[dict(name=name,path='/usr/bin/'+name,resolved='/usr/bin/'+name,links=[],owner='bash',owner_version=baseline['bash'],bytes=1,sha256='a'*64,mode=0o755)for name in names];tools=v.load(root/'tools.json');tools['tools']=toolrows;save(root/'tools.json',tools);(root/'tool-owners.log').write_bytes(('bash\n'*len(names)).encode())
   cache=dict(CMAKE_INSTALL_PREFIX=v.PREFIX,CMAKE_C_COMPILER='/usr/bin/gcc',CMAKE_CXX_COMPILER='/usr/bin/g++',LLVM_TARGETS_TO_BUILD='AArch64',LLVM_ENABLE_PROJECTS='clang;lld',LLVM_BUILD_LLVM_DYLIB='ON',LLVM_LINK_LLVM_DYLIB='ON');runtimecache=dict(CMAKE_INSTALL_PREFIX=v.PREFIX,CMAKE_C_COMPILER=v.PREFIX+'/bin/clang',CMAKE_CXX_COMPILER=v.PREFIX+'/bin/clang++',LLVM_ENABLE_RUNTIMES='compiler-rt;libunwind',LIBUNWIND_INSTALL_LIBRARY_DIR='lib',COMPILER_RT_BUILD_PROFILE='ON')
   for filename,values in(('tools-CMakeCache.txt',cache),('runtimes-CMakeCache.txt',runtimecache)):
    values.update({f'CMAKE_{kind}_LINKER_FLAGS':'-Wl,-z,max-page-size=16384'for kind in('EXE','SHARED','MODULE')});(root/filename).write_text(''.join(k+':STRING='+value+'\n'for k,value in values.items()))
   argv=dict(makepkg=['/usr/bin/makepkg','--config','/work/makepkg.conf','--cleanbuild','--nosign','--noconfirm','--log'],**{'packages-unsorted':['/usr/bin/pacman','-Q'],'tool-owners':['/usr/bin/pacman','-Qqo','--',*['/usr/bin/'+n for n in names]],'pkginfo':['/usr/bin/bsdtar','-xOf','/work/output/'+r.PACKAGE,'.PKGINFO'],'buildinfo':['/usr/bin/bsdtar','-xOf','/work/output/'+r.PACKAGE,'.BUILDINFO']})
   for name,command in argv.items():
    path=root/spec['command_receipts'][name];row=v.load(path);row['argv']=command;row['log_pin']=v.hashed(root/spec['command_logs'][name]);save(path,row)
   result['output_files']={p.name:dict(**v.hashed(p),mode=0o644)for p in root.iterdir()if p.name!='actor-result.json'};save(root/'actor-result.json',result);verdict=r.namespace(root,result,spec);self.assertEqual(verdict['files'],44)
   r.B.install(spec,lambda *_:None);v.commands(root,SUCCESSOR_SOURCE)
   (root/'stage-runtimes.log').write_bytes(b'changed actual stage log')
   with self.assertRaises(ValueError):v.commands(root,SUCCESSOR_SOURCE)

 def test_null_future_selectors_refuse(self):
  b=v.load(HERE/'binding.TEMPLATE.json');self.assertTrue(all(value is None for value in b['actual'].values()))
  with self.assertRaises(ValueError):r.binding(b,self.pins)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--parent-source',type=Path,required=True);parser.add_argument('--historical-source',type=Path,required=True);parser.add_argument('--ancestor-source',type=Path,required=True);parser.add_argument('--successor-source',type=Path,required=True);a=parser.parse_args();PARENT_SOURCE,HISTORICAL_SOURCE,ANCESTOR_SOURCE,SUCCESSOR_SOURCE=a.parent_source,a.historical_source,a.ancestor_source,a.successor_source;unittest.main(argv=[__file__],verbosity=2)
