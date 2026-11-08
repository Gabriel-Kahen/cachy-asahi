#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New unbound provenance DATA controls; no ELF/compiler/callback execution."""
import argparse,ast,base64,copy,hashlib,json,os,re,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
LOCAL=HERE.parent/'reader/security_reader_v1.py'
READER=LOCAL if LOCAL.exists()else HERE/'overlay/native/security_reader_v1.py'
CONTRACT=HERE.parent/'producer/candidate/security-contract-v1.json'
if not CONTRACT.exists():CONTRACT=HERE/'overlay/native/security-contract-v1.json'
HELPER=HERE.parent/'producer/candidate/security_native_v1.py'
if not HELPER.exists():HELPER=HERE/'overlay/native/security_native_v1.py'
BASELINE_HELPER=BASELINE_CONTRACT=None
ARGS=None
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for flag,default in [('reader',READER),('contract',CONTRACT),('helper',HELPER)]:parser.add_argument('--'+flag,type=Path,default=default)
 for flag in('baseline-helper','baseline-contract'):parser.add_argument('--'+flag,type=Path,required=True)
 parser.add_argument('--results',type=Path);parser.add_argument('legacy_result',nargs='?',type=Path);ARGS=parser.parse_args()
 READER,CONTRACT,HELPER,BASELINE_HELPER,BASELINE_CONTRACT=ARGS.reader,ARGS.contract,ARGS.helper,ARGS.baseline_helper,ARGS.baseline_contract
DENIED={'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg',
 'socket.__new__','socket.connect','socket.bind','socket.getaddrinfo','ctypes.dlopen','ctypes.dlsym','ctypes.call_function'}
def no_actors(event,args):
 if event in DENIED:raise AssertionError('NEW_PROVENANCE_DATA_ACTOR_DENIED:'+event)
if __name__=='__main__':sys.addaudithook(no_actors)
def need(value,why):
 if not value:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
NAMES={'_cleanup_require','_cleanup_pin','_observer_integer','_observer_inode','_observer_elf','validate_observer_provenance','validate_observation'}
tree=ast.parse(READER.read_bytes());functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in NAMES]
need({n.name for n in functions}==NAMES,'closed new DATA validator function set')
namespace=dict(need=need,pin=pin,json=json,re=re,os=os,base64=base64)
exec(compile(ast.Module(body=functions,type_ignores=[]),'new-unbound-observer-provenance-validator','exec'),namespace)
validate=namespace['validate_observer_provenance'];validate_observation=namespace['validate_observation']

def synthetic_elf(manifest):
 """An explicitly unbound non-executable byte fixture, not a native ELF result."""
 raw=bytearray(0x3200);raw[:7]=b'\x7fELF\x02\x01\x01'
 def put(at,size,n):raw[at:at+size]=n.to_bytes(size,'little')
 for at,size,n in [(16,2,3),(18,2,183),(20,4,1),(32,8,64),(40,8,0x3100),(52,2,64),(54,2,56),(56,2,2),(58,2,64),(60,2,4),(62,2,1)]:put(at,size,n)
 for at,flags,offset,address,size in [(64,5,0x1000,0x1000,64),(120,4,0x2000,0x2000,len(manifest))]:
  for off,width,n in [(0,4,1),(4,4,flags),(8,8,offset),(16,8,address),(32,8,size),(40,8,size),(48,8,4096)]:put(at+off,width,n)
 names=b'\0.shstrtab\0.cachy_provenance\0.text\0';raw[0x3000:0x3000+len(names)]=names
 raw[0x1000:0x1040]=b'UNBOUND-NOT-AARCH64-INSTRUCTIONS'.ljust(64,b'\0')
 raw[0x2000:0x2000+len(manifest)]=manifest
 for index,name,kind,flags,address,offset,size in [(1,b'.shstrtab',3,0,0,0x3000,len(names)),(2,b'.cachy_provenance',1,2,0x2000,0x2000,len(manifest)),(3,b'.text',1,6,0x1000,0x1000,64)]:
  for off,width,n in [(0,4,names.index(name)),(4,4,kind),(8,8,flags),(16,8,address),(24,8,offset),(32,8,size)]:put(0x3100+index*64+off,width,n)
 return bytes(raw)

def fixture(policy=None,baseline=None,commands=None):
 """Reusable unbound fixture: policy, observation, provenance, baseline, commands."""
 policy=copy.deepcopy(policy if policy is not None else json.loads(CONTRACT.read_bytes())['upgrade']['observation'])
 versions=policy.get('provenance',{}).get('package_versions',dict(gcc='UNBOUND-gcc',binutils='UNBOUND-binutils',glibc='UNBOUND-glibc',**{'linux-api-headers':'UNBOUND-headers'}))
 if baseline is None:baseline=''.join(k+' '+v+'\n'for k,v in sorted({**versions,**{f'unbound-{i:03d}':'0'for i in range(345)}}.items())).encode()
 all_versions=dict(line.decode().split(' ',1)for line in baseline.splitlines());versions={n:all_versions[n]for n in('gcc','binutils','glibc','linux-api-headers')}
 policy['provenance']={**policy.get('provenance',{}),'schema':1,'protocol':'observer-shim-recorded-provenance-v1','scope':'OBSERVER_SHIM_RECORDED_SOURCE_COMPILE_LOADED_OBJECT_BINDING','section':'.cachy_provenance','manifest_cap':16384,'maps_cap':65536,'object_cap':1048576,'value_cap':1572864,'compiler_paths':[base+suffix for base in('/usr/bin/gcc','/usr/bin/aarch64-unknown-linux-gnu-gcc','/usr/bin/aarch64-linux-gnu-gcc')for suffix in('','-16','-16.1.1')],'inventory':pin(baseline),'package_versions':versions}
 home='/tmp/security-test-aaaaaaaa';compiler=dict(path='/usr/bin/gcc',**pin(b'UNBOUND compiler DATA'),inode=[55,400],mode=0o755,uid=0,gid=0,nlink=1)
 recipe=dict(argv=['/usr/bin/cc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-include',home+'/alpm-observer-provenance.h','-o',home+'/alpm-observer.so',home+'/alpm-observer.c','-ldl'],cwd=home,env=dict(PATH='/usr/bin:/bin',HOME=home,LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1'))
 manifest=dict(schema=1,protocol='observer-shim-recorded-provenance-v1',source=policy['source_pin'],header=policy['header'],compiler=compiler,toolchain=dict(inventory=pin(baseline),packages=versions),recipe=recipe)
 note=canonical(manifest);raw=synthetic_elf(note);compiled=pin(raw)
 point=dict(type='FIRST_UPGRADE_ZERO',pid=202,ppid=101,event=1,percent=0,howmany=1,current=1,old_only_errno=2,new_only_errno=2,old_desc_errno=2,new_desc_errno=2,lock=dict(dev=55,ino=123,mode=0o100000,uid=0,gid=0,nlink=1,bytes=0),pacman_inode=[55,201],libalpm_inode=[55,202],symbol_object_verified=1,observer_inode=[55,700],observer_fd_inode=[55,700],observer_load=dict(base=0x100000,pc=0x101008,start=0x101000,end=0x102000,offset=0x1000,dev_major=os.major(55),dev_minor=os.minor(55),inode=700))
 retirement=dict(pid=203,exit=0,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',forced_cleanup=False,cleanup_member_uids=[],elapsed_seconds=0.1)
 obs=dict(schema=1,protocol=policy['protocol'],phase=policy['phase'],observer_source=policy['source_pin'],observer_compiled=compiled,compiler_retirement=retirement,runtime=dict(pacman=dict(**pin(b'UNBOUND pacman'),inode=[55,201]),libalpm=dict(bytes=4096,sha256=policy['libalpm_sha256'],inode=[55,202])),owner_pid=101,witness_paths={k:policy[k]for k in('old_only','new_only')},source_binary_correspondence='OPEN',interruption='NOT_RUN',recovery='NOT_RUN',records=[point,dict(type='END',pid=202,registrations=1,hits=1,errors=0)])
 refresh_observation(obs)
 compile_row=dict(step='compile-upgrade-observer',exit=0,stdout=pin(b''),stderr=pin(b''),recipe=copy.deepcopy(recipe))
 commands=copy.deepcopy(commands)if commands is not None else[compile_row]
 for row in commands:
  if row['step']=='compile-upgrade-observer':row['recipe']=copy.deepcopy(recipe);compile_row=row
 header=('static const unsigned char cachy_observer_provenance[] __attribute__((used,section(".cachy_provenance"))) = {'+','.join(str(x)for x in note)+'};\n').encode()
 file=dict(**compiled,inode=[55,700],mode=0o500,uid=0,gid=0,nlink=1)
 proof=dict(schema=1,protocol=manifest['protocol'],scope='OBSERVER_SHIM_RECORDED_SOURCE_COMPILE_LOADED_OBJECT_BINDING',manifest=manifest,manifest_pin=pin(note),generated_header=pin(header),object_base64=base64.b64encode(raw).decode(),object=compiled,before=file,after=copy.deepcopy(file),compiler_retirement=copy.deepcopy(retirement),compile_record=copy.deepcopy(compile_row),inputs_after={n:copy.deepcopy(manifest[n])for n in('source','header','compiler')},source_binary_semantics='NOT_CLAIMED',upstream_source_binary_correspondence='OPEN')
 return policy,obs,proof,baseline,commands

def refresh_observation(obs):
 obs['raw_ascii']=''.join(json.dumps(r,separators=(',',':'))+'\n'for r in obs['records']);obs['raw_pin']=pin(obs['raw_ascii'].encode())
def replace_object(obs,proof,change):
 raw=bytearray(base64.b64decode(proof['object_base64']));change(raw);raw=bytes(raw);value=pin(raw);proof['object_base64']=base64.b64encode(raw).decode();proof['object']=value;obs['observer_compiled']=value
 for name in('before','after'):proof[name].update(value)

def refresh_manifest(obs,proof):
 note=canonical(proof['manifest']);proof['manifest_pin']=pin(note)
 header=('static const unsigned char cachy_observer_provenance[] __attribute__((used,section(".cachy_provenance"))) = {'+','.join(str(x)for x in note)+'};\n').encode()
 proof['generated_header']=pin(header);replace_object(obs,proof,lambda raw:None)
 raw=synthetic_elf(note);proof['object_base64']=base64.b64encode(raw).decode();proof['object']=pin(raw);obs['observer_compiled']=pin(raw)
 for name in('before','after'):proof[name].update(pin(raw))

class Provenance(unittest.TestCase):
 def check(self,values):
  policy,obs,proof,baseline,commands=values;validate_observation(obs,policy);return validate(proof,obs,policy,baseline,commands)
 def refuses(self,change):
  values=fixture();change(*values)
  with self.assertRaises((ValueError,KeyError,TypeError,UnicodeError,OverflowError)):self.check(values)
 def test_new_complete_unbound_DATA_chain(self):
  values=fixture();self.assertIs(self.check(values),values[2]);self.assertEqual(values[2]['source_binary_semantics'],'NOT_CLAIMED')
 def test_missing_provenance_refused(self):self.refuses(lambda p,o,v,b,c:v.pop('manifest'))
 def test_source_substitution_refused(self):
  def change(p,o,v,b,c):v['manifest']['source']=v['inputs_after']['source']=pin(b'wrong source');refresh_manifest(o,v)
  self.refuses(change)
 def test_header_substitution_refused(self):
  def change(p,o,v,b,c):v['manifest']['header']=v['inputs_after']['header']=pin(b'wrong header');refresh_manifest(o,v)
  self.refuses(change)
 def test_compiler_after_substitution_refused(self):self.refuses(lambda p,o,v,b,c:v['inputs_after']['compiler'].update(sha256='0'*64))
 def test_retained_compiler_three_hardlinks_valid(self):
  values=fixture();p,o,v,b,c=values;v['manifest']['compiler']['nlink']=v['inputs_after']['compiler']['nlink']=3;refresh_manifest(o,v);self.check(values)
 def test_compiler_zero_links_refused(self):
  def change(p,o,v,b,c):v['manifest']['compiler']['nlink']=v['inputs_after']['compiler']['nlink']=0;refresh_manifest(o,v)
  self.refuses(change)
 def test_compiler_link_cap_refused(self):
  def change(p,o,v,b,c):v['manifest']['compiler']['nlink']=v['inputs_after']['compiler']['nlink']=65;refresh_manifest(o,v)
  self.refuses(change)
 def test_compiler_link_drift_refused(self):self.refuses(lambda p,o,v,b,c:v['inputs_after']['compiler'].update(nlink=2))
 def test_compiler_writable_by_others_refused(self):
  def change(p,o,v,b,c):v['manifest']['compiler']['mode']=v['inputs_after']['compiler']['mode']=0o777;refresh_manifest(o,v)
  self.refuses(change)
 def test_compiler_path_escape_refused(self):
  def change(p,o,v,b,c):v['manifest']['compiler']['path']=v['inputs_after']['compiler']['path']='/tmp/compiler';refresh_manifest(o,v)
  self.refuses(change)
 def test_environment_loader_injection_refused(self):
  def change(p,o,v,b,c):v['manifest']['recipe']['env']['LD_PRELOAD']='/tmp/other.so';refresh_manifest(o,v)
  self.refuses(change)
 def test_compile_failure_refused(self):
  def change(p,o,v,b,c):v['compile_record']['exit']=c[0]['exit']=1
  self.refuses(change)
 def test_second_compile_refused(self):self.refuses(lambda p,o,v,b,c:c.append(copy.deepcopy(c[0])))
 def test_actual_compile_recipe_missing_refused(self):
  def change(p,o,v,b,c):v['compile_record'].pop('recipe');c[0].pop('recipe')
  self.refuses(change)
 def test_actual_compile_recipe_mismatch_refused(self):
  def change(p,o,v,b,c):v['compile_record']['recipe']['argv'][0]=c[0]['recipe']['argv'][0]='/usr/bin/gcc'
  self.refuses(change)
 def test_compile_record_rebinding_refused(self):self.refuses(lambda p,o,v,b,c:v['compile_record'].update(stdout=pin(b'other')))
 def test_forced_compiler_retirement_refused(self):
  def change(p,o,v,b,c):o['compiler_retirement']['forced_cleanup']=v['compiler_retirement']['forced_cleanup']=True
  self.refuses(change)
 def test_lost_compiler_owner_refused(self):
  def change(p,o,v,b,c):o['compiler_retirement']['ownership_lost']=v['compiler_retirement']['ownership_lost']=True
  self.refuses(change)
 def test_object_digest_refused(self):self.refuses(lambda p,o,v,b,c:v['object'].update(sha256='0'*64))
 def test_object_after_mutation_refused(self):self.refuses(lambda p,o,v,b,c:v['after'].update(sha256='0'*64))
 def test_writable_object_refused(self):
  def change(p,o,v,b,c):v['before']['mode']=v['after']['mode']=0o700
  self.refuses(change)
 def test_object_alias_refused(self):
  def change(p,o,v,b,c):v['before']['nlink']=v['after']['nlink']=2
  self.refuses(change)
 def test_loaded_object_inode_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_inode']=[55,701];refresh_observation(o)
  self.refuses(change)
 def test_held_fd_inode_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_fd_inode']=[55,701];refresh_observation(o)
  self.refuses(change)
 def test_mapping_backing_inode_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_load']['inode']=701;refresh_observation(o)
  self.refuses(change)
 def test_mapping_device_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_load']['dev_minor']+=1;refresh_observation(o)
  self.refuses(change)
 def test_mapping_pc_outside_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_load']['pc']=0x103000;refresh_observation(o)
  self.refuses(change)
 def test_mapping_file_offset_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_load']['offset']+=1;refresh_observation(o)
  self.refuses(change)
 def test_callback_inode_boolean_even_matching_one_refused(self):
  def change(p,o,v,b,c):
   v['before']['inode'][0]=v['after']['inode'][0]=1;o['records'][0]['observer_inode'][0]=True;o['records'][0]['observer_fd_inode'][0]=1;o['records'][0]['observer_load'].update(dev_major=os.major(1),dev_minor=os.minor(1));refresh_observation(o)
  self.refuses(change)
 def test_mapping_boolean_integer_refused(self):
  def change(p,o,v,b,c):o['records'][0]['observer_load']['pc']=True;refresh_observation(o)
  self.refuses(change)
 def test_raw_record_spoof_refused(self):self.refuses(lambda p,o,v,b,c:o['records'][0]['observer_load'].update(inode=701))
 def test_bad_ELF_magic_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(0,0)))
 def test_wrong_ELF_machine_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(18,62)))
 def test_truncated_ELF_table_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__delitem__(slice(0x3100,None))))
 def test_note_substitution_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(0x2000,32)))
 def test_nonallocated_note_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(0x3100+2*64+8,0)))
 def test_writable_note_load_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(120+4,6)))
 def test_nonexecutable_pc_segment_even_rehashed_refused(self):self.refuses(lambda p,o,v,b,c:replace_object(o,v,lambda r:r.__setitem__(64+4,4)))
 def test_generated_header_substitution_refused(self):self.refuses(lambda p,o,v,b,c:v['generated_header'].update(sha256='0'*64))
 def test_toolchain_package_substitution_refused(self):
  def change(p,o,v,b,c):v['manifest']['toolchain']['packages']['gcc']='other';refresh_manifest(o,v)
  self.refuses(change)
 def test_provenance_policy_cap_increase_refused(self):self.refuses(lambda p,o,v,b,c:p['provenance'].update(object_cap=2*1024**2))
 def test_arbitrary_usr_bin_compiler_refused(self):
  def change(p,o,v,b,c):v['manifest']['compiler']['path']=v['inputs_after']['compiler']['path']='/usr/bin/sh';refresh_manifest(o,v)
  self.refuses(change)
 def test_compiler_driver_substitution_refused(self):
  def change(p,o,v,b,c):v['manifest']['recipe']['argv'][0]='/usr/bin/gcc';refresh_manifest(o,v)
  self.refuses(change)
 def test_noncanonical_base64_refused(self):self.refuses(lambda p,o,v,b,c:v.update(object_base64=v['object_base64']+'\n'))
 def test_upstream_closure_credit_refused(self):self.refuses(lambda p,o,v,b,c:v.update(upstream_source_binary_correspondence='VERIFIED'))
 def test_compiler_semantic_credit_refused(self):self.refuses(lambda p,o,v,b,c:v.update(source_binary_semantics='PROVED'))
 def test_extra_provenance_claim_refused(self):self.refuses(lambda p,o,v,b,c:v.update(reproducible=True))

def functions(path):
 return {n.name:n for n in ast.walk(ast.parse(path.read_bytes()))if isinstance(n,ast.FunctionDef)}
def dumped(value):return ast.dump(value,include_attributes=False)
def calls(function,attribute):
 return [n for n in ast.walk(function)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='os'and n.func.attr==attribute]
def message_calls(function,message):
 return [n for n in ast.walk(function)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and any(isinstance(a,ast.Constant)and a.value==message for a in n.args)]
def c_function(source,name):
 m=re.search(r'\b'+re.escape(name)+r'\([^)]*\)\s*\{',source);need(m is not None,'C function declaration exists')
 at=m.end();depth=1
 while depth:
  need(at<len(source),'complete C function DATA');depth+=(source[at]=='{')-(source[at]=='}');at+=1
 return source[m.start():at]

class Preservation(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.new=functions(HELPER);cls.old=functions(BASELINE_HELPER)
  cls.policy=json.loads(CONTRACT.read_bytes())['upgrade']['observation'];cls.old_policy=json.loads(BASELINE_CONTRACT.read_bytes())['upgrade']['observation']
 def test_existing_failure_diagnostic_AST_held(self):self.assertEqual(dumped(self.new['emit_observation_fd_failure']),dumped(self.old['emit_observation_fd_failure']))
 def test_explicit_wait_background_launcher_AST_held(self):self.assertEqual(dumped(self.new['dockerfile']),dumped(self.old['dockerfile']))
 def test_original_record_FD_fresh_and_bounds_AST_held(self):
  for message in('fresh ordinary owned observation FD','same bounded owned observation FD','whole complete observation DATA'):
   a=message_calls(self.new['observe_real_upgrade'],message);b=message_calls(self.old['observe_real_upgrade'],message);self.assertEqual(len(a),1);self.assertEqual([dumped(n)for n in a],[dumped(n)for n in b])
 def test_original_record_open_and_predicates_AST_held(self):
  def select(fn):
   return [n for n in ast.walk(fn)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in('fd','predicates')for t in n.targets)]
  self.assertEqual([dumped(n)for n in select(self.new['observe_real_upgrade'])],[dumped(n)for n in select(self.old['observe_real_upgrade'])])
 def test_original_record_close_is_finally_held(self):
  for fn in(self.old['observe_real_upgrade'],self.new['observe_real_upgrade']):
   found=[n for n in ast.walk(fn)if isinstance(n,ast.Try)and any(isinstance(q,ast.Call)and isinstance(q.func,ast.Attribute)and isinstance(q.func.value,ast.Name)and q.func.value.id=='os'and q.func.attr=='close'and len(q.args)==1 and isinstance(q.args[0],ast.Name)and q.args[0].id=='fd'for block in n.finalbody for q in ast.walk(block))]
   self.assertEqual(len(found),1)
 def test_direct_python_to_pacman_command_held(self):
  def target(fn):
   return [n for n in ast.walk(fn)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='c'and n.func.attr=='run'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='required-install']
  before=target(self.old['observe_real_upgrade']);after=target(self.new['observe_real_upgrade']);self.assertEqual(len(before),1);self.assertEqual(len(after),1)
  a=copy.deepcopy(after[0]);a.keywords=[ast.keyword(arg=k.arg,value=ast.Tuple(elts=k.value.elts[:2],ctx=ast.Load()))if k.arg=='observe'and isinstance(k.value,ast.Tuple)else k for k in a.keywords]
  self.assertEqual(dumped(a),dumped(before[0]))
 def test_original_C_eligibility_callback_and_getters_held(self):
  old,new=self.old_policy['source'],self.policy['source']
  for text in('parent != getppid() || parent <= 1','strcmp(exe, "/usr/bin/pacman")','(s.st_mode & 0777) != 0600','s.st_size > 16384','if(original) original(original_ctx, event, pkg, percent, howmany, current);','s.st_size + n > 16384','if(!hits && eligible()','dladdr((void *)real'):
   self.assertIn(text,old);self.assertIn(text,new)
  for name in('alpm_option_get_progresscb','alpm_option_get_progresscb_ctx'):self.assertEqual(c_function(new,name),c_function(old,name))
  for text in('kill(','killpg(','abort(','_exit(','system(','popen(','execve(','fork('):self.assertNotIn(text,new)

if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
 report=ARGS.results or ARGS.legacy_result
 if report is not None:
  with report.open('x')as f:json.dump(dict(status='PASS'if result.wasSuccessful()else'FAIL',controls=result.testsRun,failures=len(result.failures),errors=len(result.errors),fixture='UNBOUND_SYNTHETIC_ELF_DATA_ONLY_NOT_COMPILED_OR_EXECUTED',actor_network_FFI_denied=True,old_suite_replays=0,reader_validate_replays=0,C_callbacks=0,Git_API_native=0),f,sort_keys=True,indent=2);f.write('\n')
 raise SystemExit(not result.wasSuccessful())
