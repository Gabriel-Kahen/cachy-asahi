"""New DATA controls only; no namespace/native/Source operand actor executes."""
import ast,copy,errno,hashlib,importlib.util,json,os,re,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;N=HERE/'producer-overlay/native'
MAP=json.loads((HERE/'profile.json').read_bytes())['source_map_sha256'];SLOT='/opt/native-source-tools-alpm-v1/build-current'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(value,message):
 if not value:raise ValueError(message)
def load_functions(path,names,constants=()):
 nodes=[n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in constants for t in n.targets)]
 ns=dict(need=need,Path=Path,json=json,re=re,os=os,stat=__import__('stat'),digest=lambda b:pin(b)['sha256']);exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns);return ns
P=load_functions(N/'source_tools_probe_v1.py',{'namespace_observation','namespace_unshare','namespace_read','namespace_context','namespace_binary'},('NS_MODES','NS_STATUS','NS_POLICY'))
A=load_functions(N/'source_tools_alpm_v1.py',{'observe_namespace_failure'},('NS_OBSERVATION_MODES',));A['SOURCE']=Path('/opt/native-source-tools-alpm-v1/source');A['time']=types.SimpleNamespace(monotonic=lambda:0)
R=load_functions(N/'source_tools_reader_v1.py',{'source_tools_namespace_data'});R['pin']=pin
spec=importlib.util.spec_from_file_location('_new_namespace_factory',HERE/'assemble_source.py');FACTORY=importlib.util.module_from_spec(spec);spec.loader.exec_module(FACTORY)

def context():
 return dict(uid=1001,euid=1001,gid=1001,egid=1001,cwd=SLOT,groups=[1001],group_count=1,groups_truncated=False,status_fields=dict(CapEff='0000000000000000',NoNewPrivs='0',Seccomp='2'),status_state='OBSERVED',namespaces=dict(user='user:[1]',mnt='mnt:[2]',net='net:[3]'),maps={n:dict(status='OBSERVED',text='0 0 4294967295\n')for n in('uid_map','gid_map')},policy={n:dict(status='UNKNOWN',reason='FileNotFoundError',errno=2)for n in('userns_clone','max_user_namespaces','apparmor_userns')},lsm=dict(status='OBSERVED',text='docker-default (enforce)\n'),mounts=dict(status='OBSERVED',rows=[]),bwrap=dict(status='UNKNOWN',reason='MOCKED_DATA'))
def observation(mode):
 call=None if mode=='context'else dict(interface='libc.unshare',flags=P['NS_MODES'][mode],returncode=-1,errno=1,errno_name='EPERM')
 return dict(schema=1,status='NAMESPACE_PREREQUISITE_DATA_ONLY',mode=mode,source_map_sha256=MAP,before=context(),after=context(),syscall=call,scope='OWN_BUILD_ACTOR_SELF_ONLY_NO_CHILD_OR_GLOBAL_MUTATION',namespace_acceptance='NOT_ESTABLISHED',native_acceptance='NOT_ADMITTED')

# Exact public failed-command fixture, retained as DATA; never replayed.
FAILED_FIXTURE = {'first_failure': {'command_index': 3, 'message': 'command failed or retirement unknown: build-a', 'phase': 'build-a', 'type': 'Failure'}, 'commands': [{'argv': ['/usr/bin/pacman', '-Q'], 'channels': 'stdout+stderr combined in pipe order', 'cwd': '/tmp/source-tools-test-my19gpwy', 'expected': 0, 'log': '000-baseline-inventory.log', 'log_pin': {'bytes': 6800, 'sha256': '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'}, 'step': 'baseline-inventory', 'success': True, 'supervision': {'error': None, 'exit': 0, 'group_census': 'EMPTY_TWICE', 'output_complete': True, 'ownership': 'REAPED', 'passed': True, 'reaped': True, 'seconds': 0.030707040000038432, 'signals': [], 'timeout': False}}, {'argv': ['/usr/bin/pacman', '-Qqe'], 'channels': 'stdout+stderr combined in pipe order', 'cwd': '/tmp/source-tools-test-my19gpwy', 'expected': 0, 'log': '001-baseline-reasons-explicit.log', 'log_pin': {'bytes': 1973, 'sha256': 'ca16d2d4c493a9e479fad487cd5f1dacfed23e78d593a800d25d043ec2d8c0c0'}, 'step': 'baseline-reasons-explicit', 'success': True, 'supervision': {'error': None, 'exit': 0, 'group_census': 'EMPTY_TWICE', 'output_complete': True, 'ownership': 'REAPED', 'passed': True, 'reaped': True, 'seconds': 0.04084430599999678, 'signals': [], 'timeout': False}}, {'argv': ['/usr/bin/pacman', '-Qqd'], 'channels': 'stdout+stderr combined in pipe order', 'cwd': '/tmp/source-tools-test-my19gpwy', 'expected': 0, 'log': '002-baseline-reasons-dependencies.log', 'log_pin': {'bytes': 1536, 'sha256': 'b5ae92589d577a77cb6f5f3e825d3a725109ea3a6cd7ea45586b7c681a6bc232'}, 'step': 'baseline-reasons-dependencies', 'success': True, 'supervision': {'error': None, 'exit': 0, 'group_census': 'EMPTY_TWICE', 'output_complete': True, 'ownership': 'REAPED', 'passed': True, 'reaped': True, 'seconds': 0.040936542999986614, 'signals': [], 'timeout': False}}, {'argv': ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=/opt/native-source-tools-alpm-v1/build-current', 'PKGDEST=/opt/native-source-tools-alpm-v1/build-current', 'SRCDEST=/opt/native-source-tools-alpm-v1/build-current', 'BUILDDIR=/opt/native-source-tools-alpm-v1/build-current', 'SOURCE_DATE_EPOCH=1793145600', 'PACKAGER=cachy-asahi native TEST builder', '/usr/bin/makepkg', '--cleanbuild', '--nodeps', '--nosign', '--noconfirm', '--config', '/opt/native-source-tools-alpm-v1/source/native/source-tools-makepkg-v1.conf'], 'channels': 'stdout+stderr combined in pipe order', 'cwd': '/opt/native-source-tools-alpm-v1/build-current', 'expected': 0, 'log': '003-build-a.log', 'log_pin': {'bytes': 2043, 'sha256': 'ffb9dc9f626d8d618388ef239c18c1dcb435d6c2b0fa8d34feb35ae797bc2d21'}, 'step': 'build-a', 'success': False, 'supervision': {'error': None, 'exit': 4, 'group_census': 'EMPTY_TWICE', 'output_complete': True, 'ownership': 'REAPED', 'passed': False, 'reaped': True, 'seconds': 1.7737968879999926, 'signals': [], 'timeout': False}}]}
FAILED_LOG = b'==> WARNING: PACKAGER should have the format \'Example Name <email@address.invalid>\'\n==> Making package: cachy-asahi-source-tools 0.1.0-1 (Sat Oct 31 08:44:48 2026)\n==> WARNING: Skipping dependency checks.\n==> Retrieving sources...\n  -> Found private-source.tar.gz\n  -> Found fixtures.tar.gz\n  -> Found cachy-asahi-source-tools\n  -> Found check_package.py\n  -> Found test_package.py\n  -> Found multi_package_roundtrip.py\n  -> Found README.md\n  -> Found source-provenance.json\n  -> Found payload-map.json\n  -> Found NOTICE\n  -> Found LICENSE\n==> Validating source files with sha256sums...\n    private-source.tar.gz ... Passed\n    fixtures.tar.gz ... Passed\n    cachy-asahi-source-tools ... Passed\n    check_package.py ... Passed\n    test_package.py ... Passed\n    multi_package_roundtrip.py ... Passed\n    README.md ... Passed\n    source-provenance.json ... Passed\n    payload-map.json ... Passed\n    NOTICE ... Passed\n    LICENSE ... Passed\n==> Removing existing $srcdir/ directory...\n==> Extracting sources...\n  -> Extracting private-source.tar.gz with bsdtar\n  -> Extracting fixtures.tar.gz with bsdtar\n==> Starting check()...\n{"payload_files": null, "private_source_files": 11, "status": "PASS"}\n{"payload_files": 17, "private_source_files": 11, "status": "PASS"}\nTraceback (most recent call last):\n  File "/opt/native-source-tools-alpm-v1/build-current/src/test_package.py", line 58, in <module>\n    print(json.dumps(run(args.recipe_root, args.srcdir, args.hide_checkout), sort_keys=True))\n                     ~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n  File "/opt/native-source-tools-alpm-v1/build-current/src/test_package.py", line 30, in run\n    assert hidden.returncode == 0, hidden.stdout + hidden.stderr\n           ^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with \'sysctl kernel.unprivileged_userns_clone=1\'.\n\n==> ERROR: A failure occurred in check().\n    Aborting...\n'

def failure_fixture():
 report=copy.deepcopy(FAILED_FIXTURE);report['source_map_sha256']=MAP;logs={report['commands'][3]['log']:FAILED_LOG};commands=types.SimpleNamespace(records=report['commands'],timeout=180,deadline=450)
 def run(step,argv,cwd):
  mode=argv[argv.index('--namespace-mode')+1];body=(json.dumps(observation(mode),sort_keys=True)+'\n').encode();name='%03d-%s.log'%(len(commands.records),step);logs[name]=body;commands.records.append(dict(step=step,argv=argv,cwd=str(cwd),expected=0,success=True,log=name,log_pin=pin(body),supervision=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[],seconds=.01)));return body
 return report,commands,logs,run
class NamespaceDataControls(unittest.TestCase):
 def collect(self,report,commands,logs,run):
  with patch.dict(A,T=types.SimpleNamespace(ordinary=lambda path,cap:logs[Path(path).name],data_pin=pin)):
   A['observe_namespace_failure'](run,commands,Path('/out'),report,'a',Path(SLOT),MAP)
 def validate(self,report,logs):
  prefix='journey/source-tools-alpm-v1/';files={prefix+n:dict(kind='file',**pin(raw))for n,raw in logs.items()};view=types.SimpleNamespace(read=lambda path:logs[path.removeprefix(prefix)]);return R['source_tools_namespace_data'](view,files,report,MAP)
 def test_exact_syscall_modes_are_data_only(self):
  calls=[]
  def syscall(flags):calls.append(flags);return dict(interface='libc.unshare',flags=flags,returncode=-1,errno=1,errno_name='EPERM')
  with patch.dict(P,namespace_context=context,namespace_unshare=syscall):
   for mode in P['NS_MODES']:
    result=P['namespace_observation'](mode,MAP);self.assertEqual(result['namespace_acceptance'],'NOT_ESTABLISHED');self.assertEqual(result['native_acceptance'],'NOT_ADMITTED')
  self.assertEqual(calls,[v for v in P['NS_MODES'].values()if v])
 def test_root_actor_refused_before_syscall(self):
  value=context();value['uid']=value['euid']=0;calls=[]
  with patch.dict(P,namespace_context=lambda:value,namespace_unshare=lambda flags:calls.append(flags)):
   with self.assertRaises(ValueError):P['namespace_observation']('user',MAP)
  self.assertEqual(calls,[])
 def test_unknown_mode_refused(self):
  with self.assertRaises(ValueError):P['namespace_observation']('privileged',MAP)
 def test_libc_exact_errno_without_real_syscall(self):
  calls=[]
  class Call:
   def __call__(self,flags):calls.append(flags);return -1
  call=Call();fake=types.SimpleNamespace(CDLL=lambda *args,**kw:types.SimpleNamespace(unshare=call),c_int=int,set_errno=lambda value:None,get_errno=lambda:errno.EPERM)
  with patch.dict(sys.modules,ctypes=fake):value=P['namespace_unshare'](0x10000000)
  self.assertEqual(calls,[0x10000000]);self.assertEqual((value['returncode'],value['errno'],value['errno_name']),(-1,1,'EPERM'))
 def test_proc_read_byte_cap_is_unknown(self):
  fake=types.SimpleNamespace(O_RDONLY=0,O_CLOEXEC=0,O_NOFOLLOW=0,O_NONBLOCK=0,open=lambda *a:7,read=lambda fd,size:b'x'*size,close=lambda fd:None)
  with patch.dict(P,os=fake):value=P['namespace_read']('/proc/self/status',16)
  self.assertEqual(value,dict(status='UNKNOWN',reason='BYTE_CAP'))
 def test_proc_short_reads_continue_to_eof(self):
  chunks=iter((b'ab',b'cd',b''));fake=types.SimpleNamespace(O_RDONLY=0,O_CLOEXEC=0,O_NOFOLLOW=0,O_NONBLOCK=0,open=lambda *a:7,read=lambda fd,size:next(chunks),close=lambda fd:None)
  with patch.dict(P,os=fake):value=P['namespace_read']('/proc/self/status',16)
  self.assertEqual(value,dict(status='OBSERVED',text='abcd'))
 def binary_fixture(self,changed=False):
  import stat
  fields=dict(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o755,st_uid=0,st_gid=0,st_nlink=1,st_size=4,st_mtime_ns=1,st_ctime_ns=1);before=types.SimpleNamespace(**fields);after=types.SimpleNamespace(**dict(fields,st_ino=3))if changed else before;calls=[];chunks=iter((b'ab',b'cd',b''));counts=[]
  def fstat(fd):counts.append(fd);return before if len(counts)==1 else after
  def xattr(fd,name):self.assertIsInstance(fd,int);calls.append(fd);return b'\x00\x01'
  fake=types.SimpleNamespace(O_RDONLY=0,O_CLOEXEC=0,O_NOFOLLOW=0,O_NONBLOCK=0,open=lambda *a:7,fstat=fstat,read=lambda fd,size:next(chunks),close=lambda fd:None,getxattr=xattr,stat=lambda *a,**kw:after)
  return fake,calls
 def test_bwrap_metadata_hash_caps_share_one_stable_fd(self):
  fake,calls=self.binary_fixture()
  with patch.dict(P,os=fake):value=P['namespace_binary']()
  self.assertEqual(value['sha256'],pin(b'abcd')['sha256']);self.assertEqual(value['file_capabilities'],'0001');self.assertEqual(calls,[7])
 def test_changed_bwrap_identity_remains_unknown(self):
  fake,calls=self.binary_fixture(True)
  with patch.dict(P,os=fake):value=P['namespace_binary']()
  self.assertEqual(value['status'],'UNKNOWN')
 def test_six_same_context_observations_preserve_failure_and_clocks(self):
  report,commands,logs,run=failure_fixture();first=copy.deepcopy(report['first_failure']);self.collect(report,commands,logs,run)
  self.assertEqual(len(report['namespace_observations']['a']['observations']),6);self.assertEqual(report['first_failure'],first);self.assertEqual((commands.timeout,commands.deadline),(180,450));self.assertEqual(len(commands.records),10)
  for row in commands.records[4:]:self.assertEqual(row['argv'][:11],commands.records[3]['argv'][:11]);self.assertEqual(row['cwd'],SLOT)
  self.assertEqual(self.validate(report,logs)['a']['status'],'VALIDATED_NAMESPACE_PREREQUISITE_DATA_ONLY')
 def test_unqualified_original_never_probes(self):
  report,commands,logs,run=failure_fixture();report['commands'][3]['supervision']['group_census']='PRESENT_OR_REUSED';self.collect(report,commands,logs,run);self.assertNotIn('namespace_observations',report);self.assertEqual(len(commands.records),4)
 def test_other_failure_never_probes(self):
  report,commands,logs,run=failure_fixture();logs[report['commands'][3]['log']]=b'other error';self.collect(report,commands,logs,run);self.assertEqual(len(commands.records),4)
 def test_original_deadline_is_never_extended(self):
  report,commands,logs,run=failure_fixture();commands.deadline=5;self.collect(report,commands,logs,run);self.assertEqual(commands.deadline,5);self.assertEqual(len(commands.records),4);self.assertEqual(report['namespace_observations']['a']['stopped'],'ORIGINAL_DEADLINE_BUDGET')
 def test_failed_observer_stops_without_replacing_original(self):
  report,commands,logs,run=failure_fixture();first=copy.deepcopy(report['first_failure'])
  def bad(*args,**kwargs):raise ValueError('owned observation failed')
  self.collect(report,commands,logs,bad);self.assertEqual(report['first_failure'],first);self.assertEqual(commands.timeout,180);self.assertTrue(report['namespace_observations']['a']['stopped'].startswith('OBSERVATION_UNAVAILABLE'))
 def test_reader_wrong_map_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);item=report['namespace_observations']['a']['observations'][1];row=commands.records[item['command_index']];data=json.loads(logs[row['log']]);data['source_map_sha256']='a'*64;body=json.dumps(data).encode();logs[row['log']]=body;item['output']=row['log_pin']=pin(body)
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_wrong_syscall_flags_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);item=report['namespace_observations']['a']['observations'][1];row=commands.records[item['command_index']];data=json.loads(logs[row['log']]);data['syscall']['flags']=0;body=json.dumps(data).encode();logs[row['log']]=body;item['output']=row['log_pin']=pin(body)
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_raw_pin_tamper_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);logs[commands.records[4]['log']]+=b'!'
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_privileged_launcher_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);commands.records[4]['argv'][2]='root'
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_cwd_change_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);commands.records[4]['cwd']='/root'
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_unknown_retirement_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);commands.records[4]['supervision']['ownership']='UNKNOWN'
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_unlisted_namespace_attempt_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);row=copy.deepcopy(commands.records[-1]);row['step']='namespace-a-extra';commands.records.append(row)
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_unrelated_mount_metadata_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);item=report['namespace_observations']['a']['observations'][0];row=commands.records[item['command_index']];data=json.loads(logs[row['log']]);data['before']['mounts']['rows']=[dict(mount_id='1',parent_id='0',mountpoint='/unrelated',filesystem='tmpfs',options=['rw'])];data['after']=copy.deepcopy(data['before']);body=json.dumps(data).encode();logs[row['log']]=body;item['output']=row['log_pin']=pin(body)
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_reader_extra_context_field_refused(self):
  report,commands,logs,run=failure_fixture();self.collect(report,commands,logs,run);item=report['namespace_observations']['a']['observations'][0];row=commands.records[item['command_index']];data=json.loads(logs[row['log']]);data['before']['lsm']['extra']='unreviewed';data['after']=copy.deepcopy(data['before']);body=json.dumps(data).encode();logs[row['log']]=body;item['output']=row['log_pin']=pin(body)
  with self.assertRaises(ValueError):self.validate(report,logs)
 def test_six_maintained_replacements_are_exact_data(self):
  original={name:('inert '+name).encode()for name in FACTORY.PRODUCER_BEFORE};wanted={name:pin(raw)for name,raw in original.items()}
  with patch.object(FACTORY,'PRODUCER_BEFORE',wanted):result=FACTORY.retired_producer(original)
  self.assertEqual(len(result),6)
  for name,row in FACTORY.PRODUCER_AFTER.items():self.assertEqual(pin(result[name]),{k:row[k]for k in('bytes','sha256')})
 def test_obsolete_probe_replacement_pin_refused(self):
  original={name:('inert '+name).encode()for name in FACTORY.PRODUCER_BEFORE};wanted={name:pin(raw)for name,raw in original.items()};original['native/source_tools_probe_v1.py']=b'wrong probe'
  with patch.object(FACTORY,'PRODUCER_BEFORE',wanted),self.assertRaises(ValueError):FACTORY.retired_producer(original)

def deny(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in {'os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg'}:raise AssertionError('NEW_NAMESPACE_DATA_CONTROL_ACTOR_DENIED:'+event)
sys.addaudithook(deny)
if __name__=='__main__':unittest.main(verbosity=2)
