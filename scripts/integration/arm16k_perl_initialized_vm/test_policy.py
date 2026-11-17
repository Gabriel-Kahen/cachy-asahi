"""Synthetic preservation + actual safe r74 proof metadata; no raw or private reads."""
import ast,base64,copy,hashlib,importlib.util,json,sys,unittest
from types import SimpleNamespace
from pathlib import Path
S=Path(__file__).parent;B=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114');LEGACY=B/'Root-warm-baseline-inputs-r1/constructed-source/arm16k_perl5423_vm'
def module(n):
 sp=importlib.util.spec_from_file_location('initialized_test_'+n,S/(n+'.py'));m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
P,Q,E=module('policy'),module('qualification'),module('ssh_empty');T=module('test_ssh_empty');L=Q.legacy(LEGACY)
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn'))or event in('os.system','os.kill','os.killpg','fcntl.flock','resource.setrlimit'):raise AssertionError('no actor/role/process in test')
 if event=='open'and args and type(args[0])in(str,bytes):
  name=args[0].decode()if isinstance(args[0],bytes)else args[0]
  if name.endswith(('.raw','credentials.canonical.private.json','collection.lock')):raise AssertionError('no actual raw/credentials/lock')
sys.addaudithook(fence)
def scan():
 proof=E.aggregate(T.Reader(),17,4);nodes={}
 def row(n,kind='directory',mode=0o755,size=4096):return dict(inode=n,links=2,type=kind,mode=mode,uid=0,gid=0,size=size,xattrs={},mtime=100,mtime_ns=0)
 for n,(path,kind,mode)in enumerate(P.PUBLIC,100):
  r=row(n,kind,mode)
  if kind=='file':r['sha256']='a'*64
  if kind=='symlink':r['target_b64']=base64.b64encode(b'../usr/lib/os-release').decode()
  nodes[path]=r
 for n,path in enumerate(P.PARENTS,1):nodes[path]=row(4 if path=='root'else n,mode=0o700 if path=='root'else 0o755)
 nodes['root/.ssh']=dict(proof['inode_metadata'],xattrs={});nodes['root']['inode']=4
 log=b'MODEL_BASELINE_LOG\n';nodes['var/log/pacman.log']=dict(row(99,'file',0o644,len(log)),sha256=hashlib.sha256(log).hexdigest())
 return dict(nodes=nodes,records={},filesystem_free_bytes=1024**3,log_data_b64=base64.b64encode(log).decode(),retained_log_data_b64=None,root_ssh_empty_proof=proof)
def runtime(s):
 body=base64.b64decode(s['log_data_b64']);return dict(candidate_namespace={},baseline_namespace={},dependency_transaction={},restoration_allowances=dict(install_date_path=None,database_timestamp_paths=[],cache_directory_timestamps=[],normal_pacman_log='/var/log/pacman.log',pacman_log_before=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())))
class Controls(unittest.TestCase):
 def test_new_Source_is_whole_sealed_and_default_templates_are_unissued(self):
  raw=(S/'source.lock.json').read_bytes();self.assertEqual(Q.source(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))['bytes'],len(raw))
 def test_initialized_exact_state_composes_genuine_legacy_preservation(self):
  a=scan();v=P.preserve(a,copy.deepcopy(a),{},runtime(a),L);self.assertEqual(v['status'],'PASS_INITIALIZED_STATE_PRESERVATION_DATA_ONLY');self.assertIsNone(v['Root_acceptance'])
 def test_each_public_node_content_metadata_or_replacement_refuses(self):
  for path,kind,mode in P.PUBLIC:
   for key,value in [('inode',999),('links',3),('size',8192),('mtime_ns',1),('xattrs',{'user.MODEL':'eA=='})]+([('sha256','b'*64)]if kind=='file'else[('target_b64','L01PREVM')]if kind=='symlink'else[]):
    a=scan();b=copy.deepcopy(a);b['nodes'][path][key]=value
    with self.subTest(path=path,key=key),self.assertRaises(ValueError):P.preserve(a,b,{},runtime(a),L)
 def test_empty_SSH_directory_and_parent_never_removed_normalized_or_replaced(self):
  for path,key,value in [('root/.ssh','inode',18),('root/.ssh','mode',0o755),('root/.ssh','mtime_ns',1),('root','inode',18),('root','links',3),('etc','mtime_ns',1)]:
   a=scan();b=copy.deepcopy(a);b['nodes'][path][key]=value
   with self.subTest(path=path,key=key),self.assertRaises(ValueError):P.preserve(a,b,{},runtime(a),L)
  a=scan();b=copy.deepcopy(a);del b['nodes']['root/.ssh']
  with self.assertRaises(ValueError):P.preserve(a,b,{},runtime(a),L)
 def test_captured_state_is_not_mutated_by_later_scan_xattrs(self):
  a=scan();captured=P.snapshot(a);a['nodes']['etc/.updated']['xattrs']['user.MODEL']='eA=='
  self.assertEqual(captured['public_nodes']['etc/.updated']['xattrs'],{})
 def test_nonempty_or_unproved_SSH_snapshot_refuses(self):
  for what in('child','proof'):
   a=scan()
   if what=='child':a['nodes']['root/.ssh/MODEL_PRIVATE_NO_BODY']={}
   else:a['root_ssh_empty_proof']=None
   with self.assertRaises(ValueError):P.snapshot(a)
 def test_actual_r74_empty_aggregate_is_bound_but_is_not_namespace_qualification(self):
  c=json.loads((B/'Root-warm-perl-ssh-empty-proof-trial-r1/Root-terminal-closure.ACTUAL.json').read_bytes());proof=c['policy_result'];self.assertEqual(c['runtime'],'r74');bound=Q.empty_inputs(proof,c);self.assertEqual(bound['links'],2);self.assertEqual(proof['root_ssh_emptiness']['headers_seen'],3)
  for field in('owned_absence_independently_verified','scope_collected_twice','policy_exit_code'):
   bad=copy.deepcopy(c);bad[field]=[]if field=='owned_absence_independently_verified'else False if field=='scope_collected_twice'else 3
   with self.assertRaises(ValueError):Q.empty_inputs(proof,bad)
 def test_r72_presence_and_cold_certificate_are_never_reused(self):
  c=json.loads((B/'Root-warm-perl-fixed-metadata-trial-r1/Root-terminal-closure.ACTUAL.json').read_bytes())
  with self.assertRaises(ValueError):Q.empty_inputs(c['policy_result'],c)
  cold=json.loads((B/'Root-perl-ARM16K-migrated-FIRST-trial-r14/Root-inputs/issued-bound-r1/baseline-certificate.ACTUAL.json').read_bytes())
  with self.assertRaises(ValueError):Q.baseline_selection(cold)
 def test_unissued_templates_refuse_before_source_raw_or_certificates(self):
  a=json.loads((S/'scan-authority.TEMPLATE.json').read_bytes());d=json.loads((S/'qualification.TEMPLATE.json').read_bytes())
  self.assertIsNone(a['accepted']);self.assertIsNone(d['baseline_certificate']);self.assertIsNone(d['scan_certificate'])
  with self.assertRaises(ValueError):Q.authorize_scan(a,{}, {},1000000)
  with self.assertRaises(ValueError):Q.qualify(d,{}, {}, {}, {}, {}, {}, {})
 def test_original_default_absence_gates_remain_genuine_and_unchanged(self):
  a=scan();R=Q.module('root_ssh',LEGACY)
  with self.assertRaises(ValueError):R.preserve(L.contracts,a,a)
  self.assertEqual(len(L.preboot.ABSENCE_POLICY),9);self.assertEqual(L.adapter.source(Q.SOURCE65['sha256']),Q.SOURCE65)

 def test_complete_ALPM_and_actual_provider_ownership_checks_are_composed(self):
  nodes={'usr':dict(type='directory'),'usr/lib':dict(type='directory'),'usr/lib/provider':dict(type='file',size=10,sha256='a'*64,mode=0o755,uid=0,gid=0)}
  records={'var/lib/pacman/local/model-1/desc':'%NAME%\nmodel\n\n%VERSION%\n1\n','var/lib/pacman/local/model-1/files':'%FILES%\nusr/lib/provider\n'}
  model=dict(nodes=nodes,records=records);owned=L.image.owners(model,{'model':'1'})
  expected={'/usr/lib/provider':dict(resolved='/usr/lib/provider',bytes=10,sha256='a'*64,mode=0o755,owner='model')};L.image.qualify(model,expected,owned)
  with self.assertRaises(ValueError):L.image.owners(model,{'model':'2'})
  bad=copy.deepcopy(expected);bad['/usr/lib/provider']['sha256']='b'*64
  with self.assertRaises(ValueError):L.image.qualify(model,bad,owned)
  bad=copy.deepcopy(model);del bad['records']['var/lib/pacman/local/model-1/files']
  with self.assertRaises(ValueError):L.image.owners(bad,{'model':'1'})
 def scanner_reader_MODEL(self,nonempty=False):
  proof=E.aggregate(T.Reader(),17,4);calls=[];body={2:T.block([(2,b'.',2),(2,b'..',2),(4,b'root',2)]),4:T.block([(4,b'.',2),(2,b'..',2),(17,b'.ssh',2)]),17:T.block([(17,b'.',2),(4,b'..',2)]+([(99,b'MODEL_PRIVATE_NAME',1)]if nonempty else []))}
  class Base:
   def __init__(self):self.data=copy.deepcopy(body)
   def inode(self,n):
    if n not in(2,4,17):raise AssertionError('no private child inode')
    calls.append(('inode',n));row=dict(T.Reader().row,inode=n,mode=0o700 if n in(4,17)else 0o755)
    row['xattrs']=self.xattrs(b'',0);return row,bytes([n])
   def xattrs(self,*args):calls.append(('xattr',17));return {'user.MODEL':'eA=='}
   def chunks(self,fields,raw):calls.append(('chunks',fields['inode']));yield self.data[fields['inode']]
   def inventory(self):
    # Adversarial same-metadata mutation after the empty guard may never enqueue
    # a private child. The scanner uses only the already verified empty block.
    row,raw=self.inode(17);self.data[17]=T.block([(17,b'.',2),(4,b'..',2),(99,b'MODEL_PRIVATE_NAME',1)])
    cached=b''.join(self.chunks(row,raw));return {'selected_directory_bytes':cached}
  tree=ast.parse((S/'scanner.py').read_bytes());node=next(n for n in ast.walk(tree)if isinstance(n,ast.ClassDef)and n.name=='Reader')
  env=dict(F=SimpleNamespace(Ext4Reader=Base),K=SimpleNamespace(need=E.need),E=E,L=L,empty_document={'root_ssh_emptiness':proof},original=proof['inode_metadata'],guard=lambda:None,deadline=100,clock=lambda:0)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'new_scanner_reader_MODEL','exec'),env);return env['Reader'](),calls
 def test_initialized_scanner_refuses_nonempty_before_inventory_or_xattrs(self):
  r,calls=self.scanner_reader_MODEL(True)
  with self.assertRaises(ValueError):r.inventory()
  self.assertFalse(any(n=='xattr'for n,*_ in calls));self.assertFalse(any(n=='inode'and inode==99 for n,inode in calls))
 def test_initialized_scanner_uses_only_verified_empty_bytes_on_inventory_race(self):
  r,calls=self.scanner_reader_MODEL();result=r.inventory();self.assertNotIn(b'MODEL_PRIVATE_NAME',result['selected_directory_bytes']);self.assertEqual(r._empty['non_dot_entries_seen'],0)
  self.assertEqual(sum(n=='chunks'and inode==17 for n,inode in calls),1);self.assertFalse(any(n=='inode'and inode==99 for n,inode in calls))

if __name__=='__main__':unittest.main(verbosity=2)
