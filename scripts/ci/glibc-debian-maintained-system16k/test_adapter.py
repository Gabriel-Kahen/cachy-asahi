# SPDX-License-Identifier: MIT
"""Portable inert source/phase controls. No compiler/container/VM/network actors."""
import ast,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
A=load('maintained16k_adapter',HERE/'adapter.py');G=load('maintained16k_phase',HERE/'phase_gate.py');SHARED=load('maintained16k_shared',ROOT/A.SHARED)
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));p.start();self.addCleanup(p.stop)
 def emit(self):return A.emit(ROOT,self.work/'output')
 def test_current53source_pins_and_new_recipe_identity(self):
  self.assertEqual(len(A.source(ROOT)['files']),53);self.assertEqual(SHARED.EXPECTED['pkgbuild_sha256'],'9d6d5e688c95febe85321abc69fbfe1b7781a02e318771ae43851d8c29f68bb8');self.assertEqual(SHARED.EXPECTED['version'],'2.43.caa3-1')
 def test_emitted10files_are_unbound_and_canonical_helpers_reused(self):
  result=self.emit();self.assertEqual(len(result['files']),10);folder=self.work/'output'/A.NEW;policy=json.loads((folder/'input-policy.json').read_bytes());self.assertIsNone(policy['binding']);self.assertNotIn('private16k',policy);self.assertEqual(policy['candidate'],SHARED.EXPECTED)
  for p in folder.glob('*.py'):ast.parse(p.read_bytes())
  self.assertEqual(A.pin((ROOT/A.OLD/'input-policy.json').read_bytes()),A.source(ROOT)['files'][A.OLD+'/input-policy.json'])
 def test_unbound_trial_and_finalize_refuse_before_any_actor_or_output(self):
  self.emit();folder=self.work/'output'/A.NEW
  with patch.dict(os.environ,DEBIAN_MAINTAINED_SYSTEM16K_SOURCE_ROOT=str(ROOT)):
   c=load('common',folder/'common.py');run=load('maintained16k_run',folder/'run.py')
   with self.assertRaisesRegex(ValueError,'UNBOUND'):c.bindings()
   api=run.namespace(ROOT)
   for name in ('trial','finalize'):
    with self.assertRaisesRegex(ValueError,'UNBOUND'):api[name](NS())
  self.assertEqual({p.name for p in self.work.iterdir()},{'output'})
 def test_finite_ast_anchor_drift_refuses(self):
  raw=(ROOT/A.OLD/'common.py').read_bytes().replace(b'2.43.caa1-1',b'2.43.other-1')
  with self.assertRaisesRegex(ValueError,'anchors'):A.adapt(raw,'common.py')
 def test_normal_proofs_and_libc_version_are_unchanged(self):
  raw=(ROOT/A.OLD/'common.py').read_bytes();new,_=A.adapt(raw,'common.py');old=ast.parse(raw);tree=ast.parse(new)
  for name in ('normal_receipt','stage','elf_closure','validator_source'):
   before=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name);after=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name);self.assertEqual(ast.dump(before),ast.dump(after))
  self.assertIn(b"value['runtime']['glibc_version']=='2.43'",new);self.assertIn(b"len(value['runtime_files'])==19",new);self.assertNotIn(b"glibc_version']=='2.43.caa3",new)
 def test_controller_capture_launcher_preserve_original_budgets(self):
  for name in ('run.py','capture.py','enter-system.py'):
   raw,_=A.adapt((ROOT/A.OLD/name).read_bytes(),name);text=raw.decode()
   if name=='run.py':
    for term in ('--cap-drop=ALL','--network=none','--read-only','--pids-limit=128','--memory=2g','--cpus=2','size=128m',"len(lines)==3",'len(raw)<=512*1024'):self.assertIn(term,text)
   if name=='capture.py':
    self.assertIn('driver.run_command(argv',text);self.assertIn("unchanged static page-probe compile",text);self.assertNotIn('compile_suite(',text)
   if name=='enter-system.py':
    for term in ('os.chroot','os.setgroups([])','os.setgid(23001)','os.setuid(23001)','os.execve'):self.assertIn(term,text)
 def fixture(self):
  files={};root=self.work/'packet';root.mkdir();C=NS(SOURCE=ROOT)
  def add(n,v):
   raw=v if isinstance(v,bytes) else A.encoded(v);(root/n).write_bytes(raw);row=A.pin(raw);files[n]=row;return dict(path=n,**row)
  def ref(r,row,cap=256*1024**2):p=r/row['path'];self.assertEqual(A.pin(p.read_bytes()),{k:row[k] for k in ('bytes','sha256')});return p
  nodes={'usr/lib/libc.so.6':dict(type='file',mode=0o755,uid=0,gid=0,bytes=4,sha256='0'*64)};candidate=dict(nodes=nodes,metadata=dict(pkgname=[SHARED.EXPECTED['package']],pkgver=[SHARED.EXPECTED['version']]))
  C.load=lambda r,n:SHARED if n==G.SHARED else NS(archive=lambda p:candidate);C.ref=ref;C.read=lambda p,cap=256*1024**2:Path(p).read_bytes();archives={s:add(s+'.pkg',b'synthetic package') for s in ('a','b')};probes={n:add(n,b'synthetic probe') for n in ('smoke-normal','exec-child','plugin.so')};compiles={s:add('compile'+s,dict(synthetic=True)) for s in ('a','b')};pair=dict(status='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR',candidate=SHARED.EXPECTED,hardware='NOT_RUN',source_sha='1'*40,run_id=1,provider_pkgbuild_sha256=SHARED.EXPECTED['pkgbuild_sha256'],archive_sha256=archives['a']['sha256'],payload=dict(node_count=1,node_manifest_sha256=hashlib.sha256(SHARED.encoded(nodes)).hexdigest()));normal=dict(status='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES',candidate=SHARED.EXPECTED,source_sha='1'*40,run_id=1,files=probes,compile_receipts=compiles);authority=(ROOT/'scripts/ci/glibc-debian-maintained-provider/root-maintained-source-authority.json').read_bytes();value=dict(status=G.STATUS,candidate=SHARED.EXPECTED,files=files,source_authority=add('authority',authority),provider_pair=add('pair',pair),probe_receipt=add('normal',normal),provider_pkgbuild_sha256=SHARED.EXPECTED['pkgbuild_sha256'],held=add('held',b'synthetic held'),archives=archives,probes=probes);return C,root,value
 def test_first16k_phase_accepts_pair_normal_held_authority_without_prior16k(self):
  C,root,value=self.fixture();result=G.validate(C,root,value);self.assertEqual(result['run_id'],1);self.assertNotIn('private16k',value)
 def test_old_phase_identity_or_fabricated_prior16k_refused(self):
  C,root,value=self.fixture()
  for field,bad in (('status','ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS'),('candidate',dict(SHARED.EXPECTED,version='2.43.caa1-1')),('private16k',{})):
   changed=copy.deepcopy(value);changed[field]=bad
   with self.assertRaises(ValueError):G.validate(C,root,changed)
 def test_packet_and_payload_bounds_not_widened(self):
  C,root,value=self.fixture();changed=copy.deepcopy(value);changed['files']['extra']=dict(bytes=512*1024**2,sha256='0'*64)
  with self.assertRaises(ValueError):G.validate(C,root,changed)
  value['files']['a.pkg']['sha256']='0'*64
  with self.assertRaises(ValueError):G.validate(C,root,value)
if __name__=='__main__':unittest.main()
