# SPDX-License-Identifier: MIT
"""Portable ordinary-source and tiny genuine-FD controls; no native result replay."""
import ast,contextlib,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location('_fixed_case_factory',HERE/'prepare.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def functions(raw,names,space):
 nodes=[n for n in ast.parse(raw.decode()).body if isinstance(n,ast.FunctionDef)and n.name in names];assert len(nodes)==len(names);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<whole-pinned-source-functions>','exec'),space);return space

def export_fixture(source,expected,destination):
 source=B.canonical(source);seen={};directories=set()
 for root,dirs,files in os.walk(source,followlinks=False):
  root=Path(root)
  if root==source:
   if '.git'in dirs:dirs.remove('.git')
   files=[n for n in files if n!='.git']
  for n in dirs:
   p=root/n;B.need(not p.is_symlink(),'checkout directory alias');directories.add(p.relative_to(source).as_posix())
  for n in files:
   p=root/n;seen[p.relative_to(source).as_posix()]=B.read(p)
 B.need(B.pins(seen)==expected and directories=={p.as_posix()for n in seen for p in Path(n).parents if p.as_posix()!='.'},'entire exported public fixture; Git admin stays outside')
 destination.mkdir(mode=0o700)
 for n,b in seen.items():p=destination/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 return destination

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  global D,P,F,BEFORE
  cls.tmp=tempfile.TemporaryDirectory(prefix='gnu-fixed-source-controls-');D=Path(cls.tmp.name);v=B.profile();P=export_fixture(Path(os.environ['GNU_FIXED_PARENT']),v['before'],D/'parent');cls.expected=export_fixture(Path(os.environ['GNU_FIXED_EXPECTED']),v['after'],D/'expected');cls.v=v;cls.out=D/'emitted';B.emit(P,cls.out);F=load('_pinned_fixed_case_helper',cls.out/B.HELPER);BEFORE={n[8:]:b for n,b in B.snapshot(P)[0].items()if n.startswith('runtime/')}
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_entire_source_reproduction_default_runtime_and_actual_null(self):
  self.assertEqual(B.pins(B.snapshot(self.out)[0]),self.v['after']);self.assertEqual(B.snapshot(self.out)[0],B.snapshot(self.expected)[0]);self.assertEqual(len(BEFORE),667)
  for n,b in B.snapshot(P)[0].items():
   if n.startswith('runtime/'):self.assertEqual(B.read(self.out/n),b)
  q=json.loads(B.read(self.out/B.PROFILE));self.assertTrue(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertEqual(F.render(BEFORE,'both'),(BEFORE,{}))
 def test_original_codec_data_bounded_whole_decoded_equivalence(self):
  codec=json.loads(B.read(HERE/'payload/before-bodies-zlib.json'));self.assertEqual(len(codec),8)
  for n,text in codec.items():
   raw=B.read(P/n);z=B.zlib.decompressobj();self.assertEqual(z.decompress(B.base64.b64decode(text,validate=True),len(raw)+1),raw);self.assertTrue(z.eof);self.assertFalse(z.unused_data or z.unconsumed_tail)
  payload=B.snapshot(HERE/'payload')[0];bad=dict(payload);bad['before-bodies-zlib.json']=b'{}\n'
  with self.assertRaises(ValueError):B.transformed(B.snapshot(P)[0],bad,self.v)
 def test_cli_and_all_current_source_guards_under_original300(self):
  target=D/'cli';p=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--parent',str(P),'--output',str(target)],capture_output=True,timeout=30);self.assertEqual((p.returncode,p.stderr),(0,b''));r=json.loads(p.stdout);self.assertIsNone(r['current_source']);self.assertIsNone(r['Root_acceptance']);self.assertEqual(B.snapshot(target)[0],B.snapshot(self.expected)[0])
  # This executes only the entire current source entry/older source bodies.
  code="import runpy,sys,subprocess;from unittest.mock import patch;sys.argv=[sys.argv[1],'source','--source',sys.argv[2]];p=sys.argv[0];sys.path.insert(0,str(__import__('pathlib').Path(p).parent));\nwith patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS_API_GIT')),patch.object(subprocess,'check_output',side_effect=AssertionError('NO_ACTORS_API_GIT')):runpy.run_path(p,run_name='__main__')"
  p=subprocess.run([sys.executable,'-I','-B','-Werror','-c',code,str(target/B.LANE/'entry.py'),str(target)],capture_output=True,timeout=300);self.assertEqual((p.returncode,p.stderr),(0,b''));q=json.loads(p.stdout);self.assertEqual(q['files'],749);self.assertEqual(q['whole_lifetime_parent747']['files'],747);self.assertIsNone(q['actual_run'])
 def test_canonical_fresh_disjoint_and_foreign_inputs_prewrite(self):
  alias=D/'parent-alias';alias.symlink_to(P,target_is_directory=True)
  for path in(P/'no',HERE/'no',D/'missing/../no',alias/'no',Path('relative'),self.out):
   with self.assertRaises(ValueError):B.emit(P,path)
  bad=D/'bad-parent';shutil.copytree(P,bad);p=bad/'runtime/immutable/worker.py';raw=p.read_bytes();p.write_bytes(raw+b'\n')
  with self.assertRaises(ValueError):B.emit(bad,D/'must-not-exist')
  self.assertFalse((D/'must-not-exist').exists());p.write_bytes(raw);(bad/'empty-foreign').mkdir()
  with self.assertRaises(ValueError):B.emit(bad,D/'must-not-exist')
  (bad/'empty-foreign').rmdir();p.unlink();p.symlink_to(P/'runtime/immutable/worker.py')
  with self.assertRaises(ValueError):B.emit(bad,D/'must-not-exist')
  p.unlink();p.write_bytes(raw);os.link(p,bad/'alias')
  with self.assertRaises(ValueError):B.emit(bad,D/'must-not-exist')
 def test_late_same_bytes_inode_replacement_refuses_before_write(self):
  parent=D/'late-parent';shutil.copytree(P,parent);real=B.transformed
  def mutate(*a):
   out=real(*a);p=parent/'runtime/immutable/worker.py';r=parent/'runtime/immutable/replacement';r.write_bytes(p.read_bytes());os.replace(r,p);return out
  with patch.object(B,'transformed',side_effect=mutate),self.assertRaisesRegex(ValueError,'late complete'):B.emit(parent,D/'late-output')
  self.assertFalse((D/'late-output').exists())
 def test_pinned_profile_payload_and_late_operand_drift(self):
  factory=D/'factory';shutil.copytree(HERE,factory);local=load('_owned_drift_factory',factory/'prepare.py');p=factory/'payload/fixed_case.py';p.write_bytes(p.read_bytes()+b'\n')
  with self.assertRaises(ValueError):local.emit(P,D/'payload-output')
  self.assertFalse((D/'payload-output').exists());p.write_bytes(B.read(HERE/'payload/fixed_case.py'));r=factory/'profile.json';r.write_bytes(r.read_bytes()+b' ')
  with self.assertRaises(ValueError):local.emit(P,D/'profile-output')
  r.write_bytes(B.read(HERE/'profile.json'));real=local.transformed
  def mutate(*a):
   out=real(*a);p.write_bytes(p.read_bytes()+b'\n');return out
  with patch.object(local,'transformed',side_effect=mutate),self.assertRaises(ValueError):local.emit(P,D/'late-operand-output')
  self.assertFalse((D/'late-operand-output').exists())

 def lifetime(self,case):
  sys.path.insert(0,str(P/'runtime/runtime-vm/scripts/update'));import aux_copy
  if case=='old':return aux_copy._isolated(aux_copy.disposable_copy.__file__,aux_copy.LIFETIME_SHA256),aux_copy
  after,_=F.render(BEFORE,case);space=dict(P=types.SimpleNamespace(need=F.need),types=types);functions(after['immutable/worker_api.py'],{'clone','fixed_case_lifetime'},space);return space['fixed_case_lifetime'](aux_copy),aux_copy

 def cleanup(self,case,seconds,clock_at_cleanup=0):
  module,aux=self.lifetime(case);events=[];clock=types.SimpleNamespace(now=0)
  class Limits(aux.roots.Limits):
   def tick(self):
    if self.deadline in(120,600):clock.now=clock_at_cleanup
    F.need(clock.now<self.deadline,'root observation deadline')
  rootspace=dict(vars(aux.roots));rootspace['Limits']=Limits
  query=load('_private_original_mount_query',P/'runtime/runtime-vm/scripts/ci/expanded600-installer-vm/observer600.py');rootspace['_mount_id']=query._mount600(aux.roots._mount_id)
  for name in('_mount_id','_open_root'):
   original=rootspace[name]
   def traced(*a,_name=name,_call=original,**kw):events.append((_name,str(a[0])));return _call(*a,**kw)
   rootspace[name]=traced
  module.roots=types.SimpleNamespace(**rootspace);module.time=types.SimpleNamespace(monotonic=lambda:clock.now)
  # Only fixture materialization is substituted. The entire original cleanup
  # body and all descriptor/mount/identity calls execute on genuine private FDs.
  def copied(src,dst,**kwargs):shutil.copytree(src,dst,symlinks=True);return {'INERT_PRIVATE_FIXTURE':True}
  module.measure_copy=types.SimpleNamespace(copy_data=copied)
  with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='caa-gnu-cleanup-fd-fixture-')as td:
   root=Path(td);source=root/'source';source.mkdir();(source/'sub').mkdir();(source/'sub/é').write_bytes(b'inert\x00data');os.link(source/'sub/é',source/'alias');foreign=root/'foreign';foreign.write_bytes(b'preserve');(source/'link').symlink_to(foreign);work=root/'work';before={p.relative_to(source).as_posix():p.lstat().st_ino for p in source.rglob('*')};fds=len(os.listdir('/proc/self/fd'));caught=None;report=None
   try:
    with module.copied_root(source,work,limits=Limits(deadline=10000),cleanup_seconds=seconds)as(target,report):self.assertEqual((target/'sub/é').read_bytes(),b'inert\x00data')
   except OSError as e:
    print('PRIVATE_CLEANUP_OS_ERROR',case,[(p.relative_to(work).as_posix(),p.is_symlink())for p in work.rglob('*')],file=sys.stderr);raise
   except ValueError as e:caught=e
   self.assertEqual(len(os.listdir('/proc/self/fd')),fds);self.assertEqual(foreign.read_bytes(),b'preserve');self.assertEqual({p.relative_to(source).as_posix():p.lstat().st_ino for p in source.rglob('*')},before)
   if caught:return str(caught),None,events
   self.assertFalse(work.exists());return None,report['cleanup'],events

 def test_genuine_fd_original_and_selected_cleanup_outputs_calls_equivalent(self):
  a=self.cleanup('old',120);b=self.cleanup('pristine',600);self.assertEqual(a[:2],b[:2]);self.assertEqual(a[:2],(None,'PASS-owned-workspace-removed'));self.assertEqual([e[0]for e in a[2]],[e[0]for e in b[2]])

 def test_genuine_fd_independent_cleanup_deadline_and_strict_selected600(self):
  self.assertEqual(self.cleanup('old',120,150)[0],'root observation deadline');self.assertEqual(self.cleanup('pristine',600,150)[:2],(None,'PASS-owned-workspace-removed'));self.assertEqual(self.cleanup('modified',600,601)[0],'root observation deadline')
  module,_=self.lifetime('old')
  with tempfile.TemporaryDirectory(dir=D)as td,self.assertRaisesRegex(ValueError,'bounded cleanup budgets'):
   with module.copied_root(Path(td)/'source',Path(td)/'work',limits=types.SimpleNamespace(),cleanup_seconds=600):pass

 def test_loader_hash_alias_and_wrong_source_refuse_before_cleanup(self):
  _,aux=self.lifetime('old');after,_=F.render(BEFORE,'pristine');space=dict(P=types.SimpleNamespace(need=F.need),types=types);factory=functions(after['immutable/worker_api.py'],{'clone','fixed_case_lifetime'},space)['fixed_case_lifetime']
  with tempfile.TemporaryDirectory(dir=D)as td:
   p=Path(td)/'lifetime.py';raw=Path(aux.disposable_copy.__file__).read_bytes();p.write_bytes(raw+b'\n');a=types.SimpleNamespace(_isolated=aux._isolated,LIFETIME_SHA256=aux.LIFETIME_SHA256,disposable_copy=types.SimpleNamespace(__file__=str(p)))
   with self.assertRaises(ValueError):factory(a)
   p.unlink();p.symlink_to(aux.disposable_copy.__file__)
   with self.assertRaises((ValueError,OSError)):factory(a)

 def test_private_profile_derivation_whole_maps_drift_and_alias_before_writes(self):
  helper=F
  for case in('both','pristine','modified'):
   with tempfile.TemporaryDirectory(dir=D,prefix='private-profile-')as td:
    root=Path(td)/'selected-runtime';shutil.copytree(self.out/'runtime',root);value=helper.prepare(root,case);expected,_=F.render(BEFORE,case);self.assertEqual(helper.snapshot(root),expected);self.assertIs(value['actual_acceptance'],False);self.assertEqual(helper.verify_selected(self.out,root,case)['case'],case)
    code=root/'immutable/worker.py';code.write_bytes(code.read_bytes()+b'\n');manifest=json.loads((root/'runtime-source.json').read_bytes());manifest['files']['immutable/worker.py']=F.pin(code.read_bytes());(root/'runtime-source.json').write_bytes(F.enc(manifest))
    with self.assertRaisesRegex(ValueError,'every selected executable'):helper.verify_selected(self.out,root,case)
  with self.assertRaisesRegex(ValueError,'caller-private'):helper.prepare(self.out/'runtime','pristine')
  for kind in('foreign','symlink','hardlink','drift'):
   with tempfile.TemporaryDirectory(dir=D,prefix='private-refusal-')as td:
    root=Path(td)/'selected-runtime';shutil.copytree(self.out/'runtime',root);p=root/'immutable/worker.py'
    if kind=='symlink':raw=p.read_bytes();p.unlink();q=Path(td)/'outside';q.write_bytes(raw);p.symlink_to(q)
    if kind=='hardlink':os.link(p,Path(td)/'alias')
    if kind=='drift':p.write_bytes(p.read_bytes()+b'\n')
    before=p.read_bytes()
    with self.assertRaises(ValueError):helper.prepare(root,'foreign'if kind=='foreign'else'pristine')
    self.assertEqual(p.read_bytes(),before)

if __name__=='__main__':unittest.main(verbosity=2)
