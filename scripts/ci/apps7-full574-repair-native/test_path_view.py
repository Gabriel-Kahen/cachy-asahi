# SPDX-License-Identifier: MIT
"""Private predicate equivalence, full graph/race/refusal/IO controls; no actor."""
import copy,importlib.util,itertools,json,os,random,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if(p/'manifests/packages.toml').is_file())
def load(n,p):
 spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);sys.modules[n]=m;spec.loader.exec_module(m);return m
P=load('native_path_view_test',HERE/'path_view.py')
A=load('whole_apps7_closure_path_test',ROOT/'scripts/ci/apps7-full574-repair-native/closure.py')
roots=sys.modules['full_root'];caps=sys.modules['_apps574_file_capabilities'];copy_scope=sys.modules['_apps574_copy_scope'];aux_copy=sys.modules['aux_copy']
# Original binding is independently reconstructed; candidate closure import may
# already select its native view. No customer module/global is modified.
BASE=A.fast.bind(ROOT,roots,caps,copy_scope,aux_copy,A.source_bytes)
NEW=P.bind(A.fast,ROOT,roots,caps,copy_scope,aux_copy,A.source_bytes)
def outcome(fn,*args,**kwargs):
 try:return('RETURN',fn(*args,**kwargs))
 except Exception as e:return(type(e).__name__,str(e))
def stable(value):
 v=copy.deepcopy(value)
 for k in('filesystem_free_bytes','filesystem_free_inodes'):v['footprint'].pop(k,None)
 return v

def fixture(root):
 for i in range(3):
  parent=root/'usr/share'/('branch'+str(i));parent.mkdir(parents=True)
  for j in range(7):(parent/('f'+str(j))).write_bytes(('whole:'+str(i)+':'+str(j)).encode()*5)
 (root/'usr/share/branch0/link').symlink_to('f0');os.link(root/'usr/share/branch1/f0',root/'usr/share/branch1/hardlink')
 (root/'var/lib/pacman/local/ordinary-1-1').mkdir(parents=True);(root/'var/lib/pacman/local/ordinary-1-1/desc').write_bytes(b'%NAME%\nordinary\n\n%VERSION%\n1-1\n\n')

def observe(view,root,limit=None):
 limits=limit or roots.Limits(deadline=time.monotonic()+600);v=view.roots.observe(root,limits=limits,hardlinks='generic-development-internal');return v,view.caps.observe(root,v['nodes'],limits)if v['complete']else None

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);fixture(self.root);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors/API/Git'));p.start();self.addCleanup(p.stop)
 def test_original_posix_grammar_exhaustive_short_and_generated_unicode(self):
  values=[None,False,0,[],Path('a')]
  alphabet=['a','.','/','\\','\0','\n','é','\udc80'];values +=[''.join(p)for n in range(5)for p in itertools.product(alphabet,repeat=n)]
  rng=random.Random(573);chars=['a','/','.','\\','\t','\r','\x1f','\x7f','\x80','é','中','😀','\udc80','\udcff','\ud800']
  values +=[''.join(rng.choice(chars)for _ in range(rng.randrange(1,100)))for _ in range(3000)]
  for v in values:self.assertEqual(outcome(roots.installer.relative,v),outcome(P.relative,v),repr(v))
 def test_cap_path_exact_grammar_unicode_byte_depth_bounds_and_errors(self):
  values=[None,0,False,[],Path('a'),'','.',*[''.join(p)for n in range(4)for p in itertools.product(['a','.','/','\\','é','\n'],repeat=n)]]
  values +=[chr(i)for i in range(256)]+['\udc80','\udcff','\ud800','😀'*1024,'😀'*1025,'a'*caps.MAX_PATH,'a'*(caps.MAX_PATH+1),'a/'*128+'z']
  for depth in(1,2,128):
   limits=types.SimpleNamespace(max_depth=depth)
   for v in values:self.assertEqual(outcome(caps._path,v,limits),outcome(P.cap_path,v,limits,caps.MAX_PATH),(depth,repr(v)))
 def test_whole_observation_and_cap_graph_exact_all_stable_fields(self):
  a,ac=observe(BASE,self.root);b,bc=observe(NEW,self.root);self.assertTrue(a['complete']);self.assertEqual(stable(a),stable(b));self.assertEqual(ac,bc);self.assertEqual(ac,{})
  for key in('unsupported','unsupported_counts','hardlink_groups','nodes','eligible'):self.assertEqual(a[key],b[key])
 def test_unknown_xattr_external_hardlink_and_root_symlink_refuse_identically(self):
  p=self.root/'usr/share/branch0/f0';os.setxattr(p,'user.private-refusal',b'x');v=BASE.roots.observe(self.root,limits=roots.Limits(deadline=time.monotonic()+600),hardlinks='generic-development-internal')
  for view in(BASE,NEW):
   with self.assertRaisesRegex(ValueError,'unknown xattr'):view.caps.observe(self.root,v['nodes'],roots.Limits(deadline=time.monotonic()+600))
  os.removexattr(p,'user.private-refusal');outside=self.root.parent/(self.root.name+'-outside');os.link(p,outside);self.addCleanup(lambda:outside.unlink(missing_ok=True))
  a,_=observe(BASE,self.root);b,_=observe(NEW,self.root);self.assertFalse(a['complete']);self.assertEqual(stable(a),stable(b))
  alias=self.root.parent/(self.root.name+'-alias');alias.symlink_to(self.root);self.addCleanup(alias.unlink)
  self.assertEqual(outcome(BASE.roots.observe,alias,limits=roots.Limits(deadline=time.monotonic()+600)),outcome(NEW.roots.observe,alias,limits=roots.Limits(deadline=time.monotonic()+600)))
 def test_depth_node_byte_and_deadline_refusals_preserved(self):
  for changes in(dict(max_depth=1),dict(max_nodes=4),dict(max_bytes=1),dict(deadline=0)):
   kw=dict(deadline=time.monotonic()+600);kw.update(changes)
   a=outcome(BASE.roots.observe,self.root,limits=roots.Limits(**kw),hardlinks='generic-development-internal');b=outcome(NEW.roots.observe,self.root,limits=roots.Limits(**kw),hardlinks='generic-development-internal')
   if a[0]=='RETURN':self.assertEqual(stable(a[1]),stable(b[1]));self.assertFalse(a[1]['complete'])
   else:self.assertEqual(a,b)
 def test_private_bind_leaves_original_modules_and_function_bodies_unchanged(self):
  self.assertIs(roots.installer.relative.__globals__,roots.installer.__dict__);self.assertIsNot(NEW.roots.installer,roots.installer);self.assertIsNot(NEW.caps._graph,caps._graph)
  for n in('_graph','validate_map','_scan','observe','restore'):
   fn=getattr(NEW.caps,n);self.assertIs(getattr(fn,'__wrapped__',fn).__code__,getattr(caps,n).__code__)
  wrapped=NEW.roots.observe.__wrapped__;closed=dict(zip(wrapped.__code__.co_freevars,(c.cell_contents for c in wrapped.__closure__)));self.assertIs(closed['private_roots'].observe.__code__,roots.observe.__code__)
 def test_complete_cap_graph_stale_metadata_and_missing_nodes_refuse(self):
  observed=BASE.roots.observe(self.root,limits=roots.Limits(deadline=time.monotonic()+600),hardlinks='generic-development-internal');p=self.root/'usr/share/branch0/f0';p.chmod(0o600)
  for view in(BASE,NEW):
   with self.assertRaisesRegex(ValueError,'pinned node metadata'):view.caps.observe(self.root,observed['nodes'],roots.Limits(deadline=time.monotonic()+600))
  p.chmod(0o644);p.unlink()
  for view in(BASE,NEW):
   with self.assertRaisesRegex(ValueError,'actual node graph'):view.caps.observe(self.root,observed['nodes'],roots.Limits(deadline=time.monotonic()+600))
 def test_live_named_file_drift_still_refused(self):
  p=self.root/'usr/share/branch0/f1'
  for view in(BASE,NEW):
   before=p.read_bytes();original=roots._file_hash;changed=False
   def mutate(fd,info,limits):
    nonlocal changed
    value=original(fd,info,limits)
    if not changed and info.st_ino==p.stat().st_ino:p.write_bytes(before+b'changed');changed=True
    return value
   space=roots.observe.__globals__
   if view is NEW:
    fn=view.roots.observe.__wrapped__;closed=dict(zip(fn.__code__.co_freevars,(c.cell_contents for c in fn.__closure__)));space=closed['private_roots'].observe.__globals__
   with patch.dict(space,{'_file_hash':mutate}):value=view.roots.observe(self.root,limits=roots.Limits(deadline=time.monotonic()+600),hardlinks='generic-development-internal')
   self.assertTrue(changed);self.assertFalse(value['complete']);self.assertIn('named entry drift',value['unsupported_counts'])
   p.write_bytes(before)
 def test_original_binding_source_drift_refuses_before_execution(self):
  with self.assertRaisesRegex(ValueError,'whole native Apps binding'):P.bind(A.fast,ROOT,roots,caps,copy_scope,aux_copy,lambda _:b'drift')
 def test_complete_python_filesystem_call_sequence_equal(self):
  calls={}
  for role,view in(('baseline',BASE),('candidate',NEW)):
   rows=[];original={n:getattr(os,n)for n in('open','close','stat','fstat','fstatvfs','read','readlink','listxattr','getxattr','lseek','scandir')}
   def wrapper(name):
    def call(*args,**kwargs):
     def data(x):return os.fspath(x)if isinstance(x,os.PathLike)else x
     rows.append((name,tuple(data(x)for x in args),tuple(sorted((k,data(v))for k,v in kwargs.items()))));return original[name](*args,**kwargs)
    return call
   from contextlib import ExitStack
   with ExitStack()as stack:
    for n in original:stack.enter_context(patch.object(os,n,wrapper(n)))
    value,mapping=observe(view,self.root)
   self.assertTrue(value['complete']);self.assertEqual(mapping,{});calls[role]=rows
  self.assertEqual(calls['baseline'],calls['candidate'])
if __name__=='__main__':unittest.main(verbosity=2)
