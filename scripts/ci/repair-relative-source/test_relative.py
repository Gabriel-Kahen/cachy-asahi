"""Exact oracle/private facade/real FD parity; no native observation or gain claim."""
import ast,hashlib,importlib.util,json,os,random,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;NEW=Path(os.environ['REPAIR_RELATIVE_EXPECTED']);OLD=Path(os.environ['REPAIR_RELATIVE_INPUT']);LANE='scripts/ci/apps7-full574-repair16k/adapter.py'

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
A=load('_relative_current_adapter',NEW/LANE);B=load('_relative_parent_adapter',OLD/LANE);R=load('_relative_helper',NEW/'apps16-repair/relative_query.py')
def fresh(text):
 m=types.ModuleType('_test_fresh_query');exec(compile(text,'<private-test-fresh-query>','exec'),vars(m));return m

def outcome(fn,v):
 try:return ('return',fn(v))
 except Exception as e:return('error',type(e).__name__,str(e))
class Controls(unittest.TestCase):
 def roots(self):return load('_private_roots_'+str(id(self)),NEW/'scripts/update/full_root.py')
 def test_exact_original_oracle_all_adversarials_and_private_fallback(self):
  raw=(NEW/R.ORIGINAL).read_bytes();self.assertEqual((len(raw),hashlib.sha256(raw).hexdigest()),R.ORIGINAL_PIN);roots=self.roots();old=roots.installer.relative;new=R.bind(old)
  class Text(str):pass
  cases=[None,False,0,b'a',Path('a'),[],{},Text('usr/bin'),'','.','..','/','a//b','a/./b','a/../b','a/','a\0b','a\\b','a/\udcff','a/é','a/new\nline']
  rng=random.Random(925);chars='a.b/\0\\ \n\té\u2028\udcff';cases+=[''.join(rng.choice(chars)for _ in range(rng.randrange(80)))for _ in range(60000)]
  self.assertEqual([outcome(old,v)for v in cases],[outcome(new,v)for v in cases]);self.assertIs(new.__wrapped__,old)
  seen=[];sentinel=object();call=R.bind(lambda v:seen.append(v)or sentinel)
  for v in (None,Text('a'),'','.', 'a//b','a/../b'):self.assertIs(call(v),sentinel)
  self.assertEqual(seen,[None,Text('a'),'','.', 'a//b','a/../b']);self.assertEqual(call('usr/lib/a.so'),'usr/lib/a.so')
 def test_private_facade_originals_and_import_isolation(self):
  roots=self.roots();before=dict(vars(roots));installer=dict(vars(roots.installer));modules=dict(sys.modules);original=roots.installer.relative;api=fresh(A.FRESH_QUERY);one=api.query_api(NEW,roots,Path.read_bytes);two=api.query_api(NEW,roots,Path.read_bytes)
  self.assertEqual(vars(roots),before);self.assertEqual(vars(roots.installer),installer);self.assertEqual(sys.modules,modules);self.assertIs(one.installer.relative.__wrapped__,original);self.assertIs(two.installer.relative.__wrapped__,original);self.assertIsNot(one.installer,two.installer);self.assertIs(one.observe.__globals__['installer'],one.installer);self.assertEqual(one.observe.__code__,roots.observe.__code__);self.assertIs(one.observe.__defaults__,roots.observe.__defaults__);self.assertIs(one.observe.__kwdefaults__,roots.observe.__kwdefaults__)
  for n,v in vars(roots.installer).items():
   if n!='relative':self.assertIs(getattr(one.installer,n),v)
 def test_wrong_source_function_globals_or_foreign_installer_refuses(self):
  for kind in('source','relative','need','Path','file','defaults'):
   roots=self.roots();m=roots.installer;read=Path.read_bytes
   if kind=='source':read=lambda p:b'foreign'
   elif kind in('relative','need'):setattr(m,kind,lambda *a:True)
   elif kind=='Path':m.Path=lambda v:v
   elif kind=='file':m.__file__='/foreign/local_transaction.py'
   elif kind=='defaults':m.relative.__defaults__=('a',)
   with self.subTest(kind=kind),self.assertRaises(ValueError):R.bind_installer(NEW,m,read)
 def scan(self,api,root,mode='refuse',deadline=None):
  events=[];base=api.Limits(deadline=time.monotonic()+60 if deadline is None else deadline,max_nodes=256,max_bytes=1048576,max_file_bytes=65536)
  class Limits:
   def __getattr__(self,k):return getattr(base,k)
   def tick(self):events.append(('tick',));base.tick()
  methods=('open','close','read','fstat','stat','fstatvfs','scandir','readlink','dup','getxattr','listxattr');originals={n:getattr(os,n)for n in methods};manager=__import__('contextlib').ExitStack()
  def wrap(n):
   def call(*a,**kw):events.append((n,a,tuple(sorted(kw.items()))));return originals[n](*a,**kw)
   return call
  with manager:
   for n in methods:manager.enter_context(patch.object(os,n,wrap(n)))
   value=api.observe(root,limits=Limits(),hardlinks=mode,shape_examples=4)
  return value,events
 def test_genuine_small_tree_full_output_syscall_order_and_ticks(self):
  with tempfile.TemporaryDirectory()as td:
   tree=Path(td)/'tree';(tree/'usr/lib/é').mkdir(parents=True);(tree/'usr/lib/é/a.so').write_bytes(b'payload\0'*100);(tree/'usr/lib/.hidden').write_bytes(b'');(tree/'usr/lib/back\\slash').write_bytes(b'x');(tree/'usr/lib/surrogate-\udcff').write_bytes(b'surrogate');(tree/'usr/lib/link').symlink_to('é/a.so')
   for mode in('refuse','generic-development-internal'):
    roots=self.roots();old=fresh(B.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes);new=fresh(A.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes);before,oldcalls=self.scan(old,tree,mode);after,newcalls=self.scan(new,tree,mode);self.assertEqual(before,after);self.assertEqual(oldcalls,newcalls);self.assertTrue(before['complete']);self.assertEqual(before['nodes']['usr/lib/é/a.so']['sha256'],hashlib.sha256(b'payload\0'*100).hexdigest())
   (tree/'escape').symlink_to('../../outside');os.link(tree/'usr/lib/é/a.so',tree/'hard')
   for mode in('refuse','generic-development-internal'):
    roots=self.roots();old=fresh(B.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes);new=fresh(A.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes);before,oldcalls=self.scan(old,tree,mode);after,newcalls=self.scan(new,tree,mode);self.assertEqual(before,after);self.assertEqual(oldcalls,newcalls);self.assertFalse(before['eligible'])
 def test_deadline_and_live_path_refusals_held(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'data').write_bytes(b'x');roots=self.roots();old=fresh(B.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes);new=fresh(A.FRESH_QUERY).query_api(NEW,roots,Path.read_bytes)
   for value in(old,new):
    with self.assertRaisesRegex(ValueError,'root observation deadline'):self.scan(value,root,deadline=0)
   alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
   for value in(old,new):
    with self.assertRaises(OSError):self.scan(value,alias)
   # Genuine directory mutation after the first live fstat must still fail.
   for i,text in enumerate((B.FRESH_QUERY,A.FRESH_QUERY)):
    target=root/('mutated'+str(i));target.mkdir();(target/'data').write_bytes(b'x');value=fresh(text).query_api(NEW,self.roots(),Path.read_bytes);original=os.fstat;changed=[]
    def mutate(fd):
     result=original(fd)
     if not changed:changed.append(True);(target/'new').write_bytes(b'new')
     return result
    with patch.object(os,'fstat',side_effect=mutate):report=value.observe(target,limits=value.Limits(deadline=time.monotonic()+60))
    self.assertFalse(report['complete']);self.assertIn('root identity drift',report['unsupported_counts'])
   # Scalar mount fault injection, with genuine open descriptors and held walker.
   for text in (B.FRESH_QUERY,A.FRESH_QUERY):
    value=fresh(text).query_api(NEW,self.roots(),Path.read_bytes);calls=[]
    def crossed(fd,limits):calls.append(fd);return len(calls)
    value.observe.__globals__['_mount_id']=crossed;report=value.observe(root,limits=value.Limits(deadline=time.monotonic()+60),hardlinks='generic-development-internal')
    self.assertFalse(report['complete']);self.assertIn('mount crossing refused',report['unsupported_counts']);self.assertEqual(len(calls),2)
 def test_whole_adapter_functions_fresh_functions_and_rendered_cli_contracts(self):
  self.assertEqual(A.functions((NEW/LANE).read_bytes()),B.functions((OLD/LANE).read_bytes()))
  def funcs(text):return{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  old,new=funcs(B.FRESH_QUERY),funcs(A.FRESH_QUERY);self.assertEqual(set(old),set(new));self.assertEqual([n for n in old if old[n]!=new[n]],['query_api'])
  for selected in(False,True):
   before,oldreceipt=B.rendered_backend(OLD,inspect_profile=selected);after,receipt=A.rendered_backend(NEW,inspect_profile=selected);self.assertEqual(B.functions(before),A.functions(after));self.assertEqual(receipt.get('owned_inspect_validation',{}).get('backend_seconds'),1200 if selected else None);self.assertEqual(receipt.get('owned_inspect_validation',{}).get('caller_seconds'),1210 if selected else None)
  self.assertEqual((NEW/'apps16-repair/inspect_validation.py').read_bytes(),(OLD/'apps16-repair/inspect_validation.py').read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
