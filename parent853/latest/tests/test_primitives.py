# SPDX-License-Identifier: MIT
"""Real owned inode/rawDB mechanics only, not installed native composition."""
import ast,copy,hashlib,importlib.util,os,sys,tempfile,time,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'implementation'))
import latest_plan as plan,latest_graph_scope as G,latest_transaction_adapter as T
RAW=(D/'implementation/held/package_graph.py').read_bytes();ALPM=(D/'implementation/held/alpm_step.py').read_bytes()
def selected_paths():return {role:dict(files=['usr/bin/'+name],directories=[])for role,name,_,_ in plan.PRODUCTS}
def row(name,version,files):return dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=files)
class Primitives(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.paths=selected_paths();self.capture_scope=G.bind(RAW,self.paths);self.rows=[]
  for name in('usr/bin','usr/share/doc','usr/share/licenses','var/lib/pacman/local','etc','home','root'):(self.root/name).mkdir(parents=True,exist_ok=True)
  for _,name,old,_ in plan.PRODUCTS:
   if old is None:continue
   self.rows.append(row(name,old,['usr/bin/'+name]));self.put(name,old,b'owned selected baseline\n')
  self.rows.append(row('retained','1-1',['usr/bin/retained']));self.put('retained','1-1',b'untouched foreign package\n');(self.root/'etc/user-sentinel').write_bytes(b'unchanged user\n');(self.root/'var/lib/pacman/local/ALPM_DB_VERSION').write_bytes(b'9\n')
 def put(self,name,version,body):
  (self.root/'usr/bin'/name).write_bytes(body);db=self.root/'var/lib/pacman/local'/(name+'-'+version);db.mkdir();(db/'desc').write_text(name+' '+version+'\n');(db/'files').write_text('usr/bin/'+name+'\n')
 def capture(self):return self.capture_scope.capture(self.root,self.rows,deadline=time.monotonic()+20)
 def lock(self,operation):
  p=self.root/'var/lib/pacman';before=self.capture_scope.key(p.stat());names=sorted(os.listdir(p));(p/'db.lck').write_bytes(b'');operation();(p/'db.lck').unlink();return dict(path='var/lib/pacman',lock_created=True,lock_removed=True,names=names,before=before,after=self.capture_scope.key(p.stat()))
 def change(self,role):
  _,name,old,new=plan.product(role)
  if old is not None:
   (self.root/'usr/bin'/name).unlink();db=self.root/'var/lib/pacman/local'/(name+'-'+old)
   for p in db.iterdir():p.unlink()
   db.rmdir();self.rows=[r for r in self.rows if r['name']!=name]
  self.put(name,new,b'owned selected candidate\n');self.rows.append(row(name,new,['usr/bin/'+name]));self.rows.sort(key=lambda r:r['name'])
 def test_real_singleacted_typed_changes_protect_other_four_andforeign(self):
  self.rows.sort(key=lambda r:r['name']);before=self.capture();scope=G.bind(RAW,self.paths,'apps');witness=self.lock(lambda:self.change('apps'));after=self.capture();result=G.protected(scope,before,after,witness);self.assertEqual(result['status'],'PROTECTED_KNOWN606_GRAPH_HELD');self.assertFalse(result['whole_root']);self.assertNotEqual(before,after)
  for name in('usr/bin/cachy-asahi-doctor','usr/bin/retained','etc/user-sentinel'):
   bad=copy.deepcopy(after);bad['nodes'][name]['identity'][1]+=1
   with self.subTest(name=name),self.assertRaises(ValueError):G.protected(scope,before,bad,witness)
 def test_real_allfive_scopes_do_not_allow_otherselected_changes(self):
  self.rows.sort(key=lambda r:r['name']);before=self.capture();witness=self.lock(lambda:self.change('boot'));after=self.capture()
  self.assertTrue(G.protected(G.bind(RAW,self.paths,'boot'),before,after,witness))
  for role in('apps','doctor','ksm','welcome'):
   with self.subTest(role=role),self.assertRaises(ValueError):G.protected(G.bind(RAW,self.paths,role),before,after,witness)
 def test_real_installed_Boot_samebytes_replacement_refuses_during_Apps_action(self):
  self.rows.sort(key=lambda r:r['name']);before=self.capture();boot=self.lock(lambda:self.change('boot'));installed=self.capture();G.protected(G.bind(RAW,self.paths,'boot'),before,installed,boot)
  def changed():
   self.change('apps');p=self.root/'usr/bin/cachy-asahi-boot-report';raw=p.read_bytes();p.unlink();p.write_bytes(raw)
  witness=self.lock(changed);after=self.capture()
  with self.assertRaises(ValueError):G.protected(G.bind(RAW,self.paths,'apps'),installed,after,witness)
 def test_commonparents_devices_trust_andotherexecutables_cannot_be_selected(self):
  for key,value in(('directories',['usr']),('directories',['usr/bin']),('files',['usr/bin/pacman']),('files',['etc/pacman.conf']),('files',['proc/self/status'])):
   paths=selected_paths();paths['apps'][key]=value
   with self.subTest(value=value),self.assertRaises(ValueError):G.bind(RAW,paths,'apps')
  with self.assertRaises(ValueError):G.bind(RAW,selected_paths(),'foreign')
 def test_acted_protected_hardlink_boundary_refuses(self):
  before=self.capture();bad=copy.deepcopy(before);bad['hardlinks'].append(dict(nlink=2,members=['usr/bin/cachy-asahi-apps','usr/bin/cachy-asahi-doctor']))
  with self.assertRaises(ValueError):G.protected(G.bind(RAW,self.paths,'apps'),bad,bad,None)
 def test_graph_functions_exact_AST_exceptselected_DBdomain(self):
  module=G.bind(RAW,self.paths,'apps');original=ast.parse(RAW);changed=ast.parse(RAW.decode().replace(G.ANCHOR,G.REPLACEMENT,1));a={n.name:ast.dump(n)for n in original.body if isinstance(n,ast.FunctionDef)};b={n.name:ast.dump(n)for n in changed.body if isinstance(n,ast.FunctionDef)};self.assertEqual({n for n in a if a[n]!=b[n]},{'selected'});self.assertEqual(module.MAX_NODES,200000);self.assertEqual(module.MAX_BYTES,6*1024**3)
 def test_allfive_exact_signed_step_inverses_andclock_security_statements(self):
  for role,_,_,_ in plan.PRODUCTS:
   text,edits=T.derive(ALPM,role);back=text
   for before,after in reversed(edits):back=back.replace(after,before,1)
   self.assertEqual(back.encode(),ALPM);self.assertIn('deadline=time.monotonic()+90',text);self.assertIn('deny_exec()',text);self.assertIn('alpm_trans_prepare',text);self.assertIn('alpm_trans_commit',text);self.assertIn('EXPKEYSIG',text);self.assertIn('group_retired',text)
  with self.assertRaises(ValueError):T.derive(ALPM,'unknown')
  with self.assertRaises(ValueError):T.derive(ALPM+b'\n','apps')
if __name__=='__main__':unittest.main(verbosity=2)
