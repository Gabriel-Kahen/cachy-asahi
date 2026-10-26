"""Source-only selected actual globals and genuine private descriptor graphs."""
import copy,importlib.util,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;sys.path.insert(0,str(D));import desktop622 as N
Q=json.loads((D/('composition.json'if(D/'composition.json').exists()else'input-profile.json')).read_bytes());CORE=Path(os.environ.get('CORE622_CORE_SOURCE',D.parent/'core7-baseline-scriptlet-trial-root-20261022/source'));CASE=Path(os.environ.get('CORE622_PARENT51',D.parent/'core7-serial-line-framing-trial-root-20261025/source'))
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.saved=dict(sys.modules);cls.paths=sys.path[:];sys.path.insert(0,str(CASE));cls.adapter=load('_actual_core51_adapter_for622',CASE/'adapter.py');cls.original=cls.adapter.core(CORE);cls.selected=N.core(cls.original,Q)
 @classmethod
 def tearDownClass(cls):
  sys.path[:]=cls.paths
  for n in set(sys.modules)-set(cls.saved):sys.modules.pop(n,None)
  sys.modules.update(cls.saved)
 def test_complete607_622_exactlocks_codec_and_wronginventory_refuse(self):
  before,support,after=N.plan(Q);self.assertEqual((len(before),len(support),len(after)),(607,620,622));self.assertNotIn('libfdk-aac',before);self.assertEqual(before['cachy-asahi-fdk-aac'],'3.0.0-1');self.assertEqual(len(Q['held']),602)
  for kind in('extra','missing','version','codec','actual'):
   value=copy.deepcopy(Q)
   if kind=='extra':value['before607']['foreign']='1'
   elif kind=='missing':value['before607'].pop('linux-aarch64')
   elif kind=='version':value['after622']['cachy-asahi-apps']='0.1.0-6'
   elif kind=='codec':value['before607']['libfdk-aac']='3.0.0-1'
   else:value['actual']=dict(run=1)
   with self.assertRaises(ValueError):N.plan(value)
 def test_actual_held_functions_resolve_private_selected_globals(self):
  old,new=self.original,self.selected;self.assertEqual(tuple(map(len,old.C.states())),(574,587,589));self.assertEqual(tuple(map(len,new.C.states())),(607,620,622));self.assertIsNot(new.C,old.C);self.assertIsNot(new.T,old.T);self.assertIs(new.T.inventory.__globals__,vars(new.T));self.assertIs(new.T.inventory.__globals__['database'],new.T.database);self.assertIs(new.T.public_keys.__globals__['C'],new.C);self.assertIs(new.C.configuration.__globals__['profile'],new.C.profile);self.assertIs(new.C.configuration.__code__,old.C.configuration.__code__);self.assertIs(new.T.payload.__code__,old.T.payload.__code__);self.assertIs(new.F.capture.__code__,old.F.capture.__code__)
  calls=[]
  with patch.object(new.T,'database',side_effect=lambda api,root:calls.append((api,root))or[dict(name='actual-bridge',version='1')]):self.assertEqual(new.T.inventory(None,Path('/private')),{'actual-bridge':'1'})
  self.assertEqual(calls,[(None,Path('/private'))]);self.assertIs(old.T.inventory.__globals__,vars(old.T));self.assertIs(old.T.C,old.C);self.assertEqual(old.C.profile()['counts']['base'],574)
 def test_real_private_FD_graph_hardlinks_caps_and_protection(self):
  api=self.original.api;self.selected.T.END=time.monotonic()+60
  with tempfile.TemporaryDirectory(prefix='core622-real-fd-')as td:
   root=Path(td);(root/'usr').mkdir();(root/'usr/private').write_bytes(b'bounded actual descriptor fixture');os.link(root/'usr/private',root/'usr/second');(root/'link').symlink_to('usr/private');limits=self.selected.T.budget(api);first=api['roots'].observe(root,limits=limits,hardlinks='generic-development-internal');self.assertTrue(first['complete']);self.assertEqual(first['nodes']['usr/private']['sha256'],first['nodes']['usr/second']['sha256']);self.assertTrue(first['hardlink_groups']);self.assertEqual(first['nodes']['link']['type'],'symlink')
   self.selected.C.changes(first['nodes'],first['nodes'],[],[]);(root/'usr/private').write_bytes(b'changed');second=api['roots'].observe(root,limits=self.selected.T.budget(api),hardlinks='generic-development-internal')
   with self.assertRaises(ValueError):self.selected.C.changes(first['nodes'],second['nodes'],[],[])
   class Expired:
    def tick(self):raise TimeoutError('private expired bound')
   with self.assertRaises(TimeoutError):api['roots'].observe(root,limits=Expired(),hardlinks='generic-development-internal')
 def test_full607_archive_ledger_and_wrong_signature_roles_refuse(self):
  rows=[dict(name=n,**r)for n,r in sorted(Q['archives607'].items())];record=dict(packages=rows,preparation=dict(signer_roles=dict(ephemeral_TEST='A'*40,upstream_ALARM='B'*40)));self.assertEqual(len(N.manifest(Q,record)),607)
  for mutation in('sha','missing','signer'):
   value=copy.deepcopy(record)
   if mutation=='sha':value['packages'][0]['sha256']='0'*64
   elif mutation=='missing':value['packages'].pop()
   else:value['preparation']['signer_roles'].pop('upstream_ALARM')
   with self.assertRaises(ValueError):N.manifest(Q,value)
if __name__=='__main__':unittest.main(verbosity=2)
