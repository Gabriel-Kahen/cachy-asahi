# SPDX-License-Identifier: MIT
"""Inert exact public copy-proof retention controls; no actors."""
import copy,importlib.util,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as C
L=C.load('copy_scope_retention_lifecycle',HERE/'lifecycle.py')

class Retention(unittest.TestCase):
 def setUp(self):
  blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));blocked.start();self.addCleanup(blocked.stop)
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.base=Path(temporary.name);self.workspace=self.base/'main';self.workspace.mkdir();self.out=self.base/'public';self.out.mkdir()
  self.value=dict(copy=dict(apps_bind_scope=dict(proof=dict(status='PROVED_DISJOINT_READONLY_SOURCE_AND_OWNED_WORK_BIND_ROOTS',source='/seed',destination_parent=str(self.workspace)),checkpoints=7),security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED'))
 def write(self,value):
  raw=C.encoded(value);(self.workspace/'apps-copy.json').write_bytes(raw);return raw,C.sha(raw)
 def test_exact_original_marker_hash_and_bytes_retained(self):
  raw,pin=self.write(self.value)
  with patch.object(L,'OUT',self.out):L.retain_copy(self.workspace,pin)
  self.assertEqual((self.out/'main-copy.json').read_bytes(),raw)
 def test_false_scope_or_incomplete_capability_proof_cannot_be_exported(self):
  for kind in ('hash','status','source','destination','checkpoints','bool','caps'):
   value=copy.deepcopy(self.value);scope=value['copy']['apps_bind_scope']
   if kind=='status':scope['proof']['status']='WAIVED'
   elif kind=='source':scope['proof']['source']='/foreign'
   elif kind=='destination':scope['proof']['destination_parent']='/other'
   elif kind=='checkpoints':scope['checkpoints']=6
   elif kind=='bool':scope['checkpoints']=True
   elif kind=='caps':value['copy']['security_capabilities']='OMITTED'
   raw,pin=self.write(value)
   with self.subTest(kind=kind),patch.object(L,'OUT',self.out),self.assertRaises(ValueError):L.retain_copy(self.workspace,'0'*64 if kind=='hash' else pin)
   self.assertEqual(list(self.out.iterdir()),[])

if __name__=='__main__':unittest.main(verbosity=2)
