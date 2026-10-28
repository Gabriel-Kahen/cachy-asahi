# SPDX-License-Identifier: MIT
"""Refusal/source-registration controls, never positive joint native fixtures."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import preflight as P
class Controls(unittest.TestCase):
 def setUp(self):self.source=P.HERE.parents[2];self.pins=json.loads((P.HERE/'source-pins.json').read_bytes())
 def test_exact_namespace_and_default_qualification(self):P.validate(self.source,self.pins)
 def test_owner_drift_refuses(self):
  pins=copy.deepcopy(self.pins);pins['files'][P.LANE+'/owner.py']['sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'canonical owner source differs'):P.validate(self.source,pins)
 def test_extra_namespace_and_activated_policy_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for n in self.pins['files']:p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((self.source/n).read_bytes())
   extra=root/P.LANE/'unexpected-private.json';extra.write_text('{}')
   with self.assertRaisesRegex(ValueError,'exact canonical owner namespace'):P.validate(root,self.pins)
   extra.unlink();p=root/P.LANE/'input-policy.json';policy=json.loads(p.read_bytes());policy['actual_run']=1;p.write_bytes(json.dumps(policy).encode());pins=copy.deepcopy(self.pins);pins['files'][P.LANE+'/input-policy.json']=P.pin(p.read_bytes())
   with self.assertRaisesRegex(ValueError,'original NULL policy'):P.validate(root,pins)
 def test_partial_role_carrier_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);output=root/'forbidden'
   with self.assertRaisesRegex(ValueError,'entire committed historical role'):P.emit(self.source,root,output)
   self.assertFalse(output.exists())
 def test_alias_source_refuses(self):
  with tempfile.TemporaryDirectory()as td:
   alias=Path(td)/'alias';alias.symlink_to(self.source,target_is_directory=True)
   with self.assertRaisesRegex(ValueError,'ordinary source operand'):P.validate(alias,self.pins)
if __name__=='__main__':unittest.main()
