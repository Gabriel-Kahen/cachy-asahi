# SPDX-License-Identifier: MIT
"""Docker28 metadata spelling must not widen initializer privileges."""
import ast
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
tree=ast.parse((HERE/'payload/hosted/producer.py').read_bytes());namespace={}
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exact_cap_add')
exec(compile(ast.Module(body=[function],type_ignores=[]),'<FENCED exact capability predicate>','exec'),namespace)
predicate=namespace['exact_cap_add']
volume=ast.parse((HERE.parent/'successor_v2/payload/hosted/volume.py').read_bytes())
init=ast.literal_eval(next(n.value for n in volume.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INIT_CODE'for t in n.targets)))

class CapabilityControls(unittest.TestCase):
    def test_initializer_exact_one_spelling(self):
        for raw in (['CHOWN'],['CAP_CHOWN']):self.assertTrue(predicate(raw,['CHOWN']))
        for raw in (None,[],['CHOWN','CHOWN'],['CHOWN','CAP_CHOWN'],['CAP_CHOWN','SETUID'],['CAP_SYS_ADMIN'],'CHOWN',('CHOWN',),['chown']):self.assertFalse(predicate(raw,['CHOWN']))
    def test_no_caps_and_no_unknown_expected_set(self):
        for raw in (None,[]):self.assertTrue(predicate(raw,[]))
        for raw in (['CHOWN'],['CAP_CHOWN']):self.assertFalse(predicate(raw,[]))
        self.assertFalse(predicate(['CAP_SYS_ADMIN'],['SYS_ADMIN']))
    def test_kernel_initializer_remains_single_capability(self):
        self.assertIn("==1",init.replace(' ',''))

if __name__=='__main__':unittest.main()
