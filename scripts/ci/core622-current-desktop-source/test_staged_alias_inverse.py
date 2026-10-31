# SPDX-License-Identifier: MIT
"""Eight DATA controls for the emitted ad090 inverse; no full Source import/gate."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest

ALIASES=('.github/workflows/native-arm-build.yml',
         '.github/workflows/native-arm-core7-real-systemd.yml')
MESSAGE='entire source66 ad090 inverse, no historical result authority'
CASE_NAMES=('need','encoded','decode','pin','identity','read')


def case_helpers(raw):
    """Compile only the actual six required Case definitions, never its module."""
    tree=ast.parse(raw,filename='case.py')
    selected=[]
    for name in CASE_NAMES:
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name]
        if len(nodes)!=1 or nodes[0].decorator_list:
            raise ValueError('one undecorated actual Case helper: '+name)
        if any(isinstance(n,(ast.Import,ast.ImportFrom))for n in ast.walk(nodes[0])):
            raise ValueError('Case helper imports are outside the pure extraction')
        selected.append(copy.deepcopy(nodes[0]))
    scope=dict(Path=Path,os=os,stat=stat,json=json,hashlib=hashlib)
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),
                 'case.py:required-DATA-helpers','exec'),scope)
    return types.SimpleNamespace(**{n:scope[n]for n in CASE_NAMES})


def inverse_prefix(raw,case):
    """Stop at the actual first complete66 comparison, before any older tail."""
    tree=ast.parse(raw,filename='source622.py')
    found=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='same66_before']
    if len(found)!=1 or found[0].decorator_list:
        raise ValueError('one undecorated actual same66_before')
    fn=copy.deepcopy(found[0]);stops=[]
    for i,node in enumerate(fn.body):
        call=node.value if isinstance(node,ast.Expr)else None
        if (isinstance(call,ast.Call)and isinstance(call.func,ast.Attribute)
            and isinstance(call.func.value,ast.Name)and call.func.value.id=='C'
            and call.func.attr=='need'and len(call.args)==2
            and isinstance(call.args[1],ast.Constant)and call.args[1].value==MESSAGE):
            stops.append(i)
    if len(stops)!=1:
        raise ValueError('exact first ad090 fullmap comparison required')
    fn.body=fn.body[:stops[0]+1]+[ast.Return(value=ast.Name(id='prior',ctx=ast.Load()))]
    if any(isinstance(n,(ast.Import,ast.ImportFrom))for n in ast.walk(fn)):
        raise ValueError('inverse prefix must not import Source or actors')
    aliases=[n for n in tree.body if isinstance(n,ast.Assign)
             and any(isinstance(t,ast.Name)and t.id=='ALIASES'for t in n.targets)]
    if len(aliases)!=1 or ast.literal_eval(aliases[0].value)!=ALIASES:
        raise ValueError('exact two actual workflow aliases')
    scope=dict(C=case,Path=Path,ast=ast,ALIASES=ALIASES)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),
                 'source622.py:first-ad090-fullmap-prefix','exec'),scope)
    return scope['same66_before']


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ['CORE622_RESILIENCE_SOURCE']).absolute()
        if root!=root.resolve()or any(p.is_symlink()for p in(root,*root.parents)):
            raise ValueError('canonical pre-emitted Source input')
        # Definitions only: neither case.py nor source622.py is imported/executed.
        cls.C=case_helpers((root/'case.py').read_bytes())
        parent=cls.C.decode(cls.C.read(root/'composition-parent.json',4*1024**2))
        record=parent['runner_resilience']
        if (record['schema']!=1 or record['parent_source']!='ad09020a776c93fad3c2625c836a99cbde0c83b9'
            or record['actual']is not None or len(record['before'])!=66):
            raise ValueError('complete unbound actual ad090 predecessor')
        cls.values={n:cls.C.read(root/n,4*1024**2)for n in record['before']}
        cls.record=record
        cls.prefix=staticmethod(inverse_prefix(cls.values['source622.py'],cls.C))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='core622-alias-inverse-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        for name,raw in self.values.items():
            path=self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o644)

    def mutate(self,name):
        path=self.root/name
        path.write_bytes(path.read_bytes()+b'\n# deliberately changed DATA operand\n')

    def assert_fullmap_refusal(self):
        with self.assertRaisesRegex(ValueError,'^'+MESSAGE+'$'):
            self.prefix(self.root)

    def test_complete_current_alias_edits_restore_exact_ad090(self):
        self.assertEqual(len(self.values),66)
        for alias in ALIASES:
            self.assertEqual(self.record['edits'][alias],self.record['edits']['workflow.yml.in'])
            self.assertEqual(self.values[alias],self.values['workflow.yml.in'])
        prior=self.prefix(self.root)
        self.assertEqual({n:self.C.pin(raw)for n,raw in prior.items()},self.record['before'])
        self.assertEqual(prior[ALIASES[0]],prior[ALIASES[1]])
        self.assertEqual(prior[ALIASES[0]],prior['workflow.yml.in'])

    def test_omitting_both_alias_edits_refuses_exact_two_alias_deltas(self):
        path=self.root/'composition-parent.json';parent=self.C.decode(path.read_bytes())
        for alias in ALIASES:
            self.assertIn(alias,parent['runner_resilience']['edits'])
            del parent['runner_resilience']['edits'][alias]
        path.write_bytes(self.C.encoded(parent))
        try:
            self.prefix(self.root)
        except ValueError as error:
            self.assertEqual(str(error),MESSAGE)
            # Inspect the failing actual prefix frame, without replacing any need.
            tb=error.__traceback__;frame=None
            while tb is not None:
                if tb.tb_frame.f_code.co_name=='same66_before':frame=tb.tb_frame
                tb=tb.tb_next
            self.assertIsNotNone(frame)
            prior=frame.f_locals['prior'];before=frame.f_locals['current']['before']
            actual={n:self.C.pin(raw)for n,raw in prior.items()}
            self.assertEqual({n for n in actual.keys()|before.keys()
                              if actual.get(n)!=before.get(n)},set(ALIASES))
        else:self.fail('missing both alias edit rows was accepted')

    def test_first_alias_body_drift_refused(self):
        self.mutate(ALIASES[0]);self.assert_fullmap_refusal()

    def test_second_alias_body_drift_refused(self):
        self.mutate(ALIASES[1]);self.assert_fullmap_refusal()

    def test_workflow_template_body_drift_refused(self):
        self.mutate('workflow.yml.in');self.assert_fullmap_refusal()

    def test_unrelated_case_body_drift_refused(self):
        self.mutate('case.py');self.assert_fullmap_refusal()

    def test_missing_alias_refused(self):
        (self.root/ALIASES[0]).unlink()
        with self.assertRaises(FileNotFoundError):self.prefix(self.root)

    def test_symlink_alias_refused(self):
        path=self.root/ALIASES[1];path.unlink()
        path.symlink_to(self.root/'workflow.yml.in')
        with self.assertRaisesRegex(ValueError,'ordinary input ancestors'):
            self.prefix(self.root)


def run_controls():
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    return dict(status='PASS'if result.wasSuccessful()and result.testsRun==8 else'FAIL',
                tests=result.testsRun,errors=len(result.errors),failures=len(result.failures),
                Source_module_imports=0,full_Source_verify=0,historical_Source_gate=0,
                factory_emissions=0,constructors=0,native=0,acceptance=False)


if __name__=='__main__':
    value=run_controls();print(json.dumps(value,sort_keys=True))
    raise SystemExit(value['status']!='PASS')
