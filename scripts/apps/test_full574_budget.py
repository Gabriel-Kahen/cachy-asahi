# SPDX-License-Identifier: MIT
"""Finite source/temp-data controls; no actors or full574 acceptance."""
import ast,copy,importlib.util,io,json,sys,tempfile,time,unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
T=load('budget_backend',HERE/'transaction.py');C=load('budget_adapter',HERE/'full574_closure.py')
class Budget(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        common=dict(schema_version=1,purpose=C.PURPOSE,execution_budget=dict(C.EXECUTION_BUDGET),**{n:'a'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256')})
        self.policy=dict(common,baseline_lock_sha256=C.LOCK_SHA256,candidates={},source_capabilities={})
        self.lease=dict(common,execution_budget=dict(C.EXECUTION_BUDGET),token='b'*32,source='/INERT-NO-ROOT-READ',source_identity=[1,2])
    def args(self):
        args=NS()
        for key,value in (('policy',self.policy),('lease',self.lease)):
            raw=T.encoded(value);path=self.root/key;path.write_bytes(raw)
            setattr(args,'full574_'+key,str(path));setattr(args,'full574_'+key+'_sha256',T.sha(raw))
        return args
    def test_exact_pinned_pair_selects600_only_and_preserves_all_other_limits(self):
        with patch.object(T,'load',return_value=C),patch.object(T.time,'monotonic',return_value=100):
            generic=T.limits();dedicated=T.limits(self.args())
            self.assertEqual(generic.deadline,400);self.assertEqual(dedicated.deadline,700)
            for key in vars(generic):
                if key!='deadline':self.assertEqual(getattr(dedicated,key),getattr(generic,key),key)
            self.assertEqual(T.execution_seconds(NS()),300)
    def test_legacy_mixed_unknown_and_wrong_type_budgets_refuse_before_source(self):
        for side in ('policy','lease'):
            for value in (None,dict(backend_seconds=300,caller_seconds=310),dict(backend_seconds=600,caller_seconds=310),dict(backend_seconds=600.0,caller_seconds=610),dict(backend_seconds=600,caller_seconds=610,extra=1)):
                policy,lease=copy.deepcopy(self.policy),copy.deepcopy(self.lease)
                target=policy if side=='policy' else lease
                if value is None:target.pop('execution_budget')
                else:target['execution_budget']=value
                with patch.object(C,'pinned_json',side_effect=[policy,lease]),patch.object(C,'current_payloads',side_effect=AssertionError('must refuse before candidate/root checks')),self.assertRaises(ValueError):
                    C.Adapter(self.args(),T,T.limits())
    def test_real_policy_pin_drift_and_partial_arguments_refuse(self):
        args=self.args();Path(args.full574_lease).write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'policy-or-lease-pin'):C.execution_seconds(args,T)
        with self.assertRaisesRegex(ValueError,'explicit-policy-and-lease'):C.execution_seconds(NS(full574_policy='inert'),T)
    def test_apply_supervisor_selects600_and_generic_stays300_without_spawning(self):
        prefix=['transaction.py','apply','--workspace',str(self.root),'--apps-source','inert','--apps-provenance-sha256','a'*64,'--repository-source','inert','--confirm-disposable-transaction']
        full=self.args();options=[part for key,value in vars(full).items() for part in ('--'+key.replace('_','-'),str(value))]
        for argv,expected in ((prefix,300),(prefix+options,600)):
            row=dict(termination=None,direct_child_reaped=True,returncode=0,stdout=T.encoded(dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION')),group_kill_sent=False)
            with patch.object(sys,'argv',argv),patch.object(T,'load',return_value=C),patch.object(T,'root_guard'),patch.object(T.SUP,'run',return_value=row) as run,redirect_stdout(io.StringIO()):
                self.assertEqual(T.main(),0)
            self.assertEqual(run.call_args.kwargs['timeout'],expected);self.assertEqual(run.call_args.kwargs['output_limit'],1024**2)
    def test_native_caller_and_interrupted_window_are_dedicated_and_finite(self):
        lane=ROOT/'scripts/ci/apps-full574-native'
        # The verification runner supplies the proposed lane path explicitly.
        lane=Path(__file__).parents[1]/'ci/apps-full574-native'
        tree=ast.parse((lane/'lifecycle.py').read_text())
        call=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='call')
        self.assertEqual(ast.literal_eval(call.args.kw_defaults[0]),610)
        text=(lane/'lifecycle.py').read_text();self.assertIn('end=time.monotonic()+600',text);self.assertIn('time_limit=600,reap_limit=5',text)
        job=(lane/'job.py').read_text();self.assertIn("interruption['time_limit']==600",job);self.assertIn("interruption['seconds']<=605",job)
        self.assertIn("3000 if role=='lifecycle' else 900",job)
    def test_generic_guards_and_all_transaction_operations_remain(self):
        original=ROOT/'scripts/apps/transaction.py'
        before=ast.parse(original.read_text());after=ast.parse((HERE/'transaction.py').read_text())
        functions=lambda tree:{n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
        old,new=functions(before),functions(after)
        for name in set(old)-{'limits','prepare_copy','apply','main'}:
            self.assertEqual(ast.dump(old[name]),ast.dump(new[name]),name)
        class OriginalBudget(ast.NodeTransformer):
            def visit_Call(self,node):
                self.generic_visit(node)
                if isinstance(node.func,ast.Name) and node.func.id=='limits':node.args=[]
                return node
        for name in ('prepare_copy','apply'):
            self.assertEqual(ast.dump(OriginalBudget().visit(old[name])),ast.dump(OriginalBudget().visit(new[name])),name)
if __name__=='__main__':unittest.main(verbosity=2)
