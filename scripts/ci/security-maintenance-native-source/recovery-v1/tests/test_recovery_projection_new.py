"""Extract only projection decision AST into fake bounded DATA namespaces.

No Source module import, capsule Reader, native process or filesystem mutator.
The fake read/add inputs are in-memory public bytes; caps/privacy code is held.
"""
import ast
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import re
import types
import unittest
D=Path(__file__).resolve().parents[1]
NATIVE=next(p for p in (D/'proposed-overlay/native',D/'overlay/native')if (p/'public_projection.py').is_file())
PT=ast.parse((NATIVE/'public_projection.py').read_bytes())
RT=ast.parse((NATIVE/'reader.py').read_bytes())
OP='security-alpm-interrupted-recovery-v1'
PROTOCOL='security-upgrade-interruption-empty-db-v1'


def need(value,reason):
    if not value:raise ValueError(reason)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def functions(tree):return {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}


def isolated(nodes,namespace):
    # This closed AST set contains DATA checks only; no source top-level imports.
    module=ast.fix_missing_locations(ast.Module(body=copy.deepcopy(nodes),type_ignores=[]))
    exec(compile(module,'<bounded-projection-DATA-AST>','exec'),namespace)
    return namespace


def reference(raw=b'{"public":"recovery DATA"}'):
    return dict(schema=1,protocol=PROTOCOL,path='recovery-evidence.json',pin=pin(raw))


def basic_namespace():
    class Refusal(ValueError):
        def __init__(self,message,**context):super().__init__(message)
    C=types.SimpleNamespace(need=need,PAYLOAD_CAP=16*1024**2,CAP=32*1024**2,pin=pin,
        _load=json.loads,_mode=lambda mode:need(type(mode)is int and 0<=mode<=0o777,'mode'),
        refusal_context=lambda *args:contextlib.nullcontext(),CapsuleRefusal=Refusal)
    env={'C':C,'re':re}
    return isolated([functions(PT)['_pin'],functions(PT)['recovery_projection_pin']],env)


def projection_gate(authority,result,leaves):
    """Execute only actual nested add() plus changed journey selection block."""
    env=basic_namespace();project=functions(PT)['_project']
    add=next(n for n in project.body if isinstance(n,ast.FunctionDef)and n.name=='add')
    first=next(i for i,n in enumerate(project.body)if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name)and t.id=='journey'for t in n.targets))
    last=next(i for i,n in enumerate(project.body[first:],first)if isinstance(n,ast.Expr)
        and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='add'
        and n.value.args and isinstance(n.value.args[0],ast.Constant)and n.value.args[0].value=='journey/build-summary.json')
    marker=next(n for n in PT.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name)and t.id=='PRIVATE_MARKER'for t in n.targets))
    isolated([marker],env)
    rawleaves=dict(leaves)
    if result is not None:rawleaves['journey/result.json']=json.dumps(result).encode()
    def read(root,name,optional=False):
        if name not in rawleaves:
            if optional:return None
            raise FileNotFoundError(name)
        return rawleaves[name],0o600
    env.update(public='FAKE_PUBLIC_ROOT',value=authority,selected={},source_modes={},REPORTS={'python':{},'extension':{},'build-systems':{}},
        _read=read,_names=lambda root,name:sorted(k.removeprefix('journey/')for k in rawleaves if k.startswith('journey/')),
        privacy=types.SimpleNamespace(inspect_privacy=lambda *a:{},validate_context=lambda *a:None))
    isolated([add]+project.body[first:last+1],env)
    return env['selected']


def reader_gate(authority,result,leaves):
    """Execute only changed recovery gate, using an in-memory fake view."""
    function=functions(RT)['retained_public_projection']
    first=next(i for i,n in enumerate(function.body)if isinstance(n,ast.ImportFrom)and n.module=='public_projection')+1
    last=next(i for i,n in enumerate(function.body[first:],first)if isinstance(n,ast.For)and isinstance(n.target,ast.Tuple))
    blobs=dict(leaves);selected={k:{}for k in leaves};selected['receipt.json']={}
    if result is not None:selected['journey/result.json']={}
    def load(name):return authority if name=='receipt.json' else result
    env=basic_namespace();env.update(view=types.SimpleNamespace(load=load,read=lambda n:blobs[n]),selected=selected,pin=pin,need=need)
    isolated(function.body[first:last],env)
    return env['recovery_pin']


class ProjectionRecoveryData(unittest.TestCase):
    def test_exact_new_operation_and_result_pin_pass_both_gates(self):
        body=b'{"public":"recovery DATA"}';result={'recovery':reference(body)}
        selected=projection_gate({'operation':OP},result,{'journey/recovery-evidence.json':body})
        self.assertEqual(selected['journey/recovery-evidence.json'],body)
        self.assertEqual(reader_gate({'operation':OP},result,selected),pin(body))
    def test_other_operations_reject_even_valid_pin(self):
        for op in ('security-alpm-v1','source184',None,OP+'-extra'):
            with self.subTest(op=op),self.assertRaises(ValueError):
                projection_gate({'operation':op},{'recovery':reference()},{'journey/recovery-evidence.json':b'{}'})
    def test_unreferenced_sidecar_rejected(self):
        for result in (None,{},dict(recovery=None)):
            with self.subTest(result=result),self.assertRaises(ValueError):projection_gate({'operation':OP},result,{'journey/recovery-evidence.json':b'{}'})
    def test_unknown_journey_sidecar_rejected(self):
        body=b'{}'
        with self.assertRaises(ValueError):projection_gate({'operation':OP},{'recovery':reference(body)},
            {'journey/recovery-evidence.json':body,'journey/unbounded-evidence.json':b'{}'})
    def test_missing_required_sidecar_rejected(self):
        result={'recovery':reference()}
        with self.assertRaises(FileNotFoundError):projection_gate({'operation':OP},result,{})
        with self.assertRaises(ValueError):reader_gate({'operation':OP},result,{})
    def test_changed_sidecar_bytes_rejected_both_gates(self):
        result={'recovery':reference(b'original DATA')};leaves={'journey/recovery-evidence.json':b'changed DATA'}
        with self.assertRaises(ValueError):projection_gate({'operation':OP},result,leaves)
        with self.assertRaises(ValueError):reader_gate({'operation':OP},result,leaves)
    def test_typed_pin_and_eight_mib_cap_refused(self):
        helper=basic_namespace()['recovery_projection_pin']
        for invalid in (dict(bytes=0,sha256='a'*64),dict(bytes=True,sha256='a'*64),dict(bytes=8*1024**2+1,sha256='a'*64),dict(bytes=2,sha256='A'*64)):
            row=reference();row['pin']=invalid
            with self.subTest(pin=invalid),self.assertRaises(ValueError):helper({'operation':OP},{'recovery':row})
    def test_closed_reference_schema_path_and_protocol(self):
        helper=basic_namespace()['recovery_projection_pin']
        for key,value in (('schema',True),('schema',2),('path','../recovery-evidence.json'),('path','extra.json'),('protocol','old-observation-only')):
            row=reference();row[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):helper({'operation':OP},{'recovery':row})
        row=reference();row['additional']='no'
        with self.assertRaises(ValueError):helper({'operation':OP},{'recovery':row})
    def test_existing_selected_data_privacy_scan_still_applies(self):
        # The held regex recognizes a conventional secret assignment.
        body=b'secret=benign-private-marker-fixture'
        with self.assertRaises(ValueError):projection_gate({'operation':OP},{'recovery':reference(body)},{'journey/recovery-evidence.json':body})
    def test_old_empty_or_nonrecovery_journey_still_allowed(self):
        self.assertEqual(projection_gate({'operation':'source184'},None,{}),{})
        self.assertEqual(projection_gate({'operation':'source184'},{'ordinary':'report'},{}),{'journey/result.json':b'{"ordinary": "report"}'})
    def test_outer_reader_allowance_is_exact_and_conditional(self):
        function=functions(RT)['retained_public_projection']
        loop=next(n for n in function.body if isinstance(n,ast.For)and isinstance(n.target,ast.Tuple))
        branch=next(n for n in loop.body if isinstance(n,ast.AugAssign)and isinstance(n.target,ast.Name)and n.target.id=='allowed')
        self.assertEqual(ast.unparse(branch.value),"target == 'journey/recovery-evidence.json' and recovery_pin is not None")
        self.assertIn('private_marker.search',ast.unparse(loop))
        self.assertIn('16 * 1024 ** 2',ast.unparse(loop))

class BaselineFormatData(unittest.TestCase):
    def fixture(self):
        return dict(db={**{'base%03d-1-1'%i:dict(kind='dir') for i in range(349)},
            'ALPM_DB_VERSION':dict(kind='file',bytes=2,sha256=pin(b'9\n')['sha256'])}), b''.join(('base%03d 1-1\n'%i).encode() for i in range(349))
    def helper(self):
        candidates=(D/'candidate/security_recovery_reader.py',NATIVE/'security_recovery_reader.py')
        tree=ast.parse(next(p for p in candidates if p.is_file()).read_bytes())
        return isolated([functions(tree)['need'],functions(tree)['validate_baseline_inventory']],{})['validate_baseline_inventory']
    def test_349_package_dirs_plus_db_version_file_matches_without_mutation(self):
        baseline,inventory=self.fixture();before=copy.deepcopy(baseline)
        roots=self.helper()(baseline,inventory)
        self.assertEqual(len(roots),349);self.assertNotIn('ALPM_DB_VERSION',roots)
        self.assertEqual(baseline,before)
    def test_wrong_package_directory_or_version_refused(self):
        for kind in ('directory','version'):
            baseline,inventory=self.fixture()
            if kind=='directory':baseline['db']['wrong-1-1']=baseline['db'].pop('base000-1-1')
            else:inventory=inventory.replace(b'base000 1-1',b'base000 2-1')
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.helper()(baseline,inventory)

if __name__=='__main__':unittest.main()
