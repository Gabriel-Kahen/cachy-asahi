"""Source209 wiring DATA controls. Parses source; never imports or runs it."""
import ast
import hashlib
import json
import operator
from pathlib import Path
import sys
import unittest

D=Path(__file__).resolve().parents[1]
BODIES, TREES = {}, {}


def configure(bodies):
    global BODIES, TREES
    BODIES = bodies
    TREES = {Path(name).stem: ast.parse(raw, filename='<rendered-Source>/' + name)
             for name, raw in bodies.items() if name.startswith('native/') and name.endswith('.py')}


def read(name):
    return BODIES['native/' + name]


def text(name):
    return read(name).decode('utf-8')


def functions(tree):
    return {n.name:n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}


def calls(tree,name):
    return [n for n in ast.walk(tree) if isinstance(n,ast.Call) and
        (isinstance(n.func,ast.Name) and n.func.id==name or isinstance(n.func,ast.Attribute) and n.func.attr==name)]


def data(node,env=None):
    """Evaluate a closed subset of literal DATA expressions, never eval/exec."""
    env=env or {}
    if isinstance(node,ast.Constant):return node.value
    if isinstance(node,ast.Name):return env[node.id]
    if isinstance(node,(ast.List,ast.Tuple,ast.Set)):return [data(n,env)for n in node.elts]
    if isinstance(node,ast.BinOp):
        op={ast.Add:operator.add,ast.Mult:operator.mul,ast.Pow:operator.pow}[type(node.op)]
        return op(data(node.left,env),data(node.right,env))
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='dict':
        return {k.arg:data(k.value,env)for k in node.keywords}
    raise ValueError('not literal DATA: '+ast.dump(node))


def literal_assignments(tree):
    values={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            try:values[node.targets[0].id]=data(node.value,values)
            except (ValueError,KeyError,TypeError):pass
    return values


def exported(tree):
    names=set(functions(tree))
    for node in tree.body:
        if isinstance(node,ast.Assign):
            names|={n.id for target in node.targets for n in ast.walk(target) if isinstance(n,ast.Name)}
        elif isinstance(node,ast.ImportFrom):names|={v.asname or v.name for v in node.names}
        elif isinstance(node,ast.Import):names|={v.asname or v.name.split('.')[0]for v in node.names}
    return names


def accepts(test,definition,call,method=False):
    args=definition.args
    positional=args.posonlyargs+args.args
    if method:positional=positional[1:]
    required=len(positional)-len(args.defaults)
    if args.vararg is None:test.assertLessEqual(len(call.args),len(positional))
    test.assertGreaterEqual(len(call.args),required)
    allowed={v.arg for v in positional+args.kwonlyargs}
    if args.kwarg is None:test.assertLessEqual({v.arg for v in call.keywords},allowed)
    test.assertFalse(any(isinstance(v,ast.Starred) for v in call.args))
    required_kw={arg.arg for arg,default in zip(args.kwonlyargs,args.kw_defaults) if default is None}
    test.assertLessEqual(required_kw,{value.arg for value in call.keywords})


class WiringData(unittest.TestCase):
    def test_exact_source209_map208_complete_python_syntax(self):
        leaves=set(BODIES)
        self.assertEqual(len(leaves),209)
        manifest=json.loads(read('source-map.json'))
        self.assertEqual(len(manifest['files']),208)
        self.assertEqual(leaves,set(manifest['files'])|{'native/source-map.json'})
        self.assertEqual(literal_assignments(TREES['common'])['RECOVERY_MAP_ROWS'],208)
        for name,tree in TREES.items():self.assertIsInstance(tree,ast.Module,name)
    def test_all_native_local_imports_and_symbols_close(self):
        local=set(TREES)
        for name,tree in TREES.items():
            for node in ast.walk(tree):
                if isinstance(node,ast.ImportFrom):
                    self.assertEqual(node.level,0,(name,node.module))
                    module=node.module.split('.')[0]
                    self.assertIn(module,local|sys.stdlib_module_names,(name,module))
                    if module in local:
                        for item in node.names:self.assertIn(item.name,exported(TREES[module]),(name,module,item.name))
                elif isinstance(node,ast.Import):
                    for item in node.names:self.assertIn(item.name.split('.')[0],local|sys.stdlib_module_names,(name,item.name))
    def test_helper_calls_exported_episode_methods_with_matching_arity(self):
        helper=TREES['security_native_v1'];native=TREES['security_recovery_native']
        episode=functions(native)['RecoveryEpisode'];methods=functions(episode)
        prepare=calls(helper,'prepare_recovery');self.assertEqual(len(prepare),1)
        accepts(self,methods['__init__'],prepare[0],True)
        self.assertEqual([ast.unparse(n)for n in prepare[0].args],['sys.modules[__name__]','c','archive','prior','paths','prior_paths','fingerprint','public','trust','map_hash'])
        found=[n for n in ast.walk(helper) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
            and isinstance(n.func.value,ast.Name) and n.func.value.id=='recovery_context']
        self.assertEqual([n.func.attr for n in sorted(found,key=lambda n:n.lineno)],['normal_completed','episode','close','close'])
        for call in found:accepts(self,methods[call.func.attr],call,True)
        wrapper=functions(native)['prepare']
        self.assertTrue(any(isinstance(n,ast.Call) and ast.unparse(n.func)=='RecoveryEpisode.__init__' for n in ast.walk(wrapper)))
    def test_adapter_and_owned_runner_call_signatures_match(self):
        native=TREES['security_recovery_native']
        adapter=functions(functions(TREES['security_recovery_adapter'])['NativeCommandAdapter'])
        for name in ('capture_reference','remove_candidate','install_prior'):
            found=calls(native,name);self.assertEqual(len(found),1);accepts(self,adapter[name],found[0],True)
        owned=functions(functions(TREES['security_interruption_owner'])['OwnedProcessRunner'])
        constructors=calls(native,'OwnedProcessRunner');self.assertEqual(len(constructors),1)
        accepts(self,owned['__init__'],constructors[0],True)
        self.assertEqual(ast.unparse(constructors[0].args[0]),"PREFIX / 'owned'")
        assignments=[n for n in ast.walk(native) if isinstance(n,ast.Assign)
            and n.value is constructors[0]]
        self.assertEqual([ast.unparse(t) for n in assignments for t in n.targets],['self.runner'])
        self.assertEqual(calls(TREES['security_recovery_adapter'],'OwnedProcessRunner'),[])
        adapter_calls=calls(native,'NativeCommandAdapter');self.assertEqual(len(adapter_calls),1)
        accepts(self,adapter['__init__'],adapter_calls[0],True)
        self.assertEqual([ast.unparse(k.value) for k in adapter_calls[0].keywords if k.arg=='runner'],['self.runner'])
        for name in ('run','interrupt'):
            found=[n for n in calls(native,name) if isinstance(n.func,ast.Attribute)
                and ast.unparse(n.func.value)=='self.runner']
            self.assertEqual(len(found),1);accepts(self,owned[name],found[0],True)
        recover=functions(TREES['security_recovery'])['recover'];call=calls(native,'recover');self.assertEqual(len(call),1)
        accepts(self,recover,call[0]);self.assertEqual({n.arg for n in call[0].keywords},{'metadata_normalizer','journal'})
    def test_owner_staged_scope_exact_join_and_docker_destination(self):
        owner=TREES['owner'];scope=next(n for n in ast.walk(owner)if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='recovery_scope'for t in n.targets)).value
        self.assertEqual({n.arg for n in scope.keywords},{'protocol','binding','caller_verified_source','disposable_native_image'})
        fields={n.arg:n.value for n in scope.keywords}
        self.assertEqual(data(fields['protocol']),'security-recovery-native-scope-v1')
        self.assertIs(data(fields['caller_verified_source']),True);self.assertIs(data(fields['disposable_native_image']),True)
        self.assertEqual(ast.unparse(fields['binding']),'dict(own, map_sha256=args.map_sha256)')
        saves=[n for n in calls(owner,'save')if len(n.args)==2 and isinstance(n.args[1],ast.Name)and n.args[1].id=='recovery_scope']
        self.assertEqual(len(saves),1);self.assertEqual(ast.unparse(saves[0].args[0]),"context / 'security-recovery-binding.json'")
        helper_strings=[n.value for n in ast.walk(TREES['security_native_v1'])if isinstance(n,ast.Constant)and type(n.value)is str]
        self.assertTrue(any('COPY security-recovery-binding.json /opt/native-security-v1/recovery/native-scope.json\n'in n for n in helper_strings))
        native_text=text('security_recovery_native.py')
        self.assertIn("SCOPE = PREFIX / 'native-scope.json'",native_text)
        self.assertIn("PREFIX = Path('/opt/native-security-v1/recovery')",native_text)
    def test_contract_embedded_blocking_c_and_retained_normal_c(self):
        contract=json.loads(read('security-contract-v1.json'))
        policy=contract['recovery']['observation'];body=policy['source'].encode('ascii')
        self.assertEqual(body,(D/'controls/fixtures/blocking-observer.c').read_bytes())
        self.assertEqual(policy['source_pin'],dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest()))
        self.assertIn(b'RECOVERY_BLOCK_V1:',body)
        self.assertNotEqual(policy['source_pin'],contract['upgrade']['observation']['source_pin'])
        self.assertNotIn('recovery_block',contract['upgrade']['observation']['source'])
    def test_reader_sidecar_signature_names_and_inherited_caps(self):
        contract=json.loads(read('security-contract-v1.json'))['recovery']
        function=functions(TREES['security_recovery_reader'])['validate_recovery_sidecar']
        call=calls(TREES['security_reader_v1'],'validate_recovery_sidecar');self.assertEqual(len(call),1)
        accepts(self,function,call[0]);self.assertEqual(len(call[0].args),9)
        self.assertEqual(ast.unparse(call[0].args[0]),"view.read('journey/recovery-evidence.json')")
        self.assertIn("'native/expected349.lock'",ast.unparse(call[0].args[-1]))
        self.assertEqual(contract['sidecar'],'recovery-evidence.json')
        self.assertEqual(contract['sidecar_cap'],8*1024**2);self.assertEqual(contract['result_cap'],2*1024**2)
        self.assertEqual(literal_assignments(TREES['security_recovery_native'])['CAP'],8*1024**2)
        caps=literal_assignments(TREES['capsule']);self.assertEqual(caps['CAP'],32*1024**2);self.assertEqual(caps['PAYLOAD_CAP'],16*1024**2)
        helper=text('security_native_v1.py');reader=text('security_reader_v1.py')
        self.assertIn("(output/'recovery-evidence.json').write_bytes(evidence)",helper)
        self.assertIn("{'journey/result.json','journey/recovery-evidence.json'}",reader)
        self.assertTrue(any(len(n.args)==2 and data(n.args[1])==8*1024**2 for n in calls(function,'parse')))
    def test_reader_cleanup_pair_matches_actual_fs_mutations(self):
        fs=TREES['security_recovery_fs'];reader=TREES['security_recovery_reader']
        mutations=[]
        for tree,env in ((fs,literal_assignments(fs)),(reader,literal_assignments(TREES['security_recovery_state']))):
            found=[n.value for n in ast.walk(tree)if isinstance(n,ast.keyword)and n.arg=='mutations']
            self.assertEqual(len(found),1);mutations.append(data(found[0],env))
        self.assertEqual(mutations[0],mutations[1])
        self.assertEqual([v['operation']for v in mutations[0]],['rmdir','unlink'])
        cleanup=functions(fs)['cleanup']
        direct=[n for n in ast.walk(cleanup) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
            and ast.unparse(n.func)in('os.rmdir','os.unlink')]
        self.assertEqual([ast.unparse(n.func)for n in sorted(direct,key=lambda n:n.lineno)],['os.rmdir','os.unlink'])

if __name__ == '__main__':
    import argparse
    import importlib.util
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('factory_controls', D/'test_factory_recovery_new.py')
    factory = importlib.util.module_from_spec(spec); spec.loader.exec_module(factory)
    factory.SOURCE_ROOTS.add(args.parent_source.resolve())
    sys.addaudithook(factory.audit)
    configure(factory.maintained(D).render(args.parent_source.resolve())[1])
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WiringData))
    raise SystemExit(not result.wasSuccessful() or bool(factory.DENIED))
