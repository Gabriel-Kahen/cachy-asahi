# SPDX-License-Identifier: MIT
"""Exact runtime composition DATA; no role, native package, grant or Source issued."""
import ast
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        ATTEMPTS.append(event)
        raise AssertionError('PROJECT19_DELTA_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('project19_delta_controls', HERE / 'delta.py')
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)


def source367_rows():
    """Exact old runtime bytes recovered from the pinned v18 finite inverse."""
    old = D.predecessor(); result = {}
    for name, (raw, mode) in D.v18_leaves().items():
        for before, after in reversed(old.PATCHES[name]):
            if raw.count(after.encode()) != 1: raise AssertionError('exact v18 inverse')
            raw = raw.replace(after.encode(), before.encode())
        result[name] = raw, mode
    return result


def dependency_calls(raw, function):
    f = next(node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == function)
    return [node for node in ast.walk(f) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == 'dependencies']


class DeltaControls(unittest.TestCase):
    def test_render_source367_runtime_through_whole_pinned_v18_equals_payload(self):
        before = source367_rows(); result = D.render_leaves(before)
        self.assertEqual(result, D.payload_leaves()); self.assertEqual(set(result), set(D.V18_PINS))
        self.assertEqual(D.predecessor().render_leaves(before), D.v18_leaves())
        for name, (raw, mode) in result.items():
            self.assertEqual(mode, 0o644); self.assertIn(b'project_provider.py', raw)
            self.assertNotIn(b"'hosted/build_dependencies.py'", raw)
            self.assertNotIn(b"with_name('build_dependencies.py')", raw)

    def test_all_other_original_functions_constants_imports_and_classes_remain_exact(self):
        changed = {'hosted/bootstrap.py': {'run'}, 'hosted/qualification.py': {'validate_result', 'run'}, 'actor/qualify.py': {'run'}}
        for name, (raw, _) in D.payload_leaves().items():
            original = D.v18_leaves()[name][0]; old, new = ast.parse(original), ast.parse(raw)
            self.assertEqual(len(old.body), len(new.body))
            for a, b in zip(old.body, new.body):
                if isinstance(a, ast.FunctionDef) and a.name in changed[name]: continue
                self.assertEqual(ast.dump(a), ast.dump(b), (name, getattr(a, 'name', type(a).__name__)))
                self.assertEqual(ast.get_source_segment(original.decode(), a), ast.get_source_segment(raw.decode(), b))
        actor = D.payload_leaves()['actor/qualify.py'][0]
        for marker in (b"'qualification cap0/NNP'", b"'qualification-data'", b"'qualification-probe'", b"need(len(receipts)==9", b"'aggregate60s native probe cap'", b"'explicit limited qualification grant'"):
            self.assertIn(marker, actor)

    def test_complete_runtime_inverse_removes_only_declared_substitutions(self):
        for name, (raw, mode) in D.payload_leaves().items():
            for old, new in reversed(D.PATCHES[name]):
                self.assertEqual(raw.count(new.encode()), 1); raw = raw.replace(new.encode(), old.encode())
            self.assertEqual((raw, mode), D.v18_leaves()[name])

    def test_changed_missing_wrong_mode_or_nonbytes_parent_refuses(self):
        original = source367_rows()
        for mutate in (lambda x: x.pop('hosted/bootstrap.py'),
                       lambda x: x.update({'hosted/bootstrap.py': (x['hosted/bootstrap.py'][0] + b'\n', 0o644)}),
                       lambda x: x.update({'actor/qualify.py': (x['actor/qualify.py'][0], 0o755)}),
                       lambda x: x.update({'actor/qualify.py': ('NOT_BYTES', 0o644)})):
            before = copy.deepcopy(original); mutate(before)
            with self.assertRaises(ValueError): D.render_leaves(before)

    def test_frozen_delta_or_runtime_body_mode_alias_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory(prefix='project19-frozen-MODEL-') as temporary:
            root = Path(temporary); (root / 'delta.py').write_bytes((D.V18 / 'delta.py').read_bytes())
            for name in D.V18_PINS:
                target = root / 'payload' / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((D.V18 / 'payload' / name).read_bytes()); target.chmod(0o644)
            with patch.object(D, 'V18', root):
                self.assertEqual(set(D.payload_leaves()), set(D.V18_PINS))
                path = root / 'payload/hosted/bootstrap.py'; raw = path.read_bytes(); path.write_bytes(raw + b'\n')
                with self.assertRaises(ValueError): D.payload_leaves()
                path.write_bytes(raw); path.chmod(0o600)
                with self.assertRaises(ValueError): D.payload_leaves()
                path.chmod(0o644); path.unlink(); path.symlink_to(root / 'delta.py')
                with self.assertRaises(ValueError): D.payload_leaves()
                (root / 'delta.py').write_bytes(b'raise AssertionError("UNREVIEWED")\n')
                with self.assertRaises(ValueError): D.predecessor()

    def test_bootstrap_model_dispatch_passes_verified_context_and_same_actual_image(self):
        calls = []; state = {'policy': {'MODEL_UNISSUED': True}}; verified = {'signature_math': 'MODEL_VERIFIED_BOUNDARY'}
        def record(name, result=None):
            def call(*args, **kwargs): calls.append((name, args, kwargs)); return result
            return call
        dependency = SimpleNamespace(policy=record('policy', state), prepare_context=record('prepare_context', verified),
            extend_dockerfile=record('extend_dockerfile', b'MODEL_DOCKERFILE'), observe=record('observe', {'MODEL': 'observation'}),
            validate_observation=record('validate_observation'), pin=record('pin', {'MODEL': 'pin'}))
        namespace = dict(dependencies=dependency, root=Path('/MODEL/source'), context=Path('/MODEL/context'), out=Path('/MODEL/output'),
            dependency_policy=state, dependency_audit=verified, call=object(), tick=object(), rootfs=Path('/MODEL/rootfs'),
            image='sha256:' + 'a' * 64, dependency_observation={'MODEL': 'observation'}, own={'base_tag': 'MODEL_BASE'},
            fingerprint_expected='F' * 40, normal_dockerfile=lambda *args: b'MODEL_ORIGINAL', encode=lambda v: b'MODEL_CANONICAL_POLICY')
        for node in dependency_calls(D.payload_leaves()['hosted/bootstrap.py'][0], 'run'):
            eval(compile(ast.Expression(body=node), 'MODEL-selected-dependency-call', 'eval'), namespace)
        selected = {name: (args, kw) for name, args, kw in calls}
        self.assertEqual(selected['prepare_context'][0], (namespace['root'], namespace['context'], namespace['out'], state, namespace['call'], namespace['tick']))
        self.assertEqual(selected['extend_dockerfile'][0], (b'MODEL_ORIGINAL', state, verified))
        self.assertEqual(selected['observe'][1], {'image_id': namespace['image']})
        self.assertEqual(selected['validate_observation'][1], {'image_id': namespace['image'], 'native': False, 'tick': namespace['tick']})
        self.assertEqual(selected['policy'][1], {'tick': namespace['tick']})
        self.assertEqual(selected['pin'][0], (b'MODEL_CANONICAL_POLICY',))

    def test_actor_and_both_hosted_replays_bind_image_and_native_provider_state(self):
        actor = dependency_calls(D.payload_leaves()['actor/qualify.py'][0], 'run')
        observes = [n for n in actor if n.func.attr == 'observe']; validates = [n for n in actor if n.func.attr == 'validate_observation']
        self.assertEqual(len(observes), 1); self.assertEqual(len(validates), 1)
        self.assertIn("image_id=p['image_id']", ast.unparse(observes[0])); self.assertIn('native=True', ast.unparse(observes[0]))
        self.assertIn("image_id=p['image_id']", ast.unparse(validates[0]))
        self.assertIn('tick=tick', ast.unparse(validates[0]))
        self.assertTrue(all('tick=tick' in ast.unparse(n) for n in actor if n.func.attr == 'policy'))
        hosted = [n for n in dependency_calls(D.payload_leaves()['hosted/qualification.py'][0], 'validate_result') if n.func.attr == 'validate_observation']
        self.assertEqual(len(hosted), 2)
        self.assertTrue(all("image_id=boot['image']" in ast.unparse(n) and 'tick=tick' in ast.unparse(n) for n in hosted))
        raw = D.payload_leaves()['hosted/qualification.py'][0]
        self.assertIn(b"for phase in ('data','probe'):", raw)
        self.assertIn(b"'whole retained native dependency observation'", raw)

    def test_heavy_bootstrap_admission_is_inside_protected_try_after_budget_tick_definition(self):
        run = next(n for n in ast.parse(D.payload_leaves()['hosted/bootstrap.py'][0]).body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        tick = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == 'tick')
        protected = next(n for n in run.body if isinstance(n, ast.Try))
        call = protected.body[0]
        self.assertIsInstance(call, ast.Assign); self.assertEqual(ast.unparse(call.value), 'dependencies.policy(root, tick=tick)')
        self.assertLess(tick.lineno, call.lineno)
        prefix = [n for n in run.body if n.lineno < protected.lineno]
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'policy' for top in prefix for n in ast.walk(top)))
        self.assertIn("report['base_intent']", ast.unparse(protected.body[1]))
        def cancelled(): raise ValueError('MODEL_AGGREGATE_DEADLINE')
        def policy(root, *, tick): tick(); return {'UNREACHABLE': True}
        namespace = dict(dependencies=SimpleNamespace(policy=policy), root=Path('/MODEL/source'), tick=cancelled, dependency_policy=None, report={})
        with self.assertRaisesRegex(ValueError, 'MODEL_AGGREGATE_DEADLINE'):
            exec(compile(ast.Module(body=protected.body[:2], type_ignores=[]), 'MODEL-budgeted-admission', 'exec'), namespace)
        self.assertIsNone(namespace['dependency_policy']); self.assertNotIn('base_intent', namespace['report'])

    def test_hosted_result_replay_reuses_existing_aggregate_tick_with_data_default_compatibility(self):
        tree = ast.parse(D.payload_leaves()['hosted/qualification.py'][0])
        validate = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'validate_result')
        self.assertEqual([a.arg for a in validate.args.kwonlyargs], ['tick'])
        self.assertIsInstance(validate.args.kw_defaults[0], ast.Lambda)
        for call in dependency_calls(D.payload_leaves()['hosted/qualification.py'][0], 'validate_result'):
            if call.func.attr in {'policy', 'validate_observation', 'read'}:
                self.assertIn('tick=tick', ast.unparse(call))
        run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        calls = [n for n in ast.walk(run) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'validate_result']
        self.assertEqual(len(calls), 1); self.assertEqual(ast.unparse(calls[0]), 'validate_result(value, provider, boot, data, tick=tick)')
        old = ast.parse(D.v18_leaves()['hosted/qualification.py'][0]); original = next(n for n in old.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        for call in ast.walk(run):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'validate_result':
                call.keywords = [k for k in call.keywords if k.arg != 'tick']
        self.assertEqual(ast.dump(run), ast.dump(original), 'only the runtime validation call threads its existing clock')

    def test_no_actual_actor_attempt(self):
        self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
