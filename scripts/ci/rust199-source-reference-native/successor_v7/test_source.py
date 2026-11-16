# SPDX-License-Identifier: MIT
"""Notice constructor DATA controls; no candidate, actor, Reader or native execution."""
import ast
import copy
import importlib.util
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('notice_source_proposal', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class SourceControls(unittest.TestCase):
    def fixture(self):
        spec=importlib.util.spec_from_file_location('v7_fixture_support',HERE/'test_support.py')
        support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
        root=support.assembled(False)
        before=p.fs.snapshot(root)
        prefix=p.PREFIX
        candidate={name.removeprefix(prefix):row for name,row in before.items() if name.startswith(prefix)}
        oldmap=dict(schema=1,commit='dd6871d566661c4fe9eba055ae19e1e017e0b69d',files=p.fs.descriptors(candidate))
        before['candidate-map.json']=(p.encode(oldmap),0o644)
        contract=json.loads((HERE/'payload/contract.json').read_bytes())
        contract['candidate']={key:oldmap[key] for key in ('commit','files')}
        volume=contract['work_volume_initialization']
        volume.pop('compiler_build_and_stage0_unchanged');volume.pop('notice_preservation_candidate_binding')
        volume['original_candidate_and_stage0_unchanged']=True
        before['contract.json']=(p.encode(contract),0o644)
        recipe=before[prefix+'PKGBUILD'][0]
        for action in ('prepare','build','package'):
            suffix=' --destination "$pkgdir"' if action=='package' else ''
            recipe=recipe.replace(f'  python -I "$srcdir/reference.py" {action} --work "$srcdir"{suffix} || return'.encode(),f'  /usr/bin/python -I -B /source/actor/entry.py {action} || return'.encode())
        before['recipe/PKGBUILD']=(recipe,0o644)
        marker=dict(schema=6,pending=None,scope='LLVM260_READER7_PROSPECTIVE_REJOIN_ONLY_NO_ROLES')
        before['llvm260-reader7-rejoin.json']=(p.encode(marker),0o644)
        entry=p.fs.pin(before['hosted/entry.py'][0])['sha256'].encode()
        workflow=(HERE.parent/'successor_v6/workflow.yml.in').read_bytes().replace(b'__ENTRY_SHA__',entry)
        for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'):
            before[name]=(workflow,0o644)
        before['source-map.json']=(p.encode(dict(schema=1,operation='rust199-source-reference-native-v1',actual=p.ACTUAL,files=p.fs.descriptors(before))),0o644)
        parent=dict(files=len(before),bytes=sum(len(raw) for raw,mode in before.values()),tree=p.fs.tree(before),
                    map_sha256=p.fs.pin(before['source-map.json'][0])['sha256'],factory_commit='FENCED')
        return before,parent
    def test_only_notice_leaves_change_and_inverse_is_complete(self):
        before, parent = self.fixture()
        with patch.object(p, 'PARENT', parent):
            after = p.render(before)
            self.assertEqual(set(after) - set(before), {p.PREFIX + 'notice_preservation.py', p.PREFIX + 'notice-catalogue.DATA.json', 'notice_binding.py', p.REVISION})
            for name in ('resource-policy.json', 'frozen/rust199-admission-v1.py', 'hosted/bootstrap.py'):
                self.assertEqual(after[name], before[name])
            marker = json.loads(after[p.REVISION][0])
            self.assertTrue(marker['unadmitted'])
            self.assertIsNone(marker['pending'])
            self.assertEqual(p.undo(after, before, marker), before)
    def test_changed_map_notice_and_protected_source_refuse_inverse(self):
        before, parent = self.fixture()
        with patch.object(p, 'PARENT', parent):
            after = p.render(before)
            marker = json.loads(after[p.REVISION][0])
            for name in ('source-map.json', p.PREFIX + 'reference.py', 'hosted/bootstrap.py', p.REVISION):
                bad = dict(after)
                bad[name] = (b'FENCED changed', 0o644)
                with self.subTest(name=name), self.assertRaises(ValueError): p.undo(bad, before, marker)
            bad = dict(after)
            bad['hosted/bootstrap.py'] = (b'FENCED changed', 0o644)
            body = json.loads(bad['source-map.json'][0])
            body['files'] = p.fs.descriptors({n: row for n, row in bad.items() if n != 'source-map.json'})
            bad['source-map.json'] = (p.encode(body), 0o644)
            with self.assertRaises(ValueError): p.undo(bad, before, marker)
    def test_wrong_parent_refuses_before_render(self):
        with self.assertRaises(ValueError): p.render({})
    def test_whole_parent_capture_and_input_alias_refusal(self):
        before, parent = self.fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-notice-parent-') as directory:
            root = Path(directory)
            for name, (raw, mode) in before.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            with patch.object(p, 'PARENT', parent):
                self.assertEqual(p.capture(root), before)
                (root / 'hosted/bootstrap.py').write_bytes(b'FENCED changed')
                with self.assertRaises(ValueError): p.capture(root)
                (root / 'hosted/bootstrap.py').unlink()
                (root / 'hosted/bootstrap.py').symlink_to(root / 'resource-policy.json')
                with self.assertRaises((OSError, ValueError)): p.capture(root)
    def test_complete_constructor_and_wrong_profile_existing_output_refusals(self):
        before, parent = self.fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-notice-constructor-') as directory:
            root = Path(directory)
            parent_root, constructor = root / 'parent', root / 'constructor'
            parent_root.mkdir()
            constructor.mkdir()
            for name, (raw, mode) in before.items():
                path = parent_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            for name, (raw, mode) in p.fs.snapshot(HERE / 'payload').items():
                path = constructor / 'payload' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            with patch.object(p, 'PARENT', parent), patch.object(p, 'HERE', constructor):
                files = p.render(before)
                profile = dict(schema=7, unadmitted=True, actual=p.ACTUAL, parent=parent, scope=p.SCOPE,
                               constructor_files=p.inputs(), files=len(files), bytes=sum(len(raw) for raw, _ in files.values()),
                               tree=p.fs.tree(files), map_sha256=p.fs.pin(files['source-map.json'][0])['sha256'])
                raw = p.encode(profile)
                (constructor / 'constructor-profile.json').write_bytes(raw)
                expected = p.fs.pin(raw)['sha256']
                with self.assertRaises(ValueError): p.construct(parent_root, root / 'wrong-profile', '0' * 64)
                self.assertFalse((root / 'wrong-profile').exists())
                result = p.construct(parent_root, root / 'output', expected)
                self.assertTrue(result['unadmitted'])
                self.assertEqual(p.fs.snapshot(root / 'output'), files)
                with self.assertRaises((OSError, ValueError)): p.construct(parent_root, root / 'output', expected)
                with self.assertRaises(ValueError): p.construct(parent_root, constructor / 'overlap', expected)
    def test_complete_hosted_source_gate_and_stale_binding_refusals(self):
        before,parent=self.fixture()
        with patch.object(p,'PARENT',parent):files=p.render(before)
        with tempfile.TemporaryDirectory(prefix='FENCED-v7-source-gate-') as directory:
            root=Path(directory)
            for name,(raw,mode) in files.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
            spec=importlib.util.spec_from_file_location('FENCED_v7_hosted_gate',root/'hosted/entry.py')
            entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
            digest=p.fs.pin(files['source-map.json'][0])['sha256']
            self.assertEqual(entry.source_gate(root,digest)['schema'],1)
            original_marker=files[p.REVISION]
            for mutation in ('pending','authority','binding','missing_helper','old_map'):
                changed=dict(files)
                marker=json.loads(original_marker[0])
                if mutation=='pending':marker['pending']='FENCED_NOT_READY'
                elif mutation=='authority':marker['actual']['source']='a'*40
                elif mutation=='binding':marker['candidate_binding']['tree']='0'*40
                elif mutation=='missing_helper':changed.pop(p.PREFIX+'notice_preservation.py')
                else:changed['candidate-map.json']=before['candidate-map.json']
                if mutation in ('pending','authority','binding'):changed[p.REVISION]=(p.encode(marker),0o644)
                manifest=json.loads(files['source-map.json'][0]);manifest['files']=p.fs.descriptors({name:row for name,row in changed.items() if name!='source-map.json'})
                changed['source-map.json']=(p.encode(manifest),0o644)
                for name in set(files)|set(changed):
                    path=root/name
                    if name in changed:path.write_bytes(changed[name][0]);path.chmod(changed[name][1])
                    elif path.exists():path.unlink()
                with self.subTest(mutation=mutation),self.assertRaises((OSError,ValueError)):
                    entry.source_gate(root,p.fs.pin(changed['source-map.json'][0])['sha256'])
    def test_effective_recipe_and_srcinfo_hash_every_local_notice_input(self):
        before,parent=self.fixture()
        with patch.object(p,'PARENT',parent):files=p.render(before)
        recipe=files[p.PREFIX+'PKGBUILD'][0].decode()
        info=files[p.PREFIX+'.SRCINFO'][0].decode()
        def array(name):return re.findall(r"'([^']*)'",re.search(r'^'+name+r'=\((.*?)\)',recipe,re.M|re.S).group(1))
        sources,sums=array('source'),array('sha256sums')
        self.assertEqual(len(sources),len(sums))
        self.assertEqual(sources,[line.split(' = ',1)[1] for line in info.splitlines() if line.startswith('\tsource = ')])
        self.assertEqual(sums,[line.split(' = ',1)[1] for line in info.splitlines() if line.startswith('\tsha256sums = ')])
        archives=json.loads(files[p.PREFIX+'inputs.json'][0])['archives']
        for name,digest in zip(sources,sums):
            self.assertNotIn('/',name)
            expected=archives[name]['sha256'] if name in archives else p.fs.pin(files[p.PREFIX+name][0])['sha256']
            self.assertEqual(digest,expected,name)
        self.assertIn('notice_preservation.py',sources)
        self.assertIn('notice-catalogue.DATA.json',sources)
    def test_build_commands_resources_proofs_and_nonbinding_functions_stay_exact(self):
        before,parent=self.fixture()
        with patch.object(p,'PARENT',parent):after=p.render(before)
        exceptions={'actor/entry.py':{'source_gate','gate'},'hosted/producer.py':{'snapshot'},
                    'hosted/entry.py':{'source_gate'},'admission.py':{'candidate_binding','validate_dispatch','projection','operational'}}
        for name,allowed in exceptions.items():
            def stable(raw):
                tree=ast.parse(raw)
                tree.body=[node for node in tree.body if not (isinstance(node,ast.FunctionDef) and node.name in allowed)]
                return ast.dump(tree)
            self.assertEqual(stable(before[name][0]),stable(after[name][0]),name)
        for name in ('actor/phase.py','actor/qualify.py'):
            def stable(raw):
                tree=ast.parse(raw)
                tree.body=[node for node in tree.body if not (isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='REFERENCE_SHA' for target in node.targets))]
                return ast.dump(tree)
            self.assertEqual(stable(before[name][0]),stable(after[name][0]),name)
        for name in before:
            if name.startswith(('llvm-v2/','frozen/')) or name in ('resource-policy.json','hosted/bootstrap.py','hosted/materials.py','hosted/qualification.py','hosted/phase_transfer.py'):
                self.assertEqual(before[name],after[name],name)
        old=p.fs.pin(before['hosted/entry.py'][0])['sha256'].encode();new=p.fs.pin(after['hosted/entry.py'][0])['sha256'].encode()
        for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml'):
            self.assertEqual(before[name][0].count(old),2)
            self.assertEqual(before[name][0].replace(old,new),after[name][0])
    def test_payload_has_no_build_actor_or_authority_changes(self):
        rows = p.fs.snapshot(HERE / 'payload')
        self.assertEqual(set(rows), p.LEAVES)
        value = json.loads(rows[p.PREFIX + 'notice-catalogue.DATA.json'][0])
        self.assertEqual(value['catalogue_basis']['seal_sha256'], p.SEAL)
        self.assertIsNone(value['Root_review'])
        self.assertIsNone(value['accepted'])
        self.assertEqual(len(value['files']), 425)


if __name__ == '__main__':
    unittest.main()
