# SPDX-License-Identifier: MIT
"""Source successor DATA and pre-entry ordering controls; never runs an actor."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest
from types import ModuleType

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('rust_work_source_data',HERE/'prepare.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
SOURCE=Path('/tmp/rust199-native-source-DATA-20261115-r1/source-tree')


class SourceControls(unittest.TestCase):
    def test_exact_parent_inverse_and_protected_inputs(self):
        before=p.parent(SOURCE);files=p.render(before);revision=json.loads(files['work-volume-revision.json'][0])
        self.assertEqual(p.undo(files,before,revision),before)
        self.assertEqual(revision['copy_up_cause'],'UNPROVEN')
        for name in revision['protected']:self.assertEqual(files[name],before[name])
        self.assertEqual(len(files),279)
        self.assertTrue(all(value is None for value in json.loads(files['source-map.json'][0])['actual'].values()))
        self.assertEqual(files['.github/workflows/native-arm-build.yml'],files['.github/workflows/native-arm-rust199-source-reference-v1.yml'])
    def test_parent_or_literal_drift_refuses(self):
        before=p.parent(SOURCE);bad=dict(before);bad['actor/phase.py']=(b'FENCED drift',0o644)
        with self.assertRaises(ValueError):p.render(bad)
        with self.assertRaises(ValueError):p.actor_entry(before['actor/entry.py'][0].replace(b'TRUST=(',b'TRUST_OTHER=(',1))
    def test_actual_outer_check_precedes_work_write_and_nested_fakeroot_unchanged(self):
        raw=p.actor_entry(p.parent(SOURCE)['actor/entry.py'][0]);tree=ast.parse(raw)
        execute=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        text=ast.unparse(execute)
        self.assertLess(text.index('OBSERVED_WORK_ROOT_BEFORE_ENTRY'),text.index('os.open('))
        self.assertLess(text.index('OBSERVED_OPEN_WORK_ROOT_BEFORE_VERIFICATION'),text.index('volume.verify_work('))
        self.assertLess(text.index('volume.verify_work('),text.index('OUT.mkdir('))
        self.assertLess(text.index('volume.verify_work('),text.index('prepare_layout('))
        self.assertIn("if action in ('prepare', 'makepkg')",text)
        self.assertIn("action == 'package' and info.st_uid == 0",text)
        self.assertIn("result['work_preentry'] = retain(",text)
        self.assertIn('WORK_VOLUME_ADMISSION_SHA256',raw.decode())
    def test_closed_namespace_and_pinned_volume_binding(self):
        raw=p.actor_entry(p.parent(SOURCE)['actor/entry.py'][0]).decode()
        self.assertIn("volume.binding(a['source'],a['image']['id'],trust['ROOT_ADMISSION_SHA256'])",raw)
        self.assertIn("value==volume.admission(binding)",raw)
        self.assertIn("volume.verify_receipt(initialized,binding)",raw)
        self.assertIn("'volume-admission.json','volume-initialization.json'",raw)
        self.assertIn("result.update(trust)",raw)
    def test_four_pins_survive_nested_command_environment(self):
        raw=p.actor_entry(p.parent(SOURCE)['actor/entry.py'][0]);module=ModuleType('FENCED_source_entry')
        exec(compile(raw,'FENCED_source_entry','exec'),module.__dict__)
        trust={name:'a'*64 for name in module.TRUST};env=module.command_environment({'PATH':'/FENCED'},trust)
        self.assertEqual(set(trust),{'ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256','WORK_VOLUME_ADMISSION_SHA256'})
        self.assertTrue(all(env[name]==value for name,value in trust.items()))
        del trust['WORK_VOLUME_ADMISSION_SHA256']
        with self.assertRaises(ValueError):module.command_environment({},trust)
    def test_existing_budget_and_no_candidate_actor_import(self):
        files=p.render(p.parent(SOURCE));value=json.loads(files['contract.json'][0])['work_volume_initialization']['budget']
        self.assertEqual(value,dict(seconds=60,cpus=2,memory_bytes=134217728,swap_bytes=0,pids=32,user='0:0',cap_add=['CHOWN'],recursive=False,additional_actors=0,additional_seconds=0))
        for name,(raw,_) in files.items():
            if name in ('hosted/volume.py','hosted/producer.py','actor/entry.py'):ast.parse(raw)


if __name__=='__main__':unittest.main()
