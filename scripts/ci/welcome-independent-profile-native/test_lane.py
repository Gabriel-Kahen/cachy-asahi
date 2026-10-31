#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite actor-free profile derivation controls; synthetic data never native credit."""
import ast
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as K
import adapter
import profile_adapter as A

ROOT=Path(os.environ.get('WELCOME_PROFILE_SOURCE',Path(__file__).resolve().parents[3])).absolute()
if not (ROOT/'scripts/ci/welcome-management-native').is_dir():
    # Private proposal invocation explicitly sets this; installed canonical needs no override.
    ROOT=Path.cwd().absolute()


def prepared(root,selected):
    code=adapter.materialize(ROOT,selected,root/'code');sys.path.insert(0,str(code))
    for name in ('native_contract','candidates','management_contract','management_root','management_phase','doctor_lifetime','profile_adapter'):
        sys.modules.pop(name,None)
    n=K.load('native_contract',code/'native_contract.py');c=K.load('candidates',code/'candidates.py')
    m=K.load('management_contract',code/'management_contract.py')
    p=K.load('profile_prepare_control',code/'prepare.py')
    ui=K.read(ROOT/'scripts/ci/welcome-management-native/input-policy.json')['ui']
    def stage(source,assets,output):
        output.mkdir();lock=dict(status='SYNTHETIC_TEMPLATE_CONTROL_ONLY',eligibility='PRIVATE_GUI_TRIAL_ONLY',products={},policy=dict(ui=ui))
        (output/'candidate-lock.json').write_bytes(K.encoded(lock));return lock
    try:
        with patch.object(n,'verify_source'),patch.object(c,'verify_source'),patch.object(n,'policy',return_value=dict(ui=ui)),patch.object(c,'stage',side_effect=stage):
            p.prepare(ROOT,root/'runner',root/'assets')
    finally:sys.path.remove(str(code))
    return root/'runner'


class Profiles(unittest.TestCase):
    def test_unbound_before_derivative_or_actor(self):
        unbound=dict(schema_version=1,status='UNBOUND_INDEPENDENT_PROFILES',profiles=list(K.PROFILES),
            candidate_policy_sha256=None,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE')
        with patch.object(K,'read',return_value=unbound),patch('subprocess.Popen',side_effect=AssertionError('actor forbidden')):
            for selected in K.PROFILES:
                with self.assertRaisesRegex(ValueError,'UNBOUND'):K.gate(ROOT,selected,{'files':{}})
    def test_profile_mandatory_and_finite(self):
        for selected in (None,'','both','minimal,overlay','../overlay'):
            with self.assertRaises(ValueError):K.profile(selected)
    def test_exact_original_pins(self):K.files(ROOT,K.read(K.HERE/'source-pins.json')['files'])
    def test_counted_anchor_refuses_drift(self):
        for text in ('x','anchor anchor'):
            with self.assertRaisesRegex(ValueError,'anchor differs'):A.replace(text,'anchor','new')
    def test_closed_derivative_drift_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out=adapter.materialize(ROOT,'minimal',Path(d)/'code');(out/'run.py').write_text('changed')
            with self.assertRaisesRegex(ValueError,'drift'):adapter.materialize(ROOT,'minimal',out)
    def test_cross_profile_derivative_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out=adapter.materialize(ROOT,'minimal',Path(d)/'code')
            with self.assertRaisesRegex(ValueError,'drift'):adapter.materialize(ROOT,'overlay',out)
    def test_native_guards_and_distinct_status(self):
        for selected in K.PROFILES:
            v=adapter.bodies(ROOT,selected)
            for name in ('lifecycle.py','installed.py','doctor_lifetime.py','management_phase.py','candidates.py','input-policy.json','infrastructure-pins.json','a11y_driver.c'):
                self.assertEqual(v[name],(ROOT/adapter.ORIGINAL/name).read_bytes())
            self.assertIn(K.NATIVE.encode(),v['run.py']);self.assertNotIn(b"status='PASS_NATIVE_MANAGEMENT_PAIR_READONLY_LIFECYCLE_AND_GUI'",v['run.py'])
            self.assertIn(b'len(frame_rows)==12',v['job.py']);self.assertIn(b'len(owner[\'containers\'])==8',v['job.py'])
            self.assertIn(b'len(gui_report[\'cleanup\'])==14',v['job.py'])
    def test_exact_argv_operand(self):
        self.assertEqual(K.profile_argv(['run','--profile','overlay']),['--profile','overlay'])
        for argv in (['run'],['run','--profile=overlay'],['--profile','minimal','--profile','overlay'],['--profile']):
            with self.assertRaises(ValueError):K.profile_argv(argv)
    def test_proof_choice_and_manifest_binding(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'manifest';p.write_text('{}')
            proof=dict(profile='minimal',scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',manifest_sha256=K.pin(p)['sha256'],entry_argv=['--profile','minimal'])
            K.binding(proof,'minimal',p)
            for field,item in (('profile','overlay'),('entry_argv',['--profile','overlay']),('manifest_sha256','0'*64)):
                bad=dict(proof,**{field:item})
                with self.assertRaises(ValueError):K.binding(bad,'minimal',p)
    def test_both_generated_profiles(self):
        for selected in K.PROFILES:
            with self.subTest(profile=selected),tempfile.TemporaryDirectory() as d:
                out=prepared(Path(d),selected)
                for p in out.glob('*.py'):ast.parse(p.read_text(),filename=p.name)
                runtime=(out/'desktop574_runtime.py').read_text();guest=(out/'base_guest.py').read_text()
                frames=tuple(selected+'-'+view for view in A.VIEWS)
                self.assertEqual(runtime.count(repr(frames)),2);self.assertIn("phases == {"+repr(selected)+'}',runtime)
                self.assertIn('time.monotonic() + 1300',runtime);self.assertIn('TimeoutStartSec=1200',(out/'desktop574_fixture.sh').read_text())
                self.assertIn('management_root.serve',guest);self.assertIn('DL.service_lease()',guest)
                self.assertEqual(guest.count('for stage, config in '),1)
                selector=next(n for n in ast.walk(ast.parse(guest)) if isinstance(n,ast.For) and isinstance(n.target,ast.Tuple) and [getattr(x,'id',None) for x in n.target.elts]==['stage','config'])
                self.assertEqual(len(selector.iter.elts),1);self.assertEqual(ast.literal_eval(selector.iter.elts[0].elts[0]),selected)
                self.assertIn("if stage=="+repr(selected)+':',(out/'desktop574_guest.py').read_text())
                self.assertIn('DL.validate(finals[0]',(out/'contract.py').read_text());self.assertNotIn('DL.validate_profiles(profile_retirements)',(out/'contract.py').read_text())
                self.assertIn("'foreign or missing profile event'",(out/'contract.py').read_text())
                self.assertEqual((out/'doctor_lifetime.py').read_bytes(),(ROOT/adapter.ORIGINAL/'doctor_lifetime.py').read_bytes())
                subprocess.run(['/usr/bin/bash','-n',str(out/'desktop574_fixture.sh')],capture_output=True,check=True)
                proof=K.read(out/'runner-proof.json');self.assertEqual(proof['profile'],selected)
                for name,row in proof['files'].items():self.assertEqual(K.pin(out/name),row)
    def test_selected_management_contract_keeps_all17_and_retirement(self):
        # Reuse the original inert fixture factory, never collected artifact code.
        original_path=ROOT/adapter.ORIGINAL
        sys.path.insert(0,str(original_path))
        try:fixture=K.load('independent_original_event_fixture',original_path/'test_gui.py')
        finally:sys.path.remove(str(original_path))
        rows,lock=fixture.events()
        original=K.load('independent_original_management_contract',original_path/'management_contract.py')
        for selected in K.PROFILES:
            with tempfile.TemporaryDirectory() as d:
                code=adapter.materialize(ROOT,selected,Path(d)/'code')
                module=K.load('independent_selected_management',code/'management_contract.py')
                chosen=[r for r in rows if r.get('stage')==selected]
                value=module.verify_result(chosen,lock)
                self.assertEqual([r['stage'] for r in value['phases']],[selected])
                with self.assertRaises(ValueError):module.verify_result(rows,lock)
                with self.assertRaises(ValueError):original.verify_result(chosen,lock)
                missing=copy.deepcopy(chosen);missing.remove(next(r for r in missing if r['event']=='management_action'))
                with self.assertRaises(ValueError):module.verify_result(missing,lock)
                bad=copy.deepcopy(chosen);next(r for r in bad if r['event']=='management_result')['retirement_proof']['group_absent']=False
                with self.assertRaises(ValueError):module.verify_result(bad,lock)
    def test_profile_owner_is_once_only_and_never_renews_service(self):
        import types
        for selected in K.PROFILES:
            with tempfile.TemporaryDirectory() as d:
                code=adapter.materialize(ROOT,selected,Path(d)/'code');sys.path.insert(0,str(code))
                try:r=K.load('independent_selected_root',code/'management_root.py')
                finally:sys.path.remove(str(code))
                owners={};retired=set();owner={'profile_nonce':'a'*32}
                with patch.object(r.DL,'parent',return_value=owner) as parent:
                    self.assertEqual(r.issue_profile(owners,retired,selected,'a'*32),owner)
                    with self.assertRaises(ValueError):r.issue_profile(owners,retired,selected,'b'*32)
                    with self.assertRaises(ValueError):r.issue_profile({},set(),next(p for p in K.PROFILES if p!=selected),'b'*32)
                    self.assertEqual(parent.call_count,1)
    def test_isolated_generated_imports_for_both_entrypoints(self):
        probe="""import runpy,sys
from pathlib import Path
root=Path(sys.argv[1]);entry=sys.argv[2];before=list(sys.path)
ns=runpy.run_path(str(root/entry),run_name='profile_import_control')
base=ns['load']('isolated_base','base_guest.py')
assert Path(base.management_root.__file__)==root/'management_root.py'
assert base.management_root.INDEPENDENT_PROFILE==sys.argv[3]
assert base.DL.SECONDS==1080 and base.DL.SERVICE_SECONDS==1200
assert sys.path==before
"""
        for selected in K.PROFILES:
            with tempfile.TemporaryDirectory() as d:
                out=prepared(Path(d),selected)
                for entry in ('desktop574_guest.py','doctor_worker.py'):
                    subprocess.run([sys.executable,'-I','-B','-c',probe,str(out),entry,selected],cwd=d,check=True,capture_output=True)
                emitter=(out/'service_outcome.py').read_text()
                self.assertIn("('SERVICE_RESULT','EXIT_CODE','EXIT_STATUS')",emitter);self.assertIn('signal.alarm(2)',emitter)
                subprocess.run([sys.executable,'-I','-B','-c',"import runpy,sys;runpy.run_path(sys.argv[1],run_name='emitter_import_control')",str(out/'service_outcome.py')],cwd=d,check=True,capture_output=True)
    def test_workflow_preserves_resource_and_secret_bounds(self):
        path=K.HERE.parents[2]/'.github/workflows/native-arm-welcome-independent-profile.yml'
        # Canonical placement is source/.github; private placement is proposed/.github.
        if not path.exists():path=ROOT/'.github/workflows/native-arm-welcome-independent-profile.yml'
        text=path.read_text();original=(ROOT/'.github/workflows/native-arm-welcome-management.yml').read_text()
        import re
        self.assertEqual(set(re.findall(r'secrets\.([A-Z0-9_]+)',text)),set(re.findall(r'secrets\.([A-Z0-9_]+)',original)))
        for bound in ('timeout-minutes: 155','timeout-minutes: 85','4500s','330s','2300s'):
            self.assertIn(bound,text)
        self.assertIn('options: [minimal, overlay]',text)
        self.assertEqual(text.count('--profile "$PROFILE"'),4)
        self.assertIn('welcome-independent-${{ inputs.profile }}-${{ github.run_id }}-${{ github.run_attempt }}',text)
        self.assertLess(text.index('job.py" proof'),text.index('secrets.'))
    def test_sequential_contract_still_requires_both(self):
        original=(ROOT/adapter.ORIGINAL/'prepare.py').read_text()
        self.assertIn('DL.validate_profiles(profile_retirements)',original)
        self.assertIn("for stage in ('minimal','overlay'):",original)
        self.assertIn('len(frame_rows)==24',(ROOT/adapter.ORIGINAL/'job.py').read_text())


if __name__=='__main__':unittest.main()
