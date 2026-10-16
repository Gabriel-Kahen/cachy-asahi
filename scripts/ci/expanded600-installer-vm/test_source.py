# SPDX-License-Identifier: MIT
"""Inert checks only: no Docker, native build, GPG, ALPM, namespace or VM actors."""
import ast
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import sys
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import adapter
import ci
import gate
import materializer

LEGACY=Path(os.environ['EXPANDED600_LEGACY_ROOT'])
SEVEN=Path(os.environ['EXPANDED600_SEVEN_ROOT'])


class Selection(unittest.TestCase):
    def pending(self):
        actual=C.read
        value=copy.deepcopy(C.policy(bound=False))
        value.update(status='AWAITING_ROOT_PREREQUISITES_AND_EIGHT_PAIR_INPUT',eight_pair_source=None,eight_pair_index=None,
                     prerequisites=dict(observer587=None,native600=None))
        return patch.object(C,'read',side_effect=lambda path,*args,**kwargs:
                            copy.deepcopy(value) if Path(path)==C.HERE/'input-policy.json' else actual(path,*args,**kwargs))

    def test_exact_inventory_keeps_setup3_updater2_only_bang_changes(self):
        old,new=C.locks();self.assertEqual(len(new),600)
        self.assertEqual({n for n in old if old[n]!=new[n]},{C.BANG})
        self.assertEqual(new['cachy-asahi-setup'],'0.1.0-3')

    def test_missing_root_bindings_fail(self):
        with self.pending():
            self.assertEqual(C.policy(bound=False)['eight_pair_source'],None)
            with self.assertRaisesRegex(ValueError,'pending Root'):C.policy()

    def test_pending_ci_creates_no_output_or_actors(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'must-not-exist';argv=['ci.py']
            for name in ('implementation','legacy-source','preparation-source','product','updater','desktop','updater-v2-source',
                         'native','fdk','cache','setup4-pair','seven-pairs','eight-pairs','audio-inputs'):
                argv += ['--'+name,directory]
            argv += ['--output',str(output),'--implementation-revision','a'*40]
            with self.pending(),patch.object(sys,'argv',argv),patch.object(C,'load') as actors,self.assertRaisesRegex(ValueError,'pending Root'):
                ci.main()
            self.assertFalse(output.exists());actors.assert_not_called()

    def test_pending_gate_exposes_no_input_ref(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'github-output'
            argv=['gate.py','--implementation',directory,'--source','a'*40,'--workflow-sha','a'*40,'--preflight']
            with self.pending(),patch.object(sys,'argv',argv),patch.dict(os.environ,GITHUB_OUTPUT=str(output)),self.assertRaisesRegex(ValueError,'pending Root'):
                gate.main()
            self.assertFalse(output.exists())

    def test_all_old_source_bytes_are_pinned(self):self.assertEqual(len(C.legacy(LEGACY,git=False)),83)

    def test_new_setup5_checkout_cannot_replace_old_source(self):
        with patch.object(C,'revision',return_value='a'*40),self.assertRaisesRegex(ValueError,'old helper/setup3'):
            C.legacy(LEGACY)


class Prerequisites(unittest.TestCase):
    def receipts(self,root):
        observer=dict(status='ROOT_ACCEPTED_FULL587_INSTALLER_SOFTWARE',ordinary_parent_retired='PASS',
            independent_root_readback='PASS',cleanup='PASS',hardware='NOT_RUN',source_sha='a'*40,run_id='1001')
        native=dict(status='ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION',package_count=600,expected600_sha256=C.AFTER,
            bang_version='0.1.0-2',bang_pair_bytes_buildinfo='PASS',installed_lifecycle='PASS',installed_six_modules='PASS',
            cleanup='PASS',hardware='NOT_RUN',source_sha='b'*40,run_id='1002')
        policy=C.policy(bound=False)
        for name,value in (('observer587',observer),('native600',native)):
            path=root/(name+'.json');path.write_bytes(C.encoded(value))
            policy['prerequisites'][name]=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
        return policy,observer,native

    def test_two_complete_decisions_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);policy,_,_=self.receipts(root)
            self.assertEqual(set(C.prerequisites(root,policy)),{'observer587','native600'})

    def test_root_readback_and_installed_coexistence_not_optional(self):
        for name,field in (('observer587','independent_root_readback'),('native600','installed_six_modules')):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);policy,observer,native=self.receipts(root)
                value=observer if name=='observer587' else native;value[field]='FAIL'
                path=root/(name+'.json');path.write_bytes(C.encoded(value))
                policy['prerequisites'][name]=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
                with self.subTest(field=field),self.assertRaises(ValueError):C.prerequisites(root,policy)


class Adapter(unittest.TestCase):
    def raw(self,name):return (LEGACY/'scripts/ci/full-composition-installer-vm'/name).read_bytes()

    def module(self,name):
        raw,_=adapter.transform(self.raw(name),name);module=SimpleNamespace()
        namespace=dict(__name__='_inert_600_'+name.replace('.','_'),__file__=str(LEGACY/name))
        exec(compile(raw,'<inert-'+name+'>','exec'),namespace);module.__dict__.update(namespace);return module

    def test_all_six_compile_with_closed_typed_literal_edits(self):
        counts={}
        for name in adapter.NAMES:
            output,receipt=adapter.transform(self.raw(name),name);counts[name]=receipt['edits']
            self.assertTrue(output);compile(output,name,'exec')
        self.assertEqual(counts,dict(zip(adapter.NAMES,(11,16,1,1,9,2))))

    def test_hash_drift_or_second_adaptation_refused(self):
        raw=self.raw('numeric_vm.py')
        for value in (raw.replace(b'started+600',b'started+601'),adapter.transform(raw,'numeric_vm.py')[0]):
            with self.assertRaisesRegex(ValueError,'source bytes differ'):adapter.transform(value,'numeric_vm.py')

    def test_numeric_groups_and_helper_and_deadlines_unchanged(self):
        before=self.raw('profile.py');after,_=adapter.transform(before,'profile.py')
        def literals(raw):
            return {target.id:ast.dump(node.value,include_attributes=False) for node in ast.parse(raw).body if isinstance(node,ast.Assign)
                    for target in node.targets if isinstance(target,ast.Name) and target.id in ('NUMERIC_VM','GROUP_METADATA','SONAME_OUTPUTS')}
        self.assertEqual(literals(before),literals(after))
        self.assertIn(b'0o4110',after)
        numeric,_=adapter.transform(self.raw('numeric_vm.py'),'numeric_vm.py')
        self.assertIn(b'deadline=started+600',numeric)
        installer,_=adapter.transform(self.raw('installer.py'),'installer.py')
        self.assertIn(b'seconds=4500',installer)
        for name,raw in (('installer.py',installer),('numeric_vm.py',numeric)):
            calls=[n for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                   and isinstance(n.func.value,ast.Name) and n.func.value.id=='roots' and n.func.attr=='Limits']
            self.assertEqual(len(calls),2 if name=='installer.py' else 1)
            self.assertTrue(all(any(k.arg=='max_packages' and k.value.value==600 for k in n.keywords) for n in calls))

    def test_owner_label_creation_and_cleanup_share_distinct_scope(self):
        module=self.module('run.py');argv=module.container_args(dict(nonce='a'*32),'vm','sha256:'+'b'*64,[],Path('/tmp/out'),'owned')
        self.assertIn('cachy-asahi.expanded600-installer='+'a'*32,argv)
        self.assertIn('--cap-drop=ALL',argv);self.assertIn('--read-only',argv)
        self.assertIn('--user=23001:23001',argv);self.assertNotIn('--privileged',argv)

    def receipt(self):
        module=self.module('run.py');common=SimpleNamespace(KERNEL='7.2.10-1-aarch64-ARCH')
        result=dict(event='result',status='PASS_EXPANDED600_INSTALLER',phase='complete',package_count=600,
            expected_lock_sha256=C.AFTER,hooks='DISABLED',scriptlets='DISABLED',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED')
        result.update({name:True for name in module.PASS_FLAGS})
        return module,common,[dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel=common.KERNEL,uid=0),
            result,dict(event='exit',status='PASS_EXPANDED600_INSTALLER',cleanup='PASS')]

    def test_completion_still_requires_all_parent_and_root_readback_gates(self):
        module,common,events=self.receipt();module.validate_completion(events,'a'*32,common)
        for field in module.PASS_FLAGS:
            bad=copy.deepcopy(events);bad[1][field]=False
            with self.subTest(field=field),self.assertRaises(ValueError):module.validate_completion(bad,'a'*32,common)

    def test_587_or_wrong_lock_or_old_status_cannot_pass600(self):
        module,common,events=self.receipt()
        for field,value in [('package_count',587),('expected_lock_sha256',C.BEFORE),('status','PASS_FULL_COMPOSITION_INSTALLER')]:
            bad=copy.deepcopy(events);bad[1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):module.validate_completion(bad,'a'*32,common)

    def test_retirement_precedes_independent_root_readback(self):
        raw=adapter.transform(self.raw('guest.py'),'guest.py')[0].decode()
        self.assertLess(raw.index("receipt=worker.supervise("),raw.index('result=numeric.verify_export('))
        self.assertLess(raw.index("receipt['group_retired']"),raw.index('result=numeric.verify_export('))


class Inputs(unittest.TestCase):
    def test_missing_eighth_pair_not_skipped(self):
        value=C.read(SEVEN/'index.json');value['status']='READY_EIGHT_RETAINED_FOR_SIGNED_EXPANDED600_INSTALLER'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'index.json';path.write_bytes(C.encoded(value));policy=C.policy(bound=False)
            policy['eight_pair_index']=dict(path='index.json',bytes=path.stat().st_size,sha256=C.sha(path))
            with self.assertRaisesRegex(ValueError,'eight-pair index'):materializer.accepted_pairs(root,SEVEN,LEGACY,policy)

    def test_changed_original_seven_cannot_hide_behind_new_index(self):
        value=C.read(SEVEN/'index.json');value['status']='READY_EIGHT_RETAINED_FOR_SIGNED_EXPANDED600_INSTALLER'
        value['packages'][C.BANG]={};value['packages']['cachy-asahi-doctor']['version']='99-1'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'index.json';path.write_bytes(C.encoded(value));policy=C.policy(bound=False)
            policy['eight_pair_index']=dict(path='index.json',bytes=path.stat().st_size,sha256=C.sha(path))
            with self.assertRaisesRegex(ValueError,'seven retained input rows'):materializer.accepted_pairs(root,SEVEN,LEGACY,policy)

    def test_signing_refuses_another_secret_role_before_sign(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);home.chmod(0o700)
            with (patch.object(materializer.subprocess,'check_output',return_value=''),
                  patch.object(materializer.subprocess,'run') as sign,
                  self.assertRaisesRegex(ValueError,'secret-key role')):
                materializer.sign(home,[], 'A'*40)
            sign.assert_not_called()


class Workflow(unittest.TestCase):
    def text(self):return (C.HERE.parents[2]/'.github/workflows/native-arm-expanded600-installer-vm.yml').read_text()

    def test_both_pending_and_deep_gates_precede_secrets(self):
        text=self.text();secret=text.index('${{ secrets.')
        self.assertLess(text.index('      - name: Require Root accepted prerequisites'),secret)
        self.assertLess(text.index('      - name: Verify actual Root decisions'),secret)
        self.assertIn('ref: '+C.LEGACY,text)
        self.assertIn('--legacy-source "$GITHUB_WORKSPACE/expanded600-legacy"',text)
        self.assertIn('  workflow_dispatch:',text);self.assertNotIn('  push:',text)

    def test_audio_retriever_fixed_output_contract_and_required_outcome(self):
        tree=ast.parse((LEGACY/'scripts/ci/full-development-composition/retrieve_audio.py').read_bytes())
        expected=[node.comparators[0].value for node in ast.walk(tree) if isinstance(node,ast.Compare)
            and isinstance(node.left,ast.Attribute) and isinstance(node.left.value,ast.Name)
            and node.left.value.id=='output' and node.left.attr=='name' and len(node.ops)==1
            and isinstance(node.ops[0],ast.Eq) and isinstance(node.comparators[0],ast.Constant)]
        self.assertEqual(expected,['audio-archives']);text=self.text()
        self.assertIn('--output "$RUNNER_TEMP/'+expected[0]+'"',text)
        self.assertIn('--audio-inputs "$RUNNER_TEMP/'+expected[0]+'"',text)
        self.assertIn('        id: audio_inputs',text)
        self.assertIn('AUDIO_INPUTS_OUTCOME: ${{ steps.audio_inputs.outcome }}',text)
        step=text[text.index('      - name: Required fresh signed600 installation'):]
        self.assertLess(step.index('test "$AUDIO_INPUTS_OUTCOME" = success'),step.index('timeout --signal=TERM'))

    def test_literal_shell_blocks_are_syntax_checked(self):
        import subprocess
        lines=self.text().splitlines();blocks=[];index=0
        while index<len(lines):
            if lines[index]=='        run: |':
                index+=1;block=[]
                while index<len(lines) and (lines[index].startswith('          ') or not lines[index]):
                    block.append(lines[index][10:]);index+=1
                blocks.append('\n'.join(block)+'\n')
            else:index+=1
        self.assertGreaterEqual(len(blocks),10)
        for block in blocks:subprocess.run(['bash','-n'],input=block,text=True,capture_output=True,check=True)


class Ownership(unittest.TestCase):
    def test_unknown_vm_state_retains_inputs(self):
        with tempfile.TemporaryDirectory() as directory:self.assertFalse(ci.vm_retired(Path(directory)))

    def test_matching_preactor_state_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'actor-state.json').write_bytes(C.encoded(dict(state='PRE_ACTORS',purpose='expanded600-installer-vm')))
            self.assertTrue(ci.vm_retired(root))
            (root/'actor-state.json').write_bytes(C.encoded(dict(state='STARTED',purpose='expanded600-installer-vm')))
            self.assertFalse(ci.vm_retired(root))

    def test_partial_owned_cache_cleanup_without_fabricated_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);owner=dict(purpose='expanded600-installer-vm',output=str(output))
            (output/'owner.json').write_bytes(C.encoded(owner));ready=output/'ready600';ready.mkdir();(ready/'packages').mkdir()
            (ready/'packages/archive').write_bytes(b'fixture');(ready/'packages').chmod(0o555)
            ci.cleanup_ready(ready,owner);self.assertFalse(ready.exists())

    def test_foreign_cleanup_path_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);owner=dict(purpose='expanded600-installer-vm',output=str(output))
            (output/'owner.json').write_bytes(C.encoded(owner));foreign=output/'foreign';foreign.mkdir()
            with self.assertRaises(ValueError):ci.cleanup_ready(foreign,owner)
            self.assertTrue(foreign.exists())


if __name__=='__main__':unittest.main()
