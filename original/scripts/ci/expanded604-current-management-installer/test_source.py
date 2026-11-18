# SPDX-License-Identifier: MIT
"""Finite inert authority, custody and workflow controls; no native actors."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import contract as C
import ci
import gate

ROOT=Path(os.environ['EXPANDED604_SOURCE'])


class Authority(unittest.TestCase):
    def pending(self):
        actual=C.read;value=copy.deepcopy(C.policy(bound=False));value['status']='UNBOUND_NATIVE604_ACCEPTANCE'
        value['native604']={key:None for key in value['native604']}
        return patch.object(C,'read',side_effect=lambda path,*a,**k:
             value if Path(path)==C.HERE/'input-policy.json' else actual(path,*a,**k))

    def argv(self,root):
        values=[]
        for name in ('implementation',*ci.PRODUCER_PATHS,*C.CARRIERS,*C.DECISIONS,'audio_inputs','output'):
            values+=['--'+name.replace('_','-'),str(root/name)]
        return values+['--implementation-revision','a'*40]

    def test_pending_policy_stops_ci_before_any_observation_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.pending(),patch.object(C,'revision') as revision,patch.object(C,'load') as actor,\
                 self.assertRaisesRegex(ValueError,'UNBOUND'):
                ci.main(self.argv(root))
            revision.assert_not_called();actor.assert_not_called();self.assertEqual(list(root.iterdir()),[])

    def test_pending_preflight_exposes_no_carrier_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'github-output'
            with self.pending(),patch.dict(os.environ,GITHUB_OUTPUT=str(output)),patch.object(C,'revision') as observed,\
                 self.assertRaisesRegex(ValueError,'UNBOUND'):
                gate.main(['--implementation',str(root),'--source','a'*40,'--workflow-sha','a'*40,'--preflight'])
            observed.assert_not_called();self.assertFalse(output.exists())

    def test_pending_freeze_cannot_write_manifest_or_run_git(self):
        before=(C.HERE/'source-manifest.json').read_bytes()
        with self.pending(),patch.object(subprocess,'run') as command,self.assertRaisesRegex(ValueError,'UNBOUND'):C.freeze(ROOT)
        command.assert_not_called();self.assertEqual((C.HERE/'source-manifest.json').read_bytes(),before)

    def fixture(self,root):
        # Explicitly synthetic protocol decision, exercised without policy/main authorization.
        fresh=root/'fresh';native=root/'native';fresh.mkdir();native.mkdir()
        value=C.policy(bound=False)
        binding=value['fresh600']['decision']
        held=Path(os.environ['EXPANDED604_FRESH600_DECISION'])
        target=fresh/binding['path'];target.parent.mkdir();shutil.copyfile(held,target)
        bound=value['native604'];bound.update(source_sha='a'*40,run_id='1234',carrier_source='b'*40,
             source_manifest_sha256=C.sha(C.HERE.parent/'expanded604-current-management/source-manifest.json'),
             input_policy_sha256=C.sha(C.HERE.parent/'expanded604-current-management/input-policy.json'))
        receipt=dict(status='ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION',package_count=604,
             expected604_sha256=C.TARGET_SHA,installed_lifecycle='PASS',installed_six_modules='PASS',cleanup='PASS',
             hardware='NOT_RUN',release='NOT_ADMITTED',**{k:bound[k] for k in
             ('source_sha','run_id','source_manifest_sha256','input_policy_sha256')})
        path=native/'native604.json';path.write_bytes(C.encoded(receipt))
        bound['decision']=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
        return fresh,native,value,receipt

    def test_exact_decisions_join_both_actual600_and_synthetic604_protocol(self):
        with tempfile.TemporaryDirectory() as directory:
            fresh,native,value,_=self.fixture(Path(directory))
            with patch.object(C,'revision',side_effect=lambda root:value['fresh600' if root==fresh else 'native604']['carrier_source']):
                joined=C.decisions(fresh,native,value)
            self.assertEqual(joined['fresh600']['run_id'],'38965999704');self.assertEqual(joined['native604']['package_count'],604)

    def test_failed_lifecycle_and_changed_input_closure_cannot_authorize(self):
        for mutation in ('installed_lifecycle','input_policy_sha256'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                fresh,native,value,receipt=self.fixture(Path(directory))
                receipt[mutation]='FAIL' if mutation=='installed_lifecycle' else 'c'*64
                if mutation=='input_policy_sha256':value['native604'][mutation]=receipt[mutation]
                path=native/'native604.json';path.write_bytes(C.encoded(receipt))
                value['native604']['decision']=dict(path=path.name,bytes=path.stat().st_size,sha256=C.sha(path))
                with patch.object(C,'revision',side_effect=lambda root:value['fresh600' if root==fresh else 'native604']['carrier_source']),\
                     self.assertRaises(ValueError):C.decisions(fresh,native,value)

    def test_native_policy_cannot_bind_with_only_a_run_number(self):
        value=C.policy(bound=False);value['status']='ROOT_BOUND_CURRENT604_NATIVE_ACCEPTANCE'
        value['native604']={key:None for key in value['native604']};value['native604']['run_id']='1234'
        actual=C.read
        with patch.object(C,'read',side_effect=lambda path,*a,**k:value if Path(path)==C.HERE/'input-policy.json' else actual(path,*a,**k)),\
             self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()


class Custody(unittest.TestCase):
    def test_coordinator_wires_complete604_cache_to_held_vm_and_orders_cleanup(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root=Path(directory);output=root.with_name(root.name+'-result')
            producer=output.with_name(output.name+'-producer');vm=output.with_name(output.name+'-vm')
            for path in (output,producer,vm):self.addCleanup(shutil.rmtree,path,ignore_errors=True)
            events=[];args=Authority().argv(root)
            args[args.index('--output')+1]=str(output)
            def prepare(value):
                self.assertEqual(value.code,root/'legacy_source');self.assertEqual(value.code_revision,C.LEGACY)
                producer.mkdir();(producer/'producer-owner.json').write_bytes(b'{}')
                ready=producer/'ready';ready.mkdir();events.append('producer');return ready
            def materialize(ready,owned,eight,seven,audio,legacy,target,policy,management,setup,welcome,source):
                self.assertEqual((owned,eight,seven,audio,legacy,management,setup,welcome,source),
                     (producer,root/'eight_source',root/'seven_source',root/'audio_inputs',root/'legacy_source',
                      root/'management_source',root/'setup_source',root/'welcome_source',root/'implementation'))
                self.assertEqual(target,output/'ready604');target.mkdir();(target/'manifest.json').write_bytes(b'{}');events.append('complete604')
            def host(value):
                self.assertEqual(value.ready,output/'ready604');self.assertEqual(value.code,root/'legacy_source')
                self.assertIsNone(value.code_files);vm.mkdir()
                (vm/'result.json').write_bytes(C.encoded(dict(status='PASS',container_cleanup='PASS',image_cleanup='PASS',private_cleanup='PASS')))
                events.append('vm-retired')
            def cleanup(owned):
                self.assertEqual(owned,producer);self.assertFalse((output/'ready604').exists());events.append('producer-cleanup')
                return dict(status='PASS')
            modules={'_fresh604_producer':SimpleNamespace(prepare=prepare,cleanup=cleanup),
                 '_fresh604_original_ci':SimpleNamespace(selected_tooling_inputs=lambda *a:[]),
                 '_fresh604_vm':SimpleNamespace(host=host),'_fresh604_prepare':SimpleNamespace(),
                 '_fresh604_tooling':SimpleNamespace(validate_lock=lambda *a:None)}
            original_read=C.read
            def read(path,*a,**k):
                return {} if Path(path)==root/'legacy_source/scripts/virtual/tooling.lock.json' else original_read(path,*a,**k)
            with patch.object(C,'policy',return_value={}),patch.object(C,'revision',return_value='a'*40),\
                 patch.object(C,'verify_source'),patch.object(C,'legacy'),patch.object(C,'read',side_effect=read),\
                 patch.object(C,'inputs',return_value=({},dict(summary={}),{})),\
                 patch.object(C,'load',side_effect=lambda name,path:modules[name]),\
                 patch.object(C,'scoped_load',return_value=SimpleNamespace(prepare=materialize)),\
                 patch.object(ci.adapter,'materialize',side_effect=lambda legacy,target:target.mkdir()),\
                 patch.object(ci.platform,'machine',return_value='aarch64'):
                self.assertEqual(ci.main(args),0)
            self.assertEqual(events,['producer','complete604','vm-retired','producer-cleanup'])
            self.assertEqual(C.read(output/'result.json')['caller_private_cleanup'],'PASS')

    def test_partial_owned604_cache_cleanup_and_foreign_path_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);owner=dict(purpose=ci.PURPOSE,output=str(output))
            (output/'owner.json').write_bytes(C.encoded(owner));ready=output/'ready604';ready.mkdir();(ready/'packages').mkdir()
            (ready/'packages/archive').write_bytes(b'inert');(ready/'packages').chmod(0o555)
            foreign=output/'foreign';foreign.mkdir()
            with self.assertRaises(ValueError):ci.cleanup_ready(foreign,owner)
            self.assertTrue(foreign.exists());ci.cleanup_ready(ready,owner);self.assertFalse(ready.exists())

    def test_uncertain_vm_retains_inputs_and_only_exact_preactor_is_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.assertFalse(ci.vm_retired(root))
            (root/'actor-state.json').write_bytes(C.encoded(dict(state='PRE_ACTORS',purpose='expanded600-installer-vm')))
            self.assertFalse(ci.vm_retired(root))
            (root/'actor-state.json').write_bytes(C.encoded(dict(state='PRE_ACTORS',purpose=ci.PURPOSE)))
            self.assertTrue(ci.vm_retired(root))


class Workflow(unittest.TestCase):
    def text(self):return (ROOT/'.github/workflows/native-arm-expanded604-current-management-installer.yml').read_text()
    def test_manual_early_and_complete_input_gates_precede_private_secrets(self):
        text=self.text();secret=text.index('${{ secrets.')
        for marker in ('Require Root native604 acceptance','Verify actual Root decisions','Run unchanged installer controls'):
            self.assertLess(text.index(marker),secret)
        self.assertIn('  workflow_dispatch:',text);self.assertNotIn('  push:',text)
        for name in C.DECISIONS:self.assertIn('steps.installer_policy.outputs.'+name,text)
        for marker,path in (('@OWNER_SHA256@',C.HERE/'ci.py'),('@MANIFEST_SHA256@',C.HERE/'source-manifest.json')):
            self.assertTrue(marker in text or C.sha(path) in text)
        self.assertLess(text.index('id: audio_inputs'),text.index('Verify actual Root decisions'))
        self.assertIn('test "$AUDIO_INPUTS_OUTCOME" = success',text)
        self.assertIn('--kill-after=60s 15600s',text);self.assertIn('timeout-minutes: 350',text)

    def test_nested_carriers_use_payload_in_preflight_and_native_call(self):
        text=self.text()
        for role in ('management','welcome'):
            base='--'+role+'-source "$GITHUB_WORKSPACE/expanded604-'+role+'-source'
            self.assertEqual(text.count(base+'/payload"'),2)
            self.assertNotIn(base+'"',text)
        for role in ('legacy','seven','eight'):
            self.assertEqual(text.count('--'+role+'-source "$GITHUB_WORKSPACE/expanded604-'+role+'"'),2)
        self.assertEqual(text.count('--setup-source "$GITHUB_WORKSPACE/expanded604-setup-source"'),2)

    def test_all_literal_shell_blocks_are_syntax_checked(self):
        lines=self.text().splitlines();blocks=[];i=0
        while i<len(lines):
            if lines[i]=='        run: |':
                i+=1;block=[]
                while i<len(lines) and (lines[i].startswith('          ') or not lines[i]):
                    block.append(lines[i][10:]);i+=1
                blocks.append('\n'.join(block)+'\n')
            else:i+=1
        self.assertGreaterEqual(len(blocks),10)
        for block in blocks:subprocess.run(['bash','-n'],input=block,text=True,capture_output=True,check=True)


if __name__=='__main__':unittest.main()
