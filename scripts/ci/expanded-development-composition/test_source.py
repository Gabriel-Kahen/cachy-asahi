# SPDX-License-Identifier: MIT
"""Inert input, transaction, receipt and owned-resource refusal controls."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import inputs
import bang
from owned import Containers

ROOT=Path(os.environ.get('EXPANDED_CODE_ROOT',Path.cwd())).absolute()
BUNDLE=Path(os.environ.get('EXPANDED_INPUT_PAYLOAD',ROOT/'artifacts/development/expanded-candidate-inputs-20261016/payload')).absolute()


class Inputs(unittest.TestCase):
    def setUp(self):self.index=C.read(BUNDLE/'index.json');self.policy=C.policy()

    def test_immutable_actual_seven(self):
        self.assertEqual(set(C.accepted_index(BUNDLE,self.index)),C.SCRIPTS)
        self.assertEqual(C.sha(C.checked(BUNDLE,self.policy['script_index'])),self.policy['script_index']['sha256'])

    def test_actual_retained_archives_buildinfo_payload(self):
        self.assertEqual(set(inputs.retained(BUNDLE,self.index,ROOT)),C.SCRIPTS)

    def test_retained_rows_keep_names_for_installation_plan(self):
        for name,row in inputs.retained(BUNDLE,self.index,ROOT).items():
            self.assertEqual(row['name'],name)
            self.assertEqual(row['inspected']['metadata']['.PKGINFO']['pkgname'],[name])

    def test_audio_output_matches_held_retriever_before_native_work(self):
        helper=C.load('expanded_audio_path_control',ROOT/'scripts/ci/full-development-composition/retrieve_audio.py')
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,RUNNER_TEMP=directory,GH_TOKEN=''):
            temporary=Path(directory)
            with self.assertRaisesRegex(helper.Refused,'new-private-audio-archives-required'):
                helper.retrieve(temporary/'expanded-audio')
            with self.assertRaisesRegex(helper.Refused,'workflow-actions-read-token-required'):
                helper.retrieve(temporary/'audio-archives')
            self.assertFalse(any(temporary.iterdir()))
        workflow=(ROOT/'.github/workflows/native-arm-expanded-development-composition.yml').read_text()
        self.assertIn('--output "$RUNNER_TEMP/audio-archives"',workflow)
        self.assertIn('--audio-inputs "$RUNNER_TEMP/audio-archives"',workflow)
        self.assertNotIn('$RUNNER_TEMP/expanded-audio',workflow)
        composition=workflow.split('- name: Required native pair and exact600 installed lifecycle',1)[1]
        self.assertLess(composition.index('test "$AUDIO_INPUT_OUTCOME" = success'),composition.index('python3 -B'))

    def test_entry_points_use_input_checkout_root(self):
        import argparse
        import shutil
        import gate
        import run as runner
        with tempfile.TemporaryDirectory() as directory:
            checkout=Path(directory);shutil.copyfile(BUNDLE/'index.json',checkout/'index.json')
            self.assertFalse((checkout/'artifacts').exists())
            args=argparse.Namespace(code=ROOT,code_revision=self.policy['bang_source'],script_source=checkout,
                bang_source=ROOT,combined_source=ROOT)
            def revision(path):
                return self.policy['script_source'] if Path(path)==checkout else self.policy['bang_source']
            # Isolate checkout layout: index bytes are checked normally. Archive acceptance
            # has its own real fourteen-archive test; proposed code is not integrated yet.
            with patch.object(C,'verify_self'),patch.object(inputs,'retained',return_value=self.index['packages']) as inspect:
                with patch.object(runner,'revision',side_effect=revision):
                    _,bundle,rows=runner.check(args)
                self.assertEqual(bundle,checkout);self.assertEqual(set(rows),C.SCRIPTS)
                self.assertEqual(inspect.call_args.args[0],checkout)
                argv=['gate.py','--code',str(ROOT),'--script-source',str(checkout),'--module-source',str(ROOT),
                    '--source',self.policy['bang_source'],'--workflow-sha',self.policy['bang_source']]
                with patch.object(sys,'argv',argv),patch.object(gate.subprocess,'check_output',
                    side_effect=lambda command,**kwargs:revision(command[2])+'\n'):
                    self.assertEqual(gate.main(),0)
                self.assertEqual(inspect.call_args.args[0],checkout)

    def test_seven_namespace_refusals(self):
        for mutation in ('missing','extra','bang'):
            value=copy.deepcopy(self.index)
            if mutation=='missing':value['packages'].pop(next(iter(value['packages'])))
            elif mutation=='extra':value['packages']['surprise']=next(iter(value['packages'].values()))
            else:value['packages'][C.UPGRADE]=value['packages'].pop(next(iter(value['packages'])))
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.accepted_index(BUNDLE,value)

    def test_pair_and_source_and_lifecycle_byte_refusals(self):
        for field in ('files','sources','raw_lifecycle','acceptance','evidence'):
            value=copy.deepcopy(self.index);row=next(iter(value['packages'].values()))
            ref=row[field]['b'] if field=='files' else next(iter(row[field].values())) if field=='sources' else row[field]
            ref['sha256']='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):C.accepted_index(BUNDLE,value)

    def test_failed_lifecycle_not_repaired_by_export_qualification(self):
        original=C.read
        for name,row in sorted(self.index['packages'].items()):
            with self.subTest(name=name):
                target=C.checked(BUNDLE,row['raw_lifecycle']);mutated=[]
                self.assertEqual(original(target)['status'],C.LIFE[name])
                def altered(path,cap=4*1024**2):
                    result=original(path,cap)
                    if Path(path)==target:
                        result['status']='FAIL';mutated.append(Path(path))
                    return result
                with patch.object(C,'read',side_effect=altered),self.assertRaisesRegex(
                        ValueError,'failed/incomplete raw lifecycle cannot be accepted'):
                    C.accepted_index(BUNDLE,copy.deepcopy(self.index))
                self.assertEqual(mutated,[target])

    def test_payload_source_license_refusal(self):
        value=copy.deepcopy(self.index);row=value['packages']['cachy-asahi-doctor']
        row['payload']['usr/share/licenses/cachy-asahi-doctor/LICENSE']['sha256']='0'*64
        with self.assertRaises(ValueError):C.accepted_index(BUNDLE,value)

    def test_archive_metadata_not_granted_by_index(self):
        value=copy.deepcopy(self.index);value['packages']['cachy-asahi-doctor']['metadata']['depends']=['surprise']
        with self.assertRaises(ValueError):inputs.retained(BUNDLE,value,ROOT)

    def test_actual_bang2_source_and_combined_closure(self):
        checks,_=inputs.tools(ROOT)
        self.assertEqual(bang.recipe(ROOT,self.policy,checks)['input_sha256'],self.policy['bang_inputs'])
        self.assertEqual(len(inputs.combined(ROOT,self.policy)['files']),86)

    def test_exact587_to600_only(self):
        before=C.lock((ROOT/'scripts/ci/full-development-composition/expected-updater-v2.lock').read_bytes(),587)
        audios={r['name']:r['version'] for r in C.read(ROOT/'scripts/ci/full-development-composition/audio-inputs.json')}
        scripts={n:r['version'] for n,r in self.index['packages'].items()}|{C.UPGRADE:C.NEW}
        self.assertEqual(len(C.selected(before,audios,scripts)),600)
        for mutation in ('setup','updater','bang','missing','extra'):
            old=before.copy();adds=scripts.copy()
            if mutation in ('setup','updater'):old['cachy-asahi-'+('setup' if mutation=='setup' else 'update')]='0-0'
            elif mutation=='bang':adds[C.UPGRADE]=C.OLD
            elif mutation=='missing':adds.pop('cachy-asahi-fish-done')
            else:adds['surprise']='1-1'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):C.selected(old,audios,adds)

    def test_pending_policy_stops_before_actors(self):
        pending=copy.deepcopy(self.policy);pending['status']='AWAITING_INPUTS'
        with patch.object(C,'read',return_value=pending),self.assertRaises(ValueError):C.policy()

    def test_safe_refs_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'file';path.write_bytes(b'{}')
            ref=dict(path='file',bytes=2,sha256=C.sha(path));self.assertEqual(C.checked(root,ref),path)
            for name in ('../file','/file','x/../file','./file'):
                with self.subTest(path=name),self.assertRaises(ValueError):C.checked(root,dict(ref,path=name))
            (root/'alias').symlink_to(path)
            with self.assertRaises(ValueError):C.checked(root,dict(ref,path='alias'))
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):C.read(path)


class Adapters(unittest.TestCase):
    def test_ld_checkpoint_adapter_preserves_pin_and_bounded_read_command(self):
        import lifecycle
        adapter=lifecycle.ld_adapter()
        with tempfile.TemporaryDirectory() as directory:
            helper=Path(directory)/'helper';helper.write_bytes(b'original')
            adapter.pin(helper,C.sha(helper),8)
            with self.assertRaises(ValueError):adapter.pin(helper,'0'*64,8)
        argv=[sys.executable,'-I','-B','-c','import sys; print(" ".join(sys.argv[1:]))','-p','-C','/private/cache']
        self.assertEqual(adapter.run(argv),'-p -C /private/cache\n')
        with self.assertRaisesRegex(ValueError,'command failed'):
            adapter.run([sys.executable,'-I','-B','-c','raise SystemExit(3)'])

    def test_accepted_bang_helper_one_exact_path_anchor(self):
        import inspect
        helper=C.load('control_accepted_builder',ROOT/'scripts/ci/welcome-native/run.py')
        self.assertEqual(inspect.getsource(helper.build).count("source/'packages/tools'/name"),1)

    def test_runtime_reads_installed_bytes_instead_of_source_snapshot(self):
        import installed_shells as adapter
        driver=C.load('control_coexistence_driver',ROOT/'scripts/ci/shell-modules-coexistence/run.py')
        with tempfile.TemporaryDirectory() as directory:
            temporary=Path(directory)
            # Keep the ordinary runtime filename, including separate shell extensions.
            mapping={k:str(temporary/k/Path(v).name) for k,v in {**driver.FISH,**driver.ZSH}.items()}
            for key,relative in {**driver.FISH,**driver.ZSH}.items():
                source=ROOT/Path(relative).parent;target=Path(mapping[key]).parent
                for path in source.iterdir():
                    if path.name.endswith(('.fish','.zsh')) or path.name in ('.version','.revision-hash'):
                        dest=target/path.name
                        if key=='highlight' and path.name.endswith('-highlighter.zsh'):
                            dest=target/'highlighters'/path.name.removesuffix('-highlighter.zsh')/path.name
                        dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(path.read_bytes())
            with patch.object(adapter,'RUNTIME',mapping):
                adapter.installed_join(ROOT,driver)
                Path(mapping['bang']).write_text('# wrong installed wrapper\n')
                with self.assertRaises(ValueError):adapter.installed_join(ROOT,driver)


class PacmanPlan(unittest.TestCase):
    def install(self,command):
        # Exercise the actual nested install body without entering the root
        # lifecycle or invoking pacman, trust setup, hooks or filesystem actors.
        path=Path(__file__).with_name('lifecycle.py');tree=ast.parse(path.read_bytes())
        functions=[n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='install']
        self.assertEqual(len(functions),1)
        rows=[dict(name='addon-one',version='1-1'),dict(name=C.UPGRADE,version=C.NEW)]
        pacman=['pacman','--config','/private/pacman.conf'];archives=['/addons/one.pkg.tar.xz','/addons/bang2.pkg.tar.xz']
        namespace=dict(run=command,C=C,pacman=pacman,addon_paths=archives,rows=rows)
        exec(compile(ast.Module(body=functions,type_ignores=[]),str(path),'exec'),namespace)
        return namespace['install'],pacman,archives

    def test_print_query_never_carries_mutation_only_scriptlet_flag(self):
        calls=[]
        def command(argv):
            calls.append(argv)
            if '--print' in argv:
                if '--noscriptlet' in argv:raise ValueError("invalid option: '--print' and '--noscriptlet' may not be used together")
                return 'addon-one 1-1\n'+C.UPGRADE+' '+C.NEW+'\n'
            self.assertIn('--noscriptlet',argv);return ''
        install,pacman,archives=self.install(command);install()
        self.assertEqual(calls,[pacman+['--noconfirm','-U','--print','--print-format','%n %v',*archives],
                                pacman+['--noconfirm','--noscriptlet','-U',*archives]])

    def test_query_plan_version_mismatch_stops_before_mutation(self):
        from unittest.mock import Mock
        command=Mock(return_value='addon-one 1-1\n'+C.UPGRADE+' '+C.OLD+'\n')
        install,_,_=self.install(command)
        with self.assertRaisesRegex(ValueError,'dependency/conflict preflight differs'):install()
        self.assertEqual(command.call_count,1);self.assertIn('--print',command.call_args.args[0])

    def test_query_error_stops_before_mutation(self):
        from unittest.mock import Mock
        command=Mock(side_effect=ValueError('query failed'));install,_,_=self.install(command)
        with self.assertRaisesRegex(ValueError,'query failed'):install()
        self.assertEqual(command.call_count,1);self.assertIn('--print',command.call_args.args[0])


class Receipts(unittest.TestCase):
    def good(self):
        events=[]
        for phase,count,version in (('baseline587',587,C.OLD),('install600',600,C.NEW),('same-version600',600,C.NEW),
            ('remove-to587',587,C.OLD),('restore600',600,C.NEW),('final587',587,C.OLD)):
            events.append(dict(phase=phase,count=count,bang_bang=version,status='PASS',**{k:True for k in
                ('signatures','dependencies','payload','ownership','originals_preserved','user_config_preserved')}))
        return dict(status='PASS_EXPANDED600_METADATA_LIFECYCLE',notification_delivery='NOT_RUN',services='NOT_RUN',
            audio_execution='NOT_RUN',hardware='NOT_RUN',defaults_enabled=False,baseline_sha256=C.BASE_SHA,package_count=600,
            restored_count=587,events=events,combined_shell=dict(path='combined-shell.json',bytes=1,sha256='a'*64),
            subtransactions=[dict(phase=p,count=587,bang_bang=C.NEW,status='PASS') for p in ('remove-to587-bang2','final587-bang2')],ldconfig=[dict(phase=p,state_sha256='a'*64,aux_sha256='b'*64,helper_exit='NOT_OBSERVED',
                transition=dict(kind='BASELINE' if i==0 else 'RAW_EQUAL')) for i,p in enumerate(('baseline587','install600',
                'same-version600','remove-to587-bang2','remove-to587','restore600','final587-bang2','final587'))])

    def test_exact_six_checkpoint_contract(self):C.validate_result(self.good())

    def test_count587_does_not_mean_original587(self):
        value=self.good();value['events'][-1]['bang_bang']=C.NEW
        with self.assertRaises(ValueError):C.validate_result(value)

    def test_failed_or_incomplete_checkpoint(self):
        for key in ('signatures','dependencies','payload','ownership','originals_preserved','user_config_preserved'):
            value=self.good();value['events'][2][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_result(value)
        for key in ('events','subtransactions','ldconfig'):
            value=self.good();value[key].pop()
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_result(value)

    def test_no_default_service_audio_notification_acceptance(self):
        for key in ('defaults_enabled','services','audio_execution','notification_delivery','hardware'):
            value=self.good();value[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate_result(value)

    def test_host_receipt_is_not_installed_receipt(self):
        with self.assertRaises(ValueError):C.validate_combined(dict(status='PASS_HOST_COMPOSED_SHELLS'))


class Workflow(unittest.TestCase):
    def text(self):return (C.HERE.parents[2]/'.github/workflows/native-arm-expanded-development-composition.yml').read_text()

    def test_manual_gate_precedes_secrets(self):
        text=self.text()
        self.assertEqual(text.count('  workflow_dispatch:'),1)
        self.assertNotIn('  push:',text);self.assertNotIn('  pull_request:',text)
        self.assertLess(text.index('      - name: Prove exact manual source'),text.index('${{ secrets.'))
        self.assertIn('--workflow-sha "$WORKFLOW_SOURCE"',text)
        self.assertNotIn('full-composition-installer-vm/ci.py',text)

    def test_all_literal_shell_blocks_parse(self):
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
        for block in blocks:subprocess.run(['bash','-n'],input=block,text=True,check=True,capture_output=True)


class Ownership(unittest.TestCase):
    def test_reservation_persisted_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger=Containers(Path(directory)/'owned.json','sha256:'+'a'*64)
            with patch('owned.capture',return_value=''):
                argv=ledger.launch(['docker','run','--name','cachy-asahi-control-abc','sha256:'+'a'*64])
            self.assertIn(C.LABEL+'='+ledger.token,argv)
            self.assertEqual(C.read(ledger.path)['containers'][0]['status'],'RESERVED')

    def test_lease_cannot_be_reclaimed_by_second_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'owned.json';ledger=Containers(path,'sha256:'+'a'*64)
            try:
                with self.assertRaises(FileExistsError):Containers(path,'sha256:'+'a'*64)
            finally:ledger.close()

    def test_foreign_name_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger=Containers(Path(directory)/'owned.json','sha256:'+'a'*64)
            with patch('owned.capture',return_value='foreign'),self.assertRaises(ValueError):
                ledger.launch(['docker','run','--name','cachy-asahi-control-abc','sha256:'+'a'*64])
            self.assertEqual(ledger.rows,[])

    def test_wrong_label_never_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger=Containers(Path(directory)/'owned.json','sha256:'+'a'*64)
            ledger.rows=[dict(name='cachy-asahi-control-abc',id=None,status='RESERVED')]
            record=dict(Id='b'*64,Name='/cachy-asahi-control-abc',Image=ledger.image,Config=dict(Labels={C.LABEL:'foreign'}))
            observation=__import__('types').SimpleNamespace(returncode=0,stderr='',stdout=json.dumps([record]))
            with patch('owned.subprocess.run',return_value=observation),patch('owned.capture') as remove,self.assertRaises(ValueError):ledger.cleanup()
            remove.assert_not_called()


if __name__=='__main__':unittest.main()
