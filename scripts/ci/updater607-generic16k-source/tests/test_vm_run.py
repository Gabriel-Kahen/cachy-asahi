"""Actual VM run prefix, stopped before external commands; not VM execution.

SOURCE and kernel DATA are real. Only prerequisite authority and external
command boundaries are replaced. All five source/DATA operands are explicit.
"""
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

FACTORY = Path(__file__).resolve().parents[1]
CHILD, HELD, FRESH, DATA, OLD = (
    Path(os.environ[name]).resolve() for name in
    ('EMITTED_SOURCE','HELD_SOURCE','FRESH16K_SOURCE','KERNEL_DATA_SOURCE','OLD_UPDATER16K_SOURCE'))
sys.path[:0] = [str(CHILD), str(CHILD/'parent360/implementation')]
import common
import runtime
import authority


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class Boundary(RuntimeError):
    """The first real supervisor command is intentionally not executed."""


class RunPrefixControls(unittest.TestCase):
    def harness(self,source,case='normal',wrong_signer=False,tamper=None):
        selected=load('_run_prefix_selected',source/'selected.py')
        custody=load('_run_prefix_custody',source/'custody.py')
        custody.verify()
        state=dict(gpg=[],external=[],prerequisites=[],captured=None)
        with tempfile.TemporaryDirectory(prefix='vm-run-prefix-',dir=FACTORY) as td:
            root=Path(td);public=root/'public';public.mkdir();raw=root/'producer';raw.mkdir()
            signer=raw/'test-signing';signer.mkdir();(signer/'MODEL_TEST_KEY_ONLY').write_bytes(b'inert signer-path fixture\n')
            kernel=root/'kernel-data';kernel.mkdir()
            original={name:common.pin(common.read(DATA/name)) for name in ('Image','config','kernel-input.json')}
            for name in original:shutil.copyfile(DATA/name,kernel/name)
            if tamper:
                path=kernel/tamper;content=path.read_bytes();path.write_bytes(bytes([content[0]^1])+content[1:])
            context=dict(source='9'*40,run='123',attempt='1',ref='refs/heads/codex/PREFIX_CONTROL_ONLY',page_profile='generic16k')
            api=runtime.Integration.__new__(runtime.Integration)
            api._owner=types.SimpleNamespace(verify_result=lambda *_:self.fail('guest verifier must not execute'))
            extra=types.SimpleNamespace(latest_decisions=root/'unused-authority-operand')
            a=types.SimpleNamespace(implementation=HELD,fresh16k_source=FRESH,kernel_input=kernel,case=case)
            def inputs():state['prerequisites'].append('api.inputs')
            def gates(value):
                self.assertEqual(value,extra.latest_decisions);state['prerequisites'].append('authority.gates')
            with patch.object(api,'inputs',side_effect=inputs),patch.object(authority,'gates',side_effect=gates):
                transport=selected.vm(api,None,extra,context,custody.verify_dependencies)
                C=transport.C
                paths={};argv=['docker','run','--rm']
                directories={'/inputs','/upgrade-code','/upgrade-pair','/measurement-source','/out'}
                for dest in sorted(transport.MOUNTS):
                    if dest=='/measurement':
                        argv+=['--mount','type=volume,src=PREFIX-CONTROL-ONLY,dst=/measurement,volume-nocopy'];continue
                    if dest=='/upgrade-signing':
                        path=signer
                        if wrong_signer:
                            path=root/'ordinary-wrong-signer';path.mkdir();(path/'fixture').write_bytes(b'ordinary wrong signer\n')
                    else:
                        path=root/'mounts'/dest.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
                        if dest in directories:
                            path.mkdir();(path/'fixture').write_bytes(('ordinary input '+dest+'\n').encode())
                        else:path.write_bytes(('ordinary file '+dest+'\n').encode())
                    paths[dest]=path
                    mount='type=bind,src='+str(path)+',dst='+dest
                    if dest in transport.RO:mount+=',readonly'
                    argv+=['--mount',mount]
                for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID','SYS_CHROOT','SETFCAP','KILL','FSETID'):
                    argv+=['--cap-add='+cap]
                markers=dict(CACHY_ASAHI_COMPOSITION='7'*32,CACHY_ASAHI_BOUND_UPDATE='8'*32)
                argv+=['--env='+key+'='+value for key,value in markers.items()]
                image='sha256:'+'a'*64
                bindings,env=transport.mounts(argv)  # Actual parser, also called by production run.
                self.assertEqual(set(bindings),transport.MOUNTS-{'/measurement'})
                self.assertEqual(env,markers)
                def gpg(cmd,log,seconds):
                    self.assertEqual(cmd,['/usr/bin/gpgconf','--homedir',str(raw/'test-signing'),'--kill','all'])
                    self.assertEqual(log,public/'updater16k-signing-retirement.log');self.assertEqual(seconds,15)
                    state['gpg'].append(list(cmd))
                def boundary(cmd,cwd,environment,seconds,cap):
                    state['external'].append(list(cmd))
                    self.assertEqual(cmd[:2],['/usr/bin/docker','inspect'])
                    self.assertEqual(seconds,30);self.assertEqual(cap,2*1024**2)
                    work=public.parent/'update16k';self.assertEqual(cwd,work)
                    self.assertEqual(environment,dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(work),TMPDIR=str(work)))
                    selection=C.decode(C.read(work/'selection.json'))
                    self.assertRegex(selection['nonce'],r'^[a-f0-9]{32}$')
                    self.assertEqual(cmd,['/usr/bin/docker','inspect','caa-apps6-update16k-'+selection['nonce']+'-prepare'])
                    self.assertEqual(selection['current607'],context);self.assertEqual(selection['case'],case)
                    self.assertEqual(selection['bindings'],{n:dict(readonly=b['readonly']) for n,b in bindings.items()})
                    self.assertEqual(selection['env'],markers);self.assertEqual(selection['image'],image)
                    self.assertEqual(selection['source_files'],C.check_source(HELD))
                    expected=transport._current607_runner_bytes(C.HERE,context)
                    copied={p.name:C.read(p) for p in work.glob('*.py')}
                    self.assertEqual(copied,expected);self.assertEqual(set(copied),set(selection['runner_files']))
                    for name,payload in copied.items():
                        self.assertEqual(selection['runner_files'][name],dict(bytes=len(payload),sha256=C.sha(payload)))
                    tree=ast.parse(copied['guest.py'])
                    binding=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CURRENT607_EXPECTED' for t in n.targets))
                    self.assertEqual(ast.literal_eval(binding),context)
                    self.assertEqual(C.row(work/'Image'),original['Image'])
                    self.assertEqual(common.read(work/'Image'),common.read(DATA/'Image'))
                    input_map=C.decode(C.read(work/'input-map.json'))
                    self.assertEqual(input_map,transport.snapshot(bindings))
                    self.assertIn('/upgrade-signing/MODEL_TEST_KEY_ONLY',input_map)
                    self.assertEqual(paths['/upgrade-signing'],raw/'test-signing')
                    state['captured']=dict(helper_files=len(copied),selection=selection,input_nodes=len(input_map),
                                           Image=C.row(work/'Image'),signer=str(raw/'test-signing'))
                    raise Boundary('STOPPED_BEFORE_FIRST_DOCKER_INSPECT_NO_ACTOR_EXECUTION')
                original_load=C.load
                def external_loader(name,path):
                    module=original_load(name,path)  # Load the actual supervisor before interception.
                    self.assertEqual(name,'supervisor')
                    self.assertEqual(Path(module.__file__),HELD/'scripts/ci/glibc-owned-runtime/runner.py')
                    self.assertEqual(C.row(module.__file__),custody.profile()['dependencies']['held']['files']['scripts/ci/glibc-owned-runtime/runner.py'])
                    self.assertTrue(callable(module.run_command))
                    module.run_command=boundary
                    state['supervisor_loaded']=str(module.__file__)
                    return module
                prior_handler=signal.getsignal(signal.SIGALRM);prior_timer=signal.getitimer(signal.ITIMER_REAL)
                self.assertEqual(prior_timer,(0.0,0.0))
                with patch.object(C,'load',side_effect=external_loader),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS_EXECUTION')),patch.object(subprocess,'run',side_effect=AssertionError('NO_SUBPROCESS_EXECUTION')),patch.object(subprocess,'check_output',side_effect=AssertionError('NO_SUBPROCESS_EXECUTION')):
                    try:transport.run(a,argv,image,public,raw,types.SimpleNamespace(command=gpg),3900)
                    except (Boundary,TypeError,ValueError) as error:
                        state['error']=error
                        state['traceback_files']=[];tb=error.__traceback__
                        while tb:
                            state['traceback_files'].append(tb.tb_frame.f_code.co_filename);tb=tb.tb_next
                    else:self.fail('the external command boundary must stop this test')
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL),prior_timer)
                self.assertIs(signal.getsignal(signal.SIGALRM),prior_handler)
                work=public.parent/'update16k';state['work_exists']=work.exists()
                state['input_map_exists']=(work/'input-map.json').exists()
                if (public/'updater16k-cleanup.json').exists():state['cleanup']=C.decode(C.read(public/'updater16k-cleanup.json'))
            self.assertEqual(original,{name:common.pin(common.read(DATA/name)) for name in original})
        return state

    def test_actual_fixed_run_all_three_cases_reaches_command_boundary_and_retires_private_work(self):
        for case in ('normal','precommit-exit86','postcommit-exit87'):
            with self.subTest(case=case):
                state=self.harness(CHILD,case)
                self.assertIsInstance(state['error'],Boundary);self.assertEqual(len(state['gpg']),1)
                self.assertEqual(len(state['external']),1);self.assertIsNotNone(state['captured'])
                self.assertEqual(state['captured']['helper_files'],5);self.assertGreater(state['captured']['input_nodes'],0)
                self.assertFalse(state['work_exists']);self.assertEqual(state['cleanup']['status'],'PASS')
                self.assertEqual(state['cleanup']['actors'],[]);self.assertEqual(state['cleanup']['group_records'],[])
                self.assertEqual(state['cleanup']['error']['type'],'Boundary')
                self.assertEqual(state['prerequisites'],['authority.gates','api.inputs'])

    def test_actual_old_run_counterfactual_detects_bytes_path_shadow_before_commands(self):
        state=self.harness(OLD)
        self.assertIsInstance(state['error'],TypeError)
        self.assertIn("'bytes' and 'str'",str(state['error']))
        self.assertIn(str(OLD/'vm/vm.py'),state['traceback_files'])
        self.assertEqual(state['gpg'],[]);self.assertEqual(state['external'],[])
        self.assertIsNone(state['captured']);self.assertTrue(state['work_exists'])
        self.assertFalse(state['input_map_exists'])

    def test_actual_fixed_run_refuses_different_ordinary_signer_path(self):
        state=self.harness(CHILD,wrong_signer=True)
        self.assertIsInstance(state['error'],ValueError)
        self.assertIn('existing owned TEST signer only',str(state['error']))
        self.assertEqual(state['gpg'],[]);self.assertEqual(state['external'],[])
        self.assertIsNone(state['captured']);self.assertFalse(state['input_map_exists'])

    def test_actual_kernel_verifier_refuses_tampered_ordinary_Image_and_config_before_commands(self):
        for name in ('Image','config'):
            with self.subTest(member=name):
                state=self.harness(CHILD,tamper=name)
                self.assertIsInstance(state['error'],ValueError)
                self.assertEqual(state['gpg'],[]);self.assertEqual(state['external'],[])
                self.assertIsNone(state['captured']);self.assertFalse(state['work_exists'])


if __name__=='__main__':unittest.main()
