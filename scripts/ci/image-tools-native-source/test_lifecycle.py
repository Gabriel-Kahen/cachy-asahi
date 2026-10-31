#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exercise actual inside()/cleanup control flow with process/socket actors denied."""
import argparse
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
OLD=Path(os.environ['IMAGE_TOOLS_NATIVE_SOURCE']).resolve()/'native'
ENV_SOURCE=OLD.parent
PARSER=argparse.ArgumentParser(add_help=False)
PARSER.add_argument('--lifecycle',type=Path,default=ENV_SOURCE/'native/image_alpm_v1.py' if ENV_SOURCE else HERE/'image_alpm_v2.py')
PARSER.add_argument('--tools',type=Path,default=ENV_SOURCE/'native/image_tools_v1.py' if ENV_SOURCE else OLD/'image_tools_v1.py')
PARSER.add_argument('--demonstrate-old',action='store_true')
ARGS,UNIT_ARGS=PARSER.parse_known_args()


def deny_actors(event,args):
    if (event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.fork','os.forkpty',
        'os.posix_spawn','os.posix_spawnp','os.exec','os.kill','os.killpg','ctypes.dlopen')):
        raise AssertionError('process/socket/native actor forbidden:'+event)
sys.addaudithook(deny_actors)


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    spec.loader.exec_module(value)
    return value


F=module(HERE/'prepare.py','lifecycle_source_factory');policy=F.profile()
source_rows,source_bodies=F.snapshot(OLD.parent)
assert source_rows==policy['expected']['files']
assert F.tree_id(source_bodies,{n:r['mode'] for n,r in source_rows.items()})==policy['expected']['tree']
T=module(ARGS.tools,'image_tools_v1')
A=module(OLD/'image_alpm_v1.py' if ARGS.demonstrate_old else ARGS.lifecycle,'_inside_under_control')


class PrimaryCommandFailure(RuntimeError):pass
class RetentionFailure(OSError):pass
class ResultWriteFailure(OSError):pass
class InitializerFailure(RuntimeError):pass
class RetirementFailure(RuntimeError):pass


def model(subject, *, retire_failed=False, socket_unknown=False, result_write_failed=False,
          index_write_failed=False, final_write_failed=False, first_file_failed=False,
          partial_initialization=False, initialization_failed=False, state_drift=False,
          no_agent_output=b'gpg-connect-agent: no gpg-agent running in this session\n'):
    """The real lifecycle runs; only external actors/native premises are modeled.

    All fixture paths are owned. No package, key, socket or process is created.
    Protected snapshots use the actual byte/mode/owner snapshot implementation.
    """
    original_getuid,original_getgid=os.getuid(),os.getgid()
    with tempfile.TemporaryDirectory(prefix='image-inside-model-') as temporary:
        root=Path(temporary);source=root/'source';(source/'native').mkdir(parents=True)
        (source/'native/image-contract-v1.json').write_bytes(b'{"fixture":"MODEL ONLY"}\n')
        protected={name:root/'protected'/name for name in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')}
        for path in protected.values():path.mkdir(parents=True);(path/'owned-state').write_bytes(b'owned model state\n')
        work=Path(tempfile.mkdtemp(prefix='image-tools-test-model-',dir='/tmp'))
        work.chmod(0o700);scope=root/'evidence/journey/image-alpm-v1'
        base=b'base 1-1\n';events=[];primary=PrimaryCommandFailure('original modeled signing command failed')
        save_calls=[];first_writes=[];instances=[]
        original_is_file=Path.is_file;original_read_bytes=Path.read_bytes;original_write=Path.write_bytes
        original_mkdir=Path.mkdir;original_save=subject.save_result;original_retain=subject.retain_exception
        marker=work/'signing/MODEL-NO-KEY-OR-SOCKET'
        def is_file(path):return True if path==Path('/builder-packages.lock') else original_is_file(path)
        def read_bytes(path):return base if path==Path('/builder-packages.lock') else original_read_bytes(path)
        def write_bytes(path,raw):
            if path==scope/'first-failure.json':
                first_writes.append(len(raw))
                if first_file_failed and len(first_writes)>1:raise ResultWriteFailure('modeled final first-file write failed')
            return original_write(path,raw)
        def mkdir(path,*args,**kwargs):
            if partial_initialization and path==work/'trust':raise InitializerFailure('modeled partial home initialization failed')
            return original_mkdir(path,*args,**kwargs)
        def save(path,report):
            save_calls.append(report.get('phase','initial-or-command'))
            if result_write_failed and len(save_calls)==2:raise ResultWriteFailure('modeled intermediate result write failed')
            if final_write_failed and 'phase' in report:raise ResultWriteFailure('modeled final result write failed')
            return original_save(path,report)
        def retain(*args,**kwargs):
            if index_write_failed:raise RetentionFailure('modeled command-index retention failed')
            return original_retain(*args,**kwargs)
        def protected_state():return {name:T.snapshot_receipt(path) for name,path in protected.items()}
        def recipes(*args):
            output=root/'recipes';output.mkdir();return output
        def builds(run,*args):
            result={}
            for label in ('a','b'):
                path=root/('archive-'+label);path.write_bytes(b'owned inert archive model\n');result[label]=path
            return result
        class Commands:
            def __init__(self,output,home,*args,**kwargs):
                self.output=Path(output);self.records=[];instances.append(self)
                if initialization_failed:raise InitializerFailure('modeled Commands initialization failed')
            def run(self,step,argv,cwd,expected=0):
                events.append(step)
                raw=base if 'inventory' in step else b''
                if step.startswith('no-autostart-'):raw=no_agent_output
                if step.endswith('-explicit'):raw=b'base\n'
                failure=None
                if step=='generate-test-key':
                    marker.write_bytes(b'OWNED MODEL DATA; NO SECRET KEY OR SOCKET\n');marker.chmod(0o600);failure=primary
                elif step=='retire-signing' and retire_failed:failure=RetirementFailure('modeled daemon retirement unknown')
                elif step=='retire-trust' and state_drift:(protected['alpm_db']/'owned-state').write_bytes(b'changed model DB\n')
                if not (step=='generate-test-key' and index_write_failed):
                    log='%03d-%s.log'%(len(self.records),step);(self.output/log).write_bytes(raw)
                    self.records.append(dict(step=step,argv=argv,cwd=str(cwd),expected=expected,success=failure is None,
                        log=log,log_pin=T.data_pin(raw),supervision={'model':'NO ACTOR EXECUTED'},channels='MODELED DATA'))
                if failure is not None:raise failure
                return raw
        common=types.ModuleType('common');common.verify_source=lambda *args:None
        policy={'recipe':{'payload_files':{}},'makepkg_config':{'path':'native/unused-model.conf'}}
        result=None;raised=None
        try:
            with ExitStack() as stack:
                for context in (
                    patch.dict(sys.modules,{'common':common}),
                    patch.object(subject,'PREFIX',root),patch.object(subject,'SOURCE',source),patch.object(subject,'STORE',root/'evidence'),
                    patch.object(subject.os,'getuid',return_value=0),patch.object(subject.os,'geteuid',return_value=0),
                    patch.object(subject.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')),
                    patch.object(subject.tempfile,'mkdtemp',return_value=str(work)),patch.object(subject.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=original_getuid,pw_gid=original_getgid)),
                    patch.object(T,'source_policy',return_value=(policy,base)),patch.object(T,'load_workflow',return_value=types.SimpleNamespace(Commands=Commands)),
                    patch.object(T,'extract_recipes',side_effect=recipes),patch.object(T,'_own_tree',return_value=None),
                    patch.object(T,'compare_archives',return_value={'status':'MODELED DATA; NO NATIVE BUILD'}),patch.object(T,'retain_diagnostics',return_value=None),
                    patch.object(subject,'build_pair',side_effect=builds),patch.object(subject,'protected_state',side_effect=protected_state),
                    patch.object(subject,'save_result',side_effect=save),patch.object(subject,'retain_exception',side_effect=retain),
                    patch.object(Path,'is_file',is_file),patch.object(Path,'read_bytes',read_bytes),patch.object(Path,'write_bytes',write_bytes),patch.object(Path,'mkdir',mkdir)):
                    stack.enter_context(context)
                if socket_unknown:stack.enter_context(patch.object(subject.stat,'S_ISSOCK',side_effect=lambda mode:mode==(stat.S_IFREG|0o600)))
                try:result=subject.inside(source,'a'*64)
                except BaseException as error:raised=error
            persisted=json.loads((scope/'result.json').read_bytes()) if (scope/'result.json').is_file() else None
            return dict(result=result,persisted=persisted,raised=raised,primary=primary,events=events,
                work_exists=work.exists(),private_marker_exists=marker.exists(),
                fixture_scope='OWNED DATA MODEL OF ACTUAL inside(); NATIVE ACTUALS NULL')
        finally:
            # There are no actors/sockets in this model; retire only its owned data.
            if work.exists():shutil.rmtree(work)


class ActualInsideFlow(unittest.TestCase):
    def test_uncertain_daemon_retirement_keeps_private_evidence(self):
        observed=model(A,retire_failed=True)
        self.assertIsNone(observed['raised']);self.assertTrue(observed['work_exists']);self.assertTrue(observed['private_marker_exists'])
        report=observed['result'];self.assertEqual(report['status'],'FAIL')
        self.assertFalse(report['cleanup']['homes_retired']);self.assertFalse(report['cleanup']['private_directory_absent'])
        self.assertEqual(report['first_failure']['type'],'PrimaryCommandFailure')

    def test_socket_uncertainty_keeps_private_evidence(self):
        observed=model(A,socket_unknown=True)
        self.assertIsNone(observed['raised']);self.assertTrue(observed['work_exists'])
        self.assertFalse(observed['result']['cleanup']['no_sockets']);self.assertFalse(observed['result']['cleanup']['private_directory_absent'])

    def test_qualified_retirement_removes_only_owned_work(self):
        observed=model(A)
        self.assertIsNone(observed['raised']);self.assertFalse(observed['work_exists'])
        self.assertTrue(all(observed['result']['cleanup'][key] for key in ('homes_retired','no_sockets','private_directory_absent')))
        self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')

    def test_command_result_write_cannot_replace_primary(self):
        observed=model(A,result_write_failed=True)
        self.assertIsNone(observed['raised']);self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')
        self.assertTrue(any(row['type']=='ResultWriteFailure' for row in observed['result']['retention_errors']))

    def test_command_index_failure_cannot_replace_primary(self):
        observed=model(A,index_write_failed=True)
        self.assertIsNone(observed['raised']);self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')
        self.assertTrue(any(row['type']=='RetentionFailure' for row in observed['result']['retention_errors']))

    def test_final_result_write_cannot_escape_over_primary(self):
        observed=model(A,final_write_failed=True)
        self.assertIsNone(observed['raised']);self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')
        self.assertEqual(observed['result']['status'],'FAIL');self.assertTrue(observed['result']['retention_errors'])

    def test_final_first_file_failure_still_retains_cleanup_result(self):
        observed=model(A,first_file_failed=True)
        self.assertIsNone(observed['raised']);self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')
        self.assertTrue(observed['persisted']['cleanup']['homes_retired']);self.assertTrue(observed['persisted']['retention_errors'])

    def test_partial_home_initialization_has_no_actor_cleanup(self):
        observed=model(A,partial_initialization=True)
        self.assertIsNone(observed['raised']);self.assertFalse(observed['work_exists']);self.assertEqual(observed['events'],[])
        self.assertTrue(observed['result']['cleanup']['no_child_launched']);self.assertEqual(observed['result']['first_failure']['type'],'InitializerFailure')

    def test_supervisor_initialization_has_no_actor_cleanup(self):
        observed=model(A,initialization_failed=True)
        self.assertIsNone(observed['raised']);self.assertFalse(observed['work_exists']);self.assertEqual(observed['events'],[])
        self.assertTrue(observed['result']['cleanup']['no_child_launched'])

    def test_exact_protected_snapshot_drift_fails_without_masking_primary(self):
        observed=model(A,state_drift=True)
        self.assertIsNone(observed['raised']);report=observed['result'];self.assertEqual(report['status'],'FAIL')
        self.assertFalse(report['restore']['alpm_db']['unchanged']);self.assertEqual(report['first_failure']['type'],'PrimaryCommandFailure')
        self.assertTrue(any(row.startswith('protected-state:') for row in report['cleanup']['failures']))

    def test_reporting_only_failure_cannot_publish_a_pass_carrier(self):
        with tempfile.TemporaryDirectory(prefix='image-report-model-') as temporary:
            scope=Path(temporary);report={'status':'PASS','first_failure':None,'commands':[]}
            failure=ResultWriteFailure('modeled error after complete PASS bytes were written')
            def save(*args):
                (scope/'result.json').write_bytes(T.encoded(report));raise failure
            with patch.object(A,'save_result',side_effect=save):
                with self.assertRaises(ResultWriteFailure) as captured:A.persist_result(scope,report,'final')
            self.assertIs(captured.exception,failure);self.assertEqual(report['status'],'FAIL')
            self.assertEqual(json.loads((scope/'result.json').read_bytes())['status'],'PASS')

    def test_socket_and_process_creation_are_banned(self):
        import socket
        with self.assertRaisesRegex(AssertionError,'actor forbidden'):socket.socket()
        import subprocess
        with self.assertRaisesRegex(AssertionError,'actor forbidden'):subprocess.Popen(['/NO-ACTOR'])


    def test_exact_absence_model_keeps_rejected_cleanup_and_primary(self):
        exact=b'gpg-connect-agent: no gpg-agent running in this session\n'
        for scenario in (dict(no_agent_output=b''), dict(no_agent_output=exact[:-1]),
                         dict(no_agent_output=exact+b'extra\n'),
                         dict(retire_failed=True), dict(socket_unknown=True)):
            with self.subTest(scenario=scenario):
                observed=model(A,**scenario)
                self.assertIsNone(observed['raised']);self.assertTrue(observed['work_exists'])
                self.assertFalse(observed['result']['cleanup']['private_directory_absent'])
                self.assertEqual(observed['result']['first_failure']['type'],'PrimaryCommandFailure')


if __name__=='__main__':
    if ARGS.demonstrate_old:
        findings={}
        for name,kwargs in (('unknown_retirement',dict(retire_failed=True)),('socket_uncertainty',dict(socket_unknown=True)),
            ('intermediate_result_mask',dict(result_write_failed=True)),('index_mask',dict(index_write_failed=True)),
            ('final_result_escape',dict(final_write_failed=True)),('final_first_file_escape',dict(first_file_failed=True))):
            observed=model(A,**kwargs);report=observed['result'] or observed['persisted']
            findings[name]=dict(raised_type=type(observed['raised']).__name__ if observed['raised'] else None,
                work_exists=observed['work_exists'],marker_exists=observed['private_marker_exists'],
                first_failure=report['first_failure'],cleanup=report['cleanup'])
        print(json.dumps(dict(status='DEMONSTRATED_OLD_SOURCE_CONTROL_FLOW_GAPS',actual_native=None,findings=findings),sort_keys=True,indent=2))
    else:unittest.main(argv=[sys.argv[0],*UNIT_ARGS],verbosity=2)
