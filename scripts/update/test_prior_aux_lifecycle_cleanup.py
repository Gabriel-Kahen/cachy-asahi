# SPDX-License-Identifier: MIT
"""Actor-free cleanup regressions over the maintained fixture's actual main AST.

All namespace, mount, key, process and case boundaries below are inert MODEL
objects. This does not rerun or replace the retained genuine host lifecycle.
"""
import ast
import builtins
import copy
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import posixpath
from types import SimpleNamespace
import unittest

SOURCE=Path(__file__).with_name('test_prior_aux_lifecycle.py')
OLD_AUTHOR='3ab6007b93e037bdf072642f55147d26aff78959'
OLD_SOURCE_SHA='8fd402e691ab28f294710e54a2a60fe0456545894be90c5c2477761d094a14b1'
# Exact finally statements from that whole-pinned author, including indentation.
OLD_FINALLY="""        group=Path(fence['group'])
        status['resource_peak']={n:(group/n).read_text().strip() for n in ('memory.peak','pids.peak')}
        status['key_retirement']=retire_agents(args.sandbox,args.evidence)
        os.chdir(HERE)
        unmounted=subprocess.run(['/usr/bin/umount',str(args.sandbox)],capture_output=True,timeout=5)
        status['unmount']={'exit':unmounted.returncode,'stderr':unmounted.stderr.decode(errors='replace')}
        if unmounted.returncode: status['status']='FAIL-cleanup'
        (args.evidence/'lifecycle.json').write_bytes(encoded(status))
        need(unmounted.returncode==0,'private fixture unmount failed')
"""
OLD_FINALLY_SHA='ba02ce6844bef8c3229a39d7aaffd76ff936be146f9ed2429fd55a03024ce856'
CASES=('commit','stale-prior','postcommit-drift')
PURE_BUILTINS={name:getattr(builtins,name)for name in
    ('any','len','int','str','dict','type','isinstance','print','BaseException','RuntimeError')}
tree=ast.parse(SOURCE.read_bytes())
definitions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
assert not any(isinstance(n,(ast.Import,ast.ImportFrom))for n in ast.walk(definitions['main']))
CURRENT=compile(ast.Module(body=[definitions['need'],definitions['main']],type_ignores=[]),str(SOURCE)+':main-AST','exec')
assert hashlib.sha256(OLD_FINALLY.encode()).hexdigest()==OLD_FINALLY_SHA
OLD=compile(ast.parse('def old_cleanup(args,fence,status):\n'+OLD_FINALLY),'<pinned-author-finally-MODEL>','exec')


class PrimaryFailure(RuntimeError):pass


class BrokenStderr:
    def __init__(self):self.attempted=[]
    def write(self,text):
        self.attempted.append(text)
        raise OSError('MODEL unavailable stderr')
    def flush(self):pass


class ModelPath:
    def __init__(self,world,value):self.world,self.value=world,str(value)
    def __str__(self):return self.value
    def __truediv__(self,name):return ModelPath(self.world,posixpath.join(self.value,str(name)))
    def absolute(self):return ModelPath(self.world,posixpath.normpath(posixpath.join(self.world.cwd,self.value)))
    def iterdir(self):return iter(())
    def mkdir(self,**kwargs):self.world.events.append('MODEL mkdir')
    def read_text(self):
        if self.value=='/proc/self/uid_map':return '0 1000 1\n'
        if self.value=='/proc/net/dev':return 'lo: 0\n'
        name=posixpath.basename(self.value)
        if name not in ('memory.peak','pids.peak'):raise AssertionError('unexpected MODEL read')
        self.world.events.append(name)
        if name in self.world.peak_errors:raise self.world.peak_errors[name]
        return {'memory.peak':'201\n','pids.peak':'4\n'}[name]
    def write_bytes(self,raw):
        if self.value!='/MODEL/evidence/lifecycle.json':raise AssertionError('unexpected MODEL write')
        self.world.events.append('report_write')
        if self.world.write_error:raise self.world.write_error
        self.world.files[self.value]=raw
        return len(raw)


class World:
    def __init__(self):
        self.cwd='/MODEL/caller';self.events=[];self.commands=[];self.files={};self.completed=[]
        self.peak_errors={};self.agent_error=None;self.agent_result=dict(gpgconf_exit=0,owned_agents_absent=True)
        self.chdir_error=None;self.unmount_error=None;self.unmount_exit=0;self.write_error=None
        self.primary=None;self.stderr=io.StringIO();self.status=None
        self.args=SimpleNamespace(worker=None,sandbox=self.path('sandbox'),evidence=self.path('/MODEL/evidence'))
    def path(self,value):return value if isinstance(value,ModelPath)else ModelPath(self,value)
    def command(self,argv,**kwargs):
        self.commands.append((list(argv),kwargs))
        if argv[0]=='/usr/bin/mount':return SimpleNamespace(returncode=0,stderr=b'')
        if argv[0]!='/usr/bin/umount':raise AssertionError('unexpected MODEL command')
        self.events.append('unmount')
        if self.unmount_error:raise self.unmount_error
        return SimpleNamespace(returncode=self.unmount_exit,stderr=b'MODEL umount stderr')
    def retire(self,*args):
        self.events.append('key_retirement')
        if self.agent_error:raise self.agent_error
        return copy.deepcopy(self.agent_result)
    def chdir(self,path):
        self.events.append('leave_mount')
        if self.chdir_error:raise self.chdir_error
        self.cwd=str(path)
    @contextmanager
    def signing(self,*args):yield ('MODEL signer',b'MODEL public',None)
    def run_case(self,sandbox,evidence,mode,*args):
        self.cwd='/MODEL/caller/sandbox/copied-root'
        if self.primary is not None and mode=='stale-prior':raise self.primary
        row=dict(case=mode,status='MODEL case artifact',transaction=dict(
            commit_started=mode!='stale-prior',packages_committed=mode!='stale-prior',checkpoint_changed=mode=='commit'))
        self.completed.append(copy.deepcopy(row))
        return row
    def encoded(self,value):
        self.status=value
        return (json.dumps(value,sort_keys=True)+'\n').encode()
    def scope(self):
        world=self
        class Parser:
            def __init__(self,**kwargs):pass
            def add_argument(self,*args,**kwargs):pass
            def parse_args(self):return world.args
        return dict(__builtins__=PURE_BUILTINS,__doc__='MODEL only',argparse=SimpleNamespace(ArgumentParser=Parser),Path=self.path,
            fenced=lambda:dict(group='/MODEL/cgroup'),os=SimpleNamespace(getuid=lambda:0,environ={},chdir=self.chdir),
            subprocess=SimpleNamespace(run=self.command),PROFILE='MODEL',HOST_FILES={},ALPM_SHA='MODEL',
            signing=self.signing,CASES=CASES,HERE=self.path('/MODEL/source'),retire_agents=self.retire,
            run_case=self.run_case,encoded=self.encoded,json=json,sys=SimpleNamespace(stderr=self.stderr))
    def invoke(self,old=False):
        namespace=self.scope()
        try:
            exec(CURRENT,namespace)
            if old:
                exec(OLD,namespace)
                namespace['old_cleanup'](self.args,dict(group='/MODEL/cgroup'),dict(status='PASS-host-TEST-lifecycle',cases=[]))
            else:namespace['main']()
        except BaseException as error:return error
        return None
    def report(self):return json.loads(self.files['/MODEL/evidence/lifecycle.json'])
    def fallback(self):return json.loads(self.stderr.getvalue())


class Controls(unittest.TestCase):
    def assert_attempts(self,world):
        observed=[x for x in world.events if x in('memory.peak','pids.peak','key_retirement','leave_mount','unmount','report_write')]
        self.assertEqual(observed,['memory.peak','pids.peak','key_retirement','leave_mount','unmount','report_write'])
        unmount=[(argv,kw)for argv,kw in world.commands if argv[0]=='/usr/bin/umount']
        self.assertEqual(len(unmount),1);self.assertEqual(unmount[0][0],['/usr/bin/umount','/MODEL/caller/sandbox'])
        self.assertEqual(unmount[0][1]['timeout'],5)
    def assert_hold(self,report):
        self.assertEqual(report['status'],'FAIL-cleanup');self.assertEqual(report['cleanup']['status'],'HOLD')
        self.assertTrue(report['cleanup']['errors'])
    def test_pinned_original_skips_unmount_report_and_successor_attempts_both(self):
        for stage in('memory.peak','key_retirement'):
            with self.subTest(stage=stage):
                old=World();new=World()
                for world in(old,new):
                    if stage=='memory.peak':world.peak_errors[stage]=OSError('MODEL peak read')
                    else:world.agent_error=TimeoutError('MODEL TEST retirement timeout')
                self.assertIsNotNone(old.invoke(old=True));self.assertNotIn('unmount',old.events);self.assertFalse(old.files)
                self.assertIsInstance(new.invoke(),RuntimeError);self.assert_attempts(new);self.assert_hold(new.report())
    def test_happy_cleanup_preserves_case_artifacts_and_pass(self):
        world=World();self.assertIsNone(world.invoke());self.assert_attempts(world);report=world.report()
        self.assertEqual(report['case_status'],'PASS-host-TEST-lifecycle');self.assertEqual(report['status'],report['case_status'])
        self.assertEqual(report['cleanup'],dict(status='PASS',errors=[]));self.assertEqual(report['cases'],world.completed)
        self.assertEqual(report['report_write'],dict(status='PASS'));self.assertEqual(world.stderr.getvalue(),'')
    def test_each_peak_read_failure_is_independent(self):
        for field in('memory.peak','pids.peak'):
            with self.subTest(field=field):
                world=World();world.peak_errors[field]=OSError('MODEL unavailable peak');self.assertIsInstance(world.invoke(),RuntimeError)
                self.assert_attempts(world);report=world.report();self.assert_hold(report);self.assertIsNone(report['resource_peak'][field])
                other='pids.peak'if field=='memory.peak'else'memory.peak';self.assertIsNotNone(report['resource_peak'][other])
                self.assertEqual([r['stage']for r in report['cleanup']['errors']],['resource_peak/'+field])
    def test_agent_exception_and_unknown_absence_never_report_clean(self):
        for result in(None,{},dict(gpgconf_exit=1,owned_agents_absent=True),dict(gpgconf_exit=0,owned_agents_absent=False),dict(gpgconf_exit=0,owned_agents_absent=None)):
            with self.subTest(result=result):
                world=World();world.agent_result=result;self.assertIsInstance(world.invoke(),RuntimeError);self.assert_attempts(world)
                report=world.report();self.assert_hold(report);self.assertIsNone(report['key_retirement']['owned_agents_absent'])
                self.assertEqual(report['key_retirement']['status'],'UNKNOWN')
    def test_chdir_failure_still_uses_captured_plain_absolute_unmount(self):
        world=World();world.chdir_error=OSError('MODEL leave mount failed');self.assertIsInstance(world.invoke(),RuntimeError)
        self.assert_attempts(world);report=world.report();self.assert_hold(report)
        self.assertEqual([r['stage']for r in report['cleanup']['errors']],['leave_mount'])
    def test_unmount_exception_nonzero_and_unknown_exit_hold(self):
        for outcome in('exception',1,None):
            with self.subTest(outcome=outcome):
                world=World()
                if outcome=='exception':world.unmount_error=TimeoutError('MODEL umount timeout')
                else:world.unmount_exit=outcome
                self.assertIsInstance(world.invoke(),RuntimeError);self.assert_attempts(world);self.assert_hold(world.report())
                self.assertEqual([r['stage']for r in world.report()['cleanup']['errors']],['unmount'])
    def test_primary_survives_cleanup_failures_and_complete_report_fallback(self):
        world=World();world.primary=PrimaryFailure('MODEL transaction primary');world.peak_errors={n:OSError('MODEL peak')for n in('memory.peak','pids.peak')}
        world.agent_error=TimeoutError('MODEL keys');world.chdir_error=OSError('MODEL cwd');world.unmount_error=OSError('MODEL umount');world.write_error=OSError('MODEL report')
        self.assertIs(world.invoke(),world.primary);self.assert_attempts(world);report=world.fallback();self.assert_hold(report)
        self.assertEqual(report['primary_error'],dict(type='PrimaryFailure',message=str(world.primary)))
        self.assertEqual(report['active_case'],'stale-prior');self.assertEqual(report['case_status'],'FAIL')
        self.assertEqual(report['cases'],world.completed);self.assertEqual(report['report_write'],dict(status='FAIL'))
        self.assertEqual([r['stage']for r in report['cleanup']['errors']],['resource_peak/memory.peak','resource_peak/pids.peak','key_retirement','leave_mount','unmount','report_write'])
    def test_report_failure_retains_completed_case_truth_in_stderr(self):
        world=World();world.write_error=OSError('MODEL evidence full');self.assertIsInstance(world.invoke(),RuntimeError)
        self.assert_attempts(world);report=world.fallback();self.assert_hold(report)
        self.assertEqual(report['case_status'],'PASS-host-TEST-lifecycle');self.assertEqual(report['cases'],world.completed)
        self.assertEqual(len(report['cases']),3);self.assertEqual(report['report_write'],dict(status='FAIL'))
    def test_broken_stderr_does_not_mask_original_primary(self):
        world=World();world.primary=PrimaryFailure('MODEL original failure');world.write_error=OSError('MODEL report full');world.stderr=BrokenStderr()
        self.assertIs(world.invoke(),world.primary);self.assert_attempts(world);self.assert_hold(world.status)
        self.assertEqual([r['stage']for r in world.status['cleanup']['errors']],['report_write','report_fallback'])
        self.assertEqual(world.status['cases'],world.completed);self.assertEqual(world.status['case_status'],'FAIL')


if __name__=='__main__':unittest.main(verbosity=2)
