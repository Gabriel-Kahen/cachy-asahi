"""Focused retained-input, isolation and failure checks; never launch Docker/GPG."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = next(p for p in Path(__file__).resolve().parents if (p/'scripts/checks/package_checks.py').is_file())
sys.path[:0] = [str(REPO/'scripts/ci'),str(REPO/'scripts/checks')]


def load(name, filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


T=load('repository_installed_run','run.py')
C=load('repository_installed_container','container.py')


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.args=SimpleNamespace(source_commit='a'*40,cache=self.root/'cache',output=self.root/'output')
        self.args.cache.mkdir()

    def test_exact_retained_predecessor_and_successor_metadata_and_payloads(self):
        rows=T.archives()
        self.assertEqual([r['version'] for r in rows],['0.1.0-3','0.1.0-4'])
        self.assertEqual([len(r['payload']) for r in rows],[4,6])
        self.assertEqual(rows[0]['payload']['usr/bin/cachy-asahi-setup'],rows[1]['payload']['usr/bin/cachy-asahi-setup'])
        with patch.object(T,'HERE',self.root):
            (self.root/'fixtures').mkdir()
            for path in (Path(__file__).parent/'fixtures').iterdir():shutil.copyfile(path,self.root/'fixtures'/path.name)
            T.archives()
            path=self.root/'fixtures'/rows[0]['filename'];path.write_bytes(path.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'original archive bytes differ'):T.archives()

    def test_remote_context_rejected_before_any_daemon_probe(self):
        with patch.object(T.native,'run',return_value=json.dumps([{'Endpoints':{'docker':{'Host':'tcp://foreign:2376'}}}])) as command:
            with self.assertRaisesRegex(ValueError,'not local'):T.local_context()
            command.assert_called_once_with(['docker','context','inspect'],timeout=10)
        with patch.object(T.native,'run',return_value=json.dumps([{'Endpoints':{'docker':{'Host':'unix:///var/run/docker.sock'}}}])):
            T.local_context()

    def test_container_command_is_offline_and_mounts_only_explicit_inputs(self):
        command=T.container_command(['docker'],'owned','sha256:'+'b'*64,
            [(self.root/'input','/inputs',True),(self.root/'result','/results',False)],'c'*32)
        self.assertIn('--network=none',command);self.assertIn('--cap-drop=ALL',command)
        self.assertIn('--security-opt=no-new-privileges',command);self.assertIn('--user=0:0',command)
        self.assertNotIn('--privileged',command);self.assertNotIn('--cap-add=SYS_ADMIN',command)
        mounts=[command[i+1] for i,v in enumerate(command) if v=='--mount']
        self.assertEqual(mounts,['type=bind,src='+str(self.root/'input')+',dst=/inputs,readonly',
                                 'type=bind,src='+str(self.root/'result')+',dst=/results'])
        self.assertEqual(command[-4:],['sha256:'+'b'*64,'-I','-B','/lifecycle.py'])

    def test_cleanup_unknown_and_remaining_resources_fail(self):
        self.args.output.mkdir();(self.args.output/'native').mkdir()
        with patch.object(T.native,'run',side_effect=AssertionError('no command before known image')):
            self.assertEqual(T.cleanup(['docker'],'owned',self.args.output,True,False)['status'],'FAIL')
        image='sha256:'+'b'*64;(self.args.output/'native/image-id').write_text(image)
        with patch.object(T.native,'run',side_effect=lambda argv,**kw:image if argv[1:3]==['image','ls'] else ''):
            self.assertEqual(T.cleanup(['docker'],'owned',self.args.output,True,False)['status'],'FAIL')

    def test_cleanup_only_removes_named_container_and_recorded_image(self):
        self.args.output.mkdir();(self.args.output/'native').mkdir();image='sha256:'+'b'*64
        (self.args.output/'native/image-id').write_text(image);calls=[];queries=0
        def command(argv,**kw):
            nonlocal queries
            calls.append(argv)
            if argv[1:3]==['container','ls']:
                queries+=1;return 'owned' if queries==1 else ''
            return ''
        with patch.object(T.native,'run',side_effect=command):result=T.cleanup(['docker'],'owned',self.args.output,True,True)
        self.assertEqual(result['status'],'PASS')
        self.assertIn(['docker','rm','-f','owned'],calls);self.assertIn(['docker','image','rm','--no-prune',image],calls)
        self.assertFalse(any('prune' in row for row in calls))

    def orchestration(self, observed='PASS', cleanup='PASS', command_error=False):
        commands=[];builds=[]
        def build(inputs,cache,out,reviews):
            builds.append(reviews);(out/'packages.lock').write_text('retained341\n');return 'sha256:'+'b'*64
        def command(argv,*args,**kw):
            commands.append(argv)
            if command_error:raise ValueError('injected container failure')
            (self.args.output/'lifecycle/result.json').write_text(json.dumps({'status':observed,'private_fixture_cleanup':True,'final_package_count':341}))
        with patch.object(T,'ROOT',REPO),patch.object(T,'preflight',return_value=({},T.archives())), \
             patch.object(T.native,'probe',return_value={'docker_endpoint':'unix:///var/run/docker.sock'}), \
             patch.object(T.native,'audit'),patch.object(T.native,'build',side_effect=build), \
             patch.object(T.native,'sha',return_value=T.BASE),patch.object(T.native,'run',side_effect=command), \
             patch.object(T,'cleanup',return_value={'status':cleanup}) as cleaned:
            code=T.run(self.args)
        return code,json.loads((self.args.output/'summary/result.json').read_text()),builds,cleaned

    def test_lifecycle_bootstraps_without_rebuilding_either_package(self):
        code,report,builds,cleanup=self.orchestration()
        self.assertEqual((code,report['status']),(0,'PASS'));self.assertEqual(builds,[{}]);cleanup.assert_called_once()
        self.assertEqual(report['production_trust'],'NOT ACCEPTED');self.assertEqual(report['target_installation'],'NOT RUN')

    def test_container_failure_or_cleanup_failure_cannot_pass(self):
        for kwargs in ({'observed':'FAIL'},{'cleanup':'FAIL'},{'command_error':True}):
            with self.subTest(kwargs=kwargs):
                code,report,_,cleanup=self.orchestration(**kwargs)
                self.assertEqual((code,report['status']),(1,'FAIL'));cleanup.assert_called_once();shutil.rmtree(self.args.output)

    def test_fixture_snapshot_detects_user_edits_and_ownertrust_ignores_headers(self):
        path=self.root/'user.conf';path.write_text('user\n');before=C.snapshot([path]);path.write_text('edited\n')
        self.assertNotEqual(C.snapshot([path]),before)
        self.assertEqual(C.ownertrust('# created today\nBBBB:6:\nAAAA:4:\n'),['AAAA:4:','BBBB:6:'])


if __name__=='__main__':unittest.main(verbosity=2)
