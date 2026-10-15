#!/usr/bin/env python3
"""Focused mocked finished-image/probe ownership checks; no external actors."""
import copy
import fcntl
import importlib.util
import json
import os
import stat
import types
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned574',HERE/'maintained_desktop574.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
TOKEN='a'*16
IMAGE='sha256:'+'1'*64
OLD='sha256:'+'2'*64
CID='c'*64
TAG,NAME=h.owner_names(TOKEN)


class Daemon:
    def __init__(self):
        self.images={IMAGE:{'Id':IMAGE,'Architecture':'arm64','Os':'linux',
            'Config':{'Labels':{h.OWNER_LABEL:TOKEN}},'RepoTags':[TAG],'RepoDigests':[]}}
        self.containers={}
        self.queries=[];self.mutations=[]

    def probe(self):
        self.containers[CID]={'Id':CID,'Name':'/'+NAME,'Image':IMAGE,'Config':{'Labels':{h.OWNER_LABEL:TOKEN}}}

    def __call__(self,*args):
        self.queries.append(args)
        if args[:2]==('image','ls'):
            rows=list(self.images)
            if '--filter' in args:
                value=args[args.index('--filter')+1]
                if value.startswith('reference='):
                    rows=[k for k in rows if value[10:] in self.images[k]['RepoTags']]
                elif value.startswith('label='):
                    key,value=value[6:].split('=',1)
                    rows=[k for k in rows if self.images[k]['Config'].get('Labels',{}).get(key)==value]
                else:raise AssertionError(args)
            return '\n'.join(rows)
        if args[:2]==('image','inspect'):
            return json.dumps([self.images[args[2]]])
        if args[:2]==('container','inspect'):
            return json.dumps([next(v for v in self.containers.values() if v['Name']=='/'+args[2])])
        if args[:2]==('container','ls'):
            value=args[args.index('--filter')+1]
            if value.startswith('name=^/'):
                rows=[v for v in self.containers.values() if v['Name']==value[6:-1]]
            elif value.startswith('id='):rows=[v for k,v in self.containers.items() if k==value[3:]]
            elif value.startswith('ancestor='):rows=[v for v in self.containers.values() if v['Image']==value[9:]]
            else:raise AssertionError(args)
            return '\n'.join(v['Id'] if args[-1]=='{{.ID}}' else v['Name'][1:] for v in rows)
        raise AssertionError(args)

    def run(self,argv,**kwargs):
        self.mutations.append(argv)
        if argv==['/usr/bin/docker','rm','-f',CID]:self.containers.pop(CID)
        elif argv==['/usr/bin/docker','image','rm','--no-prune',IMAGE]:self.images.pop(IMAGE)
        else:raise AssertionError(argv)
        return SimpleNamespace(returncode=0)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.daemon=Daemon()
        self.owner=dict(token=TOKEN,image_tag=TAG,probe_name=NAME,probe_cidfile='probe-cid',
            before_images=[],build_started=True,build_complete=True,probe_started=True,probe_complete=True,image=IMAGE)
        self.report={'ownership':self.owner,'build_returncode':0}
        (self.root/'image-id').write_text(IMAGE)
        (self.root/'probe-cid').write_text(CID)

    def retire(self):
        with patch.object(h,'docker',side_effect=self.daemon),patch.object(h.subprocess,'run',side_effect=self.daemon.run):
            return h.retire_owned(self.root,TOKEN,self.report)

    def test_normal_finished_image_and_absent_probe_retire(self):
        result=self.retire()
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(self.daemon.mutations,[['/usr/bin/docker','image','rm','--no-prune',IMAGE]])
        self.assertTrue(result['probe']['absence_verified']);self.assertTrue(result['image']['absence_verified'])

    def test_inflight_and_partial_build_states_never_query_daemon(self):
        for change in ({'build_complete':False},{'build_started':False},{'build_complete':None}):
            self.report['ownership']=dict(self.owner,**change)
            with patch.object(h,'docker') as query,patch.object(h.subprocess,'run') as mutate:
                self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL')
                query.assert_not_called();mutate.assert_not_called()
        self.report.pop('ownership')
        with patch.object(h,'docker') as query:
            self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL');query.assert_not_called()

    def test_finished_output_recovers_from_tag_without_iid(self):
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        self.owner.pop('image');self.owner.update(probe_started=False,probe_complete=False)
        self.assertEqual(self.retire()['status'],'PASS')

    def test_known_probe_after_interruption_uses_exact_cid(self):
        self.daemon.probe();self.owner['probe_complete']=False
        result=self.retire();self.assertEqual(result['status'],'PASS')
        self.assertEqual(self.daemon.mutations[0],['/usr/bin/docker','rm','-f',CID])
        self.assertFalse(self.daemon.containers)

    def test_probe_name_recovers_missing_cidfile(self):
        self.daemon.probe();(self.root/'probe-cid').unlink();self.owner['probe_complete']=False
        self.assertEqual(self.retire()['status'],'PASS')
        self.assertEqual(self.daemon.mutations[0],['/usr/bin/docker','rm','-f',CID])

    def test_unknown_probe_creation_preserves_finished_image(self):
        (self.root/'probe-cid').unlink();self.owner['probe_complete']=False
        result=self.retire();self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['probe'],'UNKNOWN');self.assertEqual(self.daemon.mutations,[])
        self.assertIn(IMAGE,self.daemon.images)

    def test_baseline_even_if_dangling_is_never_removed(self):
        self.owner['before_images']=[IMAGE];self.daemon.images[IMAGE]['RepoTags']=[]
        result=self.retire();self.assertEqual(result['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])
        self.assertIn(IMAGE,self.daemon.images)

    def test_tag_label_cid_and_foreign_reference_conflicts_refuse(self):
        original=copy.deepcopy(self.daemon.images[IMAGE])
        for field,value in [('Id',OLD),('RepoTags',[TAG,'foreign:keep']),('RepoDigests',['foreign@sha256:keep']),('Config',{'Labels':None})]:
            self.daemon.images[IMAGE]=dict(original,**{field:value})
            with self.subTest(field=field):
                self.assertEqual(self.retire()['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])
        self.daemon.images[IMAGE]=original;self.daemon.probe();(self.root/'probe-cid').write_text('d'*64)
        self.assertEqual(self.retire()['status'],'FAIL');self.assertEqual(self.daemon.mutations,[])

    def test_foreign_container_is_not_removed_with_owned_probe(self):
        self.daemon.probe();foreign='e'*64
        self.daemon.containers[foreign]={'Id':foreign,'Name':'/foreign','Image':IMAGE}
        result=self.retire();self.assertEqual(result['status'],'FAIL')
        self.assertEqual(self.daemon.mutations,[['/usr/bin/docker','rm','-f',CID]])
        self.assertIn(foreign,self.daemon.containers);self.assertIn(IMAGE,self.daemon.images)

    def test_failed_absence_query_cannot_pass(self):
        def query(*args):
            if not self.daemon.images:raise subprocess.TimeoutExpired('mock-query',20)
            return self.daemon(*args)
        with patch.object(h,'docker',side_effect=query),patch.object(h.subprocess,'run',side_effect=self.daemon.run):
            self.assertEqual(h.retire_owned(self.root,TOKEN,self.report)['status'],'FAIL')

    def test_token_validation_and_collision_checks(self):
        for value in (None,'A'*16,'a'*15,'a/../b','a'*17):
            with self.subTest(value=value),self.assertRaises(ValueError):h.owner_names(value)
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        with patch.object(h,'docker',side_effect=self.daemon),self.assertRaisesRegex(ValueError,'collision'):
            h.owner_begin(self.root,TOKEN)

    def test_live_helper_directory_lock_refuses_cleanup_without_queries(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,fd)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        argv=['helper','cleanup','--inputs',str(self.root/'input.json'),'--output',str(self.root),'--job-token',TOKEN]
        with patch.object(sys,'argv',argv),patch.object(h,'docker') as query,self.assertRaises(BlockingIOError):h.main()
        query.assert_not_called()

    def test_owned_rejections_preserve_existing_ownership_report(self):
        original=json.dumps(self.report).encode();(self.root/'report.json').write_bytes(original)
        (self.root/'input.json').write_text('{}')
        argv=['helper','build','--inputs',str(self.root/'input.json'),'--output',str(self.root),'--job-token',TOKEN]
        for architecture in ('x86_64','aarch64'):
            with self.subTest(architecture=architecture),patch.dict(h.os.environ,{},clear=True), \
                 patch.object(sys,'argv',argv),patch.object(h,'plan',return_value=[]), \
                 patch.object(h.platform,'system',return_value='Linux'),patch.object(h.platform,'machine',return_value=architecture), \
                 patch.object(h.subprocess,'check_output',return_value='aarch64'), \
                 patch.object(h.subprocess,'run') as mutate,patch.object(h,'docker') as query:
                self.assertEqual(h.main(),1)
                mutate.assert_not_called();query.assert_not_called()
            self.assertEqual((self.root/'report.json').read_bytes(),original)

    def main_fixture(self,owned):
        (self.root/'image-id').unlink();(self.root/'probe-cid').unlink()
        (self.root/'input.json').write_text('{}');(self.root/'context').mkdir();(self.root/'home').mkdir()
        (self.root/'context/expected-packages.lock').write_bytes(b'fixture\n')
        argv=['helper','build','--inputs',str(self.root/'input.json'),'--output',str(self.root)]
        if owned:argv+=['--job-token',TOKEN]
        commands=[]
        def build(argv,**kwargs):
            commands.append(argv);self.assertEqual(argv[:3],['/usr/bin/docker','build','--progress=plain'])
            if owned:
                state=json.loads((self.root/'report.json').read_text())['ownership']
                self.assertTrue(state['build_started']);self.assertFalse(state['build_complete'])
                self.assertIn(TAG,argv);self.assertIn(h.OWNER_LABEL+'='+TOKEN,argv)
            else:self.assertNotIn('--tag',argv)
            (self.root/'image-id').write_text(IMAGE);self.daemon=Daemon()
            return SimpleNamespace(returncode=0)
        def output(argv,**kwargs):
            if argv[1]=='info':return 'aarch64\n'
            commands.append(argv);self.assertEqual(argv[-2:],[IMAGE,'/builder-packages.lock'])
            if owned:
                state=json.loads((self.root/'report.json').read_text())['ownership']
                self.assertTrue(state['build_complete']);self.assertTrue(state['probe_started']);self.assertFalse(state['probe_complete'])
                self.assertEqual(state['probe_cidfile'],'probe-cid');self.assertIn(NAME,argv)
                self.assertEqual(argv[argv.index('--cidfile')+1],str(self.root/'probe-cid'))
                (self.root/'probe-cid').write_text(CID)
            else:self.assertNotIn('--name',argv);self.assertNotIn('--cidfile',argv)
            return b'fixture\n'
        self.daemon.images={}
        with patch.dict(h.os.environ,{'INHERITED':'MUST-NOT-LEAK'},clear=True),patch.object(sys,'argv',argv), \
             patch.object(h,'plan',return_value=[]),patch.object(h,'configure'), \
             patch.object(h.platform,'system',return_value='Linux'),patch.object(h.platform,'machine',return_value='aarch64'), \
             patch.object(h,'docker',side_effect=lambda *a:self.daemon(*a)), \
             patch.object(h.subprocess,'run',side_effect=build),patch.object(h.subprocess,'check_output',side_effect=output):
            self.assertEqual(h.main(),0)
        result=json.loads((self.root/'report.json').read_text());self.assertEqual(result['status'],'PASS_NATIVE_OFFLINE_574_TRANSACTION')
        self.assertEqual(len(commands),2)
        return result

    def test_default_path_keeps_legacy_commands_and_report(self):
        self.assertNotIn('ownership',self.main_fixture(False))

    def test_owned_path_persists_intent_before_mutations(self):
        result=self.main_fixture(True);self.assertTrue(result['ownership']['probe_complete'])
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,fd)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)


class CanonicalConfigureTests(unittest.TestCase):
    def test_generated_producer_script_and_existing_transaction_policy(self):
        inputs=json.loads((HERE/'maintained-desktop574-inputs.json').read_text())
        with tempfile.TemporaryDirectory() as temporary:
            context=Path(temporary);h.configure(inputs,context)
            self.assertEqual((context/'finish-keyring.py').read_text(),h.KEYRING_FINALIZER)
            self.assertEqual(len((context/'expected-packages.lock').read_text().splitlines()),574)
            self.assertEqual(len((context/'disabled-hooks.txt').read_text().splitlines()),41)
            self.assertEqual((context/'pacman.conf').read_text(),h.PACMAN)
        self.assertEqual(h.DOCKERFILE.count('\nRUN '),1)
        self.assertLess(h.DOCKERFILE.index('pacman-key --init'),h.DOCKERFILE.index('/usr/bin/python3 -B /tmp/finish-keyring.py'))
        self.assertLess(h.DOCKERFILE.index('cmp /expected-packages.lock /builder-packages.lock'),h.DOCKERFILE.index('/usr/bin/python3 -B /tmp/finish-keyring.py'))
        self.assertIn('--noscriptlet',h.DOCKERFILE)
        self.assertNotIn('unlink(',h.KEYRING_FINALIZER)
        self.assertNotIn("'all'",h.KEYRING_FINALIZER)

class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.api=types.ModuleType('inert_keyring_finalizer')
        exec(compile(h.KEYRING_FINALIZER,'<generated-keyring-finalizer>','exec'),self.api.__dict__)
        self.directory=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)

    def finish(self,states,clock=(0,)):
        with patch.object(Path,'lstat',return_value=self.directory), \
             patch.object(self.api,'snapshot',side_effect=[{'fixed':'same'},{'fixed':'same'}]), \
             patch.object(self.api,'present',side_effect=states), \
             patch.object(self.api.subprocess,'run') as run, \
             patch.object(self.api.time,'monotonic',side_effect=clock), \
             patch.object(self.api.time,'sleep') as sleep:
            self.api.finish()
        return run,sleep

    def test_stop_is_exact_home_once_before_absence_with_finite_wait(self):
        run,sleep=self.finish([('S.gpg-agent',),('S.gpg-agent',),(),()],(10,10))
        run.assert_called_once()
        args,opts=run.call_args
        self.assertEqual(args[0],['/usr/bin/gpgconf','--homedir','/etc/pacman.d/gnupg','--kill','gpg-agent'])
        self.assertEqual(opts['timeout'],15);self.assertTrue(opts['check'])
        self.assertEqual(opts['stdout'],self.api.subprocess.DEVNULL)
        self.assertEqual(opts['stderr'],self.api.subprocess.DEVNULL)
        self.assertNotIn('GNUPGHOME',opts['env']);sleep.assert_called_once_with(0.05)

    def test_absent_producer_still_gets_one_home_scoped_stop(self):
        run,sleep=self.finish([(),(),()])
        run.assert_called_once();sleep.assert_not_called()

    def test_failure_timeout_remaining_reappearance_or_trust_drift_refuses(self):
        for mode in ('nonzero','timeout','remaining','reappeared','trust'):
            with self.subTest(mode=mode),patch.object(Path,'lstat',return_value=self.directory), \
                 patch.object(self.api,'snapshot',side_effect=[{'fixed':'same'},{'fixed':'changed' if mode=='trust' else 'same'}]), \
                 patch.object(self.api,'present',side_effect=[('S.gpg-agent',),('S.gpg-agent',) if mode=='remaining' else (),('S.gpg-agent',) if mode=='reappeared' else ()]), \
                 patch.object(self.api.subprocess,'run',side_effect=(self.api.subprocess.CalledProcessError(1,['inert']) if mode=='nonzero' else self.api.subprocess.TimeoutExpired(['inert'],15) if mode=='timeout' else None)), \
                 patch.object(self.api.time,'monotonic',side_effect=[0,5]), \
                 patch.object(self.api.time,'sleep'):
                with self.assertRaises((ValueError,self.api.subprocess.SubprocessError)):self.api.finish()

    def test_wrong_endpoint_type_and_unsafe_home_refuse_without_process(self):
        for mode,uid in ((stat.S_IFREG|0o600,0),(stat.S_IFLNK|0o777,0),(stat.S_IFSOCK|0o600,1000)):
            with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=mode,st_uid=uid)):
                with self.assertRaises(ValueError):self.api.present()
        with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0)),patch.object(self.api.subprocess,'run') as run:
            with self.assertRaises(ValueError):self.api.finish()
        run.assert_not_called()

    def test_snapshot_preserves_content_mode_owner_and_refuses_wrong_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'gnupg';home.mkdir()
            (home/'trustdb.gpg').write_bytes(b'inert public trust')
            config=root/'pacman.conf';config.write_bytes(b'inert fixed configuration')
            actual_path=Path
            self.api.HOME=home
            self.api.Path=lambda path:config if str(path)=='/etc/pacman.conf' else actual_path(path)
            lstat=Path.lstat;fstat=os.fstat
            def root_owned(info):
                values={name:getattr(info,name)for name in ('st_dev','st_ino','st_mode','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                return types.SimpleNamespace(**values,st_uid=0)
            with patch.object(Path,'lstat',lambda path:root_owned(lstat(path))), \
                 patch.object(os,'fstat',lambda fd:root_owned(fstat(fd))):
                first=self.api.snapshot();self.assertEqual(self.api.snapshot(),first)
                (home/'trustdb.gpg').write_bytes(b'changed inert public trust')
                self.assertNotEqual(self.api.snapshot(),first)
                (home/'public-keys.d').symlink_to(root,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'public key directory'):self.api.snapshot()
                (home/'public-keys.d').unlink()
                (home/'pubring.kbx').symlink_to(config)
                with self.assertRaises(ValueError):self.api.snapshot()

if __name__=='__main__':unittest.main()
