"""Focused harness controls; no package/network/GPG or product Source execution."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).absolute().parent
spec=importlib.util.spec_from_file_location('development_run',HERE/'run.py')
run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
caller=run.module('development_caller_test','caller.py')


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)

    def test_fresh_runtime_and_exclusive_reuse_refusal(self):
        path=run.private_runtime(self.base/'run')
        for name in ['', 'tmp','tmp/home','tmp/runtime','tmp/cachy-asahi-seed93-auth-cache','work','supervisor']:
            self.assertEqual(stat.S_IMODE((path/name).stat().st_mode),0o700)
        self.assertFalse((path/'tmp/seed93-public-only-home').exists())
        marker=path/'keep';marker.write_text('retain')
        with self.assertRaises(FileExistsError):run.private_runtime(path)
        self.assertEqual(marker.read_text(),'retain')

    def test_runtime_symlink_ancestor_refuses(self):
        (self.base/'link').symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(ValueError):run.private_runtime(self.base/'link/run')
        self.assertFalse((self.base/'run').exists())

    def test_one_original_guardian_command(self):
        argv=run.guarded_argv(self.base/'source',self.base/'run')
        self.assertEqual(argv[:6],['/usr/bin/timeout','--signal=TERM','--kill-after=10s','1800s','/usr/bin/python3','-I'])
        self.assertEqual(argv.count('1800s'),1)
        self.assertIn('--guarded',argv)
        self.assertNotIn('HOME',run.ENV)
        self.assertNotIn('SSH_AUTH_SOCK',run.ENV)
        seeded=run.guarded_argv(self.base/'source',self.base/'run',[self.base/'a',self.base/'b'])
        self.assertEqual(seeded[-4:],['--seed-cache',str(self.base/'a'),'--seed-cache',str(self.base/'b')])

    def test_corrected_source_pins(self):
        self.assertEqual(caller.PROFILE,'2f32684073cd945843a5685ca72d951435bb96c252d43344368193c5d3ca9155')
        self.assertEqual(caller.MANIFEST,'bd72c0d2da36117071b0a1683ed96857c71e50f73a220488f5d20f6463ba906e')
        self.assertEqual(run.PROFILE,caller.PROFILE)

    def test_namespace_exposes_only_selected_public_source_and_new_work(self):
        argv=caller.namespace(self.base/'runtime',self.base/'frozen',HERE,['worker'])
        self.assertIn('--unshare-pid',argv)
        self.assertIn('--die-with-parent',argv)
        self.assertIn('--clearenv',argv)
        mounts=[argv[i+1:i+3]for i,x in enumerate(argv)if x in ('--bind','--ro-bind')]
        self.assertIn([str(self.base/'runtime/tmp'),'/tmp'],mounts)
        self.assertIn([str(self.base/'runtime/work'),'/work'],mounts)
        self.assertIn([str(self.base/'frozen'),'/source'],mounts)
        self.assertFalse(any(src==str(Path.home())for src,dst in mounts))
        index=argv.index('--tmpfs');self.assertEqual(argv[index+1],'/etc/ssl/private')
        self.assertFalse(any(x in argv for x in ['--bind-try','--ro-bind-try','--share-pid']))

    def test_worker_uses_existing_source_api_once(self):
        api=types.SimpleNamespace(PROFILE=caller.PROFILE,authenticate_inside=Mock(return_value={'ok':True}))
        self.assertEqual(run.worker(api),{'ok':True})
        api.authenticate_inside.assert_called_once_with('/source','/work',caller.PROFILE)

    def test_supervisor_failure_and_cleanup_uncertainty_cannot_succeed(self):
        good=dict(status='PASS_PROCESS_ENVELOPE',returncode=0,cleanup_verified=True,cleanup_uncertainty=False,cancelled=False)
        for i,delta in enumerate([{},dict(returncode=1),dict(cleanup_verified=False),dict(cleanup_uncertainty=True),dict(cancelled=True)]):
            with self.subTest(delta=delta):
                path=self.base/str(i);path.mkdir()
                result=dict(good,**delta)
                api=types.SimpleNamespace(namespace=Mock(return_value=['fake']),supervise_selected=Mock(return_value=result))
                self.assertEqual(run.supervise(self.base/'source',path,api,object()),0 if not delta else 1)
                self.assertEqual(json.loads((path/'process-result.json').read_bytes()),result)
                api.supervise_selected.assert_called_once()

    def test_bad_layout_refuses_before_runtime_creation(self):
        path=self.base/'untouched'
        with self.assertRaises(ValueError):run.main(['--layout',str(self.base/'absent'),'--runtime',str(path)])
        self.assertFalse(path.exists())


    def seed_fixture(self):
        layout=self.base/'layout';layout.mkdir()
        first=self.base/'first';first.mkdir()
        second=self.base/'second';second.mkdir()
        target=self.base/'cache';target.mkdir(mode=0o700)
        row=dict(filename='selected.pkg.tar.xz',size=7,sha256=hashlib.sha256(b'archive').hexdigest(),
                 signature_size=9,signature_sha256=hashlib.sha256(b'signature').hexdigest())
        raw=json.dumps(dict(packages=[row])).encode()
        (layout/'profile.json').write_bytes(raw)
        self.addCleanup(patch.stopall)
        patch.object(run,'PROFILE',hashlib.sha256(raw).hexdigest()).start()
        return layout,first,second,target,row

    def test_seed_copies_only_selected_bytes_across_directories(self):
        layout,first,second,target,row=self.seed_fixture();name=row['filename']
        (first/name).write_bytes(b'archive');(second/(name+'.sig')).write_bytes(b'signature')
        (first/'reports.json').write_bytes(b'not selected');(first/'gpg-home').mkdir()
        self.assertEqual(run.seed_cache(layout,target,[first,second]),2)
        self.assertEqual({p.name for p in target.iterdir()},{name,name+'.sig'})
        self.assertEqual((target/name).read_bytes(),b'archive')
        self.assertNotEqual((target/name).stat().st_ino,(first/name).stat().st_ino)
        self.assertEqual(stat.S_IMODE((target/name).stat().st_mode),0o600)
        (target/name).write_bytes(b'changed')
        self.assertEqual((first/name).read_bytes(),b'archive')

    def test_bad_seed_hash_refuses_without_leaving_target(self):
        layout,first,second,target,row=self.seed_fixture()
        (first/row['filename']).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'hash or identity mismatch'):
            run.seed_cache(layout,target,[first])
        self.assertEqual(list(target.iterdir()),[])

    def test_selected_symlink_and_fifo_are_refused(self):
        layout,first,second,target,row=self.seed_fixture();source=first/row['filename']
        payload=self.base/'payload';payload.write_bytes(b'archive');source.symlink_to(payload)
        with self.assertRaises(OSError):run.seed_cache(layout,target,[first])
        source.unlink();os.mkfifo(source)
        with self.assertRaisesRegex(ValueError,'regular file'):run.seed_cache(layout,target,[first])
        self.assertEqual(list(target.iterdir()),[])

    def test_wrong_profile_pin_refuses_before_seeding(self):
        layout,first,second,target,row=self.seed_fixture()
        (layout/'profile.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'profile pin mismatch'):
            run.seed_cache(layout,target,[first])
        self.assertEqual(list(target.iterdir()),[])

    def test_existing_cache_file_is_not_overwritten(self):
        layout,first,second,target,row=self.seed_fixture();name=row['filename']
        (first/name).write_bytes(b'archive');(target/name).write_bytes(b'retain')
        with self.assertRaises(FileExistsError):run.seed_cache(layout,target,[first])
        self.assertEqual((target/name).read_bytes(),b'retain')

    def test_missing_seed_directory_refuses_before_copy(self):
        layout,first,second,target,row=self.seed_fixture()
        (first/row['filename']).write_bytes(b'archive')
        with self.assertRaisesRegex(ValueError,'physical directory'):
            run.seed_cache(layout,target,[first,self.base/'absent'])
        self.assertEqual(list(target.iterdir()),[])


if __name__=='__main__':unittest.main()
