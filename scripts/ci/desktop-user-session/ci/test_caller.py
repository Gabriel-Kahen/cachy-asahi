"""Inert caller/pinning/export controls; no Docker, seed, VM or service actor."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('managed_ci_controls',HERE/'caller.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
ROOT=HERE.parents[3]
SOURCE=ROOT if (ROOT/c.LANE/'prepare.py').is_file() else HERE/'validation-source'
MANIFEST=HERE/'source-manifest.json'


def write(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(c.encoded(value))


def unit(name,pid=0,state='active',sub='exited'):
    return dict(Id=name,LoadState='loaded',ActiveState=state,SubState=sub,Result='success',
                MainPID=pid,ExecMainCode=0,ExecMainStatus=0)


def events():
    names=['user@23001.service','user-runtime-dir@23001.service']
    identity=dict(status='PASS',address='unix:path=/run/user/23001/bus',uid=23001,
                  manager_pid=422,default_target='GetUnit-PASS')
    return [dict(event='managed_session_ready',**identity,units={
                'systemd-user-sessions.service':unit('systemd-user-sessions.service'),
                names[0]:unit(names[0],422,sub='running'),names[1]:unit(names[1])}),
            dict(event='managed_user_ready',**identity),
            dict(event='phase_pass',stage='minimal'),dict(event='phase_pass',stage='overlay'),
            dict(event='session_pass',status='PASS'),
            dict(event='managed_session_cleanup',status='PASS',units=names,
                 unit_states={n:unit(n,state='inactive',sub='dead') for n in names},
                 runtime_absent=True,owned_units_stopped=True),dict(event='complete',status='PASS')]


class PinsAndPreparation(unittest.TestCase):
    def setUp(self):
        self.pin=c.sha(MANIFEST.read_bytes())
        self.manifest=c.verify(SOURCE,MANIFEST,self.pin)

    def test_exact_adoption_closure_and_manifest_digest(self):
        self.assertEqual(self.manifest['lane'],'scripts/ci/desktop-user-session')
        with self.assertRaises(ValueError):c.verify(SOURCE,MANIFEST,'0'*64)

    def test_workflow_is_manual_separate_pinned_and_has_always_retention(self):
        path=HERE/'workflow.yml'
        if not path.is_file():path=ROOT/'.github/workflows/native-arm-managed-user-session.yml'
        workflow=path.read_text()
        self.assertIn('workflow_dispatch:',workflow)
        self.assertNotIn('\n  push:',workflow)
        self.assertIn('LANE: scripts/ci/desktop-user-session',workflow)
        self.assertNotIn('      BASE: ${{ runner.temp }}',workflow)
        self.assertIn('>> "$GITHUB_ENV"',workflow)
        self.assertIn(self.pin,workflow)
        self.assertIn(c.sha((HERE/'caller.py').read_bytes()),workflow)
        self.assertIn('04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',workflow)
        self.assertIn('--job-token "$(cat "$TRIAL/job-token")"',workflow)
        self.assertEqual(workflow.count('if: always()'),3)
        self.assertIn('path: ${{ runner.temp }}/desktop-managed-trial/public/',workflow)
        self.assertNotIn('desktop-bar-notifications',workflow)

    def test_changed_source_or_source_alias_refuses_before_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'source'
            for name in self.manifest['source_files']:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(SOURCE/name,target)
            path=root/c.LANE/'managed_session.py';path.write_text('changed source\n')
            with self.assertRaisesRegex(ValueError,'source bytes differ'):c.verify(root,MANIFEST,self.pin)
            path.unlink();path.symlink_to(SOURCE/c.LANE/'managed_session.py')
            with self.assertRaisesRegex(ValueError,'ordinary absolute'):c.verify(root,MANIFEST,self.pin)

    def test_preparation_and_isolated_runtime_binding_do_not_run_native_actors(self):
        with tempfile.TemporaryDirectory() as directory:
            trial=Path(directory)/'trial'
            receipt=c.prepare(SOURCE,trial,self.manifest,'a'*40)
            self.assertEqual(receipt['status'],'READY_NOT_RUN')
            self.assertRegex(receipt['job_token'],'^[0-9a-f]{16}$')
            argv=c.runtime_argv(SOURCE,trial,Path('/unused/base'),self.manifest)
            self.assertEqual(argv[1:4],['-I','-B','-c'])
            self.assertEqual(argv[4],c.ENTRY)
            self.assertEqual(argv[5],str(trial/'runner'))
            self.assertIn('--base-dir',argv)
            (trial/'runner/managed_session.py').write_text('changed')
            with self.assertRaises(ValueError):c.runtime_argv(SOURCE,trial,Path('/unused/base'),self.manifest)


class Retention(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);self.trial=root/'trial';self.base=root/'base'
        self.trial.mkdir();self.base.mkdir()

    def success(self):
        image='sha256:'+'1'*64
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',packages=574,image=image,
            owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),
                               probe=dict(absence_verified=True)))
        inputs=json.loads((SOURCE/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
        expected=''.join(f"{r['name']} {r['version']}\n" for r in sorted(inputs['packages'],key=lambda r:r['name']))
        (self.base/'installed-packages.lock').write_text(expected)
        write(self.base/'report.json',original)
        frames={}
        for stage in ('minimal','overlay'):
            data=b'P6\n1024 768\n255\n'+b'\0\0\0'*(1024*768-1)+b'\xff\xff\xff'
            path=self.trial/'runtime/frames'/(stage+'.ppm');path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data);frames[stage]=c.ppm(data)
        runtime=dict(status=c.PASS,runtime_package_count=591,base_image=image,events=events(),
            managed_session={'status':'PASS'},base_reference_cleanup={'ok':True},
            cleanup=[{'exit':0},{'guest_disk_removed':True}],frames=frames)
        write(self.trial/'runtime/runtime.json',runtime)
        return original,runtime

    def test_complete_pixels_and_all_actual_report_gates_required(self):
        self.success()
        receipt=c.retain(SOURCE,self.trial,self.base)
        self.assertEqual(receipt['native_gate'],'PASS')
        self.assertEqual(set(receipt['frames']),{'minimal','overlay'})
        self.assertEqual(receipt['visual_review'],'ROOT REQUIRED')
        self.assertLess(receipt['retained_bytes_before_receipt'],16*1024**2)

    def test_missing_or_failed_manager_cleanup_or_pixel_cannot_pass(self):
        original,runtime=self.success()
        frames=copy.deepcopy(runtime['frames'])
        for change in ('user','vm-cleanup','base-cleanup','pixel','inventory'):
            current=copy.deepcopy(runtime);base=copy.deepcopy(original);selected=copy.deepcopy(frames)
            if change=='user':current['events'][1]['manager_pid']=999
            elif change=='vm-cleanup':current['cleanup'][0]['exit']=1
            elif change=='base-cleanup':base['owned_cleanup']['image']['absence_verified']=False
            elif change=='pixel':selected['minimal']['sha256']='0'*64
            elif change=='inventory':current['runtime_package_count']=590
            write(self.trial/'runtime/runtime.json',current);write(self.base/'report.json',base)
            with self.subTest(change=change),self.assertRaises(ValueError):c.native_gate(SOURCE,self.base,self.trial,selected)

    def test_failed_trial_still_retains_bounded_diagnostic_tails(self):
        path=self.trial/'runtime/events.log';path.parent.mkdir()
        path.write_bytes(b'x'*(2*1024**2+17))
        forbidden=self.trial/'runtime/context/private.pkg.tar.xz';forbidden.parent.mkdir();forbidden.write_bytes(b'do not export')
        receipt=c.retain(SOURCE,self.trial,self.base)
        self.assertEqual(receipt['native_gate'],'FAIL')
        row=receipt['files']['runtime/events.log']
        self.assertTrue(row['truncated']);self.assertEqual(row['retained_bytes'],2*1024**2)
        self.assertFalse(any(p.name==forbidden.name for p in (self.trial/'public').rglob('*')))

    def test_export_refuses_symlinks_and_malformed_or_uniform_frames(self):
        path=self.trial/'runtime';path.mkdir();(path/'events.log').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'ordinary absolute'):c.retain(SOURCE,self.trial,self.base)
        for data in (b'P6\n1 1\n255\nabc',b'P6\n1024 768\n255\n'+b'\0'*(1024*768*3)):
            with self.subTest(size=len(data)),self.assertRaises(ValueError):c.ppm(data)


if __name__=='__main__':unittest.main()
