#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic 587-name capacity fixtures; never the real 587-package composition."""
import argparse
import json
import functools
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from test_snapshot import module, encoded, digest, make_bundle, make_envelope

legacy = module('legacy_tiny_transaction_tests',Path(__file__).with_name('test_bound_update.py'))
scale = module('scale_under_test',Path(__file__).with_name('scale_update.py'))


class ScaleTransactions(unittest.TestCase):
    setUpClass = classmethod(legacy.ActualTransactions.setUpClass.__func__)
    assert_refused = legacy.ActualTransactions.assert_refused
    run_update = legacy.ActualTransactions.run_update

    def setUp(self):
        legacy.ActualTransactions.setUp(self)
        local=self.root/'var/lib/pacman/local'
        for index in range(580):
            name=f'synthetic-held-{index:03d}'
            self.versions[name]='1-1'
            self.owned[name]=[]
            directory=local/(name+'-1-1'); directory.mkdir()
            (directory/'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
            (directory/'files').write_text('%FILES%\n\n')
        self.base=[dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=self.owned[name])
                   for name,version in self.versions.items()]
        self.select('gz')
        self.args.measure_only=False
        self.args.scale=str(self.case/'scale.json')
        self.config=dict(schema_version=1,purpose='disposable-bound-update-scale',platform_mode='apple',
            before_lock_sha256=scale.inventory_sha(self.versions),
            after_lock_sha256=scale.inventory_sha(dict(self.versions,fixture='1-1')),
            limits=dict(root_nodes=10000,root_bytes=64*1024**2,file_bytes=8*1024**2,package_files=10000,
                archive_bytes=8*1024**2,archive_total_bytes=16*1024**2,decoded_bytes=32*1024**2,
                archive_members=10000,window_bytes=64*1024**2,seconds=30),
            capacity=dict(root_reserve_bytes=1024**2,root_reserve_inodes=100,
                workspace_future_bytes=1024**2,workspace_future_inodes=100))
        self.configure()

    def configure(self):
        Path(self.args.scale).write_bytes(encoded(self.config))
        self.args.scale_sha256=digest(self.args.scale)

    def select(self,compression):
        shutil.rmtree(self.bundle)
        self.bundle=make_bundle(self.case,self.signer,self.sign,base_packages=self.base,compression=compression)
        self.metadata.unlink()
        make_envelope(self.case,self.bundle,self.signer,self.public,self.sign)
        release=json.loads((self.bundle/'release.json').read_text())
        self.policy['transitions'][0]['evidence_sha256']=dict(release_manifest=digest(self.bundle/'release.json'),
                                                            transition_validation=release['files']['base.json'])
        self.policy_path.write_bytes(encoded(self.policy));self.args.policy_sha256=digest(self.policy_path)
        self.settings.update(metadata_sha256=digest(self.metadata),release_sha256=digest(self.bundle/'release.json'))
        self.settings_path.write_bytes(encoded(self.settings));self.args.settings_sha256=digest(self.settings_path)

    def invoke(self):
        read,write=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read)
            try:
                # This host's Btrfs reports no free-inode count. Test a declared
                # synthetic inode budget while retaining real byte availability;
                # production has no fallback and refuses unknown inode counts.
                real_statvfs=os.statvfs
                override=[]
                def fixture_statvfs(path):
                    info=real_statvfs(path)
                    if info.f_favail==0 and info.f_files==0:
                        values=list(info);values[5]=values[6]=values[7]=1000000
                        override.append(True)
                        return os.statvfs_result(values)
                    return info
                check=scale.space.check
                with mock.patch.object(scale.space,'check',functools.partial(check,statvfs=fixture_statvfs)):
                    row=scale.apply(self.args)
                row['synthetic_inode_budget_injected']=bool(override)
                with os.fdopen(write,'wb') as stream:stream.write(encoded(row))
            finally:os._exit(0)
        os.close(write)
        with os.fdopen(read,'rb') as stream:data=stream.read(1024**2+1)
        _,status=os.waitpid(pid,0);self.assertEqual(status,0);self.assertLessEqual(len(data),1024**2)
        return json.loads(data)

    def upgrade(self,compression):
        self.select(compression)
        row=self.run_update()
        self.assertEqual(row['status'],'PASS',row)
        self.assertEqual(len(row['before']),587)
        self.assertEqual(row['after'],dict(row['before'],fixture='1-1'))
        self.assertTrue(row['packages_committed'])
        self.assertEqual(row['prepared_add'],{'fixture':'1-1'})
        self.assertEqual(row['full587_composition'],'NOT ESTABLISHED')
        self.assertEqual((self.root/'usr/share/fixture/config').read_bytes(),b'TEST ONLY\n')

    def test_actual_gzip_single_upgrade_holds586_synthetic_versions(self): self.upgrade('gz')
    def test_actual_xz_single_upgrade_holds586_synthetic_versions(self): self.upgrade('xz')
    def test_actual_zstd_single_upgrade_holds586_synthetic_versions(self): self.upgrade('zst')

    def test_insufficient_capacity_refuses_before_commit(self):
        self.config['capacity']['root_reserve_bytes']=64*1024**3;self.configure()
        self.assert_refused(self.run_update(),'insufficient')

    def test_scale_input_drift_after_prepare_refused(self):
        precommit=scale.Runtime.precommit
        def change(runtime):
            Path(runtime.args.scale).write_bytes(Path(runtime.args.scale).read_bytes()+b' ')
            return precommit(runtime)
        with mock.patch.object(scale.Runtime,'precommit',change):
            self.assert_refused(self.run_update(),'scale configuration changed')

    def test_existing_ldconfig_still_refuses(self):
        path=self.root/'usr/bin/ldconfig';path.parent.mkdir(parents=True)
        path.write_bytes(b'#!/bin/sh\nexit 99\n');path.chmod(0o755)
        self.assert_refused(self.run_update(),'auxiliary-present')

    def test_absent_required_platform_package_is_not_synthesized(self):
        runtime=scale.Runtime(self.args,self.config)
        before=dict(self.versions);before.pop('speakersafetyd');before['generic-audio']='1-1'
        with self.assertRaisesRegex(ValueError,'actual protected platform packages absent'):
            runtime.authorize(self.policy,self.settings,{},before,before,{}, {})

    def test_explicit_generic_mode_uses_real_observed_names_without_apple_fallback(self):
        renamed={'asahi-audio':'glibc','speakersafetyd':'pacman','fixture-asahi-kernel':'linux-aarch64'}
        local=self.root/'var/lib/pacman/local'
        for old,new in renamed.items():
            version=self.versions.pop(old);self.versions[new]=version
            self.owned[new]=self.owned.pop(old)
            oldpath=local/(old+'-'+version);newpath=local/(new+'-'+version);oldpath.rename(newpath)
            path=newpath/'desc';path.write_text(path.read_text().replace('\n'+old+'\n','\n'+new+'\n'))
        self.base=[dict(name=name,version=version,arch='any',depend=[],provides=[],conflict=[],files=self.owned[name])
                   for name,version in self.versions.items()]
        self.select('zst')
        self.config.update(platform_mode='generic-development',before_lock_sha256=scale.inventory_sha(self.versions),
            after_lock_sha256=scale.inventory_sha(dict(self.versions,fixture='1-1')))
        self.configure()
        generic=dict(schema_version=1,purpose='cachy-asahi-generic-development-update-policy',release_id='fixture-1',
            protected_packages=sorted(set(self.versions)-{'fixture'}),
            protected_versions={name:version for name,version in self.versions.items() if name!='fixture'},
            platform_roles={'kernel':['linux-aarch64']},protected_units=self.policy['protected_units'],
            before_lock_sha256=self.config['before_lock_sha256'],after_lock_sha256=self.config['after_lock_sha256'])
        self.policy_path.write_bytes(encoded(generic));self.args.policy_sha256=digest(self.policy_path)
        self.settings['model']='generic-development-only'
        self.settings_path.write_bytes(encoded(self.settings));self.args.settings_sha256=digest(self.settings_path)
        row=self.run_update();self.assertEqual(row['status'],'PASS',row)
        self.assertEqual(row['platform_mode'],'generic-development')
        self.assertEqual(row['apple_acceptance'],'NOT ESTABLISHED')
        self.assertNotIn('speakersafetyd',row['before']);self.assertNotIn('asahi-audio',row['before'])
        self.assertEqual(row['after'],dict(row['before'],fixture='1-1'))

    def test_explicit_generic_mode_does_not_accept_an_apple_policy_file(self):
        self.config['platform_mode']='generic-development';self.configure()
        self.assert_refused(self.run_update(),'generic development policy')

    def test_supervised_cli_preserves_known_worker_failure_truth(self):
        argv=[sys.executable,'-B',str(Path(__file__).with_name('scale_update.py'))]
        for key in ('root','workspace','settings','settings_sha256','policy','bundle','metadata','signature',
                    'public_keyring','state_dir','scale','scale_sha256'):
            argv.extend(['--'+key.replace('_','-'),str(getattr(self.args,key))])
        argv.extend(['--policy-sha256','0'*64])
        completed=subprocess.run(argv,capture_output=True,timeout=40)
        row=json.loads(completed.stdout)
        self.assertEqual(completed.returncode,1)
        self.assert_refused(row)
        self.assertIs(row['packages_committed'],False);self.assertIs(row['checkpoint_changed'],False)

    def test_measure_only_has_no_package_or_checkpoint_mutation(self):
        self.args.measure_only=True
        row=self.invoke()
        self.assertEqual(row['status'],'MEASURED',row)
        self.assertGreater(row['footprint']['database_files'],587)
        self.assertFalse(row['packages_committed']);self.assertFalse(row['checkpoint_changed'])
        self.assertEqual(list(self.state.iterdir()),[])


class ScaleReportingTruth(unittest.TestCase):
    def setUp(self):
        self.args=argparse.Namespace(root='/owned/root',workspace='/owned/work',scale='scale',scale_sha256='pin',
            measure_only=False,settings='settings',settings_sha256='pin',policy='policy',policy_sha256='pin',
            bundle='bundle',metadata='metadata',signature='signature',public_keyring='keyring',state_dir='state')
        patcher=mock.patch.object(scale.bound,'guard',return_value=None)
        patcher.start();self.addCleanup(patcher.stop)
        patcher=mock.patch.object(scale,'configuration',return_value={'platform_mode':'generic-development'})
        patcher.start();self.addCleanup(patcher.stop)

    def test_reporting_fault_after_committed_return_preserves_known_facts(self):
        class ReportingFault:
            @property
            def footprints(self):raise RuntimeError('post-return reporting fault')
        committed=dict(status='PASS',commit_started=True,packages_committed=True,checkpoint_changed=True,
                       before={'fixture':'0-1'},after={'fixture':'1-1'})
        with mock.patch.object(scale,'Runtime',return_value=ReportingFault()), \
             mock.patch.object(scale.bound,'apply',return_value=committed):
            row=scale.apply(self.args)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['phase'],'scale-reporting')
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertIs(row[field],True)
        self.assertEqual(row['before'],committed['before']);self.assertEqual(row['after'],committed['after'])

    def test_interrupted_delegation_without_terminal_result_is_unknown(self):
        with mock.patch.object(scale,'Runtime'),mock.patch.object(scale.bound,'apply',side_effect=KeyboardInterrupt):
            row=scale.apply(self.args)
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertEqual(row[field],'UNKNOWN')

    def test_predelegation_failure_is_known_uncommitted(self):
        with mock.patch.object(scale,'Runtime',side_effect=ValueError('configuration fault')), \
             mock.patch.object(scale.bound,'apply') as delegate:
            row=scale.apply(self.args)
        delegate.assert_not_called()
        for field in ('commit_started','packages_committed','checkpoint_changed'):
            self.assertIs(row[field],False)


if __name__=='__main__':unittest.main(verbosity=2)
