# SPDX-License-Identifier: MIT
"""Synthetic metadata DATA controls; never invokes observe(), CLI or any actor."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_image_probe_data', HERE/'payload/hosted/image_probe.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def fixture():
    # Static lock DATA is copied into the model, not queried from this machine.
    lock = (HERE/'expected349.lock').read_text()
    config = {'/etc/pacman.conf':dict(type='file',mode=0o644,bytes=12,sha256='a'*64)}
    hooks = {root:{'.':dict(type='directory',mode=0o755)} for root in p.HOOK_ROOTS}
    observed = dict(schema=1,kind=p.KIND,machine='aarch64',page_bytes=4096,
        runtime=dict(uid=0,euid=0,gid=0,egid=0,status={**{key:'0000000000000000' for key in p.CAP_FIELDS},'Uid':'0 0 0 0','Gid':'0 0 0 0','NoNewPrivs':'1'},cgroup=dict(p.LIMITS),interfaces=['lo'],mountinfo='1 0 0:1 / / ro - overlay overlay ro\n'),
        package_inventory=p.inventory_data(lock.encode()),config_files=config,hook_snapshots=hooks,
        baseline_public_trust={name:dict(type='file',mode=0o600,bytes=8,sha256='b'*64) for name in p.PUBLIC_FILES},
        baseline_public_trust_policy=p.PUBLIC_POLICY,observed_metadata_file_bytes=len(lock.encode())+28)
    expected = dict(reviewed=True,complete_hook_snapshots=True,config_files=copy.deepcopy(config),hook_snapshots=copy.deepcopy(hooks),baseline_public_trust=p.PUBLIC_POLICY)
    return observed,expected


class ImageProbeTests(unittest.TestCase):
    def test_pure_metadata_join_has_no_runtime_qualification(self):
        result = p.compare(*fixture())
        self.assertEqual(result['root_rw_lifecycle_qualification'],'NOT_ISSUED_BY_THIS_PROBE')

    def test_each_capability_set_and_nnp_must_be_zero_one(self):
        for key in (*p.CAP_FIELDS,'NoNewPrivs'):
            observed,_ = fixture()
            observed['runtime']['status'][key] = '0' if key == 'NoNewPrivs' else '1'
            with self.assertRaises(ValueError):
                p.validate_domain(observed['runtime'])

    def test_root_credentials_and_loopback_only_domain(self):
        for field,value in (('uid',1001),('interfaces',['lo','eth0'])):
            observed,_ = fixture()
            observed['runtime'][field] = value
            with self.assertRaises(ValueError):
                p.validate_domain(observed['runtime'])

    def test_readonly_unique_root_required(self):
        for raw in ('1 0 0:1 / / rw - overlay overlay rw\n', '1 0 0:1 / / ro - overlay overlay ro\n2 0 0:2 / / ro - overlay overlay ro\n'):
            with self.assertRaises(ValueError):
                p.readonly_root(raw)

    def test_all_metadata_resource_limits_are_exact(self):
        for key in p.LIMITS:
            observed,_ = fixture()
            observed['runtime']['cgroup'][key] = 'max'
            with self.assertRaises(ValueError):
                p.validate_domain(observed['runtime'])

    def test_wrong_machine_or_page_size_refuses(self):
        for key,value in (('machine','x86_64'),('page_bytes',16384)):
            observed,expected = fixture()
            observed[key] = value
            with self.assertRaises(ValueError):
                p.compare(observed,expected)

    def test_unreviewed_or_changed_config_and_hooks_refuse(self):
        for change in ('unreviewed','config','hook'):
            observed,expected = fixture()
            if change == 'unreviewed':
                expected['reviewed'] = False
            elif change == 'config':
                observed['config_files']['/etc/pacman.conf']['sha256'] = 'c'*64
            else:
                observed['hook_snapshots'][p.HOOK_ROOTS[0]]['extra.hook'] = dict(type='file',mode=0o644,bytes=1,sha256='d'*64)
            with self.assertRaises(ValueError):
                p.compare(observed,expected)

    def test_fresh_baseline_public_bytes_are_observed_not_predicted(self):
        observed,expected = fixture()
        observed['baseline_public_trust'][p.PUBLIC_FILES[0]]['sha256'] = 'c'*64
        p.compare(observed,expected)
        del observed['baseline_public_trust'][p.PUBLIC_FILES[1]]
        with self.assertRaises(ValueError):
            p.compare(observed,expected)

    def test_file_hashes_exact_readonly_modes_without_executing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'metadata'
            path.write_bytes(b'PASSIVE METADATA DATA\n')
            for mode in (0o444,0o555):
                path.chmod(mode)
                row = p.file_data(path)
                self.assertEqual(row,dict(type='file',mode=mode,bytes=22,sha256=hashlib.sha256(b'PASSIVE METADATA DATA\n').hexdigest()))

    def test_snapshot_never_follows_symlink_and_records_absent_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'hooks'
            root.mkdir()
            (root/'mask.hook').symlink_to('/dev/null')
            row = p.snapshot(root)
            self.assertEqual(row['mask.hook'],dict(type='symlink',mode=0o777,target='/dev/null'))
            self.assertEqual(p.snapshot(Path(directory)/'absent'),{'.':{'type':'absent'}})
            alias = Path(directory)/'alias'
            alias.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):
                p.snapshot(alias)

    def test_special_file_and_oversized_metadata_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root/'fifo')
            with self.assertRaises(ValueError):
                p.node(root/'fifo')
            file = root/'file'
            file.write_bytes(b'12345')
            with self.assertRaises(ValueError):
                p.file_data(file,cap=4)

    def test_metadata_file_budget_is_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('one','two'):
                (root/name).write_bytes(b'1234')
            budget = {'bytes':0}
            with patch.object(p,'METADATA_CAP',7):
                p.file_data(root/'one',budget=budget)
                with self.assertRaisesRegex(ValueError,'aggregate metadata'):
                    p.file_data(root/'two',budget=budget)

    def test_inventory_content_and_outer_json_cap_are_checked(self):
        with self.assertRaises(ValueError):
            p.inventory_data(b'perl 5.42.3-1\n')
        with patch.object(p,'METADATA_CAP',1):
            with self.assertRaisesRegex(ValueError,'16 MiB'):
                p.encoded({'fixture':'bounded'})


if __name__ == '__main__':
    unittest.main()
