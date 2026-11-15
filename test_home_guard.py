# SPDX-License-Identifier: MIT
"""Finite guard DATA and mocked filesystem facts; no quota/Btrfs/runtime calls."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_home_guard_contracts',HERE/'contracts.py')
K=importlib.util.module_from_spec(spec);spec.loader.exec_module(K)
PARENT=Path('/home/gabe/FENCED_OUTPUT_PARENT')


def declaration(phase='prepare'):
    cap=K.RESOURCES[phase+'_allocated_cap']
    return dict(issued_by='Root',status='ROOT_REVIEWED_HOME_BTRFS_ENOSYS_CAPACITY_GUARD_FOR_ENTIRE_ACTOR',
        uid=1000,output_parent=str(PARENT),device=54,phase=phase,operation=K.OP,
        source_lock={'FENCED':'DATA'},initial_headroom_bytes=cap+K.RESOURCES['reserve_bytes'],
        live_reserve_bytes=K.RESOURCES['reserve_bytes'],method='READ_ONLY_Q_GETQUOTA_ENOSYS_AND_LIVE_FSTATVFS',
        on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP',
        filesystem=dict(root='/home/gabe',device=54,fstype='btrfs',subvolume='/@home',subvolid=257),
        unsupported_own_uid_quota=dict(query='Q_GETQUOTA',errno=38,status='UNSUPPORTED_OWN_UID_QUOTA'),
        inode_counters='ZERO_MEANS_NOT_REPORTED',output_node_cap=15000,
        other_quota_availability='UNCLAIMED',capacity_reservation=False)


def guard(row,parent=PARENT,phase='prepare',uid=1000,device=54):
    auth=dict(source_lock={'FENCED':'DATA'},resource_review=dict(quota_guard=row))
    # ordinary() performs only its original canonical-path validation. All
    # filesystem observations are synthetic and actual syscall entry is fenced.
    with patch.object(K.Path,'is_symlink',return_value=False), \
         patch.object(K.Path,'stat',return_value=SimpleNamespace(st_dev=device)), \
         patch.object(K.os,'getuid',return_value=uid), \
         patch.object(K.os,'statvfs',side_effect=AssertionError('no filesystem capacity query')), \
         patch.object(K.os,'open',side_effect=AssertionError('no file/quota access')), \
         patch.object(K,'helper',side_effect=AssertionError('no runtime helper')):
        return K.quota_guard(auth,parent,phase)


class HomeGuardControls(unittest.TestCase):
    def test_exact_explicit_home_guard_for_both_phases_preserves_data(self):
        for phase in ('prepare','boot'):
            q=declaration(phase);before=copy.deepcopy(q)
            self.assertIs(guard(q,phase=phase),q);self.assertEqual(q,before)

    def test_strict_quota_mode_keeps_original_non_home_policy(self):
        q=declaration()
        for key in ('filesystem','unsupported_own_uid_quota','inode_counters','output_node_cap','other_quota_availability','capacity_reservation'):q.pop(key)
        q.update(status='ROOT_REVIEWED_OWN_UID_QUOTA_GUARD_FOR_ENTIRE_ACTOR',method='READ_ONLY_Q_GETQUOTA',uid=42,device=77,output_parent='/dev/shm/FENCED')
        self.assertIs(guard(q,parent=Path(q['output_parent']),uid=42,device=77),q)
        q['method']='READ_ONLY_Q_GETQUOTA_ENOSYS_AND_LIVE_FSTATVFS'
        with self.assertRaises(ValueError):guard(q,parent=Path(q['output_parent']),uid=42,device=77)

    def test_wrong_or_unissued_mode_never_falls_back(self):
        for key,value in (('status',None),('status','FENCED_UNKNOWN'),('issued_by',None),('method','READ_ONLY_Q_GETQUOTA')):
            q=declaration();q[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)

    def test_only_enosys_exact_quota_observation_is_accepted(self):
        for key,value in (('errno',1),('errno',22),('errno',38.0),('query','Q_GETINFO'),('status','AVAILABLE')):
            q=declaration();q['unsupported_own_uid_quota'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)

    def test_exact_btrfs_subvolume_facts_required(self):
        for key,value in (('root','/home'),('device',55),('device',54.0),('fstype','tmpfs'),('subvolume','/'),('subvolid',258),('subvolid',257.0)):
            q=declaration();q['filesystem'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)
        q=declaration();q['filesystem']['quota_available']=True
        with self.assertRaises(ValueError):guard(q)

    def test_host_uid_device_and_strict_home_descendant_whitelist(self):
        for parent in ('/home/gabe','/home/gabe-other/x','/dev/shm/FENCED','/home/gabe/x/../other'):
            q=declaration();q['output_parent']=parent
            with self.subTest(parent=parent),self.assertRaises(ValueError):guard(q,parent=Path(parent))
        for key,value in (('uid',0),('uid',1001),('uid',1000.0),('device',55),('device',54.0),('output_parent','/home/gabe/DIFFERENT')):
            q=declaration();q[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)
        with self.assertRaises(ValueError):guard(declaration(),uid=1001)
        with self.assertRaises(ValueError):guard(declaration(),device=55)

    def test_common_phase_source_and_finite_bounds_remain_exact(self):
        for key,value in (('phase','boot'),('operation','OTHER'),('source_lock',{'FENCED':'OTHER'}),
                          ('initial_headroom_bytes',4*K.GIB-1),('initial_headroom_bytes',float(4*K.GIB)),
                          ('live_reserve_bytes',2*K.GIB-1),('on_unknown_or_exhausted','CONTINUE')):
            q=declaration();q[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)
        q=declaration();q['phase']='unknown'
        with self.assertRaises(ValueError):guard(q,phase='unknown')

    def test_no_fake_inode_quota_or_reservation_claims(self):
        for key,value in (('inode_counters','ZERO_IS_AVAILABLE'),('output_node_cap',15001),('output_node_cap',14999),
                          ('output_node_cap',15000.0),('other_quota_availability','AVAILABLE'),
                          ('capacity_reservation',True),('capacity_reservation',0),('claimed_free_inodes',12345)):
            q=declaration();q[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):guard(q)

    def test_new_template_contains_no_authority_or_runtime_observation(self):
        q=json.loads((HERE/'quota-guard-home-btrfs.TEMPLATE.json').read_bytes())
        def empty(value):return all(empty(v) for v in value.values()) if type(value) is dict else value is None
        self.assertTrue(empty(q))
        with self.assertRaises(ValueError):guard(q)


if __name__=='__main__':unittest.main()
