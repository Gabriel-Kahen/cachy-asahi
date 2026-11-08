#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""New membership DATA and synthetic strict-reader controls; no native capsule."""
import sys

def deny(event,args):
    if event.startswith(('socket.','subprocess.','ctypes.','pty.'))or event in ('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn'):
        raise RuntimeError('actor forbidden: '+event)

sys.addaudithook(deny)
import argparse
import ast
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_owner_data as controls


class GuestGroupsV3Data(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(prefix='guest-groups-v3-new-DATA-')
        self.addCleanup(self.work.cleanup)
        self.fixture=controls.ports.Fixture(Path(self.work.name)/'owner')

    def test_only_valid_or_single_duplicate_primary_membership(self):
        with self.fixture.ports():
            m=self.fixture.module
            for groups,status in [([998,1001],'EXACT_GROUP_MEMBERSHIP'),([1001,998],'EXACT_GROUP_MEMBERSHIP'),
                                  ([998,1001,1001],'SINGLE_DUPLICATE_PRIMARY_GID')]:
                self.assertEqual(m.guest_groups_v3(groups),status)
            for groups in (None,(),[],[998],[1001],[0,998,1001],[998,1002],[998,998,1001],
                           [998,1001,1001,1001],[998]*10000,[998,1001.0],[998,True],['998',1001]):
                with self.subTest(groups=str(groups)[:80]),self.assertRaises(m.MatrixGuard):m.guest_groups_v3(groups)
            valid=dict(uid=1001,euid=1001,gid=1001,egid=1001,groups=[998,1001,1001],group_count=3,groups_truncated=False)
            self.assertEqual(m.process_groups_v3(valid),'SINGLE_DUPLICATE_PRIMARY_GID')
            for key,value in [('uid',0),('euid',0),('gid',0),('egid',0),('uid',1001.0),
                              ('groups_truncated',True),('group_count',2),('group_count',3.0),('extra',False)]:
                with self.subTest(key=key),self.assertRaises(m.MatrixGuard):m.process_groups_v3(dict(valid,**{key:value}))

    def test_old_v2_refusal_and_v3_diagnostic_preserve_observed_raw_groups(self):
        with self.fixture.ports():
            m=self.fixture.module;args=SimpleNamespace(case='baseline',image='sha256:'+'a'*64)
            with patch.object(m.os,'getuid',return_value=1001),patch.object(m.os,'geteuid',return_value=1001),\
                 patch.object(m.os,'getgid',return_value=1001),patch.object(m.os,'getegid',return_value=1001),\
                 patch.object(m.os,'getgroups',return_value=[998,1001,1001]),\
                 patch.object(m.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(m,'Path',SimpleNamespace(cwd=lambda:Path('/tmp'))):
                old=m.guest_identity_data_v2(args);new=m.guest_identity_data_v3(args)
                self.assertEqual(old['failed_checks'],['groups']);self.assertEqual(new['failed_checks'],[])
                self.assertEqual(new['observed'],old['observed']);self.assertEqual(new['observed']['groups'],[998,1001,1001])
                self.assertEqual(new['group_comparison']['status'],'SINGLE_DUPLICATE_PRIMARY_GID')
                with patch.object(m.os,'getgroups',return_value=[0,998,1001]):
                    self.assertEqual(m.guest_identity_data_v3(args)['failed_checks'],['groups'])
                with patch.object(m.os,'geteuid',return_value=0):
                    self.assertIn('euid',m.guest_identity_data_v3(args)['failed_checks'])

    def test_explicit_guest_route_inverse_has_only_one_predicate_change(self):
        text=(Path(__file__).resolve().parents[1]/'payload/native/platform_namespace_policy_v1.py').read_text();tree=ast.parse(text)
        old=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='guest')
        new=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_guest_process_v3')
        source=ast.get_source_segment(text,new).replace('def _guest_process_v3(args):','def guest(args):')
        self.assertEqual(source.count('guest_groups_v3(os.getgroups())'),1)
        inverse=source.replace('guest_groups_v3(os.getgroups())','sorted(os.getgroups())==[998,1001]')
        self.assertEqual(ast.dump(ast.parse(inverse).body[0],include_attributes=False),ast.dump(old,include_attributes=False))

    def test_owner_and_matching_new_synthetic_reader_keep_first_line_and_raw_counts(self):
        f=self.fixture;f.template['process'].update(groups=[998,1001,1001],group_count=3)
        with f.ports():
            f.run();self.assertEqual(f.diagnostic['status'],controls.COMPLETE)
            marker=f.diagnostic['guest_group_comparison'];self.assertEqual(marker['duplicate_primary_gid_cases'],list(f.module.CASES))
            original=controls.ports.encoded(f.result)
            for row in f.result['cases']:
                self.assertEqual(row['context']['process']['groups'],[998,1001,1001]);self.assertEqual(row['context']['process']['group_count'],3)
                raw=__import__('base64').b64decode(row['output']['raw_b64'],validate=True)
                self.assertEqual(raw.splitlines()[0],f.module.PREFIX+controls.ports.encoded(row['context']))
            with self.assertRaises(f.module.MatrixGuard):
                f.module._frozen_context(f.result['cases'][0]['context'],json.loads(f.bodies[f.module.CONTRACT]),controls.ports.MAP,'baseline')
            _,payloads=controls.project(f);retained=dict(payloads);read=controls.read(f,payloads)
            self.assertEqual(read['projection_status'],controls.COMPLETE);self.assertEqual(read['raw_result'],f.result)
            self.assertEqual(controls.ports.encoded(f.result),original);self.assertEqual(payloads,retained)
            self.assertEqual(read['qualification']['guest_group_comparison'],marker)
            self.assertEqual(read['runtime_qualification']['guest_group_comparison'],marker)
            owner=copy.deepcopy(f.owner);owner['guest_group_comparison']['duplicate_primary_gid_cases']=[]
            with self.assertRaisesRegex(f.module.MatrixGuard,'independently recomputed raw group'):
                f.module.validate_runtime_evidence(owner,f.result,controls.raw_payloads(f),controls.expected(f),controls.source_proof(f))
            result=copy.deepcopy(f.result);result['cases'][0]['context']['process'].update(groups=[998,1001],group_count=2)
            with self.assertRaisesRegex(f.module.MatrixGuard,'exact canonical actual context/output inverse'):
                f.module.validate_result(result,json.loads(f.bodies[f.module.CONTRACT]),controls.expected(f))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--basis',required=True,type=Path)
    args,rest=parser.parse_known_args();controls.ports.configure_basis(args.basis.resolve(strict=True))
    unittest.main(argv=[sys.argv[0],*rest])
