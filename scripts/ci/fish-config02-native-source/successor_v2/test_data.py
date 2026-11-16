#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fenced DATA controls; no actor, privilege, service, cgroup or process entry."""
import ast
import copy
import importlib.util
import json
import os
import types
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
WORKFLOW=REPO/'.github/workflows/native-arm-fish-config02-source-v2.yml'


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.fork','os.exec','os.posix_spawn','resource.setrlimit'):
        raise RuntimeError('DATA-only actor fence: '+event)


sys.addaudithook(fence)


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


D=module('fish02_v2_test_data',HERE/'data.py');P=module('fish02_v2_test_prepare',HERE/'prepare.py')
B=module('fish02_v2_held32_prepare',HERE.parent/'prepare.py')
R=module('fish02_v2_test_retain',HERE/'retain.py')
# Importing either operational module must have no process/resource/namespace side effects.
O=module('fish02_v2_test_owner',HERE/'hosted_owner.py');Y=module('fish02_v2_test_payload',HERE/'payload.py')
POLICY=D.decode((HERE/'policy.json').read_bytes())


def raw(value):return json.dumps(value,sort_keys=True).encode()



def read_with_drift(reader, field=None, content=False):
    with tempfile.TemporaryDirectory(prefix='fish-read-stability-DATA-') as temporary:
        path=Path(temporary)/'leaf';path.write_bytes(b'PAYLOAD')
        initial=path.stat();original_stat=Path.lstat;original_read=Path.read_bytes;done=False
        fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_atime','st_atime_ns','st_mtime','st_ctime')
        def observed(p,*args,**kwargs):
            value=original_stat(p,*args,**kwargs)
            if p!=path or content:return value
            values={name:getattr(value,name) for name in fields}
            if done:values[field]+=1
            return types.SimpleNamespace(**values)
        def consume(p,*args,**kwargs):
            nonlocal done
            raw=original_read(p,*args,**kwargs)
            if p==path:
                done=True
                if content:
                    path.write_bytes(b'MUTATED')
                    os.utime(path,ns=(initial.st_atime_ns,initial.st_mtime_ns+1))
            return raw
        with patch.object(Path,'lstat',observed),patch.object(Path,'read_bytes',consume):
            return reader(path)

class Controls(unittest.TestCase):
    def test_read_atime_only_change_is_allowed(self):
        self.assertEqual(read_with_drift(D.read,'st_atime_ns'),b'PAYLOAD')
        self.assertEqual(read_with_drift(D.read,'st_atime'),b'PAYLOAD')
        def prior_whole_stat_read(path):
            before=path.lstat();raw=path.read_bytes()
            if path.lstat()!=before:raise ValueError('prior atime false HOLD')
            return raw
        with self.assertRaisesRegex(ValueError,'atime false HOLD'):
            read_with_drift(prior_whole_stat_read,'st_atime_ns')

    def test_read_content_and_each_security_metadata_change_refuse(self):
        for field in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'):
            with self.subTest(field=field),self.assertRaises(ValueError):read_with_drift(D.read,field)
        with self.assertRaises(ValueError):read_with_drift(D.read,content=True)

    @classmethod
    def setUpClass(cls):
        cls.held_temp=tempfile.TemporaryDirectory(prefix='fish02-held32-DATA-')
        cls.addClassCleanup(cls.held_temp.cleanup)
        cls.base=Path(cls.held_temp.name)/'Source32'
        B.construct(REPO,cls.base)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source'
        self.result=P.construct(self.base,WORKFLOW,self.root);self.map=self.result['source_map']['sha256']
        self.env=dict(GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/codex/synthetic-fish-owner',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',
                      GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='99')
        profile=D.decode((self.base/D.BASE_PREFIX/'profile.json').read_bytes())
        common=dict(accepted=True,issued_by='Root',created_utc=100,expires_utc=300,nonce='b'*32,
                    ref=self.env['GITHUB_REF'],source=self.env['GITHUB_SHA'],source_map_sha256=self.map,resources=profile['resources'])
        # Explicit synthetic model grants; never persisted/published as actual Root authority.
        self.a=dict(common,kind='ROOT_FISH02_HOSTED_ADMISSION_V1')
        self.r=dict(common,kind='ROOT_FISH02_HOSTED_RUNTIME_V1',external_supervision=self.result['owner_program'],
                    bootstrap_resource_domain=self.result['bootstrap_resource_domain'])

    def admit(self):
        a,r=raw(self.a),raw(self.r)
        return D.admission(self.root,self.map,a,r,D.pin(a)['sha256'],D.pin(r)['sha256'],self.env,200)

    def test_complete_successor_preserves_whole32_and_null_actuals(self):
        value=D.source(self.root,self.map)
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertEqual(len([n for n in value['files'] if n.startswith('held-source32/')]),32)
        self.assertEqual(sum(v['bytes'] for n,v in value['files'].items() if n.startswith('held-source32/')),D.BASE_BYTES)
        self.admit()
        proof_path=self.root/D.PREFIX/'base-read-delta.json';original=proof_path.read_bytes()
        proof=D.decode(original);proof['changes'][0]['seams'][0]['after']='MISSING_INVERSE_SEAM'
        proof_path.write_bytes(json.dumps(proof).encode())
        current=D.decode((self.root/'held-source32'/D.BASE_PREFIX/'source-map.json').read_bytes())
        with self.assertRaises(ValueError):D.original_base(self.root,current)
        proof_path.write_bytes(original)

    def test_outer_body_mode_missing_extra_and_source32_tamper_refuse(self):
        path=self.root/D.PREFIX/'payload.py';original=path.read_bytes()
        for operation in ('body','mode','extra','missing'):
            with self.subTest(operation=operation):
                if operation=='body':path.write_bytes(original+b'\n')
                if operation=='mode':path.chmod(0o755)
                if operation=='extra':(self.root/'extra.py').write_bytes(b'inert')
                if operation=='missing':path.unlink()
                with self.assertRaises((ValueError,OSError)):D.source(self.root,self.map)
                if not path.exists() or operation=='body':path.write_bytes(original)
                path.chmod(0o644)
                if (self.root/'extra.py').exists():(self.root/'extra.py').unlink()
        held=self.root/'held-source32'/D.BASE_PREFIX/'entry.py';held.write_bytes(held.read_bytes()+b'\n')
        with self.assertRaises(ValueError):D.source(self.root,self.map)

    def test_template_false_and_null_receipts_refuse(self):
        self.r['accepted']=False
        with self.assertRaises(ValueError):self.admit()
        self.r['accepted']=True;self.r['external_supervision']=None
        with self.assertRaises(ValueError):self.admit()

    def test_receipt_hash_shape_alone_is_insufficient(self):
        for field in ('external_supervision','bootstrap_resource_domain'):
            previous=self.r[field];self.r[field]={'sha256':'c'*64}
            with self.assertRaises(ValueError):self.admit()
            self.r[field]=previous

    def test_source_ref_map_resources_nonce_and_freshness_refuse(self):
        for key,value in [('source','d'*40),('ref','refs/heads/main'),('source_map_sha256','e'*64),
                          ('resources',{}),('nonce','c'*32),('created_utc',201),('expires_utc',200),('issued_by','worker')]:
            previous=self.r[key];self.r[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.admit()
            self.r[key]=previous

    def test_wrong_event_attempt_or_repository_refuse(self):
        for key,value in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_EVENT_NAME','push'),('GITHUB_REPOSITORY','other/repo')]:
            previous=self.env[key];self.env[key]=value
            with self.assertRaises(ValueError):self.admit()
            self.env[key]=previous

    def test_raw_document_hash_and_independent16k_caps_refuse(self):
        a,r=raw(self.a),raw(self.r)
        with self.assertRaises(ValueError):D.admission(self.root,self.map,a,r,'0'*64,D.pin(r)['sha256'],self.env,200)
        a=b' '*16385
        with self.assertRaises(ValueError):D.admission(self.root,self.map,a,r,D.pin(a)['sha256'],D.pin(r)['sha256'],self.env,200)

    def test_single_entry_environment_projection_has_complete_inverse(self):
        body=(self.base/D.BASE_PREFIX/'entry.py').read_bytes();projected=D.projected_entry(body)
        self.assertEqual(projected.replace(D.ENV_PROJECTION,D.ENV_ANCHOR).encode(),body)
        self.assertIn("clean['DOCKER_HOST']",projected);self.assertIn("clean['TMPDIR']",projected)
        self.assertIn("clean['DOCKER_BUILDKIT']='0'",projected)
        with self.assertRaises(ValueError):D.projected_entry(body+b'\n'+D.ENV_ANCHOR.encode())

    def test_ordinary_owner_service_plan_has_kernel_limits_no_privileged_container(self):
        args=D.service_args('b'*32,'owner',POLICY['owner'],['/usr/bin/python3','-I','-B','payload.py'],Path('/owned/volume/owner.log'),1001,1001)
        for item in ('--uid=1001','--gid=1001','--property=NoNewPrivileges=yes','--property=MemoryMax=2147483648',
                     '--property=MemorySwapMax=0','--property=TasksMax=256','--property=LimitAS=2147483648',
                     '--property=ReadWritePaths=/owned/volume/work','--property=ProtectSystem=strict'):
            self.assertIn(item,args)
        self.assertNotIn('--privileged',args);self.assertEqual(args[0],'/usr/bin/systemd-run')

    def test_dedicated_daemon_service_plan_has_distinct_parent_and_write_domain(self):
        args=D.service_args('b'*32,'daemon',POLICY['daemon'],['/usr/bin/dockerd'],Path('/owned/volume/daemon.log'))
        for item in ('--property=Delegate=yes','--property=DelegateSubgroup=daemon','--property=MemoryMax=6442450944',
                     '--property=MemorySwapMax=0','--property=TasksMax=768','--property=CPUQuota=400%'):
            self.assertIn(item,args)
        self.assertTrue(any(item.startswith('--property=ReadWritePaths=/owned/volume /sys/fs/cgroup/') for item in args))
        self.assertNotEqual(D.unit('b'*32,'owner'),D.unit('b'*32,'daemon'))

    def test_live_kernel_limit_mismatch_and_unlimited_refuse(self):
        expected={'memory.max':'2147483648','memory.swap.max':'0','pids.max':'256','cpu.max':'100000 100000'}
        D.domain(expected,POLICY['owner'])
        for key in expected:
            changed=dict(expected);changed[key]='max'
            with self.subTest(key=key),self.assertRaises(ValueError):D.domain(changed,POLICY['owner'])

    def observed(self):
        limits=lambda kind:{'memory.max':str(POLICY[kind]['memory_bytes']),'memory.swap.max':'0',
                            'pids.max':str(POLICY[kind]['pids']),'cpu.max':str(POLICY[kind]['cpus']*100000)+' 100000'}
        return dict(kind='FISH02_ACTUAL_HOSTED_DOMAINS_V2',source=self.a['source'],ref=self.a['ref'],nonce=self.a['nonce'],
                    source_map_sha256=self.map,owner=dict(pid=123,starttime=456,cgroup='/owner',limits=limits('owner')),
                    daemon=dict(pid=789,starttime=999,cgroup='/daemon',limits=limits('daemon')),
                    endpoint='unix:///owned/docker.sock',storage_bytes=POLICY['storage_bytes'],backend=POLICY['bootstrap_backend'])

    def test_actual_postdispatch_observation_joins_before_actor(self):
        value=self.observed();D.observation(value,self.a,self.map,POLICY,123,456,'/owner')
        for field,bad in [('source','f'*40),('nonce',None),('source_map_sha256','0'*64),('endpoint','tcp://unowned:2375'),('backend','auto'),('storage_bytes',None)]:
            changed=copy.deepcopy(value);changed[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):D.observation(changed,self.a,self.map,POLICY,123,456,'/owner')
        for pid,start,group in ((124,456,'/owner'),(123,457,'/owner'),(123,456,'/other')):
            with self.assertRaises(ValueError):D.observation(value,self.a,self.map,POLICY,pid,start,group)

    def test_shared_domain_and_unbounded_daemon_observations_refuse(self):
        value=self.observed();value['daemon']['cgroup']='/owner'
        with self.assertRaises(ValueError):D.observation(value,self.a,self.map,POLICY,123,456,'/owner')
        value=self.observed();value['daemon']['limits']['memory.max']='max'
        with self.assertRaises(ValueError):D.observation(value,self.a,self.map,POLICY,123,456,'/owner')

    def test_policy_aggregate_reserve_and_held_pair_budgets(self):
        self.assertGreaterEqual(POLICY['minimum_available_bytes'],POLICY['owner']['memory_bytes']+POLICY['daemon']['memory_bytes']+POLICY['host_reserve_bytes'])
        self.assertGreaterEqual(POLICY['minimum_disk_bytes'],POLICY['storage_bytes']+POLICY['host_reserve_bytes'])
        self.assertEqual((POLICY['pair_seconds'],POLICY['cleanup_seconds']),(1200,90))
        self.assertFalse(POLICY['shared_daemon']);self.assertIsNone(POLICY['Root_acceptance'])

    def test_bounded_public_retention_never_walks_private_mount_tree(self):
        out=Path(self.temp.name)/'receipts';out.mkdir();(out/'volume').symlink_to('/unreadable-nonexistent-private-tree')
        (out/'storage.img').write_bytes(b'private image omitted')
        (out/'owner-report.json').write_bytes(b'{"status":"HOLD"}');(out/'command-001.bin').write_bytes(b'')
        rows=R.selected(out);self.assertEqual(set(rows),{'owner-report.json','command-001.bin'})
        (out/'secret.json').write_bytes(b'forbidden')
        with self.assertRaises(ValueError):R.selected(out)

    def test_entry_and_owner_ordered_source_guards(self):
        body=(HERE/'payload.py').read_text()
        self.assertLess(body.index('D.observation('),body.index('exec(compile('))
        self.assertLess(body.index("D.domain({k:(parent/k)"),body.index('exec(compile('))
        self.assertIn('C.verify_source = closed_source',body)
        self.assertIn("not os.access('/tmp',os.W_OK)",body)
        workflow=WORKFLOW.read_text()
        self.assertIn('systemd-run --scope',workflow);self.assertIn('--property=RuntimeMaxSec=1290s',workflow)
        self.assertIn('if: always()',workflow)
        self.assertNotIn('docker system prune',workflow)

    def test_uncertain_service_submission_is_owned_before_transport(self):
        value=O.Controller.__new__(O.Controller)
        value.nonce='b'*32;value.policy=POLICY;value.out=Path(self.temp.name);value.units={}
        value.show=lambda kind: {'LoadState':'not-found'}
        def fail(*args,**kwargs):raise RuntimeError('synthetic systemd transport uncertainty')
        value.run=fail
        with self.assertRaises(RuntimeError):value.start('daemon',['/usr/bin/dockerd'])
        self.assertEqual(value.units,{'daemon':{'submitted':True,'cgroup':None}})

    def test_cleanup_keeps_first_error_and_attempts_both_owned_units(self):
        value=O.Controller.__new__(O.Controller);value.out=Path(self.temp.name)
        value.cleanup_end=time.monotonic()+90;value.mounted=False;value.loop=None;value.pidfds={}
        calls=[]
        def stop(kind):
            calls.append(kind)
            if kind=='owner':raise RuntimeError('synthetic uncertain owner retirement')
            return {'empty_twice':True}
        value.stop=stop
        result=value.cleanup()
        self.assertEqual(calls,['owner','daemon'])
        self.assertEqual(result['errors'],[{'step':'owner','error':'RuntimeError'}])
        self.assertEqual(result['services']['daemon'],{'empty_twice':True})

    def test_zero_length_complete_streams_are_valid_public_data(self):
        path=Path(self.temp.name)/'empty.stdout';path.write_bytes(b'')
        self.assertEqual(D.read(path,empty=True),b'')
        with self.assertRaises(ValueError):D.read(path)

    def test_all_new_python_asts_parse(self):
        for path in HERE.glob('*.py'):ast.parse(path.read_bytes(),filename=str(path))


if __name__=='__main__':unittest.main()
