#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert namespace, barrier-selection and publication controls; no guest actors."""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch,Mock

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
PROPOSED=next((p for p in HERE.parents if p.name=='proposed'),ROOT)
sys.path.insert(0,str(HERE))
import numeric_vm as n
import profile as p


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


w=load('numeric_vm_worker_controls',HERE/'installer.py')
core=load('numeric_vm_core_controls',PROPOSED/'scripts/install/local_transaction.py')


class SelectionControls(unittest.TestCase):
    def test_default_capabilities_unchanged_numeric_adds_only_fsetid(self):
        self.assertEqual(core.capability_mask(),0x400cb)
        self.assertEqual(core.capability_mask(n.SELECTION),0x400db)
    def test_both_selectors_reject_any_unknown_changed_or_boolean_mapping(self):
        changes=[]
        for key in n.SELECTION:
            value=copy.deepcopy(n.SELECTION);value.pop(key);changes.append(value)
        for group in (0,5,81,102):
            value=copy.deepcopy(n.SELECTION);value['gid_map'][0][1]=group;changes.append(value)
        value=copy.deepcopy(n.SELECTION);value['gid_map'][0][2]=True;changes.append(value)
        value=copy.deepcopy(n.SELECTION);value['extra']=True;changes.append(value)
        for value in changes:
            for check in (n.selection,core.numeric_fixture_selection):
                with self.subTest(value=value,check=check.__name__),self.assertRaises(ValueError):check(value)
    def environment(self,changed=None):
        values={'/proc/cmdline':'cachy_asahi_virtual_proof=1','/proc/self/uid_map':'0 23001 1\n',
                '/proc/self/gid_map':''.join('%d %d %d\n'%row for row in n.GIDS),'/proc/self/setgroups':'allow'}
        values.update(changed or {})
        return patch.multiple(core.os,uname=Mock(return_value=NS(machine='aarch64',release='7.2.10-1-aarch64-ARCH')),
                              sysconf=Mock(return_value=4096),getuid=Mock(return_value=0),geteuid=Mock(return_value=0),
                              getgid=Mock(return_value=0),getegid=Mock(return_value=0),getgroups=Mock(return_value=[])),\
               patch.object(Path,'read_text',lambda path:values[str(path)])
    def test_exact_actual_map_and_clear_groups_required(self):
        for changed in ({},{'/proc/self/gid_map':'0 23001 1\n'},{'/proc/self/setgroups':'deny'},
                        {'/proc/self/uid_map':'0 0 1\n'},{'/proc/cmdline':''}):
            first,second=self.environment(changed)
            with first,second:
                if changed:
                    with self.assertRaises(ValueError):core.numeric_fixture_environment(n.SELECTION)
                else:core.numeric_fixture_environment(n.SELECTION)
    def test_environment_refuses_before_any_capability_mutation(self):
        with patch.object(core,'numeric_fixture_environment',side_effect=ValueError('wrong map')),patch.object(core.C,'CDLL') as cap:
            with self.assertRaisesRegex(ValueError,'wrong map'):core.reduce_capabilities(fixture_identity_map=n.SELECTION)
            cap.assert_not_called()
    def test_default_and_mapped_launches_keep_mount_pid_proc_net_barrier(self):
        plain=w.engine_argv(91,'a'*64,92)
        mapped=w.engine_argv(91,'a'*64,92,93)
        self.assertIn('--map-root-user',plain);self.assertNotIn('--user',mapped);self.assertNotIn('--map-root-user',mapped)
        for argv in (plain,mapped):
            for flag in ('--mount','--pid','--mount-proc','--net','--fork','--kill-child=SIGKILL'):self.assertIn(flag,argv)
        self.assertIn(w.NAMESPACE_ENTRY,mapped)

    def test_namespace_entry_closes_lease_before_exec_and_cannot_execute_on_failed_join(self):
        calls=[]
        class Stop(BaseException):pass
        def execute(*args):calls.append('exec');raise Stop()
        for failure in (None,PermissionError('join refused')):
            calls.clear()
            def join(fd,kind):
                calls.append(('join',fd,kind))
                if failure is not None:raise failure
            with patch.object(sys,'argv',['entry','93','/usr/bin/unshare','--mount']),patch.object(os,'setns',side_effect=join),                 patch.object(os,'close',side_effect=lambda fd:calls.append(('close',fd))),patch.object(os,'execve',side_effect=execute):
                with self.assertRaises(Stop if failure is None else PermissionError):exec(w.NAMESPACE_ENTRY,{})
            self.assertEqual(calls,[('join',93,n.USERNS),('close',93),'exec'] if failure is None else [('join',93,n.USERNS)])


class DescriptorBudgetControls(unittest.TestCase):
    def facade(self,hard):
        actual=NS(RLIMIT_NOFILE=7,RLIMIT_CPU=0,RLIM_INFINITY=-1,getrlimit=Mock(return_value=(1024,hard)),setrlimit=Mock())
        runtime=NS(resource=actual);return actual,runtime
    def test_only_private_exact_128_request_becomes_8192(self):
        actual,runtime=self.facade(8192);n.process_binding(runtime)
        self.assertIsNot(runtime.resource,actual)
        runtime.resource.setrlimit(7,(128,128));actual.setrlimit.assert_called_once_with(7,(8192,8192))
        self.assertIs(runtime.resource.getrlimit,actual.getrlimit)
    def test_other_resource_requests_and_shared_module_are_unchanged(self):
        actual,runtime=self.facade(8192);original=actual.setrlimit;n.process_binding(runtime)
        runtime.resource.setrlimit(0,(60,65));actual.setrlimit.assert_called_once_with(0,(60,65))
        self.assertIs(actual.setrlimit,original)
    def test_changed_descriptor_request_refuses_without_mutation(self):
        actual,runtime=self.facade(8192);n.process_binding(runtime)
        for bounds in ((127,127),(256,256),(8192,8192),(128,8192)):
            with self.assertRaisesRegex(ValueError,'frozen child'):runtime.resource.setrlimit(7,bounds)
        actual.setrlimit.assert_not_called()
    def test_small_inherited_hard_limit_refuses_before_rebinding(self):
        actual,runtime=self.facade(8191)
        with self.assertRaisesRegex(ValueError,'budget unavailable'):n.process_binding(runtime)
        self.assertIs(runtime.resource,actual);actual.setrlimit.assert_not_called()
    def test_unlimited_inherited_hard_limit_is_accepted(self):
        actual,runtime=self.facade(-1);n.process_binding(runtime)
        runtime.resource.setrlimit(7,(128,128));actual.setrlimit.assert_called_once_with(7,(8192,8192))
    def test_root_readback_requires_sufficient_inherited_soft_and_hard_limits(self):
        for limits in ((8192,8192),(-1,-1),(1024,8192),(8192,8191)):
            with patch.object(n.resource,'getrlimit',return_value=limits):
                if all(value==-1 or value>=8192 for value in limits):n.observer_budget()
                else:
                    with self.assertRaisesRegex(ValueError,'observer descriptor'):n.observer_budget()
    def test_owned_guest_unit_supplies_root_readback_budget(self):
        prepare=load('numeric_budget_prepare_controls',HERE/'prepare.py')
        self.assertIn('LimitNOFILE=8192\n',prepare.UNIT)


class NumericOwnershipControls(unittest.TestCase):
    def observation(self):
        return dict(complete=True,nodes={str(inner):dict(type='file',mode=0o4110 if inner==81 else 0o2755,
             uid=23001,gid=outer,bytes=1,sha256='a'*64) for inner,outer,count in n.GIDS})
    def test_exact_reverse_map_preserves_every_content_mode_and_original_observation(self):
        raw=self.observation();before=copy.deepcopy(raw);fixed=n.normalize(raw)
        self.assertEqual(raw,before)
        for name,node in fixed['nodes'].items():
            self.assertEqual(node,dict(raw['nodes'][name],uid=0,gid=int(name)))
    def test_unknown_uid_or_gid_never_flattens(self):
        for field,value in (('uid',0),('uid',23002),('gid',81),('gid',99999)):
            raw=self.observation();raw['nodes']['81'][field]=value
            with self.assertRaisesRegex(ValueError,'numeric ownership'):n.normalize(raw)
    def test_wrong_namespace_type_or_owner_is_refused(self):
        def ioctl(fd,op,owner=None,mutate=None):
            if op==0xb703:return n.USERNS
            owner[0]=23001
        with patch.object(n.fcntl,'ioctl',side_effect=ioctl),patch.object(n.os,'fstat',return_value=NS(st_dev=3,st_ino=4)):
            self.assertEqual(n.namespace_identity(9),[3,4])
        for kind,owner in ((123,23001),(n.USERNS,0),(n.USERNS,23002)):
            def wrong(fd,op,value=None,mutate=None):
                if op==0xb703:return kind
                value[0]=owner
            with patch.object(n.fcntl,'ioctl',side_effect=wrong),patch.object(n.os,'fstat',return_value=NS(st_dev=3,st_ino=4)):
                with self.assertRaises(ValueError):n.namespace_identity(9)
    def test_typed_third_fd_transfer_keeps_spec_seals_and_namespace_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            spec=os.memfd_create('inert',os.MFD_ALLOW_SEALING);folder=os.open(temp,os.O_RDONLY|os.O_DIRECTORY)
            namespace=os.open(temp,os.O_RDONLY|os.O_DIRECTORY)
            try:
                fcntl.fcntl(spec,fcntl.F_ADD_SEALS,15);info=os.fstat(namespace)
                with patch.object(n,'namespace_identity',return_value=[info.st_dev,info.st_ino]):
                    argv=w.fd_transfer(['x',str(spec),str(folder),str(namespace)],(spec,folder),namespace)
                rows=json.loads(argv[6]);self.assertEqual([r['kind'] for r in rows],['sealed','directory','namespace'])
                self.assertEqual(rows[-1]['identity'],[info.st_dev,info.st_ino])
                with self.assertRaisesRegex(ValueError,'distinct'):w.fd_transfer(['x'],(spec,folder),folder)
            finally:
                for fd in (spec,folder,namespace):os.close(fd)


class BootstrapControls(unittest.TestCase):
    def test_helper_retired_before_lease_authority_and_no_real_fork(self):
        with tempfile.TemporaryDirectory() as temp:
            shared=Path(temp);(shared/'installer-profile.json').write_bytes(b'profile')
            profile=NS(SHARED=shared,sha=p.sha,encoded=p.encoded)
            writes=[];retired=[]
            def read(path,*args,**kwargs):
                return {'uid_map':'0 23001 1\n','gid_map':''.join('%d %d %d\n'%r for r in n.GIDS),
                        'setgroups':'allow'}[path.name]
            def retire(pid):
                self.assertFalse((shared/n.LEASE).exists());retired.append(pid)
            with patch.object(n,'root_guard'),patch.object(n.os,'pipe',side_effect=[(10,11),(12,13)]),\
                 patch.object(n.os,'fork',return_value=4242),patch.object(n.os,'close'),patch.object(n.os,'open',return_value=14),\
                 patch.object(n.os,'read',return_value=b'R'),patch.object(n.select,'select',return_value=([10],[],[])),\
                 patch.object(n,'namespace_identity',return_value=[1,2]),patch.object(n,'retire_creator',side_effect=retire),\
                 patch.object(Path,'write_text',lambda path,data:writes.append((path.name,data))),\
                 patch.object(Path,'read_text',read):
                fd,digest=n.bootstrap(profile,{'nonce':'a'*32},{'numeric_vm':n.SELECTION})
            self.assertEqual(fd,14);self.assertEqual(retired,[4242]);self.assertEqual([row[0] for row in writes],['uid_map','gid_map'])
            lease=p.decode((shared/n.LEASE).read_bytes());self.assertTrue(lease['creator_retired'])
            self.assertEqual(lease['namespace_identity'],[1,2]);self.assertEqual(digest,p.sha(shared/n.LEASE))
    def test_readiness_failure_still_retires_exact_creator_and_closes_pipes(self):
        closed=[]
        with patch.object(n,'root_guard'),patch.object(n.os,'pipe',side_effect=[(10,11),(12,13)]),\
             patch.object(n.os,'fork',return_value=4242),patch.object(n.os,'close',side_effect=closed.append),\
             patch.object(n.select,'select',return_value=([],[],[])),patch.object(n,'retire_creator') as retire:
            with self.assertRaisesRegex(ValueError,'ready'):n.bootstrap(None,{},dict(numeric_vm=n.SELECTION))
            retire.assert_called_once_with(4242)
        self.assertEqual(sorted(closed),[10,11,12,13])

    def test_creator_retirement_signals_reserved_pid_then_waits_without_reuse(self):
        calls=[]
        with patch.object(n.os,'kill',side_effect=lambda *args:calls.append(('kill',*args))),             patch.object(n.os,'waitid',side_effect=[None,NS(si_pid=4242)]) as wait,             patch.object(n.os,'waitpid',side_effect=lambda *args:calls.append(('reap',*args))),patch.object(n.time,'sleep'):
            n.retire_creator(4242)
        self.assertEqual(calls,[('kill',4242,n.signal.SIGKILL),('reap',4242,0)])
        self.assertEqual(wait.call_args.args,(os.P_PID,4242,os.WEXITED|os.WNOHANG|os.WNOWAIT))
    def test_creator_retirement_has_finite_refusal_and_does_not_reap_unobserved_child(self):
        with patch.object(n.os,'kill'),patch.object(n.os,'waitid',return_value=None),             patch.object(n.time,'monotonic',side_effect=[0,6]),patch.object(n.os,'waitpid') as reap:
            with self.assertRaisesRegex(ValueError,'deadline'):n.retire_creator(4242)
            reap.assert_not_called()


class PublicationControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.trial=Path(self.temp.name);self.evidence=self.trial/'work/evidence';self.evidence.mkdir(parents=True,mode=0o700)
        self.worker=NS(TRIAL=self.trial)
        self.uid=patch.object(n,'UID',os.getuid());self.uid.start();self.addCleanup(self.uid.stop)
        self.result={'status':'PROVISIONAL_MAPPED_PARENT'}
        self.file('result.json',p.encoded(self.result));self.file('candidate-packages.lock',b'p 1\n')
    def file(self,name,data):
        path=self.evidence/name;path.write_bytes(data);path.chmod(0o600);return path
    def test_bounded_read_refuses_size_mode_link_and_alias(self):
        fd=n.evidence_directory(self.worker)
        try:
            self.assertEqual(n.read_evidence(fd,'candidate-packages.lock'),b'p 1\n')
            with self.assertRaises(ValueError):n.read_evidence(fd,'candidate-packages.lock',maximum=1)
            path=self.evidence/'candidate-packages.lock';path.chmod(0o644)
            with self.assertRaises(ValueError):n.read_evidence(fd,'candidate-packages.lock')
            path.chmod(0o600);os.link(path,self.evidence/'hardlink')
            with self.assertRaises(ValueError):n.read_evidence(fd,'candidate-packages.lock')
            (self.evidence/'alias').symlink_to(path)
            with self.assertRaises(OSError):n.read_evidence(fd,'alias')
        finally:os.close(fd)
    def test_success_promotes_only_after_lock_is_durable(self):
        final={'status':w.PASS};n.publish(p,self.worker,final,b'p 1\n')
        self.assertEqual(p.decode((self.evidence/'result.json').read_bytes()),final)
        self.assertEqual((self.evidence/'installed-packages.lock').read_bytes(),b'p 1\n')
        self.assertFalse((self.evidence/'verified-result.tmp').exists())
    def test_preexisting_lock_never_overwritten_or_removed(self):
        path=self.file('installed-packages.lock',b'held')
        with self.assertRaises(FileExistsError):n.publish(p,self.worker,{'status':w.PASS},b'p 1\n')
        self.assertEqual(path.read_bytes(),b'held');self.assertEqual(p.decode((self.evidence/'result.json').read_bytes()),self.result)
    def test_failed_fsync_revokes_new_lock_and_never_publishes_pass(self):
        with patch.object(n.os,'fsync',side_effect=OSError('modeled sync failure')):
            with self.assertRaises(OSError):n.publish(p,self.worker,{'status':w.PASS},b'p 1\n')
        self.assertFalse((self.evidence/'installed-packages.lock').exists())
        self.assertEqual(p.decode((self.evidence/'result.json').read_bytes()),self.result)
    def test_final_sync_failure_removes_unacknowledged_pass(self):
        original=os.fsync;calls=[]
        def fail(fd):
            calls.append(fd)
            if len(calls)==4:raise OSError('final sync failure')
            return original(fd)
        with patch.object(n.os,'fsync',side_effect=fail):
            with self.assertRaises(OSError):n.publish(p,self.worker,{'status':w.PASS},b'p 1\n')
        self.assertFalse((self.evidence/'installed-packages.lock').exists());self.assertFalse((self.evidence/'result.json').exists())
    def test_provisional_or_missing_root_readback_cannot_pass_host_protocol(self):
        run=load('numeric_vm_host_controls',HERE/'run.py')
        events=[dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel='7.2.10-1-aarch64-ARCH',uid=0),
                dict(event='result',status=w.PASS,phase='complete',package_count=587,expected_lock_sha256=p.EXPECTED,
                     hooks='DISABLED',scriptlets='DISABLED',hardware='NOT RUN',native_container_P0='UNCHANGED-FAILED',
                     **dict.fromkeys(run.PASS_FLAGS,True)),dict(event='exit',status=w.PASS,cleanup='PASS')]
        for field in ('root_guest_payload_verified','parent_payload_verified','numeric_ownership_verified','numeric_namespace_verified'):
            changed=copy.deepcopy(events);changed[1].pop(field)
            with self.assertRaises(ValueError):run.validate_completion(changed,'a'*32,NS(KERNEL='7.2.10-1-aarch64-ARCH'))
        changed=copy.deepcopy(events);changed[1]['status']='PROVISIONAL_MAPPED_PARENT'
        with self.assertRaises(ValueError):run.validate_completion(changed,'a'*32,NS(KERNEL='7.2.10-1-aarch64-ARCH'))


class RootReadbackControls(unittest.TestCase):
    setUp=PublicationControls.setUp
    file=PublicationControls.file
    # Inherit private evidence fixture setup, not its unrelated test methods.
    def context(self):
        shared=self.trial/'shared';shared.mkdir();(shared/'installer-profile.json').write_bytes(b'profile')
        lock=b'dbus 1\n';self.file('candidate-packages.lock',lock)
        proxy=NS(SHARED=shared,sha=p.sha,encoded=p.encoded,decode=p.decode,GIB=p.GIB,
                 EXPECTED=hashlib.sha256(lock).hexdigest())
        raw=dict(complete=True,unsupported_counts={},hardlink_groups={},nodes={
            'helper':dict(type='file',mode=0o4110,uid=n.UID,gid=23081,bytes=1,sha256=hashlib.sha256(b'x').hexdigest())})
        payload=dict(nodes={'helper':dict(raw['nodes']['helper'],uid=0,gid=81)},hardlinks=[],ownership={'dbus':['helper']},packages={'dbus':'1'})
        for name,data in w.FIXTURES.items():
            raw['nodes'][name]=dict(type='file',mode=0o600,uid=n.UID,gid=23001,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        c=dict(nonce='a'*32,tooling_inventory={'tool':'1'})
        profile=dict(expected={'dbus':'1'},numeric_vm=n.SELECTION)
        roots=NS(Limits=lambda **values:NS(**values),observe=Mock(return_value=raw))
        driver=NS(database=Mock(side_effect=[[dict(name='dbus',version='1',files=['helper'])],[dict(name='tool',version='1')]]))
        worker=NS(TRIAL=self.trial,PASS=w.PASS,checked_inputs=Mock(return_value=(c,profile,{},payload)),
                  source_modules=Mock(return_value=(roots,None,driver,None)),compare_payload=w.compare_payload)
        target=self.evidence/'target';target.mkdir(mode=0o700);info=target.stat()
        result=dict(status='PROVISIONAL_MAPPED_PARENT',phase='complete',nonce=c['nonce'],profile_sha256=p.sha(shared/'installer-profile.json'),
                    target_identity=[info.st_dev,info.st_ino],**dict.fromkeys(('committed','namespace_barrier','payload_verified','ownership_verified',
                    'database_verified','preservation_verified','private_trust_verified','parent_inventory_preserved',
                    'source_cache_preserved','process_retirement','ordinary_parent_nnp_cap0','numeric_namespace_verified'),True))
        self.file('result.json',p.encoded(result))
        return proxy,worker,result,c,raw,payload,roots,driver
    def test_full_readback_passes_raw_ownership_to_database_and_preserves_04110(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        with patch.object(n,'root_guard'):final=n.verify_export(proxy,worker,result,c)
        self.assertEqual(final['status'],w.PASS);self.assertTrue(final['numeric_ownership_verified'])
        self.assertTrue(final['root_guest_payload_verified']);self.assertTrue(final['parent_payload_verified'])
        self.assertEqual(driver.database.call_args_list[0].kwargs['observed']['helper']['gid'],23081)
        self.assertEqual(raw['nodes']['helper']['mode'],0o4110);self.assertEqual(raw['nodes']['helper']['uid'],n.UID)
        worker.checked_inputs.assert_called_with(protected=True);self.assertEqual(worker.checked_inputs.call_count,2)
    def test_modified_content_is_refused_without_publishing(self):
        proxy,worker,result,c,raw,*_=self.context();raw['nodes']['helper']['sha256']='0'*64
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'payload differs'):n.verify_export(proxy,worker,result,c)
        self.assertFalse((self.evidence/'installed-packages.lock').exists())
        self.assertEqual(p.decode((self.evidence/'result.json').read_bytes())['status'],'PROVISIONAL_MAPPED_PARENT')
    def test_missing_package_ownership_is_refused(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        driver.database.side_effect=[[dict(name='dbus',version='1',files=[])]]
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'package ownership'):n.verify_export(proxy,worker,result,c)
        self.assertFalse((self.evidence/'installed-packages.lock').exists())
    def test_wrong_target_identity_is_refused_before_observation(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context();result['target_identity'][1]+=1
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'target identity'):n.verify_export(proxy,worker,result,c)
        roots.observe.assert_not_called()
    def test_parent_failure_is_not_repaired_by_root_observer(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context();result['process_retirement']=False
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'proof incomplete'):n.verify_export(proxy,worker,result,c)
        roots.observe.assert_not_called()
    def test_partial_observation_refuses_before_database_and_retains_original_reason(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        raw.update(complete=False,unsupported_counts={'root observation deadline':1})
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'mapped root observation incomplete'):
            n.verify_export(proxy,worker,result,c)
        driver.database.assert_not_called()
        self.assertFalse((self.evidence/'installed-packages.lock').exists())
        diagnostic=result['root_guest_observation']
        self.assertIs(diagnostic['complete'],False)
        self.assertEqual(diagnostic['unsupported_counts'],{'root observation deadline':1})
        self.assertEqual(diagnostic['deadline_seconds'],600)
        self.assertEqual(diagnostic['missing_database_nodes'],3)
    def test_actual_shared_partial_observer_reproduces_misleading_missing_database_error(self):
        roots=load('installer_partial_observer_repro',ROOT/'scripts/update/full_root.py')
        driver=load('installer_partial_database_repro',ROOT/'scripts/ci/full-root-upgrade/root_upgrade.py')
        target=self.trial/'partial';local=target/'var/lib/pacman/local';local.mkdir(parents=True)
        version=local/'ALPM_DB_VERSION';version.write_bytes(b'9\n');calls=[]
        def tick(limit):
            calls.append(True)
            if len(calls)>1:raise ValueError('root observation deadline')
        limits=roots.Limits(deadline=10**15)
        with patch.object(roots.Limits,'tick',tick):
            observed=roots.observe(target,limits=limits,hardlinks='generic-development-internal')
        self.assertTrue(version.is_file());self.assertIs(observed['complete'],False)
        self.assertEqual(observed['unsupported_counts'],{'root observation deadline':1})
        with self.assertRaisesRegex(ValueError,'database record absent from root observation'):
            driver.database(target,observed=observed['nodes'])
    def test_unsupported_complete_observation_refuses_before_database(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        raw['unsupported_counts']={'filesystem-observation-failed':1}
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'mapped root observation incomplete'):
            n.verify_export(proxy,worker,result,c)
        driver.database.assert_not_called()
        self.assertEqual(result['root_guest_observation']['unsupported_counts'],{'filesystem-observation-failed':1})
    def test_payload_failure_is_not_hidden_by_database_failure(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        raw['nodes']['helper']['sha256']='f'*64
        driver.database.side_effect=ValueError('database record absent from root observation')
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'installed payload differs'):
            n.verify_export(proxy,worker,result,c)
        driver.database.assert_not_called()
        self.assertTrue(result['root_guest_observation']['complete'])
    def test_complete_observation_still_requires_strict_database_readback(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        driver.database.side_effect=ValueError('database record absent from root observation')
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'database record absent'):
            n.verify_export(proxy,worker,result,c)
        self.assertTrue(result['root_guest_observation']['complete'])
        self.assertFalse((self.evidence/'installed-packages.lock').exists())
    def test_diagnostics_are_bounded_metadata_with_no_node_contents(self):
        proxy,worker,result,c,raw,payload,roots,driver=self.context()
        raw['unsupported_counts']={('r'*200)+str(i):1 for i in range(24)}
        raw['nodes']['helper']['contents']='must-not-export'
        value=n.observation_summary(proxy,raw,payload,0)
        self.assertLessEqual(len(p.encoded(value)),8192)
        self.assertEqual(value['unsupported_reasons_omitted'],8)
        self.assertEqual(len(value['unsupported_counts']),16)
        self.assertNotIn('must-not-export',p.encoded(value).decode())
    def test_disk_receipt_changed_is_refused_before_promotion(self):
        proxy,worker,result,c,*_=self.context();self.file('result.json',p.encoded(dict(result,phase='changed')))
        with patch.object(n,'root_guard'),self.assertRaisesRegex(ValueError,'result bytes changed'):n.verify_export(proxy,worker,result,c)
        self.assertFalse((self.evidence/'installed-packages.lock').exists())


if __name__=='__main__':unittest.main()
