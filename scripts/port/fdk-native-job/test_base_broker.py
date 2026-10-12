#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Owned fake Docker/Unix HTTP fixtures; no Docker or native build execution."""
import sys
sys.dont_write_bytecode = True

import hashlib
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import base_broker
import evidence
import producer

ADAPTER = Path(__file__).resolve().parents[1] / 'fdk-native-stage'
fixture_path = list(sys.path)
try:
    sys.path.insert(0,str(ADAPTER))
    import test_broker as fixtures
finally:
    sys.path[:] = fixture_path

IMAGE = 'sha256:' + 'c'*64
NONCE = 'd'*32
BaseBroker = base_broker.broker_class(ADAPTER)
ROOT = Path(__file__).resolve().parents[3]
INPUT_BYTES = (ROOT/'scripts/ci/inputs.lock.json').read_bytes()
assert hashlib.sha256(INPUT_BYTES).hexdigest() == evidence.INPUTS_SHA
INPUTS = json.loads(INPUT_BYTES)
VERSIONS = {row['name'][0]: row['version'][0] for row in INPUTS['rootfs_packages']}
VERSIONS.update({row['name']: row['version'] for row in INPUTS['packages']})
INVENTORY = ''.join(f'{name} {version}\n' for name,version in sorted(VERSIONS.items())).encode()
assert len(VERSIONS) == 341 and len(INVENTORY) == 6674
assert hashlib.sha256(INVENTORY).hexdigest() == evidence.INVENTORY_SHA

BUILD = r'''elif a[:1]==['build']:
 assert os.environ.get('DOCKER_BUILDKIT')=='0'
 assert all(v in a for v in ['--force-rm=true','--memory=4g','--memory-swap=4g','--cpu-period=100000','--cpu-quota=400000'])
 record=json.loads((root/'images.json').read_text());assert record['reservation']['attempted'] is True
 labels=dict(a[i+1].split('=',1) for i,v in enumerate(a) if v=='--label')
 if s.get('unknown_empty'):(root/'build-ready').write_text('ready');time.sleep(60)
 ident='sha256:'+'c'*64
 s['images'][ident]={'Id':ident,'Architecture':'arm64','Os':'linux','Config':{'Env':['PATH=/usr/bin:/bin'],'User':'alarm','Volumes':None,'Labels':labels}}
 s['image']=ident;save()
 if s.get('unknown_found'):(root/'build-ready').write_text('ready');time.sleep(60)
 if s.get('context_drift'):
  p=Path(a[-1])/'Dockerfile';p.write_bytes(p.read_bytes()+b'\n# drift\n')
 if not s.get('missing_iid'):
  p=Path(a[a.index('--iidfile')+1]);assert not p.exists();p.write_text(ident+'\n')
 print('legacy build output')
elif a[:2]==['image','ls']:
 values=list(s['images'])
 if '--filter' in a:
  key,value=a[a.index('--filter')+1].removeprefix('label=').split('=',1)
  values=[i for i in values if s['images'][i]['Config']['Labels'].get(key)==value]
  if s.get('spoof_list'):values=list(s['images'])
 for identifier in sorted(values):print(identifier)
 if s.get('interrupt_image_query'):
  s['interrupt_image_query']=False;save();pid=os.fork()
  if pid==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60);os._exit(0)
  (root/'final-cleanup-ready').write_text(str(pid))
elif a[:2]==['image','rm']:
 assert len(a)==3 and a[2].startswith('sha256:')
 if s.get('image_rm_failure'):raise SystemExit(1)
 del s['images'][a[2]];save();print(a[2])
 if s.get('interrupt_image_rm'):
  s['interrupt_image_rm']=False;save();pid=os.fork()
  if pid==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60);os._exit(0)
  (root/'final-cleanup-ready').write_text(str(pid))
elif a[:1]==['version']:print('fake Docker version')
'''
FAKE = fixtures.FAKE.replace("elif a[:2]==['image','inspect']:\n", "elif a[:2]==['image','inspect']:\n if a[2] not in s['images']:raise SystemExit(1)\n")
start=FAKE.index(" emit([{'Id':s['image']")
end=FAKE.index("\n if s.get('drift_after_image')",start)
FAKE=FAKE[:start]+" emit([s['images'][a[2]]])"+FAKE[end:]
FAKE=FAKE.replace("elif a[:2]==['container','ls']:",BUILD+"elif a[:2]==['container','ls']:")
FAKE=FAKE.replace(" if item['Config']['Cmd'][0]=='-euc':", r''' if item['Config']['Cmd']==['-euc','cat /builder-packages.lock']:
  path=root/'inventory.fixture'
  data=path.read_bytes() if path.is_file() else b'alpha 1\nbeta 2\n'
  sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
  raise SystemExit(s.get('inventory_exit',0))
 elif item['Config']['Cmd'][0]=='-euc':''')
FAKE=FAKE.replace("root/'journal.json'","root/'images-containers.json'")


class BaseBrokerTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='fdk-base-broker-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.producer=self.root/'producer';self.producer.mkdir(mode=0o700)
        self.context=self.producer/'context';self.context.mkdir()
        (self.context/'Dockerfile').write_text('FROM scratch\nADD rootfs.tar.gz /\nUSER alarm\n')
        (self.context/'rootfs.tar.gz').write_bytes(b'fixture-not-executed')
        self.iid=self.producer/'image-id'
        self.binary=self.root/'fake-docker';self.binary.write_text(FAKE);self.binary.chmod(0o755)
        self.digest=hashlib.sha256(self.binary.read_bytes()).hexdigest()
        config=self.root/'docker-config';config.mkdir(mode=0o700)
        self.env={'PATH':'/usr/bin:/bin','HOME':str(self.root),'DOCKER_CONFIG':str(config),
                  'LANG':'C.UTF-8','LC_ALL':'C','DOCKER_BUILDKIT':'0'}
        self.uid,self.gid=max(os.getuid(),1000),max(os.getgid(),1000)
        self.sock=socket.socket(socket.AF_UNIX);self.addCleanup(self.sock.close)
        self.sock.bind(str(self.root/'docker.sock'));self.sock.listen(32)
        self.endpoint='unix://'+str(self.root/'docker.sock')
        self.state={'calls':[],'daemon':'DAEMON-ORIGINAL','image':IMAGE,'nonce':NONCE,
                    'endpoint':self.endpoint,'user':f'{self.uid}:{self.gid}','containers':{},'images':{}}
        self.save()
        self.server=subprocess.Popen([sys.executable,'-B','-c',fixtures.HTTP_SERVER,str(self.root),
                    str(self.sock.fileno())],pass_fds=(self.sock.fileno(),),stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        self.addCleanup(self.stop_server)
        patcher=mock.patch.object(BaseBroker.accepted,'validate_endpoint',side_effect=lambda endpoint,uid:endpoint)
        patcher.start();self.addCleanup(patcher.stop)
        self.value=self.make()
        self.originals={name:(ADAPTER/name).read_bytes() for name in ('broker.py','runtime.py')}

    def save(self):
        (self.root/'state.json').write_text(json.dumps(self.state))

    def load(self):
        self.state=json.loads((self.root/'state.json').read_text());return self.state

    def stop_server(self):
        if self.server.poll() is None:os.killpg(self.server.pid,signal.SIGTERM)
        self.server.wait(timeout=2);self.server.stdout.close()

    def tearDown(self):
        self.assertEqual({name:(ADAPTER/name).read_bytes() for name in self.originals},self.originals)
        self.assertFalse(any(call[0]=='info' for call in self.load()['calls']))

    def make(self, expected_mounts=None):
        runtime=BaseBroker.runtime
        return BaseBroker(runtime.Runner(30,self.env,self.root/'logs'),
            runtime.Runner(1,self.env,self.root/'cleanup-logs'),self.binary,self.digest,self.endpoint,
            self.uid,self.gid,self.root/'images.json',NONCE,jobroot=self.root,context=self.context,
            iidfile=self.iid,expected_mounts=expected_mounts)

    def command(self):
        return ['docker','build','--network=none','--pull=false','--platform=linux/arm64',
                '--iidfile',str(self.iid),str(self.context)]

    def build(self):
        self.value.initialize();return self.value.bootstrap(self.command(),2)

    def test_original_build_legacy_environment_actual_argv_and_owned_cleanup(self):
        result=self.build()
        self.assertEqual((result.returncode,result.stdout),(0,b'legacy build output\n'))
        self.assertEqual(self.value.image,IMAGE)
        record=json.loads((self.root/'images.json').read_text())['reservation']
        self.assertEqual(record['phase'],'created')
        self.assertEqual(record['image_ids'],[IMAGE])
        self.assertEqual(record['dockerfile_sha256'],hashlib.sha256((self.context/'Dockerfile').read_bytes()).hexdigest())
        self.assertIn('--force-rm=true',record['actual_argv'])
        self.assertIn(base_broker.LABEL+'='+NONCE,record['actual_argv'])
        cleanup=self.value.cleanup(remove_image=True)
        self.assertEqual(cleanup['status'],'PASS')
        self.assertIs(cleanup['owned_image_absence'],True)
        self.assertEqual(cleanup['legacy_cache_cleanup'],'NOT CLAIMED')
        self.assertFalse(self.load()['images'])
        reloaded=self.make();reloaded.initialize(expected_daemon=self.value.daemon)
        self.assertTrue(reloaded.cleanup(remove_image=True)['absence_verified'])

    def test_context_and_info_captures_are_pinned_facts_without_cli_discovery(self):
        self.value.initialize()
        self.assertEqual(self.value.capture(['docker','info','--format','{{.Architecture}}']),'aarch64')
        self.assertEqual(json.loads(self.value.capture(['docker','context','inspect']))[0]['Endpoints']['docker']['Host'],self.endpoint)
        self.assertEqual(self.value.capture(['docker','version']),'fake Docker version')
        self.assertFalse(any(call[0] in ('info','context') for call in self.load()['calls']))

    def test_lock_probe_uses_owned_container_and_exact_original_output(self):
        self.build()
        command=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
                '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']
        self.assertEqual(self.value.command(command,2).stdout,b'alpha 1\nbeta 2\n')
        self.assertFalse(self.load()['containers'])
        self.assertEqual(self.value.cleanup(remove_image=True)['status'],'PASS')

    def native_delegate(self):
        native = producer.module('base_inventory_native_fixture', ROOT/'scripts/ci/native_arm.py')
        commands = producer.ProducerCommands({'snapshot':str(ROOT),'jobroot':str(self.root)},
            self.value,producer.jr.Runner(30,self.env,self.root/'delegate-logs'))
        path = self.root/'durable-diagnostic.json'
        commands.on_diagnostic = lambda value:path.write_text(json.dumps(value))
        native.subprocess = commands
        return native,commands,path

    def assert_inventory_diagnostic(self, commands, path, accepted):
        diagnostic = {'phase':'base-probe','outcome':'pass' if accepted else 'runner-failed',
            'call':'inventory-probe','refusal_code':'none' if accepted else 'base-lock-probe-inventory'}
        self.assertEqual(commands.diagnostic,diagnostic)
        self.assertEqual(json.loads(path.read_bytes()),diagnostic)
        public = evidence.public_status({'status':'FAIL','phase':'complete','work_phase':'producer',
            'cancelled':False,'source':{'status':'PASS'},'producer':{'status':'FAIL'},'fdk':{'status':'NOT RUN'},
            'cleanup':{'status':'PASS','owned_image_absence':True},'producer_diagnostic':diagnostic})
        self.assertEqual(public['error_code'],'producer-after-base-probe-inventory-probe-failed' if accepted else
            'producer-base-probe-inventory-probe-base-lock-probe-inventory')
        self.assertEqual(len(public),14)
        self.assertNotIn('producer_diagnostic',public)
        self.assertNotIn('PRIVATE',json.dumps(public))
        self.assertNotIn(str(self.root),json.dumps(public))

    def assert_owned_inventory_cleanup(self):
        cleanup = self.value.cleanup(remove_image=True)
        self.assertEqual(cleanup['status'],'PASS',cleanup)
        self.assertIs(cleanup['owned_image_absence'],True)
        self.assertFalse(self.load()['containers'])
        self.assertFalse(self.state['images'])

    def inventory_control(self, payload, exit_code=0, accepted=False):
        (self.root/'inventory.fixture').write_bytes(payload)
        self.state['inventory_exit']=exit_code;self.save()
        self.build()
        native,commands,path = self.native_delegate()
        argv=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
              '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']
        try:
            if accepted:
                self.assertEqual((native.run(argv,timeout=2)+'\n').encode(),INVENTORY)
            else:
                with self.assertRaisesRegex(ValueError,'^base-lock-probe-inventory$'):
                    native.run(argv,timeout=2)
            self.assert_inventory_diagnostic(commands,path,accepted)
            starts=[call for call in self.load()['calls'] if call[:1]==['start']]
            self.assertEqual(len(starts),1)
            self.assertEqual(starts[0][:2],['start','--attach'])
            self.assertEqual(len(starts[0]),3)
            self.assertRegex(starts[0][2],'^[0-9a-f]{64}$')
        finally:
            self.assert_owned_inventory_cleanup()

    def test_frozen_341_inventory_through_original_run_and_real_delegate(self):
        self.inventory_control(INVENTORY,accepted=True)

    def test_inventory_missing_final_newline_refused_and_owned_cleanup(self):
        self.inventory_control(INVENTORY[:-1])

    def test_inventory_unsorted_refused_and_owned_cleanup(self):
        rows=INVENTORY.splitlines(keepends=True)
        self.inventory_control(b''.join([rows[1],rows[0],*rows[2:]]))

    def test_inventory_extra_malformed_row_refused_and_owned_cleanup(self):
        self.inventory_control(INVENTORY+b'zzzz-extra invalid row\n')

    def test_inventory_private_stdout_refused_without_public_text(self):
        self.inventory_control(INVENTORY+b'PRIVATE FIXTURE CONTROL\n')

    def test_inventory_nonzero_exit_refused_despite_valid_stdout(self):
        self.inventory_control(INVENTORY,exit_code=7)

    def test_valid_sorted_extra_package_reaches_original_exact_set_refusal(self):
        # Synthetic source bytes exercise original build's equality guard only;
        # no signatures, native transaction, compiler or Docker build is run.
        inputs=copy.deepcopy(INPUTS)
        cache=self.root/'fixture-cache';cache.mkdir()
        for item in [inputs['rootfs'],*inputs['keyring_files'],*inputs['packages']]:
            payload=b'synthetic cache fixture: '+item['filename'].encode()
            (cache/item['filename']).write_bytes(payload)
            item['sha256']=hashlib.sha256(payload).hexdigest()
            if 'signature_sha256' in item:
                signature=b'synthetic signature fixture; never authenticated'
                (cache/(item['filename']+'.sig')).write_bytes(signature)
                item['signature_sha256']=hashlib.sha256(signature).hexdigest()
        for path in self.context.iterdir():path.unlink()
        self.context.rmdir()
        (self.producer/'rootfs-hooks.json').write_text('[]')
        (self.producer/'package-audit.json').write_text('{}')
        (self.producer/'inputs.lock.json').write_bytes(INPUT_BYTES)
        (self.root/'inventory.fixture').write_bytes(INVENTORY+b'zzzz-fixture-extra 1\n')
        self.value.initialize()
        native,commands,path=self.native_delegate()
        try:
            with self.assertRaisesRegex(ValueError,'^offline transaction changed the frozen package set; review packages.lock$'):
                native.build(inputs,cache,self.producer,{})
            self.assert_inventory_diagnostic(commands,path,accepted=True)
            self.assertEqual((self.producer/'packages.lock').read_bytes(),INVENTORY+b'zzzz-fixture-extra 1\n')
        finally:
            self.assert_owned_inventory_cleanup()

    def test_fake_cli_refuses_former_unsupported_start_flag_before_container_output(self):
        self.build()
        identifier='f'*64
        self.load()['containers']['flag-fixture']={'Id':identifier,
            'Config':{'Cmd':['-euc','cat /builder-packages.lock']}}
        self.save()
        try:
            result=subprocess.run([str(self.binary),'--host',self.endpoint,'start','--attach',
                '--sig-proxy=false',identifier],env=self.env,capture_output=True,timeout=2)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
        finally:
            self.load()['containers'].pop('flag-fixture');self.save()
            self.assert_owned_inventory_cleanup()

    def test_missing_iid_recovers_labelled_image_and_parent_reloads(self):
        self.state['missing_iid']=True;self.save();self.value.initialize()
        with self.assertRaises(OSError):self.value.bootstrap(self.command(),2)
        parent=self.make();parent.initialize(expected_daemon=self.value.daemon)
        self.assertEqual(parent.cleanup(remove_image=True)['status'],'PASS')
        self.assertFalse(self.load()['images'])
        self.assertEqual(json.loads((self.root/'images.json').read_text())['reservation']['image_ids'],[IMAGE])

    def test_timed_out_unknown_build_found_owned_is_removed(self):
        self.state['unknown_found']=True;self.save();self.value.initialize()
        with self.assertRaisesRegex(ValueError,'command-timeout'):self.value.bootstrap(self.command(),.1)
        self.assertEqual(self.value.cleanup(remove_image=True)['status'],'PASS')
        self.assertFalse(self.load()['images'])

    def test_timed_out_unknown_build_empty_listing_is_uncertain(self):
        self.state['unknown_empty']=True;self.save();self.value.initialize()
        with self.assertRaisesRegex(ValueError,'command-timeout'):self.value.bootstrap(self.command(),.1)
        result=self.value.cleanup(remove_image=True)
        self.assertEqual(result['status'],'FAIL');self.assertFalse(result['absence_verified'])
        self.assertIs(result['owned_image_absence'],False)
        self.assertIn('base-image-absence-uncertain',result['errors'])

    def test_cross_job_image_is_never_removed_even_with_spoofed_list(self):
        self.build()
        self.load()['images'][IMAGE]['Config']['Labels'][base_broker.LABEL]='foreign-job'
        self.state['spoof_list']=True;self.save()
        result=self.value.cleanup(remove_image=True)
        self.assertEqual(result['status'],'FAIL')
        self.assertFalse(any(call[:2]==['image','rm'] for call in self.load()['calls']))
        self.assertIn(IMAGE,self.state['images'])

    def test_changed_context_fails_and_owned_image_cleanup_still_works(self):
        self.state['context_drift']=True;self.save();self.value.initialize()
        with self.assertRaisesRegex(ValueError,'base-context-drift'):self.value.bootstrap(self.command(),2)
        self.assertEqual(self.value.cleanup(remove_image=True)['status'],'PASS')

    def test_image_removal_failure_remains_fail(self):
        self.build();self.load()['image_rm_failure']=True;self.save()
        result=self.value.cleanup(remove_image=True)
        self.assertFalse(result['absence_verified']);self.assertIs(result['owned_image_absence'],False)
        self.assertIn(IMAGE,self.load()['images'])

    def test_owned_base_and_different_nonce_stage_containers_removed_before_image(self):
        self.build();self.load()['remove_failure']=True;self.save()
        command=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
                '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']
        with self.assertRaisesRegex(ValueError,'docker-cleanup-failed'):self.value.command(command,2)
        journal=json.loads(self.value.journal_path.read_text())
        row=json.loads(json.dumps(journal['containers'][0]))
        item=json.loads(json.dumps(next(iter(self.load()['containers'].values()))))
        stage_nonce='e'*32;stage_id='f'*64;stage_name='cachy-asahi-probe-'+stage_nonce
        row.update(name=stage_name,id=stage_id)
        item.update(Id=stage_id,Name='/'+stage_name)
        item['Config']['Labels'][BaseBroker.accepted.LABEL]=stage_nonce
        journal['identity']['nonce']=stage_nonce;journal['containers']=[row]
        stage=self.root/'fdk/private';stage.mkdir(parents=True,mode=0o700)
        path=stage/'containers.json';path.write_text(json.dumps(journal))
        self.state['containers'][stage_name]=item;self.state['remove_failure']=False;self.save()
        result=self.value.cleanup(remove_image=True,container_journals=[path])
        self.assertEqual(result['status'],'PASS',result)
        self.assertFalse(self.load()['containers']);self.assertFalse(self.state['images'])
        calls=self.state['calls'];image_remove=next(i for i,c in enumerate(calls) if c[:2]==['image','rm'])
        self.assertTrue(all(i<image_remove for i,c in enumerate(calls) if c[:2]==['container','rm']))

    def test_real_sigterm_unknown_build_recovered_without_claiming_build_success(self):
        self.state['unknown_found']=True;self.save();self.value.initialize()
        result_path=self.root/'cancelled.json'
        helper="""import json,sys
sys.path.insert(0,%r)
import base_broker
from pathlib import Path
B=base_broker.broker_class(Path(%r));B.accepted.validate_endpoint=lambda endpoint,uid:endpoint
r=B.runtime;env=%r
b=B(r.Runner(20,env,Path(%r)/'worker-logs'),r.Runner(1,env,Path(%r)/'worker-cleanup'),%r,%r,%r,%r,%r,Path(%r)/'images.json',%r,jobroot=Path(%r),context=Path(%r),iidfile=Path(%r))
b.initialize(expected_daemon=%r)
with r.cancellation_handlers():
 try:b.bootstrap(%r,15)
 except r.Cancelled:
  with r.defer_signals():result=b.cleanup(remove_image=True)
  result['build_cancelled']=True;Path(%r).write_text(json.dumps(result))
 else:raise SystemExit(9)
""" % (str(Path(base_broker.__file__).parent),str(ADAPTER),self.env,str(self.root),str(self.root),
        str(self.binary),self.digest,self.endpoint,self.uid,self.gid,str(self.root),NONCE,str(self.root),
        str(self.context),str(self.iid),self.value.daemon,self.command(),str(result_path))
        process=subprocess.Popen([sys.executable,'-B','-c',helper],env=self.env,stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,start_new_session=True)
        try:
            end=time.monotonic()+4
            while not (self.root/'build-ready').exists():
                self.assertIsNone(process.poll());self.assertLess(time.monotonic(),end);time.sleep(.01)
            os.kill(process.pid,signal.SIGTERM)
            output=process.communicate(timeout=6)[0]
            self.assertEqual(process.returncode,0,output)
            result=json.loads(result_path.read_text())
            self.assertIs(result['build_cancelled'],True);self.assertIs(result['absence_verified'],True)
            self.assertFalse(self.load()['images'])
        finally:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
            process.stdout.close()

    def cleanup_signal(self, mode):
        self.build()
        if mode=='container':
            self.load()['remove_failure']=True;self.save()
            command=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
                    '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']
            with self.assertRaisesRegex(ValueError,'docker-cleanup-failed'):self.value.command(command,2)
            self.load().update(remove_failure=False,interrupt_rm=True);marker=self.root/'cleanup-ready'
        else:
            self.load()['interrupt_image_'+mode]=True;marker=self.root/'final-cleanup-ready'
        self.save();result_path=self.root/'cleanup-result.json'
        helper="""import json,sys
sys.path.insert(0,%r)
import base_broker
from pathlib import Path
B=base_broker.broker_class(Path(%r));B.accepted.validate_endpoint=lambda endpoint,uid:endpoint
r=B.runtime;env=%r;seen=[]
class Tracked(B):
 def _operation(self,args,*,cleanup=False,timeout=30):
  if cleanup and self.final_deadline is not None:seen.append(self.final_deadline)
  return super()._operation(args,cleanup=cleanup,timeout=timeout)
b=Tracked(r.Runner(20,env,Path(%r)/'worker-logs'),r.Runner(1,env,Path(%r)/'worker-cleanup'),%r,%r,%r,%r,%r,Path(%r)/'images.json',%r,jobroot=Path(%r),context=Path(%r),iidfile=Path(%r))
b.initialize(expected_daemon=%r)
with r.cancellation_handlers():result=b.cleanup(remove_image=True)
result['budget_observations']=seen;Path(%r).write_text(json.dumps(result))
""" % (str(Path(base_broker.__file__).parent),str(ADAPTER),self.env,str(self.root),str(self.root),
        str(self.binary),self.digest,self.endpoint,self.uid,self.gid,str(self.root),NONCE,str(self.root),
        str(self.context),str(self.iid),self.value.daemon,str(result_path))
        process=subprocess.Popen([sys.executable,'-B','-c',helper],env=self.env,stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,start_new_session=True)
        try:
            end=time.monotonic()+5
            while not marker.exists():
                self.assertIsNone(process.poll());self.assertLess(time.monotonic(),end);time.sleep(.01)
            time.sleep(.1)  # Fake CLI exited; owned TERM-resistant pipe holder enters runner cleanup.
            os.kill(process.pid,signal.SIGTERM)
            output=process.communicate(timeout=8)[0]
            self.assertEqual(process.returncode,0,output)
            result=json.loads(result_path.read_text())
            self.assertEqual(result['status'],'FAIL')
            self.assertIs(result['cancelled'],True)
            self.assertIs(result['absence_verified'],True)
            self.assertIs(result['owned_image_absence'],True)
            self.assertEqual(result['legacy_cache_cleanup'],'NOT CLAIMED')
            self.assertEqual(len(set(result['budget_observations'])),1)
            self.assertGreater(len(result['budget_observations']),3)
            self.assertFalse(self.load()['images']);self.assertFalse(self.state['containers'])
            with self.assertRaises(ProcessLookupError):os.kill(int(marker.read_text()),0)
        finally:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=2)
            process.stdout.close()

    def test_final_container_cleanup_cancellation_keeps_failure_and_removes_owned_image(self):
        self.cleanup_signal('container')

    def test_final_image_query_cancellation_recovers_with_same_budget(self):
        self.cleanup_signal('query')

    def test_final_image_removal_cancellation_rechecks_absence_with_same_budget(self):
        self.cleanup_signal('rm')

    def test_unsafe_container_cleanup_failure_prevents_image_removal(self):
        self.build();self.load()['remove_failure']=True;self.save()
        command=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
                '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']
        with self.assertRaises(ValueError):self.value.command(command,2)
        result=self.value.cleanup(remove_image=True)
        self.assertEqual(result['status'],'FAIL');self.assertIs(result['owned_image_absence'],False)
        self.assertFalse(any(call[:2]==['image','rm'] for call in self.load()['calls']))
        self.assertIn(IMAGE,self.state['images'])

    def test_invalid_command_context_iid_and_missing_legacy_optin_refused(self):
        self.value.initialize()
        for args in (self.command()+['--help'],[arg.replace('--network=none','--network=host') for arg in self.command()]):
            with self.assertRaises(ValueError):self.value.bootstrap(args,2)
        self.value.runner.env.pop('DOCKER_BUILDKIT')
        with self.assertRaisesRegex(ValueError,'base-legacy-builder-env'):self.value.bootstrap(self.command(),2)
        self.value.runner.env['DOCKER_BUILDKIT']='0';self.iid.write_text('existing')
        with self.assertRaisesRegex(ValueError,'base-new-iidfile'):self.value.bootstrap(self.command(),2)
        self.iid.unlink();(self.context/'link').symlink_to(self.root/'state.json')
        with self.assertRaisesRegex(ValueError,'base-context-symlink'):self.value.bootstrap(self.command(),2)
        self.assertFalse(any(call[0]=='build' for call in self.load()['calls']))


if __name__=='__main__':unittest.main()
