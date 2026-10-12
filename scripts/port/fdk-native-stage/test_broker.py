#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Real subprocess fake Docker and owned Unix socket; never contact Docker."""
import sys
sys.dont_write_bytecode = True

import hashlib
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
import broker
from runtime import Runner

IMAGE = 'sha256:' + 'a' * 64
NONCE = 'b' * 32
NAME = 'cachy-asahi-0123456789abcdef'
FAKE = r'''#!/usr/bin/python3
import hashlib,json,os,sys,time,signal,socket
from pathlib import Path
root=Path(os.environ['HOME']);path=root/'state.json';s=json.loads(path.read_text())
a=sys.argv[1:];assert a[:2]==['--host',s['endpoint']];a=a[2:]
s['calls'].append(a)
def save():path.write_text(json.dumps(s))
def emit(value):save();print(json.dumps(value))
save()
if a[:1]==['info']:raise SystemExit('docker info must never run')
elif a[:2]==['image','inspect']:
 emit([{'Id':s['image'],'Architecture':'arm64','Os':'linux','Config':{'Env':['PATH=/usr/bin:/bin'],'Volumes':s.get('volumes')}}])
 if s.get('drift_after_image'):s['daemon']='DAEMON-CHANGED';save()
 if s.get('binary_after_image'):Path(sys.argv[0]).write_bytes(Path(sys.argv[0]).read_bytes()+b'\n# drift\n')
 if s.get('socket_after_image'):
  p=Path(s['endpoint'][7:]);p.rename(root/'old.sock');v=socket.socket(socket.AF_UNIX);v.bind(str(p));v.close()
elif a[:2]==['container','ls']:
 value=a[-1];name=value.removeprefix('name=^/').removesuffix('$')
 for item in s['containers'].values():
  if item['Name']=='/'+name or value=='id='+item['Id']:print(json.dumps({'ID':item['Id'],'Names':item['Name'][1:]}))
elif a[:2]==['container','inspect']:
 item=next((v for v in s['containers'].values() if v['Id']==a[2] or v['Name']=='/'+a[2]),None)
 if item is None:raise SystemExit(1)
 emit([item])
elif a[:1]==['create']:
 name=a[a.index('--name')+1];row=next(r for r in json.loads((root/'journal.json').read_text())['containers'] if r['name']==name)
 assert row['create_attempted'] is True
 if s.get('empty_unknown'):
  (root/'create-ready').write_text('ready');time.sleep(60)
 ident=hashlib.sha256(name.encode()).hexdigest()
 env={'PATH':'/usr/bin:/bin',**row['env']}
 s['containers'][name]={'Id':ident,'Name':'/'+name,'Image':s['image'],
 'Config':{'User':s['user'],'Labels':{'org.cachy-asahi.fdk-stage.nonce':s.get('label',s['nonce'])},'Env':[k+'='+v for k,v in env.items()],'Entrypoint':['/bin/bash'],'Cmd':row['cmd']},
 'HostConfig':{'AutoRemove':False,'Privileged':False,'ReadonlyRootfs':True,'NetworkMode':'none','IpcMode':'private','PidMode':'','CgroupnsMode':'private','Memory':4294967296,'MemorySwap':4294967296,'NanoCpus':4000000000,'PidsLimit':512,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Tmpfs':{'/tmp':'rw,nosuid,nodev,exec,size=4g'}},
 'Mounts':[{'Type':'bind','Source':v,'Destination':k,'RW':k=='/out'} for k,v in row['mounts'].items()]}
 if s.get('resource_drift'):s['containers'][name]['HostConfig']['Privileged']=True
 save()
 if s.get('create_sleep'):(root/'create-ready').write_text('ready');time.sleep(60)
 print('unknown' if s.get('unknown_create') else ident)
elif a[:1]==['start']:
 assert a[1:3]==['--attach','--sig-proxy=false'];item=next(v for v in s['containers'].values() if v['Id']==a[3])
 if s.get('start_sleep'):(root/'start-ready').write_text('ready');time.sleep(60)
 if item['Config']['Cmd'][0]=='-euc':print(s['user'].replace(':','\n')+'\nalpha 1\nbeta 2')
 else:print('build output');raise SystemExit(s.get('build_code',0))
elif a[:2]==['container','rm']:
 if s.get('remove_failure'):raise SystemExit(1)
 key=next(k for k,v in s['containers'].items() if v['Id']==a[3]);del s['containers'][key];save();print(a[3])
 if s.get('interrupt_rm'):
  s['interrupt_rm']=False;save();pid=os.fork()
  if pid==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60);os._exit(0)
  (root/'cleanup-ready').write_text(str(pid))
else:raise SystemExit(9)
'''

HTTP_SERVER = r'''import json,socket,sys,time
from pathlib import Path
root=Path(sys.argv[1]);server=socket.socket(fileno=int(sys.argv[2]))
while True:
 connection,_=server.accept()
 with connection:
  request=b''
  while b'\r\n\r\n' not in request:
   data=connection.recv(4096)
   if not data:break
   request+=data
   assert len(request)<4096
  assert request.startswith(b'GET /info HTTP/1.1\r\n')
  with (root/'http-requests.log').open('ab') as log:log.write(request)
  state=json.loads((root/'state.json').read_text());mode=state.get('http_mode')
  body=json.dumps({'ID':state['daemon'],'Architecture':'aarch64','OSType':'linux'}).encode()
  if mode=='stall':time.sleep(60)
  if mode in ('chunked','chunk_separator','chunk_final','chunk_extension','chunk_trailer','chunk_truncated'):
   reply=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'+hex(len(body))[2:].encode()+b'\r\n'+body+b'\r\n0\r\n\r\n'
   if mode=='chunk_separator':reply=reply.replace(body+b'\r\n',body+b'XX')
   if mode=='chunk_final':reply=reply[:-2]
   if mode=='chunk_extension':reply=reply.replace(b'\r\n'+body,b';extension=1\r\n'+body)
   if mode=='chunk_trailer':reply=reply[:-2]+b'Trailer: refused\r\n\r\n'
   if mode=='chunk_truncated':reply=reply[:-10]
  elif mode=='truncated':reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)+10).encode()+b'\r\n\r\n'+body
  elif mode=='status':reply=b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'
  elif mode=='bomb':reply=b'HTTP/1.1 200 OK\r\n\r\n'+b'x'*(8*1024*1024+1)
  elif mode=='trailing':reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body+b'extra'
  elif mode=='ambiguous':reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nTransfer-Encoding: chunked\r\n\r\n'+body
  else:reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
  try:connection.sendall(reply)
  except (BrokenPipeError,ConnectionResetError):pass
'''


class BrokerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='fdk-broker-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'fake-docker'
        self.binary.write_text(FAKE)
        self.binary.chmod(0o755)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.config = self.root / 'config'
        self.config.mkdir(mode=0o700)
        self.sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.sock.close)
        self.sock.bind(str(self.root / 'docker.sock'))
        self.sock.listen(32)
        self.endpoint = 'unix://' + str(self.root / 'docker.sock')
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'DOCKER_CONFIG': str(self.config),
                    'LANG': 'C.UTF-8', 'LC_ALL': 'C'}
        self.uid, self.gid = max(os.getuid(), 1000), max(os.getgid(), 1000)
        self.state = {'calls': [], 'daemon': 'DAEMON-ORIGINAL', 'image': IMAGE,
                      'nonce': NONCE, 'endpoint': self.endpoint, 'user': f'{self.uid}:{self.gid}', 'containers': {}}
        self.save()
        self.server = subprocess.Popen([sys.executable, '-B', '-c', HTTP_SERVER, str(self.root),
                                        str(self.sock.fileno())], pass_fds=(self.sock.fileno(),),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        self.addCleanup(self.stop_server)
        self.mounts = {destination: str(self.root / ('m-' + str(index)))
                       for index, destination in enumerate(broker.DESTINATIONS)}
        for destination, name in self.mounts.items():
            path = Path(name)
            path.mkdir() if destination in ('/inputs', '/out') else path.write_bytes(b'fixture')
        patcher = mock.patch.object(broker, 'validate_endpoint', side_effect=lambda endpoint, uid: self.endpoint)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.value = self.make()

    def stop_server(self):
        if self.server.poll() is None:
            os.killpg(self.server.pid, signal.SIGTERM)
        try:
            self.server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(self.server.pid, signal.SIGKILL)
            self.server.wait(timeout=2)
        self.server.stdout.close()

    def tearDown(self):
        self.assertFalse(any(call[0] == 'info' for call in self.load()['calls']))

    def save(self):
        (self.root / 'state.json').write_text(json.dumps(self.state))

    def load(self):
        self.state = json.loads((self.root / 'state.json').read_text())
        return self.state

    def make(self):
        return broker.Broker(Runner(30, self.env, self.root / 'logs'),
                             Runner(1, self.env, self.root / 'cleanup-logs'), self.binary,
                             self.digest, self.endpoint, IMAGE, self.uid, self.gid,
                             self.root / 'journal.json', NONCE, expected_mounts=self.mounts)

    def command(self):
        args = ['docker','run','--rm','--name',NAME,'--pull=never','--platform','linux/arm64',
                '--user',f'{self.uid}:{self.gid}','--cap-drop=ALL','--security-opt=no-new-privileges',
                '--read-only','--pids-limit','512','--memory','4g','--cpus','4','--network','none',
                '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1',
                '--env','SOURCE_DATE_EPOCH=1791748800']
        for destination, source in self.mounts.items():
            args += ['--mount', f'type=bind,src={source},dst={destination}' +
                     (',readonly' if broker.DESTINATIONS[destination] else '')]
        return args + ['--entrypoint','/bin/bash',IMAGE,'/builder-entry.sh']

    def test_success_probe_build_logs_and_reloaded_parent_cleanup(self):
        daemon = self.value.initialize()
        self.assertEqual(daemon, {'id': 'DAEMON-ORIGINAL', 'architecture': 'aarch64'})
        self.assertEqual(self.value.probe(), f'{self.uid}\n{self.gid}\nalpha 1\nbeta 2\n'.encode())
        result = self.value.build(self.command(), 2)
        self.assertEqual((result.returncode, result.stdout), (0, b'build output\n'))
        self.assertTrue(self.value.last_cleanup['absence_verified'])
        parent = self.make()
        parent.initialize(expected_daemon=daemon)
        parent.cleanup_runner.deadline = 0
        self.assertEqual(parent.cleanup()['status'], 'PASS')
        self.assertFalse(self.load()['containers'])
        creates = [call for call in self.state['calls'] if call[0] == 'create']
        self.assertEqual(len(creates), 2)
        self.assertTrue(all('--rm' not in call and '--ipc=private' in call for call in creates))
        self.assertTrue(any(path.read_bytes() == b'build output\n' for path in (self.root/'logs').iterdir()))
        self.assertEqual(self.value.capture(['docker','info','--format','{{.Architecture}}']), 'aarch64')
        self.assertIn(b'GET /info HTTP/1.1\r\n', (self.root/'http-requests.log').read_bytes())

    def test_http_chunked_and_content_length_are_read_without_cli_helpers(self):
        for mode in (None, 'chunked'):
            self.load()['http_mode'] = mode
            self.save()
            self.assertEqual(self.value.initialize()['architecture'], 'aarch64')

    def test_http_malformed_truncated_status_and_wire_bounds_rejected(self):
        for mode in ('truncated', 'status', 'bomb', 'trailing', 'ambiguous'):
            with self.subTest(mode=mode):
                self.load()['http_mode'] = mode
                self.save()
                with self.assertRaises(ValueError):
                    self.value.initialize()

    def test_http_invalid_chunk_boundaries_and_unsupported_extensions_trailers_rejected(self):
        for mode in ('chunk_separator','chunk_final','chunk_extension','chunk_trailer','chunk_truncated'):
            with self.subTest(mode=mode):
                self.load()['http_mode'] = mode
                self.save()
                with self.assertRaisesRegex(ValueError, 'docker-daemon-chunk-framing'):
                    self.value.initialize()

    def test_image_volumes_rejected_before_any_container_creation(self):
        self.state['volumes'] = {'/unexpected-volume': {}}
        self.save()
        with self.assertRaisesRegex(ValueError, 'docker-image-volumes'):
            self.value.initialize()
        self.assertFalse(any(call[0] == 'create' for call in self.load()['calls']))

    def test_http_stall_respects_runner_deadline(self):
        self.load()['http_mode'] = 'stall'
        self.save()
        self.value.runner.deadline = time.monotonic() + .1
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'docker-daemon-timeout'):
            self.value.initialize()
        self.assertLess(time.monotonic() - start, 1)

    def test_unknown_create_found_owned_is_removed_and_absence_verified(self):
        self.value.initialize()
        self.load()['unknown_create'] = True
        self.save()
        with self.assertRaisesRegex(ValueError, 'docker-create-unknown'):
            self.value.build(self.command(), 2)
        self.assertTrue(self.value.last_cleanup['absence_verified'])
        self.assertFalse(self.load()['containers'])
        self.assertTrue(self.value.cleanup()['absence_verified'])
        parent = self.make()
        parent.initialize(expected_daemon=self.value.daemon)
        self.assertTrue(parent.cleanup()['absence_verified'])

    def test_removal_failure_is_fail_and_never_claims_absence(self):
        self.value.initialize()
        self.load()['remove_failure'] = True
        self.save()
        with self.assertRaisesRegex(ValueError, 'docker-cleanup-failed'):
            self.value.build(self.command(), 2)
        self.assertFalse(self.value.last_cleanup['absence_verified'])
        self.assertTrue(self.load()['containers'])

    def unsafe_container(self, field, value):
        self.value.initialize()
        self.load()[field] = value
        self.save()
        with self.assertRaises(ValueError):
            self.value.build(self.command(), 2)
        state = self.load()
        self.assertFalse(any(call[0] == 'start' or call[:2] == ['container','rm'] for call in state['calls']))
        self.assertFalse(self.value.last_cleanup['absence_verified'])


    def test_foreign_nonce_refuses_start_and_unrelated_removal(self):
        self.unsafe_container('label', 'foreign')

    def test_resource_drift_refuses_start(self):
        self.unsafe_container('resource_drift', True)

    def test_daemon_drift_after_query_is_detected(self):
        self.value.initialize()
        self.load()['drift_after_image'] = True
        self.save()
        with self.assertRaisesRegex(ValueError, 'docker-daemon-drift'):
            self.value.capture(['docker','image','inspect',IMAGE])
        self.assertFalse(any(call[0] == 'create' for call in self.load()['calls']))

    def after_query_drift(self, field, error):
        self.value.initialize()
        self.load()[field] = True
        self.save()
        with self.assertRaisesRegex(ValueError, error):
            self.value.capture(['docker','image','inspect',IMAGE])

    def test_binary_is_reverified_after_operation(self):
        self.after_query_drift('binary_after_image', 'docker-binary-drift')

    def test_socket_is_reverified_after_operation(self):
        self.after_query_drift('socket_after_image', 'docker-local-pin-drift')

    def test_binary_socket_config_and_expected_daemon_pins(self):
        daemon = self.value.initialize()
        with self.assertRaisesRegex(ValueError, 'docker-expected-daemon'):
            self.make().initialize(expected_daemon={**daemon, 'id': 'WRONG-DAEMON'})
        self.binary.write_bytes(self.binary.read_bytes() + b'\n# drift\n')
        with self.assertRaisesRegex(ValueError, 'docker-binary-drift'):
            self.value.capture(['docker','info','--format','{{.Architecture}}'])
        self.binary.write_text(FAKE)
        (self.config/'config.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'docker-config'):
            self.value.capture(['docker','info','--format','{{.Architecture}}'])
        (self.config/'config.json').unlink()
        original = self.root/'docker.sock'
        original.rename(self.root/'old.sock')
        changed = socket.socket(socket.AF_UNIX)
        self.addCleanup(changed.close)
        changed.bind(str(original))
        with self.assertRaisesRegex(ValueError, 'docker-local-pin-drift'):
            self.value.capture(['docker','info','--format','{{.Architecture}}'])

    def test_unapproved_commands_options_mounts_and_environment_never_create(self):
        self.value.initialize()
        for option in ('--privileged', '--pid=host', '--device=/dev/kvm', '--env=LEAK=secret'):
            args = self.command()
            args.insert(2, option)
            with self.assertRaises(ValueError):
                self.value.build(args, 2)
        for previous, changed in (('SOURCE_DATE_EPOCH=1791748800', 'SOURCE_DATE_EPOCH=1'),
                                  (NAME, 'cachy-asahi-unapproved-name')):
            with self.assertRaises(ValueError):
                self.value.build([changed if item == previous else item for item in self.command()], 2)
        self.value.expected_mounts = None
        with self.assertRaisesRegex(ValueError, 'docker-build-mounts'):
            self.value.build(self.command(), 2)
        for args in (['docker','ps'], ['docker','context','inspect'], ['docker','image','inspect','other']):
            with self.assertRaises(ValueError):
                self.value.capture(args)
        self.value.runner.env['DOCKER_HOST'] = 'tcp://remote'
        with self.assertRaisesRegex(ValueError, 'docker-environment'):
            self.value.capture(['docker','info','--format','{{.Architecture}}'])
        self.assertFalse(any(call[0] == 'create' for call in self.load()['calls']))

    def cancel_create(self, mode, expected_absence):
        self.value.initialize()
        self.load()[mode] = True
        self.save()
        helper = """import json,sys
sys.path.insert(0,%r)
import broker
from runtime import Runner,Cancelled,cancellation_handlers
from pathlib import Path
broker.validate_endpoint=lambda endpoint,uid:endpoint
env=%r
b=broker.Broker(Runner(20,env,Path(%r)/'worker-logs'),Runner(1,env,Path(%r)/'worker-cleanup'),%r,%r,%r,%r,%r,%r,Path(%r)/'journal.json',%r,expected_mounts=%r)
b.initialize(expected_daemon=%r)
with cancellation_handlers():
 try:b.build(%r,15)
 except Cancelled:Path(%r).write_text(json.dumps(b.last_cleanup))
 else:raise SystemExit(9)
""" % (str(Path(broker.__file__).parent), self.env, str(self.root), str(self.root),
        str(self.binary),self.digest,self.endpoint,IMAGE,self.uid,self.gid,str(self.root),NONCE,
        self.mounts,self.value.daemon,self.command(),str(self.root/'cancelled.json'))
        process = subprocess.Popen([sys.executable,'-B','-c',helper],env=self.env,
                                   stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            end = time.monotonic()+5
            while not (self.root/'create-ready').exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(),end)
                time.sleep(.01)
            os.kill(process.pid,signal.SIGTERM)
            output = process.communicate(timeout=8)[0]
            self.assertEqual(process.returncode,0,output)
            result = json.loads((self.root/'cancelled.json').read_text())
            self.assertIs(result['absence_verified'],expected_absence)
            self.assertFalse(self.load()['containers'])
            self.assertTrue(json.loads((self.root/'journal.json').read_text())['containers'][0]['create_attempted'])
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=2)
            process.stdout.close()


    def test_cancelled_unknown_create_found_owned_is_removed(self):
        self.cancel_create('create_sleep', True)

    def test_cancelled_unknown_create_empty_listing_is_not_absence_proof(self):
        self.cancel_create('empty_unknown', False)

    def test_signal_during_cleanup_recovers_once_and_continues_owned_names(self):
        self.value.initialize()
        self.load()['remove_failure'] = True
        self.save()
        names = (NAME, 'cachy-asahi-fedcba9876543210')
        for name in names:
            with self.assertRaisesRegex(ValueError, 'docker-cleanup-failed'):
                self.value.build([name if item == NAME else item for item in self.command()], 2)
        self.load().update(remove_failure=False, interrupt_rm=True)
        self.save()
        output_path = self.root/'cleanup-result.json'
        helper = """import json,sys
sys.path.insert(0,%r)
import broker
from runtime import Runner,cancellation_handlers
from pathlib import Path
broker.validate_endpoint=lambda endpoint,uid:endpoint
env=%r
b=broker.Broker(Runner(20,env,Path(%r)/'worker-logs'),Runner(1,env,Path(%r)/'worker-cleanup'),%r,%r,%r,%r,%r,%r,Path(%r)/'journal.json',%r)
b.initialize(expected_daemon=%r)
with cancellation_handlers():result=b.cleanup()
Path(%r).write_text(json.dumps(result))
""" % (str(Path(broker.__file__).parent), self.env, str(self.root), str(self.root),
        str(self.binary),self.digest,self.endpoint,IMAGE,self.uid,self.gid,str(self.root),NONCE,
        self.value.daemon,str(output_path))
        process = subprocess.Popen([sys.executable,'-B','-c',helper],env=self.env,
                                   stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            end = time.monotonic()+5
            while not (self.root/'cleanup-ready').exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(),end)
                time.sleep(.01)
            time.sleep(.1)  # The exited fake CLI leaves a TERM-resistant pipe holder.
            os.kill(process.pid,signal.SIGTERM)
            output = process.communicate(timeout=8)[0]
            self.assertEqual(process.returncode,0,output)
            result = json.loads(output_path.read_text())
            self.assertEqual(result['status'],'FAIL')
            self.assertIs(result['cancelled'],True)
            self.assertIs(result['absence_verified'],True)
            self.assertFalse(self.load()['containers'])
            with self.assertRaises(ProcessLookupError):
                os.kill(int((self.root/'cleanup-ready').read_text()),0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=2)
            process.stdout.close()


if __name__ == '__main__':
    unittest.main()
