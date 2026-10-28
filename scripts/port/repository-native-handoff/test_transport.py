#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Harmless fixed Python children; daemon/CLI grants are explicitly MODELED."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('handoff_transport',Path(__file__).with_name('transport.py'))
transport = importlib.util.module_from_spec(spec); spec.loader.exec_module(transport)


class FixtureTransport:
    execution = 'MODELED-daemon-harmless-Python-child'
    def invoke(self, program, *, deadline=None, limit=1024**2, **callbacks):
        return transport.supervise([sys.executable,'-I','-B','-S','-c',program],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, deadline=deadline or time.monotonic()+3,
            limit=limit,**callbacks)


class PipeTests(unittest.TestCase):
    def setUp(self):self.fixture=FixtureTransport()

    def test_natural_zero_and_nonzero_preserve_separate_pipes(self):
        for code in (0,7):
            result,obs=self.fixture.invoke(f'import os;os.write(1,b"out");os.write(2,b"err");raise SystemExit({code})')
            self.assertEqual(result,{'exit_code':code,'stdout':b'out','stderr':b'err'})
            self.assertEqual(obs['natural_returncode'],code);self.assertFalse(obs['forced_teardown'])
            self.assertTrue(obs['direct_child_reaped'])

    def test_duplex_partial_ack_writes_are_drained(self):
        ack=b'x'*65536;queued=[ack];stdout=[]
        program='''import os,time
os.write(1,b'checkpoint\\n')
data=bytearray()
while len(data)<65536:
 data.extend(os.read(0,min(1024,65536-len(data))));time.sleep(.001)
os.write(2,str(len(data)).encode())
'''
        ready=[]
        def observed(chunk):stdout.append(chunk);ready.append(True)
        def stdin():return queued.pop(0)if ready and queued else None
        write=os.write
        # Pipe capacities vary. Force bounded short writes while retaining the
        # actual child/pipe so this control always exercises ACK queue draining.
        with mock.patch.object(transport.os,'write',side_effect=lambda fd,data:write(fd,data[:4096])):
            result,obs=self.fixture.invoke(program,on_stdout=observed,on_stdin=stdin)
        self.assertEqual(result['exit_code'],0);self.assertEqual(result['stderr'],b'65536')
        self.assertEqual(result['stdout'],b''.join(stdout));self.assertEqual(obs['stdin_bytes'],65536)
        self.assertGreater(obs['stdin_writes'],1)

    def test_stderr_flood_fails_bound_and_reaps(self):
        with self.assertRaises(transport.Refused)as error:
            self.fixture.invoke('import os,time;os.write(2,b"x"*100000);time.sleep(10)',limit=1000)
        self.assertLessEqual(len(error.exception.result['stderr']),1001)
        self.assertNotEqual(error.exception.result['exit_code'],0)
        self.assertTrue(error.exception.observation['direct_child_reaped'])

    def test_absolute_deadline_cannot_be_renewed(self):
        start=time.monotonic()
        with self.assertRaises(transport.Refused)as error:
            self.fixture.invoke('import time;time.sleep(10)',deadline=start+.08)
        self.assertLess(time.monotonic()-start,1)
        self.assertTrue(error.exception.observation['forced_teardown']);self.assertNotEqual(error.exception.result['exit_code'],0)

    def test_forced_cooperative_zero_is_not_natural_success(self):
        program='import signal,time,sys;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));time.sleep(10)'
        with self.assertRaises(transport.Refused)as error:self.fixture.invoke(program,deadline=time.monotonic()+.1)
        self.assertEqual(error.exception.observation['teardown_returncode'],0)
        self.assertTrue(error.exception.observation['forced_teardown']);self.assertEqual(error.exception.result['exit_code'],-1)

    def test_early_stdin_close_refuses_ack_delivery(self):
        queue=[b'ACK\n'];ready=[]
        with self.assertRaises(transport.Refused)as error:
            self.fixture.invoke('import os,time;os.close(0);os.write(1,b"checkpoint");time.sleep(10)',
                on_stdout=lambda chunk:ready.append(True),on_stdin=lambda:queue.pop(0)if ready and queue else None)
        self.assertTrue(error.exception.observation['direct_child_reaped']);self.assertNotEqual(error.exception.result['exit_code'],0)

    def test_callback_refusal_disposes_owned_child(self):
        def refuse(_):raise ValueError('MODELED checkpoint refusal')
        with self.assertRaises(transport.Refused)as error:
            self.fixture.invoke('import os,time;os.write(1,b"checkpoint");time.sleep(10)',on_stdout=refuse,on_stdin=lambda:None)
        self.assertTrue(error.exception.observation['forced_teardown']);self.assertTrue(error.exception.observation['direct_child_reaped'])

    def test_real_term_during_stdout_callback_reaps_before_refusal(self):
        old={n:signal.getsignal(n)for n in transport.SIGNALS}
        def interrupt(_):os.kill(os.getpid(),signal.SIGTERM)
        with self.assertRaises(transport.Refused)as error:
            self.fixture.invoke('import os,time;os.write(1,b"ready");time.sleep(10)',on_stdout=interrupt,on_stdin=lambda:None)
        self.assertTrue(error.exception.observation['cancelled']);self.assertTrue(error.exception.observation['direct_child_reaped'])
        self.assertEqual(old,{n:signal.getsignal(n)for n in transport.SIGNALS})

    def test_nested_owner_receives_cancellation_after_child_disposal(self):
        notified=[];old=signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM,lambda number,frame:notified.append(number))
        try:
            with self.assertRaises(transport.Refused)as error:
                self.fixture.invoke('import os,time;os.write(1,b"ready");time.sleep(10)',
                    on_stdout=lambda _:os.kill(os.getpid(),signal.SIGTERM),on_stdin=lambda:None)
            self.assertEqual(notified,[signal.SIGTERM]);self.assertTrue(error.exception.observation['direct_child_reaped'])
        finally:signal.signal(signal.SIGTERM,old)

    def test_cooperative_forced_parent_reaps_harmless_descendant(self):
        program='''import os,signal,time
child=os.fork()
if child==0:time.sleep(10);os._exit(0)
def stop(*args):
 try:os.kill(child,signal.SIGTERM)
 except ProcessLookupError:pass
 os.waitpid(child,0);os._exit(0)
signal.signal(signal.SIGTERM,stop)
os.write(1,str(child).encode());time.sleep(10)
'''
        with self.assertRaises(transport.Refused)as error:self.fixture.invoke(program,deadline=time.monotonic()+.12)
        pid=int(error.exception.result['stdout']);self.assertFalse(Path(f'/proc/{pid}').exists())
        self.assertEqual(error.exception.observation['teardown_returncode'],0)
        self.assertNotEqual(error.exception.result['exit_code'],0)

    def test_natural_exit_disposes_inherited_pipe_descendant(self):
        program='''import os,time
child=os.fork()
if child==0:time.sleep(10);os._exit(0)
os.write(1,str(child).encode());os._exit(0)
'''
        result,obs=self.fixture.invoke(program,deadline=time.monotonic()+1)
        self.assertEqual(result['exit_code'],0);self.assertTrue(obs['group_disposal_requested'])
        pid=int(result['stdout'])
        # An adopted zombie is inert; reaping that non-child belongs to its init.
        try:state=Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[0]
        except FileNotFoundError:state=None
        self.assertIn(state,(None,'Z'));self.assertTrue(obs['direct_child_reaped'])

    def test_child_mask_restores_callers_original_state(self):
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        result,_=self.fixture.invoke('import signal;print(sorted(int(n)for n in signal.pthread_sigmask(signal.SIG_BLOCK,set())))')
        self.assertEqual(json.loads(result['stdout']),sorted(int(n)for n in mask))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),mask)

    def test_expired_boolean_nan_and_infinite_deadlines_never_spawn(self):
        for end in (time.monotonic()-1,True,float('nan'),float('inf')):
            with self.subTest(end=end),mock.patch.object(transport.subprocess,'Popen')as spawn:
                with self.assertRaises(transport.Refused):transport.supervise(['never'],env={},deadline=end,limit=10)
                spawn.assert_not_called()

    def test_post_execution_identity_drift_cannot_return_zero(self):
        calls=[]
        def guard():
            calls.append(True)
            if len(calls)==2:raise ValueError('MODELED identity drift')
        with self.assertRaises(transport.Refused)as error:self.fixture.invoke('pass',preflight=guard)
        self.assertEqual(error.exception.observation['natural_returncode'],0);self.assertNotEqual(error.exception.result['exit_code'],0)


class GrammarTests(unittest.TestCase):
    def fixture(self,root):
        obj=transport.DockerTransport.__new__(transport.DockerTransport)
        obj.scope=None;obj.cid=None;obj.created=False;obj.cancelled=False
        obj.bind('cachy-asahi-repository-'+'a'*32,'sha256:'+'b'*64)
        directory=Path(root)/('launch-'+'a'*32);directory.mkdir(mode=0o700)
        obj.validator=lambda argv:{'name':obj.scope['name'],'image_id':obj.scope['image_id'],'cidfile':directory/'cid'}
        return obj,directory/'cid'

    def create(self,obj,path):
        name,image=obj.scope['name'],obj.scope['image_id'];nonce='a'*32
        argv=['docker','create','-i','--cidfile',str(path),'--name',name,'--pull=never','--platform=linux/arm64',
            '--user','0:0','--network=none','--cgroupns=private','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit=512','--memory=8g','--cpus=4']+['--cap-add='+cap for cap in transport.CAPS]+[
            '--read-only','--tmpfs','/scratch:rw,nosuid,nodev,exec,size=6g,mode=0700',
            '--tmpfs','/test-home:rw,nosuid,nodev,exec,size=128m,mode=0700']
        for dest,ro in (('/inputs',True),('/runner',True),('/out',False)):
            argv+=['--mount','type=bind,src=/MODELED'+dest+',dst='+dest+(',readonly'if ro else'')]
        argv+=['--env','CACHY_ASAHI_REPOSITORY_CONTAINER=1','--env','CACHY_ASAHI_DISPOSABLE_REPOSITORY='+nonce,
            '--env','CACHY_ASAHI_IMAGE_ID='+image,'--entrypoint=/usr/bin/python3',image,'-B','-I','/runner/producer.py',
            '--handoff-deadline',repr(time.monotonic()+30),'--inputs','/inputs/manifest.json','--inputs-sha256','e'*64,
            '--allow-disposable-repository-test']
        return argv

    def test_exact_create_vector_is_independently_checked(self):
        with tempfile.TemporaryDirectory()as root:
            obj,path=self.fixture(root);argv=self.create(obj,path)
            obj._authorize(argv);self.assertTrue(obj.created)
            with self.assertRaises(transport.Refused):obj._authorize(argv)

    def test_overbroad_registry_cannot_grant_extra_privileges_or_args(self):
        changes=[lambda argv:argv.insert(5,'--privileged'),lambda argv:argv.__setitem__(argv.index('--network=none'),'--network=host'),
            lambda argv:argv.__setitem__(argv.index('--memory=8g'),'--memory=9g'),lambda argv:argv.append('--evil')]
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory()as root:
                obj,path=self.fixture(root);argv=self.create(obj,path);change(argv)
                with self.assertRaises(transport.Refused):obj._authorize(argv)
                self.assertFalse(obj.created)

    def test_source_reader_refuses_links_and_detects_actual_drift(self):
        with tempfile.TemporaryDirectory()as root:
            path=Path(root)/'source';path.write_bytes(b'original')
            alias=Path(root)/'alias';alias.symlink_to(path)
            with self.assertRaises((OSError,transport.Refused)):transport.read_file(alias)
            original=transport.os.read;changed=[]
            def mutate(fd,size):
                value=original(fd,size)
                if not changed:changed.append(True);path.write_bytes(b'changed!')
                return value
            with mock.patch.object(transport.os,'read',side_effect=mutate),self.assertRaises(transport.Refused):transport.read_file(path)

    def test_bound_readonly_queries_and_scoped_ids_only(self):
        with tempfile.TemporaryDirectory()as root:
            obj,path=self.fixture(root)
            obj._authorize(['docker','image','inspect',obj.scope['image_id']])
            for argv in (['docker','image','inspect','sha256:'+'e'*64],['docker','system','prune'],
                         ['docker','--host=tcp://localhost:1234','info'],['docker','container','rm','-f','c'*64]):
                with self.assertRaises(transport.Refused):obj._authorize(argv)
            obj.created=True;obj.cid='c'*64
            obj._authorize(['docker','container','rm','-f','c'*64])
            with self.assertRaises(transport.Refused):obj._authorize(['docker','container','rm','-f','d'*64])
            with self.assertRaises(transport.Refused):obj.bind(obj.scope['name'],obj.scope['image_id'])

    def test_sticky_cancel_denies_start_but_allows_owned_cleanup(self):
        with tempfile.TemporaryDirectory()as root:
            obj,path=self.fixture(root);obj.created=True;obj.cid='c'*64;obj.cancelled=True
            with self.assertRaises(transport.Refused):obj._authorize(['docker','start','--attach','--interactive',obj.cid],True)
            obj._authorize(['docker','container','inspect',obj.cid]);obj._authorize(['docker','container','rm','-f',obj.cid])

    def test_unbound_transport_cannot_query_daemon(self):
        obj=transport.DockerTransport.__new__(transport.DockerTransport);obj.scope=None
        with self.assertRaises(transport.Refused):obj._authorize(['docker','info','--format','{{.Architecture}}'])

    def test_constructor_refuses_network_or_credential_env_without_actors(self):
        base={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///run/docker.sock','DOCKER_BUILDKIT':'0','LC_ALL':'C'}
        for changes in ({'HTTP_PROXY':'https://credential.test'}, {'DOCKER_HOST':'tcp://127.0.0.1:2375'}, {'PATH':'/tmp'}):
            with self.subTest(changes=changes),mock.patch.object(transport,'read_file')as read,mock.patch.object(transport.subprocess,'Popen')as spawn:
                with self.assertRaises(transport.Refused):transport.DockerTransport(cli_sha256='a'*64,endpoint_identity=[0]*6,
                    env=dict(base,**changes),create_validator=lambda _:None)
                read.assert_not_called();spawn.assert_not_called()


if __name__=='__main__':unittest.main()
