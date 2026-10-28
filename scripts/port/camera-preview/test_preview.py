# SPDX-License-Identifier: MIT
"""Controlled state/PNG fixtures and fixed harmless Python lifetimes only."""
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

import preview

NONCE = 'a' * 32
EOS = b'Got EOS from element "pipeline0".\n'


def chunk(kind, data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)


def image(raw=None, header=None):
    header = header or struct.pack('>IIBBBBB',160,120,8,2,0,0,0)
    raw = raw if raw is not None else (b'\0'+b'\0'*480)*120
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',header)+chunk(b'IDAT',zlib.compress(raw))+chunk(b'IEND',b'')


class Clock:
    def __init__(self): self.value=0
    def monotonic(self): return self.value
    def sleep(self, value): self.value += value


class Fixture(preview.Backend):
    origin='CONTROLLED_FIXTURE'
    def __init__(self, private, fault=None):
        self.private,self.fault=private,fault; self.rows={}; self.starts=[];self.stops=[];self.reaps=[];self.deadlines=[]
    def admit(self,*args):
        return preview.Admission(os.getuid(),os.getgid(),tuple((k,'0'*64) for k in preview.GRANTS))
    def verify(self,*args): pass
    def reserve(self,role,deadline):
        self.rows[role]=preview.Observation(False,None,True,launch='NO_LAUNCH')
    def start(self,role,argv,env,deadline):
        self.starts.append((role,argv,env));self.deadlines.append(deadline)
        alive=role in ('daemon','producer','consumer') or self.fault=='hang-'+role
        self.rows[role]=preview.Observation(alive,None if alive else 0,not alive,EOS if role=='consumer' else b'')
        if role=='consumer':
            frame=self.private/'preview.png';frame.write_bytes(image());frame.chmod(0o600)
            if self.fault=='bad-frame':frame.write_bytes(b'not a PNG')
            if self.fault=='linked-frame':os.link(frame,self.private/'other.png')
            if self.fault=='bad-log':self.rows[role]=preview.Observation(True,None,False,b'x'*(preview.LOG_LIMIT+1))
        if self.fault=='exit-daemon' and role=='daemon':self.rows[role]=preview.Observation(False,0,True)
        if role=='link' and self.fault not in ('hang-consumer','bad-log'):
            output = b'' if self.fault=='missing-eos' else b'handling interrupt.\n'+EOS if self.fault=='forced-eos' else EOS
            self.rows['consumer']=preview.Observation(False,1 if self.fault=='exit-consumer' else 0,True,output)
        if self.fault=='exit-link' and role=='link':self.rows[role]=preview.Observation(False,125,True)
        if self.fault=='partial-'+role:raise OSError('private partial startup path')
    def pid(self,role):return 100+preview.ROLES.index(role)
    def registry(self,deadline):
        value={'nodes':[{'id':1,'name':'caa-camera-source.'+NONCE,'pid':101},
                        {'id':2,'name':'caa-camera-preview.'+NONCE,'pid':102}],
               'ports':[{'id':3,'node':1,'direction':'out'},{'id':4,'node':2,'direction':'in'}]}
        if self.fault=='bad-graph':value['nodes'][0]['pid']=999
        return json.dumps(value).encode()
    def observe(self,role,deadline):return self.rows[role]
    def stop(self,role,number,deadline):
        self.stops.append((role,number,deadline))
        if self.fault=='signal-cleanup':os.kill(os.getpid(),signal.SIGTERM)
        row=self.rows[role]
        self.rows[role]=preview.Observation(False,-number if row.alive else row.code,True,row.stdout,row.stderr)
    def reap(self,role,deadline):
        self.reaps.append(role)
        if self.fault=='fail-reap':raise OSError('private reap failure')
        row=self.rows[role]
        self.rows[role]=preview.Observation(row.alive,row.code,True,row.stdout,row.stderr,row.launch)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.private=Path(self.temp.name);self.private.chmod(0o700)
    def run_fixture(self,fault=None):
        for path in self.private.iterdir():path.unlink()
        backend=Fixture(self.private,fault);clock=Clock()
        with patch.object(preview,'time',clock): result=preview.supervise(backend,self.private,NONCE)
        self.assertEqual(result['physical_camera'],'NOT RUN');self.assertEqual(result['hardware'],'NOT RUN')
        self.assertEqual(result['software_transport'],'NOT RUN')
        self.assertLessEqual(clock.value,60)
        return result,backend
    def test_good_control_only_accepts_fixture_and_one_link(self):
        row,backend=self.run_fixture()
        self.assertEqual(row['status'],'PASS_CONTROLLED_FIXTURE')
        self.assertEqual([r for r,_,_ in backend.starts],list(preview.ROLES))
        self.assertTrue(all(r['reaped'] for r in row['actors'].values()))
        self.assertEqual(row['actors']['consumer']['exit'],preview.exit_record(0))
        self.assertTrue(row['actors']['consumer']['natural_eos'])
        self.assertFalse(row['actors']['producer']['natural_eos'])
        self.assertEqual(row['actors']['producer']['exit_origin'],'CLEANUP')
        self.assertEqual(row['actors']['producer']['cleanup_requests'],['TERM'])
        self.assertEqual(row['frame']['width'],160)
        self.assertNotIn(str(self.private),json.dumps(row))
    def test_failures_remain_sticky_while_all_reserved_actors_are_reaped(self):
        cases={'missing-eos':'NATURAL_EOS_UNOBSERVED','forced-eos':'NATURAL_EOS_UNOBSERVED',
               'exit-consumer':'CONSUMER_EXIT','exit-link':'LINK_EXIT','exit-daemon':'ACTOR_EXIT',
               'bad-graph':'GRAPH_REFUSED','bad-frame':'FRAME_REFUSED','linked-frame':'FRAME_REFUSED',
               'bad-log':'OUTPUT_BOUND','partial-producer':'START_UNKNOWN'}
        for fault,reason in cases.items():
            with self.subTest(fault=fault):
                row,backend=self.run_fixture(fault)
                self.assertEqual((row['status'],row['first_failure']),('FAIL',reason))
                self.assertEqual(set(backend.reaps),set(backend.rows))
                self.assertTrue(all(r.reaped for r in backend.rows.values()))
                self.assertEqual(row['cleanup'],'PASS')
                for p in self.private.iterdir():p.unlink()
    def test_deadlines_enforce_consumer20_link5_and_cleanup10_not_total_remainder(self):
        for fault,seconds in [('hang-consumer',20),('hang-link',5)]:
            row,backend=self.run_fixture(fault)
            self.assertEqual(row['first_failure'],'DEADLINE')
            self.assertLess(row['elapsed_ms'],(seconds+1)*1000)
            self.assertTrue(all(stop[2] <= seconds+10.02 for stop in backend.stops))
        row,backend=self.run_fixture()
        self.assertTrue(all(deadline<=10 for _,_,deadline in backend.stops))
    def test_cleanup_signal_and_reap_failure_never_promote_success(self):
        row,_=self.run_fixture('signal-cleanup')
        self.assertEqual((row['status'],row['first_failure']),('FAIL','CANCELLED'))
        row,_=self.run_fixture('fail-reap');self.assertEqual(row['cleanup'],'FAIL');self.assertEqual(row['status'],'FAIL')
    def test_metadata_verified_label_and_hashes_cannot_supply_runtime_authority(self):
        backend=Fixture(self.private);backend.origin='VERIFIED_SOFTWARE_RUNTIME'
        row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual(row['status'],'BLOCKED');self.assertEqual(backend.starts,[])
        self.assertTrue(all(r['launch']=='NOT_ATTEMPTED' for r in row['actors'].values()))
        row=preview.supervise(backend,self.private,NONCE,preview.RuntimeAuthority())
        self.assertEqual(row['status'],'BLOCKED');self.assertEqual(backend.starts,[])
    def test_unavailable_default_backend_blocks_before_any_actor(self):
        row=preview.supervise(preview.Backend(),self.private,NONCE)
        self.assertEqual(row['status'],'BLOCKED');self.assertEqual(row['grant_pins'],None)
    def test_exact_plan_drops_only_quiet_and_forbids_host_sources(self):
        plan=preview.command_plan(NONCE)
        for role in ('producer','consumer'):
            self.assertNotIn('-q',plan[role]);self.assertIn('-e',plan[role])
        self.assertIn('autoconnect=false',plan['consumer'])
        text=json.dumps(plan)
        for word in ('v4l2src','libcamerasrc','pulsesrc','ximagesrc','udpsink','tcpserversink'):
            self.assertNotIn(word,text)
        env=preview.environment(self.private,NONCE)
        self.assertEqual(env['PATH'],'');self.assertEqual(env['GST_PLUGIN_PATH_1_0'],'')
    def test_preexisting_frame_and_early_consumer_exit_cannot_be_promoted(self):
        path=self.private/'preview.png';path.write_bytes(image());path.chmod(0o600)
        backend=Fixture(self.private)
        row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual(row['first_failure'],'FRAME_REFUSED')
        self.assertNotIn('consumer',[role for role,_,_ in backend.starts])
        path.unlink()
        class Early(Fixture):
            def registry(self,deadline):
                self.rows['consumer']=preview.Observation(False,0,True,EOS)
                return super().registry(deadline)
        row=preview.supervise(Early(self.private),self.private,NONCE)
        self.assertEqual(row['first_failure'],'GRAPH_REFUSED')
        self.assertEqual(row['actors']['link']['launch'],'NOT_ATTEMPTED')

    def test_log_observer_error_still_attempts_every_owned_stop_and_reap(self):
        class Broken(Fixture):
            def observe(self,role,deadline):
                if role=='producer':raise OSError('private observer failure')
                return super().observe(role,deadline)
        backend=Broken(self.private);clock=Clock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup'],'FAIL')
        self.assertIn('producer',backend.reaps)
        self.assertTrue(any(role=='producer' for role,_,_ in backend.stops))
        self.assertTrue(all(r.reaped for r in backend.rows.values()))

    def test_mutable_fixture_origin_cannot_become_a_software_result(self):
        class Drift(Fixture):
            def verify(self,*args):self.origin='VERIFIED_SOFTWARE_RUNTIME'
        row=preview.supervise(Drift(self.private),self.private,NONCE)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['software_transport'],'NOT RUN')

    def test_frame_changed_during_cleanup_never_promotes_the_previous_snapshot(self):
        class Rewrite(Fixture):
            def stop(self,*args):
                super().stop(*args)
                (self.private/'preview.png').write_bytes(image((b'\0'+b'\1'*480)*120))
        backend=Rewrite(self.private);clock=Clock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual((row['status'],row['first_failure']),('FAIL','FRAME_REFUSED'))
        self.assertEqual(row['cleanup'],'PASS')

    def test_public_shape_poison_and_snapshot_alias_are_refused(self):
        row,_=self.run_fixture()
        for mutate in (lambda r:r.update(extra='secret'),lambda r:r.update(hardware='PASS'),
            lambda r:r.update(software_transport='PASS'),lambda r:r.update(device_access=True),lambda r:r.update(elapsed_ms=True),
            lambda r:r['actors']['consumer']['exit'].update(code=True),
            lambda r:r['actors']['consumer'].update(natural_eos=False),
            lambda r:r['frame'].update(width=True)):
            value=json.loads(json.dumps(row));mutate(value)
            with self.assertRaises(preview.Refused):preview.project(value)
        copied=preview.project(row);row['actors']['consumer']['exit']['code']=123
        self.assertEqual(copied['actors']['consumer']['exit']['code'],0)
        self.assertLessEqual(len(json.dumps(copied,separators=(',',':')).encode()),4096)

    def test_late_real_sigterm_at_handler_restoration_revokes_fixture_pass(self):
        previous={n:signal.getsignal(n) for n in (signal.SIGINT,signal.SIGTERM)}
        original=signal.signal;calls=[];sent=[]
        def restore(number,handler):
            calls.append(number);value=original(number,handler)
            if len(calls)==3:
                self.assertEqual(number,signal.SIGINT)
                os.kill(os.getpid(),signal.SIGTERM);sent.append(True)
            return value
        with patch.object(signal,'signal',side_effect=restore):row,_=self.run_fixture()
        self.assertTrue(sent);self.assertEqual({n:signal.getsignal(n) for n in previous},previous)
        self.assertEqual((row['status'],row['cancelled'],row['first_failure']),('FAIL',True,'CANCELLED'))
        self.assertEqual(row['cleanup'],'PASS')

    def test_two_pending_signals_are_drained_and_original_mask_restored(self):
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        original=signal.signal;calls=[]
        def restore(number,handler):
            calls.append(number);value=original(number,handler)
            if len(calls)==3:
                self.assertTrue({signal.SIGINT,signal.SIGTERM} <= signal.pthread_sigmask(signal.SIG_BLOCK,set()))
                os.kill(os.getpid(),signal.SIGINT);os.kill(os.getpid(),signal.SIGTERM)
            return value
        with patch.object(signal,'signal',side_effect=restore):row,_=self.run_fixture()
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),mask)
        self.assertFalse({signal.SIGINT,signal.SIGTERM} & signal.sigpending())
        self.assertEqual((row['status'],row['cancelled'],row['first_failure']),('FAIL',True,'CANCELLED'))
        # A caller's already-blocked signal must remain pending, not be consumed.
        signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM});calls.clear()
        try:
            with patch.object(signal,'signal',side_effect=restore):row,_=self.run_fixture()
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),mask | {signal.SIGTERM})
            self.assertIn(signal.SIGTERM,signal.sigpending())
            self.assertEqual((row['status'],row['cancelled']),('FAIL',True))
        finally:
            if signal.SIGTERM in signal.sigpending():signal.sigtimedwait({signal.SIGTERM},0)
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)

    def test_control_during_restoration_and_final_unmask_never_returns_pass(self):
        previous={n:signal.getsignal(n) for n in (signal.SIGINT,signal.SIGTERM)}
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        for point in ('restore','unmask'):
            for error in (KeyboardInterrupt,SystemExit):
                calls=[]; original=signal.signal if point=='restore' else signal.pthread_sigmask
                def fault(*args):
                    calls.append(args);value=original(*args)
                    if (point=='restore' and len(calls) in (3,4)) or (point=='unmask' and len(calls)==4):
                        raise error('private control must not appear in output')
                    return value
                with patch.object(signal,'signal' if point=='restore' else 'pthread_sigmask',side_effect=fault):row,backend=self.run_fixture()
                self.assertEqual((row['status'],row['cancelled'],row['first_failure']),('FAIL',True,'CANCELLED'))
                self.assertEqual({n:signal.getsignal(n) for n in previous},previous)
                self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),mask)
                self.assertEqual(set(backend.reaps),set(backend.rows))

    def test_start_control_cancellation_is_independent_and_all_reservations_reaped(self):
        for error in (KeyboardInterrupt,SystemExit):
            class Interrupt(Fixture):
                def start(self,role,*args):
                    super().start(role,*args)
                    if role=='producer':raise error('private start control')
            backend=Interrupt(self.private);clock=Clock()
            with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
            self.assertEqual((row['status'],row['cancelled'],row['first_failure']),('FAIL',True,'CANCELLED'))
            self.assertEqual(set(backend.reaps),set(backend.rows))
            self.assertTrue(all(value.reaped for value in backend.rows.values()))

    def test_cleanup_controls_keep_earlier_primary_and_cleanup_failure(self):
        for point in ('stop','observe','reap','verify'):
            for error in (KeyboardInterrupt,SystemExit):
                class Interrupt(Fixture):
                    interrupted=False
                    def trigger(self,where):
                        if point==where and not self.interrupted:
                            self.interrupted=True;raise error('private cleanup control')
                    def stop(self,*args):
                        super().stop(*args);self.trigger('stop')
                    def observe(self,*args):
                        if self.stops:self.trigger('observe')
                        return super().observe(*args)
                    def reap(self,*args):
                        super().reap(*args);self.trigger('reap')
                    def verify(self,*args):
                        if self.reaps:self.trigger('verify')
                for path in self.private.iterdir():path.unlink()
                backend=Interrupt(self.private,'bad-graph');clock=Clock()
                with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
                self.assertTrue(backend.interrupted)
                self.assertEqual((row['status'],row['first_failure'],row['cancelled']),('FAIL','GRAPH_REFUSED',True))
                self.assertEqual(row['cleanup'],'FAIL');self.assertNotEqual(row['cleanup_failure'],'NONE')
                self.assertEqual(set(backend.reaps),set(backend.rows))
                self.assertTrue(all(value.reaped for value in backend.rows.values()))
        class Repeated(Fixture):
            def stop(self,*args):
                super().stop(*args)
                if len(self.stops)==1:raise OSError('earlier ordinary cleanup failure')
                raise KeyboardInterrupt('later cleanup cancellation')
        for path in self.private.iterdir():path.unlink()
        backend=Repeated(self.private,'bad-graph');clock=Clock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual((row['first_failure'],row['cleanup_failure'],row['cancelled']),('GRAPH_REFUSED','STOP_FAILED',True))
        self.assertEqual(set(backend.reaps),set(backend.rows))

    def test_direct_stop_control_matches_peer_and_closed_cancel_flag(self):
        class Interrupt(Fixture):
            def stop(self,*args):
                super().stop(*args);raise KeyboardInterrupt('private stop control')
        backend=Interrupt(self.private);clock=Clock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual((row['status'],row['first_failure'],row['cleanup_failure'],row['cancelled']),('FAIL','CANCELLED','STOP_FAILED',True))
        self.assertEqual(set(backend.reaps),set(backend.rows))
        malformed=json.loads(json.dumps(row));malformed['cancelled']=False
        with self.assertRaises(preview.Refused):preview.project(malformed)

    def test_cleanup_sleep_and_final_frame_controls_do_not_skip_owned_reaping(self):
        class Gentle(Fixture):
            def stop(self,role,number,*args):
                super().stop(role,number,*args)
                if role=='producer' and number==signal.SIGTERM:self.rows[role]=preview.Observation(True,None,False)
        class InterruptClock(Clock):
            def sleep(self,value):raise KeyboardInterrupt('cleanup sleep control')
        backend=Gentle(self.private);clock=InterruptClock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual((row['status'],row['cancelled']),('FAIL',True));self.assertEqual(set(backend.reaps),set(backend.rows))
        self.assertEqual(row['actors']['producer']['cleanup_requests'],['TERM','KILL'])
        for path in self.private.iterdir():path.unlink()
        original=preview.frame;calls=[]
        def read(*args):
            calls.append(True)
            if len(calls)==2:raise SystemExit('read-before-publication control')
            return original(*args)
        with patch.object(preview,'frame',side_effect=read):row,backend=self.run_fixture()
        self.assertEqual((row['status'],row['first_failure'],row['cancelled']),('FAIL','CANCELLED',True))
        self.assertEqual(set(backend.reaps),set(backend.rows))

    def test_terminal_projection_control_revokes_candidate_before_return(self):
        for error in (KeyboardInterrupt,SystemExit):
            original=preview.project;calls=[]
            def projection(result):
                value=original(result);calls.append(value['status'])
                if len(calls)==1:raise error('after candidate read before return')
                return value
            with patch.object(preview,'project',side_effect=projection):row,_=self.run_fixture()
            self.assertEqual(calls,['PASS_CONTROLLED_FIXTURE','FAIL'])
            self.assertEqual((row['status'],row['cancelled'],row['first_failure']),('FAIL',True,'CANCELLED'))
            for path in self.private.iterdir():path.unlink()
            backend=Fixture(self.private);clock=Clock()
            def repeated(result):
                original(result);raise error('repeated publication control')
            with patch.object(preview,'time',clock),patch.object(preview,'project',side_effect=repeated):
                with self.assertRaises(error):preview.supervise(backend,self.private,NONCE)
            self.assertEqual(set(backend.reaps),set(backend.rows))

    def test_ordinary_restore_error_refuses_and_cancellation_never_overwrites_it(self):
        original=signal.signal;calls=[]
        def restore(*args):
            calls.append(args);value=original(*args)
            if len(calls)==3:raise OSError('private restoration failure')
            if len(calls)==4:raise KeyboardInterrupt('later restoration cancellation')
            return value
        with patch.object(signal,'signal',side_effect=restore):row,_=self.run_fixture()
        self.assertEqual((row['status'],row['first_failure'],row['cleanup_failure'],row['cancelled']),('FAIL','BACKEND_ERROR','BOUNDARY_FAILED',True))

    def test_terminal_exit_is_immutable_and_tree_reaping_is_not_leader_return(self):
        class Tree(Fixture):
            def start(self,role,*args):
                super().start(role,*args)
                if role=='link':self.rows['consumer']=preview.Observation(False,0,False,EOS)
            def stop(self,role,*args):
                super().stop(role,*args)
                if role=='consumer':self.rows[role]=preview.Observation(False,0,False,EOS)
        backend=Tree(self.private);clock=Clock()
        with patch.object(preview,'time',clock):row=preview.supervise(backend,self.private,NONCE)
        self.assertEqual(row['status'],'PASS_CONTROLLED_FIXTURE')
        self.assertEqual(row['actors']['consumer']['exit'],preview.exit_record(0))
        self.assertEqual(row['actors']['consumer']['cleanup_requests'],['TERM','KILL'])
        class Drift(Fixture):
            def stop(self,*args):
                super().stop(*args)
                self.rows['consumer']=preview.Observation(False,125,True,EOS)
        for path in self.private.iterdir():path.unlink()
        row=preview.supervise(Drift(self.private),self.private,NONCE)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup'],'FAIL')
        self.assertEqual(row['actors']['consumer']['exit'],preview.exit_record(0))

    def test_bad_lifecycle_types_and_output_bounds_refused(self):
        for row in (preview.Observation(False,True,True),preview.Observation(True,0,False),
                    preview.Observation(False,None,True),preview.Observation(True,None,True),
                    preview.Observation(False,256,True),preview.Observation(False,-65,True)):
            with self.assertRaises(preview.Refused):row.validate()
        with self.assertRaises(preview.Refused):preview.Observation(True,None,False,b'x'*(preview.LOG_LIMIT+1)).validate()
        preview.Observation(False,None,True,launch='NO_LAUNCH').validate()
        preview.Observation(None,None,False,launch='UNOBSERVED').validate()
    def test_registry_type_binding_duplicate_and_alias_poison(self):
        backend=Fixture(self.private);good=json.loads(backend.registry(1))
        for mutate in (lambda r:r['ports'][0].update(id=True),lambda r:r['ports'][1].update(id=3),
                       lambda r:r['nodes'][1].update(pid=101),lambda r:r['nodes'][0].update(name='host-camera'),
                       lambda r:r['ports'][0].update(direction='in'),lambda r:r.update(extra='secret')):
            value=json.loads(json.dumps(good));mutate(value)
            with self.assertRaises(preview.Refused):preview.ports(json.dumps(value).encode(),NONCE,101,102)
        with self.assertRaises(preview.Refused):preview.ports(b'{"nodes":[],"nodes":[],"ports":[]}',NONCE,101,102)


class PNGTests(unittest.TestCase):
    def test_crc_geometry_extent_filters_and_bomb_refusal(self):
        self.assertEqual(preview.png(image())['format'],'RGB8')
        poisons=[b'',image()+b'trailing',image()[:-1],image()[:-4]+b'bad!',
            image(header=struct.pack('>IIBBBBB',161,120,8,2,0,0,0)),
            image(header=struct.pack('>IIBBBBB',160,120,8,6,0,0,0)),image(b'\0'*2**20),
            image((b'\5'+b'\0'*480)*120),image(b'\0'*57719)]
        for data in poisons:
            with self.assertRaises(preview.Refused):preview.png(data)
    def test_link_symlink_mode_and_directory_replacement_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=Path(temporary);private.chmod(0o700);path=private/'preview.png';path.write_bytes(image());path.chmod(0o600)
            self.assertEqual(preview.frame(private)['sha256'],preview.digest(image()))
            os.link(path,private/'linked')
            with self.assertRaises(preview.Refused):preview.frame(private)
            (private/'linked').unlink();path.chmod(0o644)
            with self.assertRaises(preview.Refused):preview.frame(private)
            path.unlink();path.symlink_to('/dev/null')
            with self.assertRaises((preview.Refused,OSError)):preview.frame(private)
    def test_fixed_log_capture_is_bounded_regular_owned_single_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=Path(temporary);private.chmod(0o700);path=private/'consumer.stdout.log'
            path.write_bytes(EOS);path.chmod(0o600)
            self.assertEqual(preview.capture(private,path.name),EOS)
            os.link(path,private/'copy')
            with self.assertRaises(preview.Refused):preview.capture(private,path.name)
            (private/'copy').unlink();path.write_bytes(b'x'*(preview.LOG_LIMIT+1))
            with self.assertRaises(preview.Refused):preview.capture(private,path.name)
            with self.assertRaises(preview.Refused):preview.capture(private,'../secret')

    def test_cli_is_blocked_and_never_creates_a_runtime(self):
        child=subprocess.run([sys.executable,'-I','-B',preview.__file__,'--contract'],capture_output=True,timeout=5)
        self.assertEqual(child.returncode,2)
        value=json.loads(child.stdout);self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['physical_camera'],'NOT RUN')


class HarmlessProcesses(Fixture):
    """Fixed Python-only actors, never the proposed multimedia argv."""
    def __init__(self, private, fault=None):
        super().__init__(private,fault);self.processes={};self.logs={}
    def start(self,role,argv,env,deadline):
        self.starts.append((role,argv,env))
        body='import time; time.sleep(30)' if role in ('daemon','producer') else 'print(\'Got EOS from element "pipeline0".\')'
        if role=='producer' and self.fault=='ignore-term':
            body='import signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(%r).write_text(\'ready\'); time.sleep(30)' % str(self.private/'producer.ready')
        if role=='consumer':
            body='import time,sys; from pathlib import Path; p=Path(%r); end=time.monotonic()+10\nwhile not p.exists() and time.monotonic()<end:time.sleep(.001)\nif not p.exists():sys.exit(1)\nprint(\'Got EOS from element "pipeline0".\')' % str(self.private/'link.ready')
        if role=='consumer' and self.fault=='timeout':body='import time; time.sleep(30)'
        if role=='link':(self.private/'link.ready').write_text('owned fixture link')
        if role=='consumer':
            path=self.private/'preview.png';path.write_bytes(image());path.chmod(0o600)
        log=self.private/(role+'.log');stream=log.open('xb');self.logs[role]=stream
        process=subprocess.Popen([sys.executable,'-I','-B','-c',body],stdin=subprocess.DEVNULL,
            stdout=stream,stderr=subprocess.STDOUT,start_new_session=True,env={'LANG':'C','LC_ALL':'C'})
        self.processes[role]=process
        if self.fault=='ignore-term' and role=='producer':
            limit=time.monotonic()+2
            while not (self.private/'producer.ready').exists():
                if process.poll() is not None or time.monotonic()>=limit:raise AssertionError('owned fixture readiness')
                time.sleep(.001)
        if self.fault=='cancel' and role=='link':os.kill(os.getpid(),signal.SIGTERM)
        if self.fault=='partial-producer' and role=='producer':raise OSError('fixture after actual Popen before return')
    def pid(self,role):return self.processes[role].pid
    def registry(self,deadline):
        value=json.loads(super().registry(deadline))
        value['nodes'][0]['pid']=self.pid('producer');value['nodes'][1]['pid']=self.pid('consumer')
        return json.dumps(value).encode()
    def observe(self,role,deadline):
        if role not in self.processes:return preview.Observation(False,None,True,launch='NO_LAUNCH')
        process=self.processes[role];code=process.poll()
        data=(self.private/(role+'.log')).read_bytes()
        return preview.Observation(code is None,code,code is not None,data)
    def stop(self,role,number,deadline):
        self.stops.append((role,number,deadline))
        if role in self.processes:
            try:os.killpg(self.processes[role].pid,number)
            except ProcessLookupError:pass
    def reap(self,role,deadline):
        self.reaps.append(role)
        if role in self.processes:self.processes[role].wait(timeout=max(.01,deadline-time.monotonic()))
        if role in self.logs:self.logs[role].close()


class RealOwnedLifecycleTests(unittest.TestCase):
    def test_real_harmless_natural_return_and_partial_start_reap(self):
        for fault in (None,'partial-producer'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                private=Path(temporary);private.chmod(0o700);backend=HarmlessProcesses(private,fault)
                try:
                    row=preview.supervise(backend,private,NONCE)
                    self.assertEqual(row['status'],'PASS_CONTROLLED_FIXTURE' if fault is None else 'FAIL')
                    self.assertEqual(row['software_transport'],'NOT RUN')
                    self.assertTrue(all(p.poll() is not None for p in backend.processes.values()))
                    for process in backend.processes.values():
                        with self.assertRaises(ProcessLookupError):os.kill(process.pid,0)
                finally:
                    for process in backend.processes.values():
                        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
                        process.wait(timeout=2)
                    for stream in backend.logs.values():stream.close()


class RealCancellationTests(unittest.TestCase):
    def test_real_harmless_cancel_timeout_and_kill_escalation_are_reaped(self):
        for fault in ('cancel','timeout','ignore-term'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                private=Path(temporary);private.chmod(0o700);backend=HarmlessProcesses(private,fault)
                try:
                    with patch.object(preview,'CONSUMER',.05 if fault=='timeout' else 20):
                        row=preview.supervise(backend,private,NONCE)
                    self.assertEqual(row['software_transport'],'NOT RUN')
                    self.assertEqual(row['first_failure'],'CANCELLED' if fault=='cancel' else 'DEADLINE' if fault=='timeout' else 'NONE')
                    self.assertEqual(row['status'],'PASS_CONTROLLED_FIXTURE' if fault=='ignore-term' else 'FAIL')
                    self.assertTrue(all(p.poll() is not None for p in backend.processes.values()))
                    if fault=='ignore-term':self.assertIn('KILL',row['actors']['producer']['cleanup_requests'])
                finally:
                    for process in backend.processes.values():
                        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
                        process.wait(timeout=2)
                    for stream in backend.logs.values():stream.close()


if __name__ == '__main__':unittest.main()
