#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODELED Docker/protocol fixtures only; no subprocess, Docker or native actor."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('handoff_launch', Path(__file__).with_name('launch.py'))
launch = importlib.util.module_from_spec(spec); spec.loader.exec_module(launch)
CID = 'c' * 64


def response(raw=b'', code=0):
    return {'exit_code': code, 'stdout': raw, 'stderr': b''}


def frame(nonce, sequence, previous='0' * 64):
    raw = launch.encoded({'schema_version': 1, 'purpose': 'repository-native-checkpoint', 'nonce': nonce,
        'sequence': sequence, 'phase': launch.PHASES[sequence-1], 'payload': base64.b64encode(b'MODELED public observation').decode(),
        'payload_sha256': launch.digest(b'MODELED public observation'), 'previous_frame_sha256': previous})
    return launch.MARKER + raw + b'\n', launch.digest(raw)


def ack(frame, deadline):
    return launch.ACK_MARKER + launch.encoded({'schema_version': 1, 'purpose': 'repository-native-checkpoint-ack',
        'nonce': frame['nonce'], 'sequence': frame['sequence'], 'phase': frame['phase'],
        'frame_sha256': launch.digest(launch.encoded(frame)), 'durable_host_digest': True}) + b'\n'


class Transport:
    def __init__(self, case):
        self.case = case; self.calls = []; self.removed = False; self.created = False
        self.poison = None; self.partial = False; self.failed_remove = False; self.name_occupied = False
        self.bad_frame = None; self.signal_remove = False; self.terminal_oom = False
        self.missing_cid = False; self.drift_after_attach = False
        self.worker_args = None

    def inspect(self):
        expected = launch.validate_command(self.case.command, self.case.contract)
        args = self.worker_args
        row = {'Id': CID, 'Name': '/' + expected['name'], 'Image': expected['image'],
               'Config': {'User': '0:0', 'OpenStdin': True, 'Tty': False, 'Entrypoint': ['/usr/bin/python3'], 'Cmd': args,
                          'Env': ['CACHY_ASAHI_REPOSITORY_CONTAINER=1', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=' + expected['nonce'],
                                  'CACHY_ASAHI_IMAGE_ID=' + expected['image']]},
               'HostConfig': {'NetworkMode': 'none', 'CgroupnsMode': 'private', 'ReadonlyRootfs': True, 'Privileged': False,
                    'CapDrop': ['ALL'], 'CapAdd': list(launch.CAPS), 'PidsLimit': 512, 'Memory': 8*1024**3,
                    'NanoCpus': 4*10**9, 'SecurityOpt': ['no-new-privileges'], 'Tmpfs': {
                        '/scratch': 'rw,nosuid,nodev,exec,size=6g,mode=0700', '/test-home': 'rw,nosuid,nodev,exec,size=128m,mode=0700'}},
               'Mounts': [{'Type': 'bind', 'Source': str(source), 'Destination': dest, 'RW': dest == '/out'}
                          for dest, source in expected['binds'].items()],
               'State': {'Status': 'exited', 'Running': False, 'OOMKilled': self.terminal_oom, 'ExitCode': 0, 'Error': ''}}
        if self.poison: self.poison(row)
        return [row]

    def run(self, argv, *, deadline, limit):
        self.calls.append(argv)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return response(launch.encoded([{'Id': self.case.contract['image_id'], 'Architecture': 'arm64', 'Os': 'linux'}]))
        if argv[:2] == ['docker', 'info']: return response(b'aarch64\n')
        if argv[:2] == ['docker', 'create']:
            self.created = True
            self.worker_args = argv[argv.index(self.case.contract['image_id'])+1:]
            if not self.missing_cid:Path(argv[argv.index('--cidfile')+1]).write_text(CID+'\n')
            return response(b'partial\n' if self.partial else CID.encode()+b'\n')
        if argv[:3] == ['docker', 'container', 'inspect']: return response(launch.encoded(self.inspect()))
        if argv[:3] == ['docker', 'container', 'rm']:
            if self.signal_remove: os.kill(os.getpid(), signal.SIGTERM)
            if self.failed_remove: return response(code=1)
            self.removed = True; return response(CID.encode()+b'\n')
        if argv[:3] == ['docker', 'container', 'ls']:
            if self.name_occupied or self.created and not self.removed:
                return response((CID+' cachy-asahi-repository-'+self.case.contract['nonce']+'\n').encode())
            return response()
        raise AssertionError(argv)

    def attach(self, argv, *, on_stdout, on_stdin, deadline, limit):
        self.calls.append(argv); previous = '0'*64; stream = bytearray()
        for sequence in (1, 2):
            wire, previous = frame(self.case.contract['nonce'], sequence, previous)
            if self.bad_frame: wire = self.bad_frame(wire, sequence)
            stream.extend(wire)
            for start in range(0, len(wire), 7): on_stdout(wire[start:start+7])
            if on_stdin() is None: raise AssertionError('missing ACK')
        plain = b'PASS: disposable generic repository transactions; hardware/stable gates unchanged.\n'
        on_stdout(plain)
        stream.extend(plain)
        if self.drift_after_attach:(self.case.runner/'producer.py').write_bytes(b'foreign observer')
        return response(bytes(stream))


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MODELED-repository-custody-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.inputs = self.root/'inputs'; self.runner = self.root/'runner'
        self.output = self.root/'out'; self.private = self.root/'private'
        for path in (self.inputs, self.runner, self.output, self.private): path.mkdir(mode=0o700)
        shutil.copyfile(ROOT/'scripts/integration/repository.py', self.runner/'repository.py')
        (self.runner/'producer.py').write_bytes(b'# MODELED observer bytes\n')
        self.pin = launch.digest((self.runner/'producer.py').read_bytes())
        self.contract = {'schema_version': 1, 'purpose': 'disposable-generic-repository-test',
            'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True, 'daemon_arch': 'aarch64',
            'nonce': 'a'*32, 'image_id': 'sha256:'+'b'*64, 'source_commit': 'd'*40,
            'script_sha256': launch.ORIGINAL_PIN, 'upgrade_kind': 'synthetic-changed-package-fixtures', 'baseline': [], 'upgrade': []}
        (self.inputs/'manifest.json').write_bytes(launch.encoded(self.contract))
        self.command = ['docker', 'run', '--name', 'cachy-asahi-repository-'+'a'*32, '--pull=never', '--platform=linux/arm64',
            '--user', '0:0', '--network=none', '--cgroupns=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=512', '--memory=8g', '--cpus=4']+['--cap-add='+cap for cap in launch.CAPS]+[
            '--read-only', '--tmpfs', '/scratch:rw,nosuid,nodev,exec,size=6g,mode=0700', '--tmpfs',
            '/test-home:rw,nosuid,nodev,exec,size=128m,mode=0700']
        for source, dest, ro in ((self.inputs,'/inputs',True),(self.runner,'/runner',True),(self.output,'/out',False)):
            self.command += ['--mount', f'type=bind,src={source},dst={dest}'+(',readonly' if ro else '')]
        self.command += ['--env','CACHY_ASAHI_REPOSITORY_CONTAINER=1','--env','CACHY_ASAHI_DISPOSABLE_REPOSITORY='+'a'*32,
            '--env','CACHY_ASAHI_IMAGE_ID='+self.contract['image_id'],'--entrypoint=/usr/bin/python3',self.contract['image_id'],
            '-B','/runner/repository.py','--inputs','/inputs/manifest.json','--inputs-sha256',
            launch.digest((self.inputs/'manifest.json').read_bytes()),'--allow-disposable-repository-test']
        self.transport = Transport(self)

    def execute(self, **kwargs):
        options = dict(contract=self.contract, run=self.transport, deadline=time.monotonic()+100,
                       checkpoint_handler=ack, producer_pin=self.pin)
        options.update(kwargs)
        return launch.run_repository(self.command,self.root/'container.log',self.private,lambda *_:None,**options)

    def test_modeled_success_registers_before_start_and_strips_frames(self):
        receipt = self.execute(); self.assertEqual(receipt['status'],'PASS'); self.assertTrue(receipt['absence_verified'])
        self.assertEqual(len(receipt['checkpoints']),2); self.assertEqual(receipt['native_admission'],'NOT RUN')
        self.assertTrue(self.transport.removed); self.assertNotIn(launch.RESERVED,(self.root/'container.log').read_bytes())
        self.assertEqual(receipt['original_command'],self.command)
        self.assertEqual(receipt['actual_create_command'][1:3],['create','-i'])
        actual=receipt['actual_create_command'];self.assertIn('--handoff-deadline',actual)
        self.assertIn('-I',self.transport.worker_args);self.assertIn('-B',self.transport.worker_args)
        start = next(i for i,row in enumerate(self.transport.calls)if row[:2]==['docker','start'])
        self.assertTrue(any(row[:3]==['docker','container','inspect'] for row in self.transport.calls[:start]))
        for row in receipt['commands']:
            for name in ('stdout','stderr'):
                self.assertEqual(launch.digest((Path(receipt['private_root'])/row[name]['path']).read_bytes()),row[name]['sha256'])

    def test_mutated_original_policy_refused_before_transport(self):
        self.command[self.command.index('--memory=8g')]='--memory=16g'
        with self.assertRaises(launch.Refused):self.execute()
        self.assertFalse(self.transport.calls)

    def test_runner_or_manifest_drift_refused(self):
        (self.runner/'repository.py').write_bytes(b'wrong')
        with self.assertRaises(launch.Refused):self.execute()
        self.assertFalse(self.transport.calls)

    def test_existing_name_is_not_removed(self):
        self.transport.name_occupied=True
        with self.assertRaises(launch.Refused):self.execute()
        self.assertFalse(self.transport.created);self.assertFalse(self.transport.removed)

    def test_partial_create_is_disposed_but_never_promoted(self):
        self.transport.partial=True
        with self.assertRaises(launch.Refused)as error:self.execute()
        self.assertTrue(self.transport.removed);self.assertTrue(error.exception.receipt['ownership_uncertain'])
        self.assertEqual(error.exception.receipt['status'],'FAIL')

    def test_name_only_partial_recovery_never_removes_unproven_object(self):
        self.transport.partial=True;self.transport.missing_cid=True
        with self.assertRaises(launch.Refused)as error:self.execute()
        self.assertFalse(self.transport.removed);self.assertEqual(error.exception.receipt['cleanup'],'FAIL')
        self.assertIsNone(error.exception.receipt['container_id'])

    def test_foreign_cid_or_policy_is_never_removed(self):
        for poison in (lambda row:row.update(Id='e'*64),lambda row:row['HostConfig'].update(Privileged=True)):
            with self.subTest(poison=poison):
                self.transport.poison=poison
                with self.assertRaises(launch.Refused):self.execute()
                self.assertFalse(self.transport.removed)
                shutil.rmtree(self.private/('launch-'+'a'*32))
                for path in self.root.glob('container.*'):path.unlink()

    def test_terminal_oom_blocks_pass_but_removes_owned_container(self):
        self.transport.terminal_oom=True
        with self.assertRaises(launch.Refused):self.execute()
        self.assertTrue(self.transport.removed)

    def test_postproducer_source_drift_refuses_but_disposes_owned_container(self):
        self.transport.drift_after_attach=True
        with self.assertRaises(launch.Refused):self.execute()
        self.assertTrue(self.transport.removed)

    def test_cleanup_failure_remains_failure(self):
        self.transport.failed_remove=True
        with self.assertRaises(launch.Refused)as error:self.execute()
        self.assertEqual(error.exception.receipt['cleanup'],'FAIL');self.assertFalse(error.exception.receipt['absence_verified'])

    def test_bad_ack_and_wrong_nonce_fail_closed(self):
        with self.assertRaises(launch.Refused):self.execute(checkpoint_handler=lambda *_:b'wrong ACK')
        self.assertTrue(self.transport.removed);self.assertNotIn(launch.RESERVED,(self.root/'container.log').read_bytes())

    def test_real_term_during_injected_removal_finishes_then_refuses(self):
        self.transport.signal_remove=True
        old={n:signal.getsignal(n)for n in launch.SIGNALS}
        with self.assertRaises(launch.Refused)as error:self.execute()
        self.assertTrue(self.transport.removed);self.assertTrue(error.exception.receipt['cancelled'])
        self.assertEqual(error.exception.receipt['cleanup'],'PASS')
        self.assertEqual(old,{n:signal.getsignal(n)for n in launch.SIGNALS})

    def test_expired_deadline_launches_no_transport(self):
        with self.assertRaises(launch.Refused):self.execute(deadline=time.monotonic()-1)
        self.assertFalse(self.transport.calls)

    def test_prepare_callback_is_explicit_and_rechecked(self):
        calls=[]
        self.execute(contract=lambda command:(calls.append(command)or self.contract),prepare_runner=lambda command:self.pin)
        self.assertEqual(calls,[self.command])

    def test_scoped_binding_restores_and_other_launches_delegate(self):
        original=mock.Mock(return_value='delegated');module=types.SimpleNamespace(execute_container=original)
        options=dict(private_root=self.private,contract=self.contract,run=self.transport,deadline=time.monotonic()+100,
                     checkpoint_handler=ack,producer_pin=self.pin)
        with launch.scoped_executor(module,**options):
            self.assertEqual(module.execute_container(['docker','run','--name','another'],self.root/'unused'),'delegated')
            with self.assertRaises(launch.Refused):
                with launch.scoped_executor(module,**options):pass
        self.assertIs(module.execute_container,original)

    def test_scoped_launch_clips_original_timeout(self):
        module=types.SimpleNamespace(execute_container=lambda *a,**k:None)
        options=dict(private_root=self.private,contract=self.contract,run=self.transport,deadline=time.monotonic()+10000,
                     checkpoint_handler=ack,producer_pin=self.pin)
        with launch.scoped_executor(module,**options),mock.patch.object(launch,'run_repository')as run:
            before=time.monotonic();module.execute_container(self.command,self.root/'unused',timeout=10)
        self.assertGreaterEqual(run.call_args.kwargs['deadline'],before+10)
        self.assertLess(run.call_args.kwargs['deadline'],before+11)

    def test_real_term_after_pass_fsync_rewrites_held_receipt_fail(self):
        original=launch.os.fsync;injected=[]
        def sync(fd):
            original(fd)
            receipt=self.private/('launch-'+'a'*32)/'receipt.json'
            if receipt.exists() and b'"status":"PASS"'in receipt.read_bytes() and not injected:
                injected.append(True);os.kill(os.getpid(),signal.SIGTERM)
        with mock.patch.object(launch.os,'fsync',side_effect=sync),self.assertRaises(launch.Refused):self.execute()
        receipt=launch.decode((self.private/('launch-'+'a'*32)/'receipt.json').read_bytes())
        self.assertTrue(injected);self.assertEqual(receipt['status'],'FAIL');self.assertTrue(receipt['cancelled'])
        self.assertEqual(receipt['cleanup'],'PASS')

    def test_real_int_during_final_handler_restore_invalidates_pass(self):
        original=launch.signal.signal;old={n:signal.getsignal(n)for n in launch.SIGNALS};injected=[]
        def setter(number,handler):
            value=original(number,handler)
            receipt=self.private/('launch-'+'a'*32)/'receipt.json'
            if handler==old[number] and receipt.exists() and b'"status":"PASS"'in receipt.read_bytes() and not injected:
                injected.append(True);os.kill(os.getpid(),signal.SIGINT)
            return value
        with mock.patch.object(launch.signal,'signal',side_effect=setter),self.assertRaises(launch.Refused):self.execute()
        receipt=launch.decode((self.private/('launch-'+'a'*32)/'receipt.json').read_bytes())
        self.assertTrue(injected);self.assertEqual(receipt['status'],'FAIL');self.assertTrue(receipt['cancelled'])
        self.assertEqual(old,{n:signal.getsignal(n)for n in launch.SIGNALS})

    def test_public_write_failure_retains_only_failed_private_receipt(self):
        original=launch.write_new
        def writer(path,raw):
            if Path(path)==self.root/'container.log':raise OSError('MODELED publication failure')
            return original(path,raw)
        with mock.patch.object(launch,'write_new',side_effect=writer),self.assertRaises(launch.Refused):self.execute()
        receipt=launch.decode((self.private/('launch-'+'a'*32)/'receipt.json').read_bytes())
        self.assertEqual(receipt['status'],'FAIL');self.assertEqual(receipt['cleanup'],'PASS')


class ProtocolTests(unittest.TestCase):
    def protocol(self,handler=ack):return launch.Protocol('a'*32,handler,time.monotonic()+100)

    def test_wrong_nonce_duplicate_key_noncanonical_extra_and_partial_refuse(self):
        first,pin=frame('a'*32,1);second,_=frame('a'*32,2,pin)
        cases=[frame('b'*32,1)[0],first.replace(b'"nonce":',b'"nonce":"a","nonce":'),
               first.replace(b'"nonce":',b'"nonce" :'),first+second+second]
        for raw in cases:
            with self.subTest(raw=raw[:50]),self.assertRaises((ValueError,launch.Refused)):
                p=self.protocol();p.feed(raw)
        p=self.protocol();p.feed(first[:-1])
        with self.assertRaises(launch.Refused):p.finish()
        self.assertFalse(p.plain)

    def test_acks_must_be_delivered_and_payload_hash_bound(self):
        wire,_=frame('a'*32,1)
        p=self.protocol();p.feed(wire)
        with self.assertRaises(launch.Refused):p.finish()
        bad=wire.replace(b'MODELED',b'WRONG')
        value=launch.decode(wire[len(launch.MARKER):-1]);value['payload_sha256']='0'*64
        with self.assertRaises(launch.Refused):self.protocol().feed(launch.MARKER+launch.encoded(value)+b'\n')


if __name__=='__main__':unittest.main()
