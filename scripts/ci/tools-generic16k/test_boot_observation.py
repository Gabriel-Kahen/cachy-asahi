# SPDX-License-Identifier: MIT
"""Temporary files/socket node, synthetic QMP and mocked children; no VM/native actor."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guest
import run as R


class Wire:
    def __init__(self,pid,registers=' PC=0000000000001018 X00=00000000\n'):
        self.peer=(pid,os.getuid(),os.getgid());self.sent=[]
        messages=[dict(QMP={}),dict(return_value={},id=1),dict(return_value=dict(status='running',running=True),id=2),
            dict(return_value=[{'cpu-index':0,'thread-id':123}],id=3),dict(return_value=registers,id=4)]
        self.raw=b''.join((json.dumps({('return' if k=='return_value' else k):v for k,v in row.items()})+'\n').encode() for row in messages)
    def __enter__(self):return self
    def __exit__(self,*_):pass
    def settimeout(self,timeout):assert 0<timeout<=.5
    def connect(self,path):self.path=path
    def getsockopt(self,*_):return struct.pack('3i',*self.peer)
    def sendall(self,raw):self.sent.append(json.loads(raw))
    def recv(self,count):raw,self.raw=self.raw[:count],self.raw[count:];return raw


class Boot(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.nonce='a'*32
        self.map=self.root/'System.map';self.map.write_text('0000000000001000 T kernel_init\n0000000000001010 t async_wait\n0000000000001100 T other\n')
        self.receipt=dict(config=dict(path=str(self.root/'.config')),system_map=dict(path=str(self.map),bytes=self.map.stat().st_size,sha256=R.s.sha(self.map.read_bytes())))
        self.child=SimpleNamespace(pid=23456)

    def test_fixed_progress_is_ordered_nonce_bound_and_not_acceptance(self):
        raw=b'kernel noise\r\n'+''.join('TOOLS16K_PROGRESS '+self.nonce+' '+p+'\n' for p in R.PROGRESS[:5]).encode()
        value=R.progress(raw,self.nonce);self.assertEqual(value['last'],'DEV_READY');self.assertFalse(value['acceptance_credit'])
        for extra in ('TOOLS16K_PROGRESS '+self.nonce+' INIT_ENTER\n','TOOLS16K_PROGRESS '+'b'*32+' DEV_READY\n','TOOLS16K_PROGRESS '+self.nonce+' UNKNOWN\n'):
            with self.assertRaises(ValueError):R.progress(raw+extra.encode(),self.nonce)

    def test_uart_exact_full_bytes_and_large_split_samples_are_hash_joined(self):
        for raw in (b'kernel early boot\n',b'x'*70000):
            value=R.uart_observation(raw,self.nonce);self.assertEqual(value['sha256'],R.s.sha(raw))
            self.assertEqual(value['complete'],len(raw)<=65536)
            for row in value['samples']:
                data=base64.b64decode(row['base64'],validate=True)
                self.assertEqual(data,raw[row['offset']:row['offset']+row['bytes']]);self.assertEqual(row['sha256'],R.s.sha(data))
        with self.assertRaises(ValueError):R.uart_observation(b'x'*(1024**2+1),self.nonce)

    def test_nearest_symbol_is_exact_map_bound_and_never_claims_a_stack(self):
        value=R.kernel_location(' PC=0000000000001018 X00=0\n',self.receipt,'# CONFIG_RANDOMIZE_BASE is not set\n')
        self.assertEqual(value['status'],'NEAREST_SYMBOL_ONLY_NOT_CALLSTACK');self.assertEqual(value['lower'][-1]['name'],'async_wait')
        self.assertEqual(value['lower'][-1]['offset'],8)
        self.map.write_text(self.map.read_text()+'0000000000001200 T drift\n')
        with self.assertRaises(ValueError):R.kernel_location('PC=0000000000001018 ',self.receipt,'# CONFIG_RANDOMIZE_BASE is not set\n')

    def test_kaslr_user_pc_and_missing_registers_are_qualified(self):
        self.assertEqual(R.kernel_location('PC=0000000000001018 ',self.receipt,'CONFIG_RANDOMIZE_BASE=y\n')['status'],'KASLR_NOT_SYMBOLIZED')
        self.assertEqual(R.kernel_location('PC=0000000000000018 ',self.receipt,'# CONFIG_RANDOMIZE_BASE is not set\n')['status'],'PC_OUTSIDE_SYMBOL_MAP')
        self.assertEqual(R.kernel_location('running',self.receipt,'')['status'],'NO_UNIQUE_PC')
        self.assertEqual(R.kernel_location('PC=0000000000001018 ',self.receipt,'')['status'],'KASLR_STATE_UNCONFIRMED')

    def observe(self,wire):
        path=self.root/'qmp.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as node:
            node.bind(str(path))
            try:
                with patch.object(R.socket,'socket',return_value=wire),patch.object(R.os,'waitid',return_value=None):
                    return R.vm_observation(self.child,path,self.receipt,'# CONFIG_RANDOMIZE_BASE is not set\n',b'kernel boot',self.nonce,R.time.monotonic()+2)
            finally:path.unlink()

    def test_exact_owned_qmp_peer_and_only_readonly_commands(self):
        wire=Wire(self.child.pid);value=self.observe(wire)
        self.assertEqual(value['status'],'READ_ONLY_OWNED_QEMU_OBSERVED');self.assertFalse(value['acceptance_credit'])
        self.assertEqual([r['execute'] for r in wire.sent],['qmp_capabilities','query-status','query-cpus-fast','human-monitor-command'])
        self.assertEqual(wire.sent[-1]['arguments'],dict(command_line='info registers'))
        self.assertEqual(value['peer']['pid'],self.child.pid)

    def test_foreign_peer_protocol_error_and_output_bound_refuse(self):
        wire=Wire(999)
        with self.assertRaises(ValueError):self.observe(wire)
        self.assertEqual(wire.sent,[])
        wire=Wire(self.child.pid);wire.raw=b'{"QMP":{}}\n'+b'{"error":{},"id":1}\n'
        with self.assertRaises(ValueError):self.observe(wire)
        wire=Wire(self.child.pid);wire.raw=b'x'*65537
        with self.assertRaises(ValueError):self.observe(wire)

    def test_init_brackets_original_operations_without_new_external_commands(self):
        raw=R.init(self.nonce,'7.1.13-generic16k-smoke').decode()
        self.assertLess(raw.index('progress INIT_ENTER'),raw.index('/usr/bin/mount'))
        self.assertLess(raw.index('progress PYTHON_BEGIN'),raw.index('/usr/bin/python3 -I -B /guest.py'))
        self.assertLess(raw.index('/smoke || fail'),raw.index('progress PAGE_PROBE_READY'))
        self.assertNotIn('sleep',raw);self.assertNotIn('timeout',raw)
        self.assertIn('printf \'TOOLS16K_PROGRESS '+self.nonce+' %s\\n\' "$1"',raw)
        import subprocess
        with tempfile.NamedTemporaryFile('w') as script:
            script.write(raw);script.flush();subprocess.run(['bash','-n',script.name],check=True)

    def test_guest_progress_flushes_and_rejects_nonhex_nonce(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):guest.progress(self.nonce,'PYTHON_ENTER')
        self.assertEqual(output.getvalue(),'TOOLS16K_PROGRESS '+self.nonce+' PYTHON_ENTER\n')
        with self.assertRaises(ValueError):guest.progress('x'*32,'PYTHON_ENTER')

    def supervise(self,callback,deadline=False):
        read,write=os.pipe();os.write(write,b'early UART');os.close(write);pipe=os.fdopen(read,'rb');events=[]
        child=SimpleNamespace(pid=23456,stdout=pipe,wait=lambda timeout:events.append('wait') or 0)
        state=dict(status='NOT_ATTEMPTED');ticks=iter([0,61,61,61,61]+([901] if deadline else [62]*20))
        def now():return next(ticks,902 if deadline else 62)
        def signal(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(R.subprocess,'Popen',return_value=child),patch.object(R.os,'waitid',return_value=object()),\
             patch.object(R.os,'killpg',side_effect=signal),patch.object(R.time,'monotonic',side_effect=now):
            result=R.supervise(['inert'],self.root/'uart.log',900,diagnostic=(state,callback))
        return result,state,events

    def test_observer_failure_is_qualified_and_original_natural_exit_stays_required(self):
        def fail(*_):raise ValueError('diagnostic unavailable')
        result,state,events=self.supervise(fail)
        self.assertEqual(state['status'],'UNAVAILABLE');self.assertEqual(result[0],0);self.assertTrue(result[2]['natural_exit'])
        self.assertEqual(events,[R.signal.SIGTERM,R.signal.SIGKILL,'wait',0])

    def test_observer_does_not_convert_actor_deadline_to_success(self):
        calls=[]
        def collect(child,raw,deadline):calls.append((child.pid,deadline));return dict(status='OBSERVATION_ONLY',acceptance_credit=False)
        with self.assertRaisesRegex(ValueError,'owned actor deadline'):self.supervise(collect,deadline=True)
        self.assertEqual(len(calls),1);self.assertLessEqual(calls[0][1],899)


if __name__=='__main__':unittest.main(verbosity=2)
