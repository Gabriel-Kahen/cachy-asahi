#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private scalar/Unix-IPC fixtures; no live PipeWire or audio mutation."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
loader=importlib.machinery.SourceFileLoader('audio_doctor',str(HERE/'cachy-asahi-doctor'))
spec=importlib.util.spec_from_loader(loader.name,loader);D=importlib.util.module_from_spec(spec);loader.exec_module(D)

class SocketFixture:
 def __enter__(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.server=socket.socket(socket.AF_UNIX);self.server.bind(str(self.root/'pipewire-0'));self.server.listen(1);self.server.settimeout(2)
  return self
 def __exit__(self,*_):self.server.close();self.temp.cleanup()

class Audio(unittest.TestCase):
 def test_muted_zero_and_plain_volume_are_actionable_observations(self):
  for raw,level,muted,action in [(b'Volume: 0.50 [MUTED]\n','0.50',True,'muted'),(b'Volume: 0.00\n','0.00',False,'zero'),(b'Volume: 1.23\n','1.23',False,'output selection')]:
   with self.subTest(raw=raw):
    row=D.audio_row(('checked',0,raw,b''));self.assertEqual(row['state'],'checked');self.assertEqual(row['value'],dict(displayed_volume=level,muted=muted,default_sink_responded=True));self.assertIn(action,row['note'])
    report=dict(checks=[row],coverage={'checked':1},limitations=[])
    self.assertIn('volume '+level,D.human(report));self.assertIn(row['note'],D.human(report))
 def test_malformed_extra_nonfinite_error_and_private_output_not_reported(self):
  raws=[b'',b'Volume: NaN\n',b'Volume: inf\n',b'Volume: -0.50\n',b'Volume: 00.50\n',b'Volume: 0.5\n',b'Volume: 0.50',b'Volume: 0.50\nPRIVATE DEVICE\n',b'Volume: 0.50 [MUTED]PRIVATE\n',b'Volume: 0.50\x00\n',b'Volume: 0.50\r\n',b'Volume: 10000.00\n',b'x'*129]
  for raw in raws:
   with self.subTest(raw=raw):
    row=D.audio_row(('checked',0,raw,b''));self.assertEqual(row['state'],'unknown');self.assertIsNone(row['value']);self.assertNotIn('PRIVATE',json.dumps(row))
  for state,code,err in [('checked',2,b'PRIVATE NO DEFAULT SINK'),('checked',0,b'PRIVATE WARNING'),('unknown',0,b''),('unavailable',None,b'')]:
   row=D.audio_row((state,code,b'Volume: 0.50\n',err));self.assertIsNone(row['value']);self.assertNotIn('PRIVATE',json.dumps(row));self.assertIn('Check output selection',row['note'])
 def test_real_private_socket_owner_mode_and_ordinary_ancestry(self):
  with SocketFixture()as f:
   snapshot=D.audio_socket(f.root);self.assertEqual(snapshot['path'],str(f.root));self.assertEqual(snapshot,D.audio_socket(f.root))
   f.root.chmod(0o755);self.assertIsNone(D.audio_socket(f.root));f.root.chmod(0o700)
   with patch.object(D.os,'getuid',return_value=os.getuid()+1):self.assertIsNone(D.audio_socket(f.root))
   alias=f.root/'alias';alias.symlink_to(f.root,target_is_directory=True);self.assertIsNone(D.audio_socket(alias))
   link=f.root/'socket-alias';os.link(f.root/'pipewire-0',link);self.assertIsNone(D.audio_socket(f.root));link.unlink()
   (f.root/'pipewire-0').unlink();(f.root/'pipewire-0').write_bytes(b'not a socket');self.assertIsNone(D.audio_socket(f.root))
   (f.root/'pipewire-0').unlink();(f.root/'pipewire-0').symlink_to(f.root/'other');self.assertIsNone(D.audio_socket(f.root))
  self.assertIsNone(D.audio_socket(Path('relative')));self.assertIsNone(D.audio_socket(Path('/run/user/../user')))
 def test_socket_replacement_is_observable(self):
  with SocketFixture()as f:
   before=D.audio_socket(f.root);(f.root/'pipewire-0').unlink()
   with socket.socket(socket.AF_UNIX)as new:new.bind(str(f.root/'pipewire-0'));self.assertNotEqual(before,D.audio_socket(f.root))
 def collect(self,audio_check,run=None,has=lambda _:True):
  def default(argv,seconds,bus,**kwargs):
   if argv[0]=='/usr/bin/pacman':return ('checked',0,b'',b'')
   if argv[0]=='/usr/bin/wpctl':return ('checked',0,b'Volume: 0.25 [MUTED]\n',b'')
   return ('checked',0,b'LoadState=loaded\nActiveState=active\nSubState=running\n',b'')
  return D.collect(run=run or default,read=lambda _:None,has=has,bus_check=lambda:None,audio_check=audio_check,machine=dict(architecture='fixture',page_size_bytes=4096,kernel='fixture'),environ={})
 def test_no_socket_or_wpctl_launches_no_audio_client(self):
  run=Mock(return_value=('unavailable',None,b'',b''))
  for has in (lambda _:True,lambda name:name!='wpctl'):
   report=self.collect(lambda:None,run,has);row=report['checks'][-1];self.assertEqual(row['state'],'unavailable');self.assertTrue(all(c.args[0][0]!='/usr/bin/wpctl'for c in run.call_args_list))
 def test_fixed_audio_argv_and_no_bus_dependency(self):
  with SocketFixture()as f:
   events=[]
   def run(argv,seconds,bus,**kwargs):
    events.append((argv,seconds,bus,kwargs));return ('checked',0,b'Volume: 0.25 [MUTED]\n',b'')if argv[0]=='/usr/bin/wpctl'else ('unavailable',None,b'',b'')
   report=self.collect(lambda:D.audio_socket(f.root),run);row=report['checks'][-1];self.assertTrue(row['value']['muted'])
   audio=[x for x in events if x[0][0]=='/usr/bin/wpctl'];self.assertEqual(len(audio),1);argv,seconds,bus,kwargs=audio[0]
   self.assertEqual(argv,['/usr/bin/wpctl','get-volume','@DEFAULT_AUDIO_SINK@']);self.assertGreater(seconds,0);self.assertLessEqual(seconds,2);self.assertIsNone(bus);self.assertEqual(kwargs,dict(audio=str(f.root)))
   self.assertNotIn(str(f.root),json.dumps(report));self.assertNotIn('pipewire-0',json.dumps(report))
 def test_socket_changed_before_or_after_client_is_unknown(self):
  with SocketFixture()as f:
   initial=D.audio_socket(f.root);changed=dict(initial,socket=('changed',))
   for snapshots,expected in [([initial,changed],0),([initial,initial,changed],1)]:
    events=[]
    def run(argv,*a,**kw):
     if argv[0]=='/usr/bin/wpctl':events.append(argv);return ('checked',0,b'Volume: 0.50\n',b'')
     return ('unavailable',None,b'',b'')
    report=self.collect(Mock(side_effect=snapshots),run);self.assertEqual(report['checks'][-1]['state'],'unknown');self.assertEqual(len(events),expected);self.assertIsNone(report['checks'][-1]['value'])
 def test_audio_obeys_original_aggregate_deadline(self):
  with SocketFixture()as f:
   run=Mock(return_value=('unavailable',None,b'',b''))
   with patch.object(D.time,'monotonic',side_effect=[0]+[30]*5):report=self.collect(lambda:D.audio_socket(f.root),run)
   self.assertFalse(any(c.args[0][0]=='/usr/bin/wpctl'for c in run.call_args_list));self.assertEqual(report['checks'][-1]['state'],'unknown')

class RealIPC(unittest.TestCase):
 def exercise(self,payload,*,seconds=1,stall=False):
  """Actual private Unix transport and child lifetime, not PipeWire protocol."""
  with SocketFixture()as f:
   received=[];errors=[]
   def serve():
    try:
     with f.server.accept()[0]as client:
      client.settimeout(2);received.append(json.loads(client.recv(8192)))
      if stall:received.append(client.recv(1))
      else:client.sendall(payload)
    except BaseException as error:errors.append(error)
   thread=threading.Thread(target=serve);thread.start()
   code="import json,os,socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(os.environ['PIPEWIRE_RUNTIME_DIR']+'/pipewire-0');s.sendall(json.dumps(dict(pid=os.getpid(),env=dict(os.environ))).encode());data=b''\nwhile True:\n chunk=s.recv(8192)\n if not chunk:break\n data+=chunk\nsys.stdout.buffer.write(data)"
   inherited=dict(PIPEWIRE_REMOTE='tcp:PRIVATE_REMOTE',PIPEWIRE_RUNTIME_DIR='/PRIVATE_RUNTIME',LD_PRELOAD='',PYTHONPATH='/PRIVATE_MODULES',DBUS_SESSION_BUS_ADDRESS='tcp:PRIVATE_BUS')
   try:
    with patch.dict(os.environ,inherited):result=D.query([sys.executable,'-I','-c',code],seconds,audio=str(f.root))
   finally:thread.join(timeout=3)
   self.assertFalse(thread.is_alive());self.assertFalse(errors,errors);self.assertTrue(received)
   self.assertEqual(received[0]['env']['PIPEWIRE_REMOTE'],'pipewire-0');self.assertEqual(received[0]['env']['PIPEWIRE_RUNTIME_DIR'],str(f.root));self.assertEqual(received[0]['env']['XDG_RUNTIME_DIR'],str(f.root));self.assertEqual(received[0]['env']['XDG_CONFIG_HOME'],'/nonexistent')
   for name in ('HOME','LD_PRELOAD','PYTHONPATH','DBUS_SESSION_BUS_ADDRESS'):self.assertNotIn(name,received[0]['env'])
   with self.assertRaises(ProcessLookupError):os.killpg(received[0]['pid'],0)
   if stall:self.assertEqual(received[1],b'')
   return result
 def test_actual_local_socket_scalar_and_natural_child_retirement(self):
  result=self.exercise(b'Volume: 0.40 [MUTED]\n');self.assertEqual(result[:2],('checked',0));self.assertEqual(D.audio_row(result)['value']['displayed_volume'],'0.40')
 def test_stalled_local_server_deadline_kills_and_reaps_client(self):
  result=self.exercise(b'',seconds=.2,stall=True);self.assertEqual(result[0],'unknown');self.assertIsNone(D.audio_row(result)['value'])
 def test_real_child_overflow_is_unknown_without_private_output(self):
  result=self.exercise(b'PRIVATE'*20000);self.assertEqual(result[0],'unknown');self.assertLessEqual(len(result[2])+len(result[3]),D.MAX_OUTPUT);self.assertNotIn('PRIVATE',json.dumps(D.audio_row(result)))

if __name__=='__main__':unittest.main(verbosity=2)
