# SPDX-License-Identifier: MIT
"""Actual command writer/export/finish bodies; actors replaced only at boundaries."""
import argparse,ast,contextlib,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,guest,media

def row(argv,out=b'',err=b''):
 return dict(argv=argv,exit_code=0,group_absence_verified=True,time_limit=90,seconds=.1,output_limit=1024**2,stdout_bytes=len(out),stdout_sha256=C.pin(out)['sha256'],stderr_bytes=len(err),stderr_sha256=C.pin(err)['sha256'])

class Routes(unittest.TestCase):
 def test_actual_worker_observer_writer_preserves_both_streams(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);old=guest.OUT,guest.END;guest.OUT=root;guest.END=time.monotonic()+10
   try:
    def execute(argv,*a):
     out=('actual-shaped-'+argv[-1]).encode();return row(argv,out),out,b'',None
    api=dict(runtime=types.SimpleNamespace(run_command=execute));worker=dict(phase=1,commands=[]);observer=dict(phase=1,role='observer',commands=[])
    w=guest.Commands(api,worker);o=guest.Commands(api,observer);w.call(['/usr/bin/gpg','signature-status']);held=(root/'phase1-command-000.stdout').read_bytes();o.call(['/usr/bin/systemctl','PID1-readback'])
    self.assertEqual((root/'phase1-command-000.stdout').read_bytes(),held);self.assertNotEqual(held,(root/'phase1-observer-command-000.stdout').read_bytes());self.assertTrue((root/'phase1-progress.json').is_file());self.assertTrue((root/'phase1-observer-progress.json').is_file());self.assertEqual(len(worker['commands']),1);self.assertEqual(len(observer['commands']),1)
   finally:guest.OUT,guest.END=old
 def test_real_export_body_no_hidden_member_loss(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);image=root/'data.raw';image.write_bytes(b'inert-disk-boundary')
   fixed={'baseline-nodes.json':b'{}\n','capabilities.json':b'{}\n','overlay.json':b'{}\n'}
   originals={'phase1-command-000.stdout':b'actual-shaped-GPG-status','phase1-observer-command-000.stdout':b'actual-shaped-PID1-version','phase1-custody.json':b'{}','phase1-observer.json':b'{}','phase1-retirement.json':b'{}','phase1-installed-root.json.gz':b'compressed-original','baseline-automatic-root.json.gz':b'compressed-original-baseline','.phase1-progress.json.partial':b'preserved-failure-DATA','.phase1-observer-progress.json.partial':b'observer-failure-DATA','.phase1-retirement.json.partial':b'natural-retirement-partial-DATA'}
   listing=b'/2/040700/0/0/.//\n/2/040700/0/0/..//\n'+b''.join(('/%d/100600/0/0/%s/%d/\n'%(10+i,n,len(v))).encode()for i,(n,v)in enumerate(originals.items()))
   raw=C.read(VM/'runtime'/media.DONOR,256*1024);profile=C.decode(C.read(C.HERE/'profile.json',4*1024**2));self.assertEqual(C.pin(raw),profile['source_profiles']['ksm637']['files']['runtime/'+media.DONOR]);tree=ast.parse(raw);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='image_directory');namespace=dict(C=C);exec(compile(ast.Module(body=[function],type_ignores=[]),'whole-original-bounded-image-directory','exec'),namespace);parser=namespace['image_directory']
   def command(argv,seconds):
    if argv[2]=='ls -p /out':return listing
    verb,source,dest=argv[2].split(' ',2);self.assertEqual(verb,'dump');Path(dest).write_bytes((fixed if source.startswith('/workspace/')else originals)[Path(source).name]);return b''
   actor=types.SimpleNamespace(image_directory=parser,command=command,C=types.SimpleNamespace(row=lambda p:C.pin(C.read(p))))
   import gzip
   all_expected=dict(originals,**{'media-source-nodes.json.gz':gzip.compress(fixed['baseline-nodes.json'],mtime=0),'media-source-capabilities.json':fixed['capabilities.json'],'media-overlay.json':fixed['overlay.json']})
   pins=media.export_files(actor,image,root/'guest-export',dict(nonce='a'*32),os.getuid(),os.getgid());self.assertEqual(pins,{n:C.pin(v)for n,v in all_expected.items()});self.assertEqual({p.name:p.read_bytes()for p in(root/'guest-export').iterdir()},all_expected)
   bad=types.SimpleNamespace(**dict(vars(actor),image_directory=lambda raw:dict(parser(raw),**{'../escape':dict(mode=0o100600,uid=0,gid=0,size=1)})))
   (root/'guest-export').rename(root/'held-first-export')
   with self.assertRaisesRegex(ValueError,'literal public guest'):media.export_files(bad,image,root/'guest-export',dict(nonce='a'*32),os.getuid(),os.getgid())
   self.assertFalse((root/'guest-export').exists())
 def test_finish_requires_actual_success_then_binds_observer(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);old=guest.OUT;guest.OUT=root;_,_,v=__import__('test_protocol').fixture();v['custody']['nonce']=v['nonce'];v['previous']=C.pin(C.encoded(v['custody']));v['phase']=v['custody']['phase']=v['custody']['wallclock']['phase']=2;v['custody']['previous']=v['previous'];(root/'phase2-observer.json').write_bytes(C.encoded(v))
   class Stream:
    def __init__(self):self.buffer=self;self.data=b''
    def write(self,x):self.data+=x
    def flush(self):pass
   stream=Stream()
   try:
    with patch.dict(os.environ,dict(SERVICE_RESULT='exit-code',EXIT_CODE='exited',EXIT_STATUS='1'),clear=True):
     with self.assertRaisesRegex(ValueError,'natural observer'):guest.finish(dict(nonce='a'*32),2)
    self.assertFalse((root/'phase2-retirement.json').exists())
    with patch.dict(os.environ,dict(SERVICE_RESULT='success',EXIT_CODE='exited',EXIT_STATUS='0'),clear=True),patch.object(guest.sys,'stdout',stream):guest.finish(dict(nonce='a'*32),2)
    receipt=C.decode(C.read(root/'phase2-retirement.json'));self.assertEqual(receipt['observer'],C.pin(C.encoded(__import__('serial_result').project(v))));self.assertTrue(stream.data.startswith(b'\n'+C.RETIRED));self.assertEqual(C.decode(stream.data[len(b'\n'+C.RETIRED):]),receipt)
   finally:guest.OUT=old
 def test_actual_machine_writers_delimit_partial_terminal_lines(self):
  from unittest.mock import patch
  import copy
  preludes=(b'partial-console-line',bytes.fromhex('1b502b7136453631364436351b5c'),b'\x1b]0;partial-title\x07',b'\x1b[32mpartial-ansi')
  for prelude in preludes:
   with self.subTest(prelude=prelude),tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);selected,expected,fixture=__import__('test_protocol').fixture();custody=fixture['custody'];custody['nonce']=selected['nonce'];(root/'phase1-custody.json').write_bytes(C.encoded(custody))
    class Stream:
     def __init__(self):self.buffer=self;self.data=prelude
     def write(self,value):self.data+=value
     def flush(self):pass
    stream=Stream();old_state=guest.OUT,guest.END;guest.OUT=root
    def execute(argv,*unused):
     if argv==['/usr/bin/systemctl','--system','is-system-running','--wait']:out=b'running\n'
     elif argv==['/usr/lib/systemd/systemd','--version']:out=fixture['pid1']['version'].encode()
     elif argv==['/usr/bin/pacman','-Q','systemd']:out=fixture['pid1']['package_version'].encode()
     elif '--property=Version,Virtualization,SystemState'in argv:out=''.join(k+'='+v+'\n'for k,v in fixture['pid1']['manager'].items()).encode()
     else:out=''.join(k+'='+v+'\n'for k,v in fixture['worker'].items()).encode()
     return row(argv,out),out,b'',None
    def pid1(commands,unused):
     # Only private PID1/architecture syscalls are replaced by the existing typed fixture.
     # Every source-owned command writer/manager/unit/observer/finish body executes.
     commands.call(['/usr/lib/systemd/systemd','--version']);commands.call(['/usr/bin/pacman','-Q','systemd']);manager=guest.manager(commands)
     self.assertEqual(manager,fixture['pid1']['manager']);return copy.deepcopy(fixture['pid1'])
    core=types.SimpleNamespace(api={'runtime':types.SimpleNamespace(run_command=execute)})
    try:
     with patch.object(guest,'sources',return_value=core),patch.object(guest,'pid1',side_effect=pid1),patch.object(guest.sys,'stdout',stream):guest.observer(selected,1,fixture['pid1']['root'])
     observer=C.decode(C.read(root/'phase1-observer.json'));wire=__import__('serial_result').project(observer)
     observer_frame=b'\n'+C.PREFIX+C.encoded(wire).replace(b'\n',b'')+b'\n';self.assertEqual(stream.data,prelude+observer_frame)
     stream.data+=prelude
     with patch.dict(os.environ,dict(SERVICE_RESULT='success',EXIT_CODE='exited',EXIT_STATUS='0'),clear=True),patch.object(guest.sys,'stdout',stream):guest.finish(selected,1)
     retired=C.decode(C.read(root/'phase1-retirement.json'));retirement_frame=b'\n'+C.RETIRED+C.encoded(retired).replace(b'\n',b'')+b'\n'
     self.assertEqual(stream.data,prelude+observer_frame+prelude+retirement_frame);self.assertEqual(retired['observer'],C.pin(C.encoded(wire)));self.assertEqual(C.protocol(stream.data,selected,1,expected),wire)
     # This exact old-writer shape has one retirement anywhere and zero line starts.
     old=prelude+observer_frame+prelude+retirement_frame[1:]
     self.assertEqual(old.count(C.RETIRED),1);self.assertEqual(sum(line.startswith(C.RETIRED)for line in old.splitlines()),0)
     with self.assertRaisesRegex(ValueError,'retirement marker'):C.protocol(old,selected,1,expected)
     for raw in(stream.data+retirement_frame,stream.data+observer_frame):
      with self.assertRaises(ValueError):C.protocol(raw,selected,1,expected)
     for change in({'nonce':'f'*32},{'phase':2},{'service_result':'exit-code'},{'observer':{'bytes':1,'sha256':'0'*64}}):
      forged=dict(retired,**change);raw=prelude+observer_frame+prelude+b'\n'+C.RETIRED+C.encoded(forged).replace(b'\n',b'')+b'\n'
      with self.assertRaises(ValueError):C.protocol(raw,selected,1,expected)
    finally:guest.OUT,guest.END=old_state

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vm-source',type=Path,required=True);a,rest=p.parse_known_args();VM=a.vm_source.absolute();unittest.main(argv=[sys.argv[0],*rest])
