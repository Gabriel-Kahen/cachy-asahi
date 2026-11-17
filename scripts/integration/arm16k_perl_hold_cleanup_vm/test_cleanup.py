"""Real local socket framing tests; no QEMU, Docker, VM, lease or authority."""
import importlib.util,json,os,socket,tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
HERE=Path(__file__).parent
SOURCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-lifecycle-readiness-20261117-r2/constructed-source')
def module(name,root=HERE):
 s=importlib.util.spec_from_file_location('hold_cleanup_test_'+name,root/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
H=module('hold_cleanup');C=module('proposal');K=module('contracts',SOURCE)
REQUEST=b'{"execute":"quit","id":"guest-HOLD-retire"}\n'
ACK=b'{"return":{},"id":"guest-HOLD-retire"}\n'
class Controls(unittest.TestCase):
 def exchange(self,replies,expected=None,delay=0,guard=lambda:None,seconds=5,wrap=None):
  client,server=socket.socketpair();client.settimeout(2);qfile=client.makefile('rwb',buffering=0);peer=SimpleNamespace(fd=client.fileno(),stream=wrap(client)if wrap else client);received=[];errors=[]
  def actor():
   try:
    server.settimeout(6);body=bytearray()
    while not body.endswith(b'\n'):
     chunk=server.recv(44-len(body))
     if not chunk:break
     body.extend(chunk)
    received.append(bytes(body))
    if delay:threading.Event().wait(delay)
    for row in replies:server.sendall(row)
   except (OSError,AssertionError)as e:errors.append(type(e).__name__)
   finally:server.close()
  t=threading.Thread(target=actor);t.start();progress={};started=time.monotonic()
  try:
   if expected:
    with self.assertRaises(expected):H.quit_hold_qmp(K,peer,qfile,guard,started+seconds,progress)
   else:H.quit_hold_qmp(K,peer,qfile,guard,started+seconds,progress)
   self.assertEqual(client.gettimeout(),2);self.assertFalse(qfile._timeout_occurred)
  finally:qfile.close();client.close();t.join(7)
  self.assertFalse(t.is_alive());return progress,received,time.monotonic()-started
 def test_delayed_real_reply_beyond_previous_two_second_timeout_within_unchanged_five_seconds(self):
  progress,received,elapsed=self.exchange([ACK],delay=2.1)
  self.assertEqual(received,[REQUEST]);self.assertEqual(progress['stage'],'ACKNOWLEDGED');self.assertGreater(progress['idle_polls'],0);self.assertLess(elapsed,5)
 def test_fragmented_events_and_ack_use_owned_buffer(self):
  event=b'{"event":"SHUTDOWN"}\n';p,received,_=self.exchange([bytes([v])for v in event+ACK]);self.assertEqual(received,[REQUEST]);self.assertEqual(p['reply_attempts'],2);self.assertEqual(p['reply_bytes'],len(event+ACK))
 def test_partial_socket_sends_complete_exact_request(self):
  class Short:
   def __init__(self,s):self.s=s
   def __getattr__(self,n):return getattr(self.s,n)
   def send(self,b):return self.s.send(b[:2])
  p,received,_=self.exchange([ACK],wrap=Short);self.assertEqual(received,[REQUEST]);self.assertEqual(p['request_bytes'],44)
 def test_original_unbuffered_file_has_no_readahead(self):
  a,b=socket.socketpair();f=a.makefile('rwb',buffering=0)
  try:b.sendall(b'GREETING\n'+ACK);self.assertIs(type(f),socket.SocketIO);self.assertEqual(f.readline(65537),b'GREETING\n');self.assertEqual(a.recv(4096),ACK)
  finally:f.close();a.close();b.close()
 def test_socket_makefile_timeout_poisoning_reproduced_and_refused(self):
  a,b=socket.socketpair();a.settimeout(.02);f=a.makefile('rwb',buffering=0)
  try:
   b.sendall(b'{"return":')
   with self.assertRaises(TimeoutError):f.readline(65537)
   with self.assertRaises(OSError):f.readline(65537)
   self.assertTrue(f._timeout_occurred)
   with self.assertRaises(ValueError):H.quit_hold_qmp(K,SimpleNamespace(fd=a.fileno(),stream=a),f,lambda:None,time.monotonic()+5,{})
  finally:f.close();a.close();b.close()
 def test_eof_error_duplicate_nonobject_nonfinite_oversize_and_event_cap_refuse(self):
  for payload in([], [b'{"error":{},"id":"guest-HOLD-retire"}\n'],[b'{"id":"other","id":"guest-HOLD-retire","return":{}}\n'],[b'[]\n'],[b'{"return":NaN,"id":"guest-HOLD-retire"}\n'],[b'x'*65537],[b'{"event":"OTHER"}\n'*17]):
   with self.subTest(kind=str(payload)[:60]):
    p,_,_=self.exchange(payload,ValueError);self.assertNotEqual(p['stage'],'ACKNOWLEDGED');self.assertNotIn('OTHER',json.dumps(p))
 def test_idle_whole_deadline_expires_without_waiver(self):
  p,_,elapsed=self.exchange([ACK],TimeoutError,delay=.3,seconds=.1);self.assertEqual(p['stage'],'DEADLINE_EXPIRED');self.assertLess(elapsed,1)
 def test_guard_refusal_sends_no_command_and_restores_timeout(self):
  def guard():raise ValueError('PRIVATE_SENTINEL')
  p,received,_=self.exchange([],ValueError,guard=guard);self.assertEqual(received,[b'']);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(p))
 def test_descriptor_or_buffered_stream_substitution_refuses(self):
  a,b=socket.socketpair();f=a.makefile('rwb',buffering=0);buffered=b.makefile('rwb')
  try:
   for q in(buffered,):
    with self.assertRaises(ValueError):H.quit_hold_qmp(K,SimpleNamespace(fd=a.fileno(),stream=a),q,lambda:None,time.monotonic()+5,{})
   with self.assertRaises(ValueError):H.quit_hold_qmp(K,SimpleNamespace(fd=b.fileno(),stream=a),f,lambda:None,time.monotonic()+5,{})
  finally:f.close();buffered.close();a.close();b.close()
 def test_retirement_observations_are_bounded_pin_only_and_never_export_private_text(self):
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);p=out/'qemu.json';value=dict(exit=143,passed=False,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=['SIGTERM'],timeout=True,error='PRIVATE_SENTINEL',argv=['PRIVATE_SENTINEL'])
   p.write_bytes(K.canonical(value));p.chmod(0o644);report=H.retirement_observation(K,out,'guest-HOLD-retired.json');self.assertEqual(report['qemu']['observed']['exit'],143);self.assertEqual(report['guest_HOLD_retired']['status'],'ABSENT');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report));self.assertIsNone(report['VM_acceptance'])
   p.unlink();p.symlink_to('/MODEL/DO_NOT_READ');self.assertEqual(H.retirement_observation(K,out,'guest-HOLD-retired.json')['qemu']['status'],'REFUSED_UNSAFE_OR_INVALID')
   p.unlink();p.write_bytes(K.canonical(value));os.link(p,out/'alias');self.assertEqual(H.retirement_observation(K,out,'guest-HOLD-retired.json')['qemu']['status'],'REFUSED_UNSAFE_OR_INVALID')
 def test_exact_proposed_controller_preserves_authentication_ack_gate_and_normal_retirement(self):
  body=(SOURCE/'controller.py').read_bytes();changed=C.transform(body);compiled=compile(changed['controller.py'],'proposed_controller','exec');self.assertEqual(set(changed),{'controller.py','hold_cleanup.py'})
  text=changed['controller.py'].decode();self.assertIn('peer.check(row);quit_hold_qmp',text);self.assertIn("min(end,time.monotonic()+5)",text);self.assertIn("and wait.stdout.strip()==b'1'",text);self.assertIn('natural same QEMU reap/group absence',text);self.assertIn("min(cleanup_end-40,time.monotonic()+25)",text);self.assertIn("report['actor_failure_diagnostic']=capture_actor_failure",text)
  with self.assertRaises(ValueError):C.transform(body+b'\n')
if __name__=='__main__':unittest.main(verbosity=2)

class Integration(unittest.TestCase):
 def test_exact_proposed_cleanup_keeps_guest_hold_and_all_independent_retirement_joins(self):
  import types
  original=module('controller',SOURCE);A=module('actor',SOURCE);R=module('runtime',SOURCE);P=module('protocol',SOURCE);body=C.transform((SOURCE/'controller.py').read_bytes())['controller.py'];candidate=types.ModuleType('proposed_controller');candidate.__file__=str(SOURCE/'controller.py');exec(compile(body,'proposed_controller','exec'),candidate.__dict__);load=candidate.module;candidate.module=lambda n:H if n=='hold_cleanup'else load(n)
  nonce='a'*32;authority='b'*64;failure=P.GuestHold('INSTALLED','RESTORED','installed_metadata').failure;argv=['/usr/bin/qemu-system-aarch64','MODEL_NO_VM'];natural=dict(argv=argv,passed=True,reaped=True,ownership='REAPED',exit=0,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None)
  for bad in(None,'wrong-nonce','missing-qemu','forced-qemu','missing-retirement','matching-error','wrong-image','wrong-authority'):
   with self.subTest(bad=bad),tempfile.TemporaryDirectory()as tmp:
    out=Path(tmp)
    for name,value in(('qemu-argv.json',dict(argv=argv)),('qemu.json',dict(natural,signals=['SIGTERM'])if bad=='forced-qemu'else natural)):(out/name).write_bytes(K.canonical(value));(out/name).chmod(0o600)
    if bad=='missing-qemu':(out/'qemu.json').unlink()
    a,b=socket.socketpair();a.settimeout(2);qfile=a.makefile('rwb',buffering=0);requests=[]
    class Peer:
     fd=a.fileno();stream=a
     def check(self,row):K.need(row['State']['Pid']==101,'same original actor')
     def evidence(self):return dict(MODEL_AUTHENTICATED_PEER=True)
    peer=Peer();peer.argv=argv
    def respond():
     try:
      b.settimeout(1);request=b.recv(4096);requests.append(request)
      if request:b.sendall(b'{"error":{},"id":"guest-HOLD-retire"}\n'if bad=='matching-error'else ACK)
     except OSError:pass
     finally:b.close()
    t=threading.Thread(target=respond);t.start()
    class Scope:
     cid='c'*64;name='MODEL_OWNED';image='sha256:'+'d'*64;labels={'org.cachy-asahi.perl5423-nonce':nonce,'org.cachy-asahi.perl5423-authority':authority}
     def __init__(self):self.count=0;self.forced=False;self.removed=False
     def recover(self,end):
      self.count+=1;return dict(Id=self.cid,Name='/'+self.name,Image='WRONG'if bad=='wrong-image'else self.image,Config=dict(Labels=self.labels),State=dict(Pid=101,Running=self.count==1,ExitCode=1,OOMKilled=False))
     def validate(self,row):K.need(row['Image']==self.image and row['Name']=='/'+self.name and row['Config']['Labels']==self.labels,'exact actor identity')
     def call(self,args,end):
      if args[1]=='wait':
       if bad!='missing-retirement':A.retire_guest_hold(K,R,out,nonce)
       return SimpleNamespace(returncode=0,stdout=b'1\n')
      K.need(args==['docker','container','rm',self.cid],'only exact owned CID');self.removed=True;return SimpleNamespace(returncode=0)
     def listing(self,end):return None
     def cleanup(self,report):self.forced=True;report['owned_container_absence_verified']=True
    scope=Scope();report=dict(status='HOLD',failure=dict(category='GuestHold',message='ORIGINAL_GUEST_HOLD'),cleanup_errors=[])
    try:candidate.cleanup_scope(scope,peer,qfile,failure,'e'*32 if bad=='wrong-nonce'else nonce,'f'*64 if bad=='wrong-authority'else authority,out,time.monotonic()+90,lambda:None,report)
    finally:qfile.close();a.close();t.join(2)
    self.assertEqual(report['status'],'HOLD');self.assertEqual(report['failure']['message'],'ORIGINAL_GUEST_HOLD');self.assertEqual(scope.forced,bad is not None)
    if bad is None:self.assertTrue(scope.removed);self.assertEqual(report['cleanup_errors'],[]);self.assertEqual(report['guest_HOLD_cleanup']['status'],'HOLD_FAILURE_NATURALLY_RETIRED');self.assertEqual(requests,[REQUEST])
    else:self.assertTrue(report['forced_owned_cleanup_fallback']);self.assertTrue(report['cleanup_errors'])
