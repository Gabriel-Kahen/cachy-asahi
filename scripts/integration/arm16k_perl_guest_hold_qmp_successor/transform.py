# SPDX-License-Identifier: MIT
"""Exact Source387 controller hooks and one fixed adapter delivery; no actors."""
import hashlib
MODULE='hold_state_observations.py'
C=dict(bytes=25913,sha256='4b6511f0cadfce2d0af9479f6aa181c7fa042b82075e6b37be5d22ed9562eeec')
A=dict(bytes=14525,sha256='3da6380dfc005f924c287d01fbdf05e719167bb24074a4f9511a03e5f3a1e0af')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def replace(text,old,new):
 if text.count(old)!=1:raise ValueError('exact one-site Source387 transform')
 return text.replace(old,new)

HOOK='''def bind_hold_observer(peer,serial,packet_dir,packet):
 K=module('contracts');name='hold_state_observations.py';path=K.ordinary(packet_dir/name);expected=K.pin(HERE/name)
 K.need(packet['files'].get(name)==dict(**expected,mode=0o644)and K.pin(path)==expected and stat.S_IMODE(path.stat().st_mode)==0o644,'exact fixed delivered diagnostic module')
 spec=importlib.util.spec_from_file_location('fixed_hold_state_observations',path);observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
 return observer.Binding(peer,serial)


def diagnostic_sample(observer,stage,report):
 if observer is None or type(report)is not dict:return
 try:
  rows=report.setdefault('guest_HOLD_state_observations',[])
  if type(rows)is not list or len(rows)>=3:raise ValueError('fixed diagnostic slots')
  value=observer.sample(stage);K=module('contracts')
  K.need(len(K.canonical(dict(guest_HOLD_state_observations=rows+[value])))<=65536,'fixed diagnostic component budget');rows.append(value)
 except Exception:report.setdefault('guest_HOLD_state_diagnostic_unavailable',True)


'''
def _controller_pairs():
 pairs=[('def normal_hold_cleanup(scope,peer,qfile,failure,nonce,authority_sha256,out,end,guard,record):',HOOK+'def normal_hold_cleanup(scope,peer,qfile,failure,nonce,authority_sha256,out,end,guard,record,observer=None,report=None):'),
 ("peer.check(row);quit_hold_qmp(peer,qfile,guard,min(end,time.monotonic()+5),record.setdefault('qmp_quit_progress',{}))","peer.check(row)\n diagnostic_sample(observer,'BEFORE_QUIT',report)\n quit_hold_qmp(peer,qfile,guard,min(end,time.monotonic()+5),record.setdefault('qmp_quit_progress',{}))"),
 ('def cleanup_scope(scope,peer,qfile,failure,nonce,authority_sha256,out,cleanup_end,guard,report):','def cleanup_scope(scope,peer,qfile,failure,nonce,authority_sha256,out,cleanup_end,guard,report,observer=None):')]
 old='normal_hold_cleanup(scope,peer,qfile,failure,nonce,authority_sha256,out,min(cleanup_end-40,time.monotonic()+25),guard,record)';pairs.append((old,old[:-1]+',observer,report)'))
 old="except BaseException as error:\n   report.setdefault('cleanup_errors',[]).append(dict(step='normal-guest-HOLD-retirement'"
 new="except BaseException as error:\n   if record.get('qmp_quit_progress',{}).get('stage')=='DEADLINE_EXPIRED':diagnostic_sample(observer,'DEADLINE',report)\n   report.setdefault('cleanup_errors',[]).append(dict(step='normal-guest-HOLD-retirement'";pairs.append((old,new))
 pairs.append(('state=B.Cancellation();scope=serial=qmp=qfile=peer=None;hold_failure=None','state=B.Cancellation();scope=serial=qmp=qfile=peer=hold_observer=None;hold_failure=None'))
 old="serial=Serial(Watched(),deadline-r['cleanup_seconds'])";pairs.append((old,old+"\n    try:hold_observer=bind_hold_observer(peer,serial,packet_dir,packet)\n    except Exception:report['guest_HOLD_state_diagnostic_unavailable']=True"))
 pairs.append(('if isinstance(error,P.GuestHold):hold_failure=error.failure',"if isinstance(error,P.GuestHold):\n   hold_failure=error.failure;diagnostic_sample(hold_observer,'HOLD',report)"))
 old="cleanup_scope(scope,peer,qfile,hold_failure,packet['nonce'],a.authority_sha256,out,cleanup_end,cleanup_guard,report)";pairs.append((old,old[:-1]+',hold_observer)'))
 return pairs

def transform_controller(raw):
 if pin(raw)!=C:raise ValueError('exact Source387 controller preimage')
 text=raw.decode()
 for old,new in _controller_pairs():text=replace(text,old,new)
 compile(text,'source-only-controller','exec');return text.encode()

def inverse_controller(raw):
 text=raw.decode()
 for old,new in reversed(_controller_pairs()):text=replace(text,new,old)
 before=text.encode()
 if pin(before)!=C or transform_controller(before)!=raw:raise ValueError('exact Source387 controller inverse')
 return before

ADAPTER_NEEDLE=" put('expected-cache-transition.tsv',(HERE/'expected-cache-transition.tsv').read_bytes())\n"
ADAPTER_ADDITION=" put('hold_state_observations.py',(HERE/'hold_state_observations.py').read_bytes())\n"
def transform_adapter(raw):
 if pin(raw)!=A:raise ValueError('exact Source387 adapter preimage')
 return replace(raw.decode(),ADAPTER_NEEDLE,ADAPTER_NEEDLE+ADAPTER_ADDITION).encode()

def inverse_adapter(raw):
 before=replace(raw.decode(),ADAPTER_NEEDLE+ADAPTER_ADDITION,ADAPTER_NEEDLE).encode()
 if pin(before)!=A or transform_adapter(before)!=raw:raise ValueError('exact Source387 adapter inverse')
 return before
