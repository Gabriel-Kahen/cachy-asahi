# SPDX-License-Identifier: MIT
"""Explicit current607 VM transport; parent transaction bodies stay complete."""
import ast
import hashlib
import json
from pathlib import Path
import signal,time
import kernel_data

RELEASE='7.1.13-generic16k-managed-gui'
PRED4="and os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.sysconf('SC_PAGE_SIZE') == 4096"
PRED16="and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and os.uname().release == '7.1.13-generic16k-managed-gui' and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()"
OWNER_EDITS=[
 ("'audio-inputs','output')", "'audio-inputs','output','kernel-input','fresh16k-source')"),
 ("a=p.parse_args(argv);policy=C.policy()", "a=p.parse_args(argv);vm.authorize(a);policy=C.policy()"),
 ("old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)", 'vm.run(a,argv,image,public,raw,old,3900)'),
 ('GENERIC4K_LATEST607_APPS6_TO16_COPIED_ROOT_SOFTWARE_ONLY','GENERIC16K_LATEST607_APPS6_TO16_COPIED_ROOT_SOFTWARE_ONLY'),
 ("result.update(status='PASS',composition=row)","result.update(status='PASS',composition=row,generic16k=C.read(public/'updater16k-result.json'))"),
 ('failures=old.retire_outer(actor_owned,result);retired=not failures','failures=vm.retire_outer(old,actor_owned,result,public);retired=not failures')]

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def transaction(function,*args):
 # Cover preparation, QEMU and export with the original enclosing3900s span.
 # A numeric QEMU-only3900 would silently widen that original transaction span.
 need(args[-1]==3900 and signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'original3900 span with no foreign timer')
 before=time.monotonic();deadline=before+3900;prior=signal.getsignal(signal.SIGALRM)
 def expired(*_):raise TimeoutError('original enclosing3900 transaction span exhausted')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,3900)
 try:
  result=function(*args);need(time.monotonic()<deadline,'complete VM transport exceeded original3900 span');return result
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior)

def derive(raw,edits):
 before=raw.decode();after=before
 for old,new in edits:
  need(after.count(old)==1,'one selected source seam '+old[:60]);after=after.replace(old,new,1)
 restored=after
 for old,new in reversed(edits):
  need(restored.count(new)==1,'one selected source inverse');restored=restored.replace(new,old,1)
 need(restored==before,'complete parent body inverse');ast.parse(after)
 return after.encode(),dict(before=pin(raw),after=pin(after.encode()),edits=edits,whole_inverse=True)

def owner(raw):
 out,proof=derive(raw,OWNER_EDITS)
 functions=lambda data:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(data).body if isinstance(n,ast.FunctionDef)}
 a,b=functions(raw),functions(out);need([n for n in a if a[n]!=b[n]]==['main'],'only outer VM dispatch changes; verifier and retirement bodies held')
 need(pin(out)==json.loads((Path(__file__).resolve().parent/'profile.json').read_bytes())['emitted_owner'],'actor owner equals constructor source emission')
 return out.decode(),proof

def candidate(api,source,target,case,descriptor):
 config,calling=api.candidate(source,target,case)
 config_raw=config.read_bytes();value=json.loads(config_raw);ledger={}
 for name,edits in (
  ('scripts/ci/full-root-upgrade-caller/container.py',[(PRED4,PRED16)]),
  ('scripts/install/local_transaction.py',[("os.uname().release == '7.2.10-1-aarch64-ARCH'", "os.uname().release == '7.1.13-generic16k-managed-gui'"),("os.sysconf('SC_PAGE_SIZE') == 4096", "os.sysconf('SC_PAGE_SIZE') == 16384")])):
  path=target/name;raw=path.read_bytes();need(value['code_pins'][name]==pin(raw)['sha256'],'original emitted code/config join')
  out,proof=derive(raw,edits);path.write_bytes(out);value['code_pins'][name]=pin(out)['sha256'];ledger[name]=proof
 held=json.loads(json.dumps(value));held['code_pins']=json.loads(config_raw)['code_pins']
 need(held==json.loads(config_raw),'all transaction/DB/security/clock configuration outside two code pins held')
 config.write_bytes(enc(value))
 receipt=json.loads((target/'adapter.json').read_bytes());receipt['config_sha256']=pin(config.read_bytes())['sha256']
 receipt['explicit_generic16k']=dict(status='SOURCE_DERIVED_NOT_EXECUTED',page_size=16384,kernel=RELEASE,kernel_input=descriptor,ledger=ledger,original_config=config_raw.decode(),clocks='UNCHANGED',actual=None)
 (target/'adapter.json').write_bytes(enc(receipt))
 import custody
 need(custody.rows(target)==custody.profile()['emitted_cases'][case],'all current16K installer/caller/config/policy emissions match constructor')
 return config,calling

def vm(api,args,extra,context,verify_dependencies):
 import common as C
 root=Path(__file__).resolve().parent;support=root/'vm'
 contract=C.load('_current607_vm_contract',support/'contract.py')
 transport=C.load('_current607_vm_transport',support/'vm.py',{'contract':contract})
 def kernel(a):
  verify_dependencies(a.fresh16k_source,'fresh16k')
  descriptor=json.loads((root/'profile.json').read_bytes())['kernel_descriptor']
  value,image,config=kernel_data.verify(a.kernel_input,descriptor)
  profile=dict(value,profile='CURRENT607_EXPLICIT_GENERIC16K_KERNEL_DATA_V1',release=RELEASE,architecture='aarch64')
  return profile,a.kernel_input/'Image',a.kernel_input/'config'
 def authorize(a):
  verify_dependencies(a.implementation,'held')
  __import__('authority').gates(extra.latest_decisions)
  api.inputs()
  return kernel(a)
 transport.kernel=kernel;transport.authorize=authorize
 transport.old_verify=lambda a:api._owner.verify_result
 transport._CURRENT607=context
 transport._KERNEL_DESCRIPTOR=json.loads((root/'profile.json').read_bytes())['kernel_descriptor']
 original_run=transport.run
 transport.run=lambda *args:transaction(original_run,*args)
 return transport

def execute(held,argv,context,verify_dependencies):
 import common as C,runtime as R,authority
 extra,rest=R.extras(argv,require_dependency=True);authority.gates(extra.latest_decisions)
 api=R.Integration(held,extra.latest_installer,extra.six_public,extra.six_record,{k:getattr(extra,k)for k in('apps16','apps16qualification','apps16current606qualification')},context['source'],extra.dependency_incoming)
 original=R.derive_owner;proof=[]
 def selected(raw):
  body,ledger=owner(original(raw).encode());proof.append(ledger);return body
 try:
  R.derive_owner=selected;active=api.owner()
 finally:R.derive_owner=original
 api._owner=active
 class Adapter:
  @staticmethod
  def prepare(source,target,case):
   descriptor=json.loads((Path(__file__).resolve().parent/'profile.json').read_bytes())['kernel_descriptor']
   return candidate(api,source,target,case,descriptor)
 active.adapter=Adapter
 active.vm=vm(api,rest,extra,context,verify_dependencies)
 need(len(proof)==1 and proof[0]['whole_inverse'],'complete parent607 owner inversion before execution')
 return active.main(rest)
