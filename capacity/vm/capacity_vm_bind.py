# SPDX-License-Identifier: MIT
"""Explicit capacity callbacks; retains complete VM security/protocol bodies."""
import capacity_protocol as P
def budgets(profile):
 b=profile['budgets'];P.need(profile['purpose']==P.PURPOSE and profile['normal_updater_acceptance']is False and all(profile[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')) and profile['actuals']=={'capacity':None} and profile['implementation']=='fixed-statx-input-candidate' and profile['package_count']==607 and profile['page_size']==16384,'diagnostic-only unexecuted capacity source')
 P.need(all(type(v)is int and 0<v<=21600 for v in b.values()),'finite exact integer actor budgets')
 checks=(('driver',b['copy']+b['copy_workspace_cleanup']+b['control_lease_cleanup']),('caller',b['quiescence']+b['source_stage']+b['driver']+b['source_verify']),('guest_worker',2*b['capability_map']+b['caller']+b['elf_audit']),('pid1_worker',b['guest_worker']),('qemu',b['pid1_worker']),('vm_transport',b['prepare_actor']+b['qemu']+b['export_actor']+b['actor_retirement_reserve']),('host_owner',b['vm_transport']),('job_owner',b['host_owner']),('composition_step',b['job_owner']),('job',b['composition_step']+b['job_build_reserve']+b['post_composition_reserve']))
 for outer,inner in checks:P.need(b[outer]>=inner,'capacity budget nesting: '+outer)
 P.need(b['qemu']>=b['pid1_worker']+16*15,'finite guest owned-unmount reserve')
 return dict(margins={outer:b[outer]-inner for outer,inner in checks},warnings=['QEMU boot/shutdown remainder after16 finite15s unmounts='+str(b['qemu']-b['pid1_worker']-240),'job remainder after explicit build/post-composition reserves='+str(b['job']-b['composition_step']-b['job_build_reserve']-b['post_composition_reserve'])])
def bind(module,profile,verify):
 budgets(profile);P.need(callable(verify),'explicit capacity-only caller verifier')
 module._CAPACITY_PROFILE=profile
 module.old_verify=lambda a:verify
 held=module.protocol
 def protocol(raw,selected,callback):
  P.selection(selected,profile)
  result=held(raw,selected,callback)
  return P.verify_result(result,selected,lambda caller,case:None)
 module.protocol=protocol
 return module

from contextlib import contextmanager
import signal,time
@contextmanager
def deadline(seconds):
 P.need(type(seconds)is int and seconds>0,'finite capacity phase ceiling')
 started=time.monotonic();remaining,interval=signal.getitimer(signal.ITIMER_REAL);P.need(interval==0,'no repeating foreign timer');prior=signal.getsignal(signal.SIGALRM)
 def expired(*args):
  if remaining and remaining<=seconds and callable(prior):return prior(*args)
  raise TimeoutError('capacity finite phase ceiling exhausted')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,min(seconds,remaining)if remaining else seconds)
 try:yield
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior)
  if remaining:signal.setitimer(signal.ITIMER_REAL,max(0.000001,remaining-(time.monotonic()-started)))
def timed(seconds,function,*args,**kwargs):
 with deadline(seconds):return function(*args,**kwargs)
