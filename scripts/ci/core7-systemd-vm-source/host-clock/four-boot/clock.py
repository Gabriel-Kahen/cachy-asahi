# SPDX-License-Identifier: MIT
"""Source-bound launch UTC, distinct from every monotonic execution deadline."""
import re,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C
ORIGIN='CURRENT_NATIVE_HOST_CLOCK_REALTIME'
SELECTOR='caa_core_realtime'
NS=10**9

def epoch(value):
 C.need(type(value)is int and 946684800<=value<4102444800,'typed supported current host UTC epoch seconds');return value

def identity(nonce,phase):
 C.need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and type(phase)is int and phase in(1,2,3,4),'whole nonce and finite clock boot role')

def host_sample(nonce,phase):
 identity(nonce,phase);return dict(schema=1,source=ORIGIN,nonce=nonce,phase=phase,epoch_seconds=epoch(time.time_ns()//NS),host_monotonic_ns=time.monotonic_ns())

def host_record(value,nonce,phase):
 identity(nonce,phase);C.need(type(value)is dict and set(value)=={'schema','source','nonce','phase','epoch_seconds','host_monotonic_ns'}and type(value['schema'])is int and value['schema']==1 and value['source']==ORIGIN and value['nonce']==nonce and type(value['phase'])is int and value['phase']==phase and type(value['host_monotonic_ns'])is int and 0<value['host_monotonic_ns']<2**63,'whole source-owned current host clock sample');epoch(value['epoch_seconds']);return value

def kernel_epoch(raw,nonce,phase):
 identity(nonce,phase);C.need(type(raw)is str and len(raw)<=16384,'bounded actual kernel clock selectors');result={}
 for key in('caa_core_vm','caa_core_phase',SELECTOR):
  rows=[v.split('=',1)[1]for v in raw.split()if v.startswith(key+'=')];C.need(len(rows)==1,'one source-owned kernel clock selector '+key);result[key]=rows[0]
 C.need(result['caa_core_vm']==nonce and result['caa_core_phase']==str(phase)and re.fullmatch('[1-9][0-9]{8,9}',result[SELECTOR]),'exact nonce/phase and decimal launch UTC selector');return epoch(int(result[SELECTOR]))

def validate(value,nonce,phase,host=None):
 identity(nonce,phase);fields={'schema','source','nonce','phase','epoch_seconds','previous_realtime_ns','initialized_realtime_ns','monotonic_before_ns','monotonic_after_ns'}
 C.need(type(value)is dict and set(value)==fields and type(value['schema'])is int and value['schema']==1 and value['source']==ORIGIN and value['nonce']==nonce and type(value['phase'])is int and value['phase']==phase,'whole source-owned bootstrap wallclock record');start=epoch(value['epoch_seconds'])*NS
 C.need(all(type(value[n])is int and 0<=value[n]<2**63 for n in('previous_realtime_ns','initialized_realtime_ns','monotonic_before_ns','monotonic_after_ns')),'typed absolute/monotonic clock data');elapsed=value['monotonic_after_ns']-value['monotonic_before_ns'];C.need(0<=elapsed<=5*NS and start<=value['initialized_realtime_ns']<=start+elapsed+NS,'successful bounded realtime initialization readback; monotonic elapsed is separate')
 if host is not None:C.need(host_record(host,nonce,phase)['epoch_seconds']==value['epoch_seconds'],'bootstrap UTC matches exact current host launch sample')
 return value

def initialize(selected,phase,raw):
 # This mutating entry repeats the complete original bootstrap role guard.
 # No ordinary host/source-only invocation can reach clock_settime.
 import guest_guard as G
 seen,_=G.guard(selected,'bootstrap');C.need(seen==phase,'actual guarded bootstrap phase before clock mutation');seconds=kernel_epoch(raw,selected['nonce'],phase);before=time.time_ns();mono=time.monotonic_ns();time.clock_settime(time.CLOCK_REALTIME,seconds);after=time.time_ns();end=time.monotonic_ns()
 value=dict(schema=1,source=ORIGIN,nonce=selected['nonce'],phase=phase,epoch_seconds=seconds,previous_realtime_ns=before,initialized_realtime_ns=after,monotonic_before_ns=mono,monotonic_after_ns=end);return validate(value,selected['nonce'],phase)

def current(value,selected,phase,raw):
 validate(value,selected['nonce'],phase);C.need(value['epoch_seconds']==kernel_epoch(raw,selected['nonce'],phase),'same actual kernel launch-clock operand');now=time.time_ns();C.need(value['initialized_realtime_ns']<=now<=value['initialized_realtime_ns']+C.BUDGET['boot']*NS,'actual worker wallclock follows initialized UTC within unchanged boot envelope');return value


def retained(directory,selected,boots):
 """Complete four host/guest clock pairs AND whole existing rollback checks."""
 directory=Path(directory);C.need(type(boots)is list and len(boots)==4,'all four launch/wallclock roles')
 for phase,record in enumerate(boots,1):
  launch=C.decode(C.read(directory.parent/'boots'/('launch-'+str(phase)+'.json')));C.need(launch==record['host_clock'],'whole retained source-owned host launch clock');wall=C.decode(C.read(directory/('phase%d-wallclock.json'%phase)));validate(wall,selected['nonce'],phase,launch);row=C.decode(C.read(directory/('phase%d-custody.json'%phase),16*1024**2));C.need(row['wallclock']==wall==record['result']['custody']['wallclock'],'full retained initialized wallclock custody and UART')
 return dict(status='PASS_ALL_FOUR_SOURCE_BOUND_HOST_GUEST_CLOCK_JOINS',boots=4,files=8)
