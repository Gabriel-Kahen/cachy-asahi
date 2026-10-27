# SPDX-License-Identifier: MIT
"""Capacity DATA protocol joins; never normal updater acceptance."""
import hashlib,json,re
PURPOSE='generic16k-fullcopy-capacity'
STATUS='MEASURED_GENERIC16K_FULL_COPY_CAPACITY_NOT_ACCEPTANCE'
PREFIX='APPS6_COPY_CAPACITY'
ROLES=('result.json','capacity-telemetry.json','capacity-cleanup.json','updater16k-worker.json','updater16k-caller.stdout','updater16k-caller.stderr')
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def profile_pin(profile):return hashlib.sha256(encoded(profile)).hexdigest()
def selection(value,profile):
 need(type(value)is dict and value.get('capacity')==dict(purpose=PURPOSE,profile_sha256=profile_pin(profile),implementation=profile['implementation']),'exact capacity purpose/profile selection')
 current=value['current607'];need(type(current)is dict and set(current)=={'source','run','attempt','ref','page_profile'} and current['page_profile']=='generic16k','held five-key current607 context')
def verify_result(result,selected,verify):
 need(result.get('status')==STATUS,'capacity DATA status')
 need(type(result.get('files'))is dict and set(result['files'])==set(ROLES),'closed capacity guest export roles')
 for pin in result['files'].values():need(type(pin)is dict and set(pin)=={'bytes','sha256'}and type(pin['bytes'])is int and 0<=pin['bytes']<=4*1024**2 and type(pin['sha256'])is str and re.fullmatch('[0-9a-f]{64}',pin['sha256']),'strict bounded capacity export pin')
 need(sum(pin['bytes']for pin in result['files'].values())<=8*1024**2,'bounded capacity guest exports')
 trace=result['caller']['full_root_upgrade']['driver']['capacity_telemetry'];identity=trace['identity']
 need(identity['current607']==selected['current607']and identity['nonce']==selected['nonce']and identity['purpose']==PURPOSE and identity['implementation']==selected['capacity']['implementation']and trace['profile_sha256']==selected['capacity']['profile_sha256'],'actual driver telemetry source/run/nonce/profile join')
 verify(result['caller'],selected['case'])
 return result
