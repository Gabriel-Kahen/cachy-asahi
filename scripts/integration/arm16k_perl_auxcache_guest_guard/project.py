# SPDX-License-Identifier: MIT
"""UNSELECTED operational component only, not a constructed or accepted Source.

Constructor must reseal a NEW Source and preserve canonical-lock row delta.
This component preserves the entire original map/body namespace by inversion.
"""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
PREFIX='_auxcache_guest/'
LOCK=dict(bytes=69669,sha256='7c539e20651c31cb7fdb3e781889d0ad92ee8bd41109122a0555bdd4ee0c2674')
ROOT=dict(bytes=23964,sha256='0a229d3b64d389e7ecd3650d583ad1c6aab8b86380a794ed3e68d6f27f0cb49b')
ADAPTER=dict(bytes=14609,sha256='caf709f3dca4942b695cd61b859943de09c3afe1bfbfe60dab62b6d960cc8651')
OLD=b'   if [[ -f $path && ! -L $path ]];then sha256sum -- "$path";fi\n'
NEW=b'''   if [[ -f $path && ! -L $path ]];then
    if [[ $path == /var/cache/ldconfig/aux-cache ]];then
     aux_sum=$(/usr/bin/bash "$D/auxcache/canonicalize.sh" < "$path" | /usr/bin/sha256sum)
     [[ $aux_sum =~ ^[0-9a-f]{64}[[:space:]][[:space:]]-$ ]]
     printf 'AUX_DEFINED_FIELDS_V1 %s %s\\n' "${aux_sum%% *}" "$path"
    else sha256sum -- "$path";fi
   fi
'''
SEAM=b" put('hold_state_observations.py',(HERE/'hold_state_observations.py').read_bytes())\n"
DELIVERY=b" for name in('canonicalize.sh','canonicalize.awk'):put('auxcache/'+name,(HERE/'_auxcache_guest'/name).read_bytes())\n"
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def replace(b,old,new):need(b.count(old)==1,'one exact transformation seam');return b.replace(old,new,1)
def runtime():return {PREFIX+n:(HERE/n).read_bytes()for n in('canonicalize.sh','canonicalize.awk')}
def original(bodies):
 need(type(bodies)is dict and len(bodies)==389 and sum(map(len,bodies.values()))==4134606,'whole original389 census')
 need(pin(bodies['source.lock.json'])==LOCK,'whole original389 lock')
 lock=json.loads(bodies['source.lock.json']);need(set(bodies)==set(lock['files'])|{'source.lock.json'},'complete original389 membership')
 for n,row in lock['files'].items():need(pin(bodies[n])=={k:row[k]for k in('bytes','sha256')},'whole original leaf (mode retained by exact pinned lock) '+n)
 need(pin(bodies['guest/root.sh'])==ROOT and pin(bodies['adapter.py'])==ADAPTER,'exact operational original389 leaves')
def project(bodies):
 original(bodies);out=dict(bodies);out['guest/root.sh']=replace(out['guest/root.sh'],OLD,NEW);out['adapter.py']=replace(out['adapter.py'],SEAM,SEAM+DELIVERY)
 for n,b in runtime().items():need(n not in out,'fixed additions absent');out[n]=b
 need(sum(map(len,out.values()))<4194304,'unchanged 4MiB physical cap before provenance/reseal')
 return out

def inverse(out):
 out=dict(out)
 for n,b in runtime().items():need(out.pop(n,None)==b,'exact fixed runtime addition')
 out['guest/root.sh']=replace(out['guest/root.sh'],NEW,OLD);out['adapter.py']=replace(out['adapter.py'],SEAM+DELIVERY,SEAM);original(out);return out
