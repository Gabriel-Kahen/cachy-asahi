#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure two-path recovery request, literal argv plan and public DATA decoder."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ldcache_fixed_stat_decoder',HERE/'stat_decoder.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)
IMAGE='sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
RAW_BYTES=1610612736
BACKING=dict(bytes=RAW_BYTES,sha256='49da69b9262e089e08aa84063ed14ca13e66189f9c1e396616ab5f5cb5e24b81')
SOURCE=dict(bytes=60210,sha256='7beb4deb63cbd03b34738b41463380b388e67c2a8015b81f7124866e80b17b13')
TOOLS={'/usr/bin/qemu-img':dict(bytes=2567104,sha256='2139b2c8d5a9f28dbef2c5cdb663ce842648105fa76720ec691f8f5cddc8b002'),'/usr/bin/debugfs':dict(bytes=202328,sha256='9b27184084383c8607eee03b43c80eca4ef912acf4887b40a7cc420e267ad8a8')}
RESOURCES=dict(memory_bytes=536870912,cpus=1,pids=64,swap_bytes=0,whole_seconds=180,convert_seconds=60,info_seconds=10,stat_seconds=10,dump_seconds=10,initial_free_bytes=2147483648,live_reserve_bytes=536870912,raw_logical_cap_bytes=RAW_BYTES,raw_allocated_cap_bytes=RAW_BYTES,cache_cap_bytes=1048576,stream_cap_bytes=16384,metadata_output_cap_bytes=131072)

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def valid_pin(value):return type(value)is dict and set(value)=={'bytes','sha256'}and type(value['bytes'])is int and value['bytes']>0 and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256'])is not None

def declared(value):
 need(type(value)is dict and set(value)=={'kind','issued_by','accepted','Source_lock','image','overlay','backing','tools','resources','output','actual'},'closed two-path recovery schema')
 need(value['kind']=='ROOT_READONLY_R86_PUBLIC_LDCACHE_RECOVERY_V1'and value['Source_lock']==SOURCE and value['image']==IMAGE and value['tools']==TOOLS and value['resources']==RESOURCES,'fixed Source339/image529/tool/resource expectations')
 need(type(value['overlay'])is dict and set(value['overlay'])=={'path','pin','logical_cap_bytes','allocated_cap_bytes'}and value['overlay']['logical_cap_bytes']==4294967296 and value['overlay']['allocated_cap_bytes']==268435456,'bounded selected closed overlay')
 need(type(value['backing'])is dict and set(value['backing'])=={'path','pin'}and value['backing']['pin']==BACKING,'exact known backing raw tuple')
 need(type(value['actual'])is dict and all(v is None for v in value['actual'].values()),'no fabricated observation or acceptance')
 return value

def require_issued(value):
 declared(value)
 need(value['issued_by']=='Root'and value['accepted']is True,'Root must separately issue exact recovery; no default actor')
 need(valid_pin(value['overlay']['pin'])and value['overlay']['pin']['bytes']<=value['overlay']['logical_cap_bytes'],'Root whole closed-overlay pin')
 for item in (value['overlay']['path'],value['backing']['path'],value['output']):
  need(type(item)is str and item.startswith('/')and '..'not in Path(item).parts and not any(ord(c)<32 for c in item),'literal selected Root input/output paths')
 return value

def plan(value):
 require_issued(value)
 # Root owns all execution, read-only mounts, guards, natural retirement and cleanup.
 return [dict(label='chain',argv=['/usr/bin/qemu-img','info','--output=json','--backing-chain','-f','qcow2','/inputs/overlay.qcow2'],seconds=10),
         dict(label='convert',argv=['/usr/bin/qemu-img','convert','-f','qcow2','-O','raw','-S','4k','/inputs/overlay.qcow2','/output/observation.raw'],seconds=60),
         *[dict(label=label,argv=['/usr/bin/debugfs','-R',command,'/output/observation.raw'],seconds=10)
           for label,command in [('cache-before','stat /etc/ld.so.cache'),('etc-before','stat /etc'),('cache-body','dump /etc/ld.so.cache /output/cache.bin'),('cache-after','stat /etc/ld.so.cache'),('etc-after','stat /etc')]]]

def chain(raw):
 need(type(raw)is bytes and 0<len(raw)<=16384,'bounded qemu-img chain frame')
 def unique(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate chain JSON key');result[k]=v
  return result
 rows=json.loads(raw,object_pairs_hook=unique)
 need(type(rows)is list and len(rows)==2 and all(type(row)is dict for row in rows),'exact two-node chain only')
 for row,name,kind in zip(rows,('/inputs/overlay.qcow2','/prepared/guest.raw'),('qcow2','raw')):
  need(row.get('filename')==name and row.get('format')==kind and row.get('virtual-size')==RAW_BYTES,'fixed chain paths/formats/virtual size')
  need(not row.get('encrypted')and not row.get('dirty-flag')and not row.get('children')and not row.get('data-file'),'no encrypted/dirty/external graph')
 first=rows[0]
 need(first.get('backing-filename')==first.get('full-backing-filename')=='/prepared/guest.raw'and first.get('backing-filename-format')=='raw','original embedded absolute backing path, no rewrite/rebase')
 need(not any(k in rows[1]for k in('backing-filename','full-backing-filename')),'raw backing is terminal')
 data=first.get('format-specific',{}).get('data',{})
 need(type(data)is dict and not data.get('data-file')and not data.get('corrupt'),'no external data or corrupt qcow2 declaration')
 return dict(status='EXACT_TWO_NODE_CHAIN_METADATA_ONLY',frame=pin(raw))

def decode_outputs(frames,cache_body,baseline):
 need(type(frames)is dict and set(frames)=={'cache-before','cache-after','etc-before','etc-after'},'exact four stat frames only')
 need(type(cache_body)is bytes and 0<len(cache_body)<=1048576,'bounded fixed public cache dump')
 cache=S.parse_stat(frames['cache-before'],'etc/ld.so.cache');etc=S.parse_stat(frames['etc-before'],'etc')
 need(cache==S.parse_stat(frames['cache-after'],'etc/ld.so.cache')and etc==S.parse_stat(frames['etc-after'],'etc'),'repeat public metadata stable across dump')
 need(cache is not None and cache['type']=='file'and cache['mode']==0o644 and cache['uid']==cache['gid']==0 and cache['links']==1 and cache['size']==len(cache_body),'ordinary root0644 single-link cache size/body correspondence')
 need(etc is not None and etc['type']=='directory'and etc['mode']==0o755 and etc['uid']==etc['gid']==0,'literal public parent metadata')
 nodes={'etc':etc,'etc/ld.so.cache':dict(cache,sha256=pin(cache_body)['sha256'])};differences={}
 for path,row in nodes.items():
  original=baseline['nodes'][path]
  differences[path]=[name for name in ('type','inode','links','mode','uid','gid','size','mtime','mtime_ns','sha256')if name in original and row.get(name)!=original[name]]
 return dict(status='OBSERVED_TWO_PUBLIC_PATHS_ONLY_NOT_TRANSITION_ACCEPTANCE',nodes=nodes,cache=pin(cache_body),cache_header='GLIBC_NEW_1_1'if cache_body.startswith(b'glibc-ld.so.cache1.1')else'UNDECODED_NOT_VALIDATED',baseline_changed_fields=differences,xattrs='NOT_OBSERVED_BY_STAT_OR_BODY_DUMP',provider_correspondence='PENDING_ROOT_COMPARISON_WITH_FROZEN_NAMESPACE',Root_acceptance=None,VM_acceptance=None,lifecycle_acceptance=None)
