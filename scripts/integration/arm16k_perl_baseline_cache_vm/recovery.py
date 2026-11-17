#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fixed baseline public-cache request/plan; no image or process entry."""
import hashlib,importlib.util,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('baseline_public_stat',HERE/'stat_decoder.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S)
IMAGE='sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
RAW_BYTES=1610612736
BACKING=dict(bytes=RAW_BYTES,sha256='49da69b9262e089e08aa84063ed14ca13e66189f9c1e396616ab5f5cb5e24b81')
BACKING_PATH='/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-perl-initialized-FIRST-trial-r3/prepare-output/guest.raw'
CACHE=dict(bytes=17551,sha256='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215')
SOURCE=dict(bytes=60210,sha256='7beb4deb63cbd03b34738b41463380b388e67c2a8015b81f7124866e80b17b13')
TOOLS={'/usr/bin/debugfs':dict(bytes=202328,sha256='9b27184084383c8607eee03b43c80eca4ef912acf4887b40a7cc420e267ad8a8')}
RESOURCES=dict(memory_bytes=536870912,cpus=1,pids=64,swap_bytes=0,whole_seconds=180,stat_seconds=10,dump_seconds=10,initial_free_bytes=10737418240,live_reserve_bytes=2147483648,cache_cap_bytes=1048576,stream_cap_bytes=16384,metadata_output_cap_bytes=4194304)
LABELS=('cache-before','etc-before','cache-body','cache-after','etc-after')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def declared(value):
 need(type(value)is dict and set(value)=={'kind','issued_by','accepted','Source_lock','image','backing','tools','resources','expected_cache','output','actual'},'closed single-input baseline public-cache schema')
 need(value['kind']=='ROOT_READONLY_BASELINE_PUBLIC_LDCACHE_BODY_V1'and value['Source_lock']==SOURCE and value['image']==IMAGE and value['tools']==TOOLS and value['resources']==RESOURCES and value['expected_cache']==CACHE,'exact baseline Source/image/debugfs/resource/cache expectations')
 need(value['backing']==dict(path=BACKING_PATH,pin=BACKING),'one exact known prepared backing; no overlay/alias selection')
 need(type(value['actual'])is dict and set(value['actual'])=={'Root_observation','actor','runtime','nonce','profile','authority','VM','lifecycle','M2','release'}and all(v is None for v in value['actual'].values()),'all actual Root observations/grants remain NULL')
 return value
def require_issued(value):
 declared(value);need(value['issued_by']=='Root'and value['accepted']is True,'Root must separately issue baseline observation; no default actor')
 out=value['output'];need(type(out)is str and Path(out).is_absolute()and '..'not in Path(out).parts and not any(ord(c)<32 for c in out),'fresh literal Root-selected output')
 return value
def fixed_plan():
 commands=('stat /etc/ld.so.cache','stat /etc','dump /etc/ld.so.cache /output/cache.bin','stat /etc/ld.so.cache','stat /etc')
 return [dict(label=label,argv=['/usr/bin/debugfs','-R',command,'/prepared/guest.raw'],seconds=10)for label,command in zip(LABELS,commands)]
def plan(value):
 require_issued(value);return fixed_plan()
def artifact_names():return {label+suffix for label in LABELS for suffix in('.log','.retirement.json')}|{'cache.bin'}
def metadata(frames,baseline):
 need(type(frames)is dict and set(frames)=={'cache-before','cache-after','etc-before','etc-after'},'exact four fixed public stat frames')
 cache=S.parse_stat(frames['cache-before'],'etc/ld.so.cache');etc=S.parse_stat(frames['etc-before'],'etc')
 need(cache==S.parse_stat(frames['cache-after'],'etc/ld.so.cache')and etc==S.parse_stat(frames['etc-after'],'etc'),'unchanged metadata across baseline dump')
 need(cache is not None and cache['type']=='file'and cache['mode']==0o644 and cache['uid']==cache['gid']==0 and cache['links']==1 and cache['size']==CACHE['bytes'],'ordinary baseline root0644 single-link cache')
 need(etc is not None and etc['type']=='directory'and etc['mode']==0o755 and etc['uid']==etc['gid']==0,'ordinary literal public parent')
 for path,row in (('etc',etc),('etc/ld.so.cache',cache)):
  expected={k:v for k,v in baseline['nodes'][path].items()if k not in('xattrs','sha256')}
  need({k:row[k]for k in expected}==expected,'same fixed prepared baseline public inode/metadata')
 return {'etc':etc,'etc/ld.so.cache':cache}
def decode_outputs(frames,body,baseline):
 need(type(body)is bytes and pin(body)==CACHE,'exact known17551-byte baseline cache body SHA256')
 return dict(status='OBSERVED_EXACT_BASELINE_PUBLIC_CACHE_BODY_ONLY',nodes=metadata(frames,baseline),cache=CACHE,xattrs='NOT_OBSERVED',cache_semantics='NOT_DECODED',provider_transition='NOT_EVALUATED',Root_acceptance=None,VM_acceptance=None,lifecycle_acceptance=None)
