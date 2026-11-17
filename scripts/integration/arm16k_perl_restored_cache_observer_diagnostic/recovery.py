# SPDX-License-Identifier: MIT
"""Closed three-public-path comparison plan; no actor, repair or acceptance."""
import hashlib,importlib.util,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
def module(name):
 s=importlib.util.spec_from_file_location('restored_cache_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
S=module('stat_decoder');G=module('graph_predecessor')
PATHS=('etc/ld.so.cache','var/cache/ldconfig','var/cache/ldconfig/aux-cache')
FILES=(PATHS[0],PATHS[2]);KEYS=('main','directory','aux')
IMAGE=G.IMAGE;RAW_BYTES=G.RAW_BYTES;TOOLS=G.TOOLS
SOURCE=dict(bytes=69318,sha256='06d227647cbbf5d357bcccccc77dde07344bea033880a87b5405e9679810b443')
B='/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114'
BASELINE=dict(path=B+'/Root-perl-initialized-FIRST-trial-r3/prepare-output/guest.raw',pin=G.BACKING)
OVERLAY=B+'/Root-perl-initialized-FIRST-trial-r4/boot-output/overlay.qcow2'
BACKING=B+'/Root-perl-initialized-FIRST-trial-r4/prepare-output/guest.raw'
OVERLAY_PIN=dict(bytes=128122880,sha256='02a36e9b3ccecccb42b2c2275606351bb7b29b9c1148f38b9f8c962f99830c61')
BACKING_PIN=dict(bytes=1610612736,sha256='d076fdddccba9c65daf5cc795a9472058d8978f9a76d15b8bf8a06285124986e')
RESOURCES=dict(memory_bytes=536870912,cpus=1,pids=64,swap_bytes=0,whole_seconds=180,convert_seconds=60,info_seconds=10,stat_seconds=10,dump_seconds=10,initial_free_bytes=10737418240,live_reserve_bytes=2147483648,raw_logical_cap_bytes=RAW_BYTES,raw_allocated_cap_bytes=RAW_BYTES,cache_cap_bytes=1048576,stream_cap_bytes=16384,metadata_output_cap_bytes=4194304)
ACTUAL=('Root_observation','actor','runtime','nonce','profile','authority','VM','lifecycle','M2','release')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def declared(v):
 need(type(v)is dict and set(v)=={'kind','issued_by','accepted','Source_lock','image','overlay','backing','baseline','tools','resources','output','actual'},'closed restored-cache comparison request')
 need(v['kind']=='ROOT_READONLY_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_V2'and v['Source_lock']==SOURCE and v['image']==IMAGE and v['tools']==TOOLS and v['resources']==RESOURCES,'exact Source387/image529/tool/resources')
 need(v['baseline']==BASELINE,'exact known immutable baseline49da')
 need(type(v['overlay'])is dict and set(v['overlay'])=={'path','pin','logical_cap_bytes','allocated_cap_bytes'}and v['overlay']['path']==OVERLAY and v['overlay']['pin']==OVERLAY_PIN and v['overlay']['logical_cap_bytes']==4294967296 and v['overlay']['allocated_cap_bytes']==268435456,'one exact retained r94 overlay path and caps')
 need(type(v['backing'])is dict and set(v['backing'])=={'path','pin'}and v['backing']['path']==BACKING and v['backing']['pin']==BACKING_PIN,'one exact r94 prepared backing path')
 need(v['actual']==dict.fromkeys(ACTUAL),'actual Root facts remain NULL')
 return v
def require_issued(v):
 declared(v);need(v['issued_by']=='Root'and v['accepted']is True,'fresh explicit Root comparison grant required')
 need(G.valid_pin(v['overlay']['pin'])and v['overlay']['pin']['bytes']<=4294967296 and G.valid_pin(v['backing']['pin'])and v['backing']['pin']['bytes']==RAW_BYTES,'Root must whole-pin retained closed r94 overlay and backing')
 need(type(v['output'])is str and v['output'].startswith('/')and str(Path(v['output']))==v['output']and '..'not in Path(v['output']).parts and not any(ord(c)<32 or c==','for c in v['output']),'fresh literal Root-selected output')
 return v
def fixed_plan():
 rows=[dict(label='chain',argv=['/usr/bin/qemu-img','info','--output=json','--backing-chain','-f','qcow2','/inputs/overlay.qcow2'],seconds=10),dict(label='convert',argv=['/usr/bin/qemu-img','convert','-f','qcow2','-O','raw','-S','4k','/inputs/overlay.qcow2','/output/observation.raw'],seconds=60)]
 for view,image in(('baseline','/baseline/guest.raw'),('restored','/output/observation.raw')):
  for stage in('before','after'):
   rows += [dict(label=f'{view}-{key}-{stage}',argv=['/usr/bin/debugfs','-R','stat /'+path,image],seconds=10,view=view,path=path,stage=stage)for key,path in zip(KEYS,PATHS)]
   if stage=='before':rows += [dict(label=f'{view}-{key}-body',argv=['/usr/bin/debugfs','-R',f'dump /{path} /output/{view}-{key}.bin',image],seconds=10,view=view,path=path,stage='body')for key,path in(('main',FILES[0]),('aux',FILES[1]))]
 return rows
def plan(v):require_issued(v);return fixed_plan()
def labels():return tuple(r['label']for r in fixed_plan())
def artifacts():return {label+suffix for label in labels()for suffix in('.log','.retirement.json')}|{f'{v}-{k}.bin'for v in('baseline','restored')for k in('main','aux')}
def artifact_names(views):
 return {'commands.DATA.json','diagnostic.DATA.json'}|{f'{view}-{key}.bin'for view in('baseline','restored')for key,path in(('main',FILES[0]),('aux',FILES[1]))if views[view][path]is not None}
def validate_summary(v,request,source):
 need(type(v)is dict and len((json.dumps(v,sort_keys=True,indent=2)+'\n').encode())<=16384,'bounded canonical comparison summary')
 need(v.get('kind')=='OBSERVED_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_V2'and v.get('status')=='PUBLIC_CACHE_FACTS_ONLY_CAUSE_UNPROVEN'and v.get('Source_lock')==source==SOURCE and v.get('request')==request,'exact public comparison/Source/Root request identity')
 need(v.get('tools_reverified')is True and v.get('all_tools_naturally_reaped')is True and v.get('temporary_raw_removed')is True and v.get('planned_commands')==18,'actual tools/natural closure/no retained raw')
 need(all(v.get(k)is None for k in('Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')),'no later acceptance')
 comparison=v.get('cache_observation');need(type(comparison)is dict and comparison.get('restoration_cause')=='UNPROVEN'and comparison.get('cache_semantics')=='NOT_DECODED'and all(comparison.get(k)is None for k in('Root_acceptance','VM_acceptance','lifecycle_acceptance')),'facts only; no cause or semantic claim')
 views=comparison.get('views');need(type(views)is dict and set(views)=={'baseline','restored'},'exact two views')
 present=0
 for view,nodes in views.items():
  need(type(nodes)is dict and set(nodes)==set(PATHS),'only three literal public nodes')
  for path,row in nodes.items():
   if row is None:continue
   fields=set(S.FIELDS)|{'ctime','ctime_ns','crtime','crtime_ns','xattrs'}|({'sha256'}if path in FILES else set())
   need(type(row)is dict and set(row)==fields and row['type']==('directory'if path==PATHS[1]else'file'),'closed typed public node')
   for name in S.FIELDS:
    if name!='type':S.number(row[name],name)
   if path in FILES:present+=1;need(row['links']==1 and row['size']<=1048576 and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded single-link public body')
   for name in('ctime','ctime_ns','crtime','crtime_ns'):need(row[name]is None or type(row[name])is int and (0<=row[name]<=999999999 if name.endswith('_ns')else-2**31<=row[name]<2**34),'bounded independent inode time')
   a=row['xattrs'];need(type(a)is dict and set(a)=={'count','entries'}and type(a['count'])is int and 0<=a['count']<=64 and type(a['entries'])is list and len(a['entries'])==a['count'],'closed hashed xattr facts')
   for item in a['entries']:need(type(item)is dict and set(item)=={'name_sha256','value_bytes','value_sha256'}and type(item['value_bytes'])is int and 0<=item['value_bytes']<=4096 and all(type(item[n])is str and re.fullmatch('[0-9a-f]{64}',item[n])for n in('name_sha256','value_sha256')),'only bounded xattr hashes, no names/values')
 need(v.get('commands')==14+present,'actual command count accounts for skipped absent bodies')
 files=v.get('files');need(type(files)is dict and set(files)==artifact_names(views),'exact public cache/stat/retirement artifact membership; no raw')
 for name,row in files.items():
  need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=(1048576 if name.endswith('.bin')else 65536 if name=='commands.DATA.json'else 16384)and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded whole public artifact pin')
 for view in('baseline','restored'):
  for key,path in(('main',FILES[0]),('aux',FILES[1])):
   row=views[view][path]
   if row is not None:need(files[f'{view}-{key}.bin']==dict(bytes=row['size'],sha256=row['sha256']),'exact public body pin joins typed inode')
 need(sum(row['bytes']for row in files.values())+16384<=4194304,'whole four-MiB output cap including summary')
 return {k:v[k]for k in('kind','status','request','Source_lock','cache_observation','tools_reverified','commands','planned_commands','all_tools_naturally_reaped','temporary_raw_removed','Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')}
def compare(views,baseline):
 need(set(views)=={'baseline','restored'},'exact two public views')
 # r91 actually extracted this body from the same whole-pinned49da input.
 main=views['baseline'][PATHS[0]];need(main is not None and main['size']==17551 and main['sha256']=='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215','same actual r91 immutable-baseline main cache body')
 # r76 aux metadata/hash are comparison candidates, not a new recovery gate.
 reference={}
 for path in PATHS:
  expected=dict(baseline['nodes'][path]);need(expected['xattrs']=={},'reviewed reference has empty xattrs');expected['xattrs']=dict(count=0,entries=[]);observed=views['baseline'][path]or{}
  reference[path]=sorted(k for k,v in expected.items()if observed.get(k)!=v)
 changed={path:sorted(k for k in set(views['baseline'][path]or{})|set(views['restored'][path]or{})if(views['baseline'][path]or{}).get(k)!=(views['restored'][path]or{}).get(k))for path in PATHS}
 return dict(status='OBSERVED_THREE_PUBLIC_CACHES_ONLY_CAUSE_UNPROVEN',views=views,changed_fields=changed,baseline_r76_reference_changed_fields=reference,cache_semantics='NOT_DECODED',restoration_cause='UNPROVEN',Root_acceptance=None,lifecycle_acceptance=None,VM_acceptance=None)
