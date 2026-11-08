"""Passive normal-case v2 telemetry qualification, after exact original transport.

No Source import, archive read, actor, download, success or cleanup authority.
Historical fault-case v1 parsing remains in the separate unchanged route.
"""
import ast,base64,hashlib,json,math,re
PREFIX=b'UPDATER607_INITIALIZER_TELEMETRY '
PRIMARY=b'UPDATER607_PRIMARY_FAILURE '
PROFILE='I16K_STATX_HASH_SPLIT_V2';MAX=2**63-1
PHASES=('WORKER_OBSERVE','WORKER_CHECKPOINT','WORKER_HELPER_PIN','WORKER_EXEC','PARENT_SOURCE_BEFORE','PARENT_ROOT_BEFORE','PARENT_ROOT_AFTER','PARENT_SOURCE_AFTER')
KEYS={'v','profile','nonce','lane','seq','phase','state','elapsed_ns','remaining_ns','ops','saturated'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate v2 JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite v2 metadata'))
def nonce(v):return type(v)is str and re.fullmatch('[0-9a-f]{32}',v)is not None

def record(v,expected_nonce=None):
 need(type(v)is dict and set(v)==KEYS,'closed v2 record')
 need(type(v['v'])is int and v['v']==2 and v['profile']==PROFILE,'normal source requires v2 only')
 need(nonce(v['nonce'])and(expected_nonce is None or v['nonce']==expected_nonce),'bound inner telemetry nonce')
 need(v['lane']in('WORKER','PARENT')and v['phase']in PHASES and v['phase'].startswith(v['lane']+'_')and v['state']in('STARTED','PROGRESS','RETURNED','REFUSED'),'v2 lane phase state')
 need(type(v['seq'])is int and 0<=v['seq']<(6 if v['lane']=='WORKER'else 8),'bounded v2 sequence')
 need(type(v['elapsed_ns'])is int and 0<=v['elapsed_ns']<=MAX and type(v['saturated'])is bool,'bounded v2 elapsed/saturation')
 need(v['remaining_ns']is None or type(v['remaining_ns'])is int and -MAX<=v['remaining_ns']<=MAX,'signed remaining v2 deadline')
 need(type(v['ops'])is list and len(v['ops'])==10 and all(type(x)is int and 0<=x<=MAX for x in v['ops']),'ten true bounded operation counters')
 need(v['saturated']or v['ops'][8]+v['ops'][9]<=v['ops'][7],'unsaturated split cannot exceed whole hash')
 need(len(PREFIX)+len(encoded(v))+1<=768,'v2 whole canonical frame768')
 return v

def frames(raw,expected_nonce=None):
 need(type(raw)is bytes and len(raw)<=65536,'original bounded telemetry stream')
 out=[]
 for line in raw.splitlines(keepends=True):
  if not line.startswith(PREFIX):
   need(not line.startswith(PREFIX.rstrip())and not(len(line.rstrip())>=16 and PREFIX.startswith(line.rstrip())),'truncated telemetry prefix')
   continue
  need(line.endswith(b'\n')and len(line)<=768,'whole newline-terminated v2 frame768')
  out.append(record(obj(line[len(PREFIX):-1]),expected_nonce));need(len(out)<=128,'held bounded fallback stream')
 return out

def worker_stream(raw,expected_nonce):
 rows=frames(raw,expected_nonce);need(1<=len(rows)<=6,'one complete worker invocation <=6')
 for i,v in enumerate(rows):
  need(v['lane']=='WORKER'and v['seq']==i,'no duplicate or missing worker sequence')
  if i:need(v['elapsed_ns']>=rows[i-1]['elapsed_ns']and all(a>=b for a,b in zip(v['ops'],rows[i-1]['ops'])),'monotonic worker snapshots')
 return rows

def worker_pin(v):
 need(type(v)is dict and set(v)=={'bytes','sha256'}and type(v['bytes'])is int and 0<=v['bytes']<=65536 and type(v['sha256'])is str and re.fullmatch('[0-9a-f]{64}',v['sha256']),'original worker stderr pin')

def summary(v):
 need(type(v)is dict and set(v)=={'v','profile','history','saturated','worker'}and type(v['v'])is int and v['v']==2 and v['profile']==PROFILE and type(v['saturated'])is bool,'closed v2 wrapper')
 need(type(v['history'])is list and len(v['history'])<=8,'parent history8')
 for i,r in enumerate(v['history']):
  record(r);need(r['lane']=='PARENT'and r['seq']==i,'ordered unique parent sequence')
  if i:need(r['elapsed_ns']>=v['history'][i-1]['elapsed_ns']and all(a>=b for a,b in zip(r['ops'],v['history'][i-1]['ops'])),'monotonic parent history')
 worker=v['worker']
 if worker is not None:
  need(type(worker)is dict and set(worker)=={'last','records','stderr','returncode','termination','direct_child_reaped','capture_scope'}and worker['capture_scope']=='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL','closed worker summary scope')
  need(type(worker['records'])is int and 0<=worker['records']<=6 and type(worker['direct_child_reaped'])is bool,'worker count6/reap DATA')
  need(worker['returncode']is None or type(worker['returncode'])is int and -255<=worker['returncode']<=255,'worker returncode DATA')
  need(worker['termination']in(None,'timeout','output-limit','interrupted'),'worker termination DATA');worker_pin(worker['stderr'])
  need((worker['last']is None)==(worker['records']==0),'last versus original count')
  if worker['last']is not None:record(worker['last']);need(worker['last']['lane']=='WORKER'and worker['last']['seq']==worker['records']-1,'exact last worker sequence')
 rows=v['history']+([worker['last']]if worker is not None and worker['last']is not None else[])
 need(len({r['nonce']for r in rows})<=1,'one inner nonce in wrapper')
 need(len(encoded(v))<=8192,'whole v2 wrapper8192')
 return v

def source_contract(profile,read,root):
 p=profile['initializer_hash_cost_v2'];need(p['version']==2 and p['profile']==PROFILE and p['case']=='normal'and p['source_tree']==profile['initializer_v2_source_tree'],'normal-only source v2 contract')
 need(p['actual']is p['runtime_fit']is p['bottleneck']is None and p['performance_gain_claim']is False,'NULL v2 outcomes and no performance claim')
 normal=root/'emissions/cases/normal';raw=read(normal/'upgrade-config.json');config=obj(raw)
 need(pin(raw)==p['config_pin'],'new config body pin')
 adapter_raw=read(normal/'adapter.json');adapter=obj(adapter_raw)
 need(pin(adapter_raw)==p['adapter_pin']and adapter['config_sha256']==pin(raw)['sha256'],'actual adapter/config strict join')
 need(set(p['source_leaf_pins'])=={'scripts/update/full_root.py','scripts/update/aux_copy.py','scripts/update/aux_initialize.py','scripts/ci/full-root-upgrade-caller/upgrade_hook.py'},'complete four-helper normal contract')
 for name,w in p['source_leaf_pins'].items():
  body=read(normal/name);need(pin(body)==w and config['code_pins'][name]==w['sha256'],'all exact normal source body/code pins')
 need(p['frame_cap']==768 and p['wrapper_cap']==8192 and p['worker_frame_cap']==6 and p['history_cap']==8 and p['integer_max']==MAX,'held v2 protocol caps')
 need(p['held_clocks']==dict(worker_observation=150,parent_scale=1200,worker_supervision=180,caller_verify=600,copy=4260,normal_driver=10440,cleanup=300,enclosing=15840),'all source deadlines held')
 need(config['scale']['limits']['seconds']==1200 and config['verify_seconds']==600,'config parent/caller deadlines held')
 # AST data only: do not import or execute the Source producer or caller.
 caller=read(normal/'scripts/ci/full-root-upgrade-caller/upgrade_hook.py')
 nodes=[n for n in ast.parse(caller).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_NORMAL_REASON_LITERALS' for t in n.targets)]
 need(len(nodes)==1,'one pinned caller reason-literal table')
 reasons=ast.literal_eval(nodes[0].value)
 need(type(reasons)is tuple and all(type(x)is str for x in reasons),'literal reason DATA only')
 p=dict(p,reason_pins=[part(x.encode('utf-8','surrogatepass')) for x in reasons])
 return p

def part(raw):
 return dict(bytes=len(raw),sha256=pin(raw)['sha256'],prefix_base64=base64.b64encode(raw[:256]).decode(),prefix_bytes=min(len(raw),256),truncated=len(raw)>256)

def primary_record(v,reasons):
 keys={'schema_version','status','where','error_type','message','message_disposition','path','path_disposition','cleanup_authority','transaction_authority'}
 need(type(v)is dict and set(v)==keys and type(v['schema_version'])is int and v['schema_version']==1 and v['status']=='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE' and v['cleanup_authority']is False and v['transaction_authority']is False,'closed typed primary exception DATA')
 need(v['where']in('NORMAL_ROOT_OBSERVATION','COPIED_ROOT_INITIALIZATION','DRIVER_CATCH','CALLER_SOURCE_WALK','CALLER_SOURCE_HARDLINKS','CALLER_CATCH','INITIALIZER_WORKER'),'source primary site')
 need(type(v['error_type'])is str and re.fullmatch('[A-Za-z0-9_]{1,64}',v['error_type']),'bounded primary error type')
 for key in('message','path'):
  row=v[key]
  if row is None:continue
  need(type(row)is dict and set(row)=={'bytes','sha256','prefix_base64','prefix_bytes','truncated'} and type(row['bytes'])is int and 0<=row['bytes']<=MAX and type(row['prefix_bytes'])is int and row['prefix_bytes']==min(row['bytes'],256) and type(row['truncated'])is bool and row['truncated']==(row['bytes']>256),'bounded primary part')
  need(type(row['prefix_base64'])is str and len(row['prefix_base64'])<=344 and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded primary encoded part')
  raw=base64.b64decode(row['prefix_base64'],validate=True)
  need(len(raw)==row['prefix_bytes'] and base64.b64encode(raw).decode()==row['prefix_base64'] and (row['truncated'] or pin(raw)['sha256']==row['sha256']),'primary prefix pin')
  if key=='message':need(v['error_type']=='ValueError' and row in reasons,'exact source literal message pin')
  else:need(not raw.startswith(b'/') and b'\0' not in raw and all(x not in(b'.',b'..')for x in raw.split(b'/')),'relative primary path only')
 need(v['message_disposition']==('SOURCE_LITERAL_EXACT_OR_PREFIX'if v['message']is not None else'UNREVIEWED_TEXT_OMITTED') and v['path_disposition']==('OBSERVED_RELATIVE_NAME'if v['path']is not None else'UNKNOWN_OR_ABSOLUTE_OMITTED') and len(encoded(v))<=1800,'source primary dispositions/cap')

def complete_capture(v,kind,cap):
 field='preview'if kind=='preview'else'tail';text=v[field+'_base64']
 need(type(text)is str and len(text)<=4*((cap+2)//3),'bounded captured text')
 body=base64.b64decode(text,validate=True)
 need(base64.b64encode(body).decode()==text and v['truncated']is False and type(v['omitted_bytes'])is int and v['omitted_bytes']==0 and type(v['bytes'])is int and type(v[field+'_bytes'])is int and v[field+'_bytes']==len(body)==v['bytes']<=cap and pin(body)=={k:v[k]for k in('bytes','sha256')},'whole hash-joined capture, no truncated v2 qualifier')
 return body

def primary_summary(v,inner,reasons=()):
 need(type(v)is dict and set(v)=={'schema_version','status','nonce','initialization','initializer_worker','caller_verification_or_catch','authority'}and type(v['schema_version'])is int and v['schema_version']==1 and v['status']=='NORMAL_PRIMARY_FAILURES_DATA_NOT_ACCEPTANCE'and v['nonce']==inner and v['authority']=='DIAGNOSTIC_ONLY_NO_TRANSACTION_OR_CLEANUP_AUTHORITY','source typed primary/inner nonce join')
 need(v['initialization']is not None or v['caller_verification_or_catch']is not None,'primary carries an original exception')
 for key in('initialization','caller_verification_or_catch'):
  if v[key]is not None:primary_record(v[key],reasons)
 w=v['initializer_worker'];need(type(w)is dict and set(w)=={'status','returncode','termination','direct_child_reaped','stderr','unframed_stderr','authority'}and w['status']=='ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE'and w['unframed_stderr']=='OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT'and w['authority']=='DIAGNOSTIC_ONLY','source original worker failure summary')
 need(w['returncode']is None or type(w['returncode'])is int and -255<=w['returncode']<=255,'primary worker exit DATA')
 need(w['termination']in(None,'timeout','output-limit','interrupted')and type(w['direct_child_reaped'])is bool,'primary worker retirement DATA');worker_pin(w['stderr'])
 return w

def diagnostic_mirror(raw,summaries=(),reasons=()):
 rows=frames(raw);need(len(rows)==2 and rows[0]==rows[1]and rows[0]['lane']=='WORKER','exact two equal source-proven last-snapshot mirrors only')
 primary=[]
 for line in raw.splitlines(keepends=True):
  if line.startswith(PRIMARY):
   need(line.endswith(b'\n') and len(line)<=4096,'whole primary frame4096');primary.append(obj(line[len(PRIMARY):-1]))
  else:need(not(len(line.rstrip())>=16 and PRIMARY.startswith(line.rstrip())),'truncated primary prefix')
 need(len(primary)==1,'one typed primary frame, no duplicate primary');w=primary_summary(primary[0],rows[0]['nonce'],reasons)
 kinds=[('telemetry'if line.startswith(PREFIX)else'primary')for line in raw.splitlines()if line.startswith((PREFIX,PRIMARY))]
 need(kinds==['telemetry','primary','telemetry'],'source immediate-last / primary / final-last order')
 for s in summaries:
  allrows=s['history']+([s['worker']['last']]if s['worker']is not None and s['worker']['last']is not None else[])
  need(all(r['nonce']==rows[0]['nonce']for r in allrows),'no unrelated or unbound summary mirror')
  worker=s['worker']
  if worker is not None and worker['last']is not None:
   need(worker['last']==rows[0]and worker['stderr']==w['stderr']and all(worker[k]==w[k]for k in('returncode','termination','direct_child_reaped')),'mirror/retained wrapper/primary summary exact join')
 return dict(record=rows[0],mirror_copies=2,counter_records=1,primary_worker=w,complete_worker_stream=False,
             counter_scope='SATURATED_OR_PARTIAL_SNAPSHOT_LOWER_BOUNDS_NOT_WORKLOAD_TOTALS',unattributed_hash_wall_ns=None)

def summaries(data):
 out=[]
 for name,raw in data.items():
  if not name.endswith('.json'):continue
  stack=[(obj(raw),0)];visited=0
  while stack:
   item,depth=stack.pop();visited+=1;need(visited<=1048576 and depth<=64,'held finite approved-JSON telemetry walk')
   if type(item)is dict:
    if 'initializer_telemetry'in item:
     value=summary(item['initializer_telemetry'])
     if value not in out:out.append(value)
    stack.extend((x,depth+1)for x in item.values()if type(x)in(dict,list))
   elif type(item)is list:stack.extend((x,depth+1)for x in item if type(x)in(dict,list))
 rows=[r for s in out for r in s['history']+([s['worker']['last']]if s['worker']is not None and s['worker']['last']is not None else[])]
 need(len({r['nonce']for r in rows})<=1,'one normal initializer invocation')
 # Repeated wrappers are observations of one invocation, not extra work.
 seen={}
 for r in rows:
  key=(r['nonce'],r['lane'],r['seq'])
  need(key not in seen or seen[key]==r,'no conflicting retained snapshot');seen[key]=r
 return out

def captured_tail(v,cap):
 need(type(v)is dict and set(v)=={'bytes','sha256','tail_bytes','tail_base64','omitted_bytes','truncated'},'closed original suffix metadata')
 need(type(v['bytes'])is int and 0<=v['bytes']<=2*1024**2 and type(v['tail_bytes'])is int and type(v['omitted_bytes'])is int and type(v['truncated'])is bool and type(v['sha256'])is str and re.fullmatch('[0-9a-f]{64}',v['sha256']),'typed original suffix metadata')
 need(type(v['tail_base64'])is str and len(v['tail_base64'])<=4*((cap+2)//3),'bounded original suffix text')
 raw=base64.b64decode(v['tail_base64'],validate=True)
 need(base64.b64encode(raw).decode()==v['tail_base64'] and len(raw)==v['tail_bytes']==min(v['bytes'],cap) and v['omitted_bytes']==v['bytes']-len(raw) and v['truncated']==(len(raw)<v['bytes']),'exact original suffix shape')
 if not v['truncated']:need(pin(raw)=={k:v[k]for k in('bytes','sha256')},'complete original suffix pin')
 return raw

def failure_envelope(v,kind,vm):
 required={'schema_version','status','nonce','record','error_type','stdout','stderr','capture_scope','cleanup_acceptance'}
 need(type(v)is dict and set(v)==required|({'worker_capture'}if kind=='CALLER'else set()) and type(v['schema_version'])is int and v['schema_version']==1 and v['status']=='FAILED_ORIGINAL_GUEST_'+kind+'_DATA_NOT_ACCEPTANCE' and v['nonce']==vm and v['capture_scope']=='ORIGINAL_RUN_COMMAND_CAPTURE_MAY_BE_PARTIAL_ON_ERROR' and v['cleanup_acceptance']=='NOT_GRANTED','closed original failure envelope')
 need(v['error_type']is None or type(v['error_type'])is str and re.fullmatch('[A-Za-z0-9_]{1,64}',v['error_type']),'typed bounded envelope error')
 r=v['record'];keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256','emulated16k_deadline'}
 need(type(r)is dict and set(r)==keys and r['argv']==(['/usr/bin/python3','-I','-B','/runner.py']if kind=='CALLER'else['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']),'exact original caller/worker argv')
 need(type(r['exit_code'])is int and type(r['seconds'])in(int,float) and math.isfinite(r['seconds']) and 0<=r['seconds']<2**63 and type(r['group_absence_verified'])is bool and type(r['time_limit'])is int and r['time_limit']>0 and type(r['emulated16k_deadline'])is dict and r['time_limit']==r['emulated16k_deadline']['effective_seconds'] and type(r['output_limit'])is int and r['output_limit']==2*1024**2,'typed original command budgets/retirement DATA')
 w=r['emulated16k_deadline'];nominal=12480 if kind=='CALLER'else 15000
 need(set(w)=={'nominal_seconds','parent_total_seconds','parent_elapsed_ns','reserve_seconds','effective_seconds'} and all(type(x)is int for x in w.values()) and w['nominal_seconds']==nominal and w['parent_total_seconds']==15840 and 0<=w['parent_elapsed_ns']<15840*10**9 and w['reserve_seconds']==900,'exact Source caller/worker deadline witness')
 expected=min(nominal,(15840*10**9-w['parent_elapsed_ns']-900*10**9)//10**9)
 need(expected>5 and w['effective_seconds']==r['time_limit']==expected,'exact Source effective deadline equality')
 need(v['error_type']is not None or r['exit_code']!=0 or r['group_absence_verified']is not True,'failure-only envelope')
 streams={}
 for side,cap in(('stdout',4096),('stderr',8192)):
  streams[side]=captured_tail(v[side],cap)
  need(type(r[side+'_bytes'])is int and r[side+'_bytes']==v[side]['bytes'] and r[side+'_sha256']==v[side]['sha256'],'original command/capture stream join')
 need(r['stdout_bytes']+r['stderr_bytes']<=2*1024**2,'combined original capture bound')
 return streams

def forwarded_caller(caller,worker,worker_stdout,vm):
 c=caller['worker_capture']
 need(type(c)is dict and set(c)=={'bytes','sha256','frame_offset','frame_bytes','frame_sha256','scope'} and c['scope']=='SOURCE_CAPTURED_WORKER_STDOUT_FRAME_NOT_FULL_STREAM_EXPORT','closed Source forwarding custody')
 original=dict(caller);original.pop('worker_capture')
 line=b'APPS6_UPDATE16K_CALLER_FAILURE '+vm.encode()+b' '+encoded(original)
 need(len(line)<=25*1024 and all(type(c[k])is int for k in('bytes','frame_offset','frame_bytes')) and 0<=c['frame_offset'] and c['frame_bytes']==len(line) and c['frame_sha256']==pin(line)['sha256'] and c['frame_offset']+len(line)<=c['bytes'] and c['bytes']==worker['record']['stdout_bytes'] and c['sha256']==worker['record']['stdout_sha256'],'exact original forwarded line/full-worker-stream custody')
 # A bounded suffix need not export the whole worker stdout. Compare every
 # available overlap with the exact reconstructed Source-captured frame.
 start=worker['stdout']['omitted_bytes'];lo=max(start,c['frame_offset']);hi=min(c['bytes'],c['frame_offset']+len(line))
 if lo<hi:need(worker_stdout[lo-start:hi-start]==line[lo-c['frame_offset']:hi-c['frame_offset']],'forwarded caller/suffix overlap')
 if not worker['stdout']['truncated']:
  need(worker_stdout[c['frame_offset']:c['frame_offset']+len(line)]==line,'exact forwarded line offset')
  need(sum(x.startswith(b'APPS6_UPDATE16K_CALLER_FAILURE ')for x in worker_stdout.splitlines())==1,'one captured caller frame')
 return dict(caller_envelope='COMPLETE_RETAINED_FORWARDED_ENVELOPE',available_worker_suffix_bytes=len(worker_stdout),forwarded_line_available_overlap_bytes=max(0,hi-lo),full_worker_stream='OBSERVED_COMPLETE'if not worker['stdout']['truncated']else'SOURCE_ENFORCED_RECORDED_NOT_INDEPENDENTLY_OBSERVED_COMPLETE',frame_origin='SOURCE_FORWARDING_HASH_RECONSTRUCTION_WITH_AVAILABLE_SUFFIX_OVERLAP')

def qualify(data,bound,profile,read,root,proof):
 need(bound['case']=='normal' and type(bound['source'])is str and re.fullmatch('[0-9a-f]{40}',bound['source']) and type(bound['ref'])is str and re.fullmatch('codex/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}',bound['ref']) and '..'not in bound['ref'] and not bound['ref'].endswith('/') and type(bound['run'])is int and bound['run']>0 and type(bound['attempt'])is int and bound['attempt']==1,'genuine bound normal v2 case only')
 contract=source_contract(profile,read,root)
 retention=obj(data['retention.json']);proof(retention['wrapper'],bound)
 retained=summaries(data)
 base=dict(source=bound['source'],ref=bound['ref'],run=bound['run'],attempt=1,source_tree=contract['source_tree'],summaries=len(retained),acceptance=False,unattributed_hash_wall_ns=None)
 cleanup=obj(data['public/updater16k-cleanup.json'])if'public/updater16k-cleanup.json'in data else{}
 q=cleanup.get('qemu_failure')
 if not isinstance(q,dict)or'preview_base64'not in q.get('stdout',{}):
  return dict(base,status='BOUND_V2_SUMMARY_ONLY_DATA'if retained else'BOUND_V2_DATA_TELEMETRY_NOT_OBSERVED',counter_records=0,counter_scope='RETAINED_WRAPPERS_NOT_AGGREGATED')
 qraw=complete_capture(q['stdout'],'preview',65536);vm=q['nonce'];need(nonce(vm),'separate VM nonce')
 receipts=[r for r in cleanup['group_records']if r.get('argv',[None])[0]=='/usr/bin/qemu-system-aarch64'and r.get('stdout_bytes')==len(qraw)and r.get('stdout_sha256')==pin(qraw)['sha256']]
 need(len(receipts)==1 and type(receipts[0]['exit_code'])is int and receipts[0]['exit_code']==0 and receipts[0]['group_absence_verified']is True,'unique original QEMU argv/stdout/reap receipt')
 tags=('APPS6_UPDATE16K','APPS6_UPDATE16K_CALLER_FAILURE','APPS6_UPDATE16K_WORKER_FAILURE');envelopes={}
 for line in qraw.splitlines(keepends=True):
  for tag in tags:
   marker=tag.encode()+b' '
   if line.startswith(marker):
    need(line.endswith(b'\n'),'whole VM envelope');parts=line[:-1].split(b' ',2)
    need(len(parts)==3 and parts[1]==vm.encode() and tag not in envelopes,'unique exact VM-nonce envelope');envelopes[tag]=obj(parts[2])
   elif line.rstrip() and marker.startswith(line.rstrip()):need(False,'truncated VM envelope prefix')
 if not any(k in envelopes for k in tags[1:]):
  return dict(base,status='BOUND_V2_SUMMARY_ONLY_DATA'if retained else'BOUND_V2_DATA_TELEMETRY_NOT_OBSERVED',counter_records=0,counter_scope='RETAINED_WRAPPERS_NOT_AGGREGATED')
 need(set(envelopes)==set(tags),'all three original VM failure envelopes')
 boot=envelopes[tags[0]];caller=envelopes[tags[1]];worker=envelopes[tags[2]]
 actual=dict(source=bound['source'],run=str(bound['run']),attempt='1',ref='refs/heads/'+bound['ref'],page_profile='generic16k')
 need(boot['current607']==actual and type(boot['page_size'])is int and boot['page_size']==16384 and obj(data['native4k-wrapper.json'])['wrapper']['current607']==actual,'source/ref/run/attempt/boot/wrapper joins')
 cs=failure_envelope(caller,'CALLER',vm);ws=failure_envelope(worker,'WORKER',vm)
 forwarding=forwarded_caller(caller,worker,ws['stdout'],vm)
 need(not caller['stderr']['truncated'],'whole caller telemetry stream required')
 need(not frames(cs['stdout']),'initializer telemetry fd2 only')
 # Worker stdout contains the encoded caller failure object, not raw telemetry.
 # Raw telemetry on worker stderr would have a second, unbound producer route.
 need(not frames(ws['stderr']),'no unbound worker stderr telemetry')
 result=diagnostic_mirror(cs['stderr'],retained,contract['reason_pins'])
 return dict(base,status='QUALIFIED_SOURCE_BOUND_NORMAL_V2_DIAGNOSTIC_DATA_ONLY',VM_nonce=vm,initializer_nonce=result['record']['nonce'],nonces='DISTINCT_SCOPES_JOINED_NOT_ASSUMED_EQUAL',forwarding_custody=forwarding,telemetry=result,performance_claim=False)
