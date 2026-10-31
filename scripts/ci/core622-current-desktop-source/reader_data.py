# SPDX-License-Identifier: MIT
"""Concrete maintained Core622 metadata/DATA readers; no acquisition or acceptance.

Callers authenticate the complete Source/public export before using these helpers.
The separate prerequisite checkpoint never substitutes for the original Core ZIP.
"""
import hashlib,io,json,math,os,re,stat,types,zipfile
from pathlib import Path
M=1024**2
BASELINE_SOURCE='ad09020a776c93fad3c2625c836a99cbde0c83b9'
CHECKPOINT_CONTRACT_PIN={'bytes': 6760, 'sha256': '5c41f228b371ff7abdcd9d3c84d820f4732386bf8ad3f404dd91b7c57fbfe271'}
CHECKPOINT_ROLE='core622-maintained-prerequisite-metadata'
CORE_ROLE='core7-real-systemd'
CHECKPOINT_ZIP_CAP=16*M
REPO='Gabriel-Kahen/cachy-asahi'


def need(value,message):
 if not value:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(items):
  out={}
  for key,value in items:need(key not in out,'unique DATA keys');out[key]=value
  return out
 def number(text):
  value=float(text);need(math.isfinite(value),'finite DATA number');return value
 return json.loads(raw,object_pairs_hook=pairs,parse_float=number,parse_constant=lambda _:need(False,'finite DATA number'))
def integer(value,low=0,high=2**63-1):return type(value)is int and low<=value<=high

def checkpoint_contract():
 """Load only this adjacent maintained pure contract, before executing its bytes."""
 path=Path(__file__).resolve().with_name('checkpoint_contract.py');need(not path.is_symlink()and all(not p.is_symlink()for p in path.parents),'ordinary adjacent pure checkpoint contract');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);key=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=65536,'bounded singlelink pure contract');raw=bytearray()
  while len(raw)<=before.st_size:
   body=os.read(fd,min(65536,before.st_size+1-len(raw)))
   if not body:break
   raw.extend(body)
  need(len(raw)==before.st_size and key(before)==key(os.fstat(fd))==key(path.lstat())and pin(raw)==CHECKPOINT_CONTRACT_PIN,'whole stable explicitly pinned adjacent contract')
 finally:os.close(fd)
 module=types.ModuleType('_core622_maintained_checkpoint_contract');module.__file__=str(path);exec(compile(bytes(raw),str(path),'exec'),vars(module));need(module.BASELINE==BASELINE_SOURCE,'same maintained ad090 contract baseline');return module

def expected_identity(value):
 need(type(value)is dict and set(value)=={'source','ref','run','attempt'}and type(value['source'])is str and re.fullmatch('[a-f0-9]{40}',value['source'])and type(value['ref'])is str and re.fullmatch('codex/[a-z0-9-]+',value['ref'])and integer(value['run'],1,10**20-1)and type(value['attempt'])is int and value['attempt']==1,'explicit bound current Source/ref/first run, never inferred from factory baseline');return value

def run_metadata(expected,run,jobs):
 expected_identity(expected);need(all(type(run[k])is int for k in('id','run_attempt','workflow_id'))and(run['id'],run['head_sha'],run['head_branch'],run['run_attempt'],run['workflow_id'])==(expected['run'],expected['source'],expected['ref'],1,381664314)and run['status']=='completed'and run['event']=='workflow_dispatch'and run['path']=='.github/workflows/native-arm-build.yml'and run['name']=='native-arm-core622-current-desktop'and run['repository']['full_name']==REPO and run['repository']['private']is False and type(run['repository']['id'])is type(run['head_repository']['id'])is int and run['repository']['id']==run['head_repository']['id']==1414857795,'same genuine registered terminal native workflow and public repository')
 need(type(jobs)is dict and set(jobs)=={'total_count','jobs'}and type(jobs['total_count'])is int and jobs['total_count']==len(jobs['jobs'])==1,'one complete native job');job=jobs['jobs'][0];need(integer(job['id'],1)and type(job['run_id'])is type(job['run_attempt'])is int and(job['run_id'],job['run_attempt'],job['head_sha'])==(expected['run'],1,expected['source'])and job['status']=='completed'and job['name']=='native'and job['labels']==['ubuntu-24.04-arm'],'same terminal Source-owned ARM64 job');return job

def artifact_list(expected,artifacts):
 expected_identity(expected);need(type(artifacts)is dict and set(artifacts)=={'total_count','artifacts'}and type(artifacts['total_count'])is int and artifacts['total_count']==len(artifacts['artifacts'])and 1<=len(artifacts['artifacts'])<=2,'complete one-or-two artifact metadata namespace');names=[row['name']for row in artifacts['artifacts']];allowed={CORE_ROLE+'-'+str(expected['run'])+'-1',CHECKPOINT_ROLE+'-'+str(expected['run'])+'-1'};need(len(set(names))==len(names)and set(names)<=allowed and all(integer(row['id'],1)for row in artifacts['artifacts'])and len({row['id']for row in artifacts['artifacts']})==len(names),'only one exact Core and one distinct declared checkpoint, no unknown/duplicate extras');return artifacts['artifacts']

def checkpoint_artifact(expected,row):
 expected_identity(expected);need(type(row)is dict and integer(row['id'],1)and row['name']==CHECKPOINT_ROLE+'-'+str(expected['run'])+'-1'and row['expired']is False and integer(row['size_in_bytes'],1,CHECKPOINT_ZIP_CAP)and type(row['digest'])is str and re.fullmatch('sha256:[a-f0-9]{64}',row['digest']),'bounded exact unexpired checkpoint metadata');wr=row['workflow_run'];need(type(wr['id'])is type(wr['repository_id'])is type(wr['head_repository_id'])is int and(wr['id'],wr['head_sha'],wr['head_branch'],wr['repository_id'],wr['head_repository_id'])==(expected['run'],expected['source'],expected['ref'],1414857795,1414857795),'checkpoint joins same Source/ref/run/repository');return row

def checkpoint_metadata(expected,run,jobs,artifacts):
 job=run_metadata(expected,run,jobs);rows=artifact_list(expected,artifacts);selected=[row for row in rows if row['name']==CHECKPOINT_ROLE+'-'+str(expected['run'])+'-1'];need(len(selected)==1,'one declared checkpoint entry');row=checkpoint_artifact(expected,selected[0]);steps={}
 for step in job['steps']:need(step['name']not in steps,'unique Source workflow step metadata');steps[step['name']]=step
 stage='Close completed prerequisite metadata before the Core installer';upload='Upload completed prerequisite metadata checkpoint';need(stage in steps and upload in steps and steps[stage]['status']==steps[upload]['status']=='completed'and steps[stage]['conclusion']==steps[upload]['conclusion']=='success'and integer(steps[stage]['number'],1)and integer(steps[upload]['number'],1)and steps[stage]['number']<steps[upload]['number'],'completed successful checkpoint preparation/upload in Source order');return dict(status='VALIDATED_CHECKPOINT_ARTIFACT_METADATA_DATA_ONLY',identity=dict(expected),artifact=row,body_GET_authority='NONE',acceptance=False)

def core_artifact_view(expected,run,jobs,artifacts):
 """Keep the original Core row intact for the caller's unchanged Core parser."""
 run_metadata(expected,run,jobs);rows=artifact_list(expected,artifacts);core=[row for row in rows if row['name']==CORE_ROLE+'-'+str(expected['run'])+'-1'];checkpoint=[row for row in rows if row['name']==CHECKPOINT_ROLE+'-'+str(expected['run'])+'-1'];need(len(core)==1,'checkpoint-only failure never substitutes for an original Core artifact')
 if checkpoint:checkpoint_metadata(expected,run,jobs,artifacts)
 else:need(run['conclusion']!='success','successful maintained Source requires mandatory checkpoint metadata')
 return dict(total_count=1,artifacts=[core[0]])

def checkpoint_data(raw,expected,artifact):
 """Explicit opaque checkpoint bytes, independent digest, closed ZIP, pure parser."""
 expected_identity(expected);checkpoint_artifact(expected,artifact);need(type(raw)is bytes and 0<len(raw)<=CHECKPOINT_ZIP_CAP and pin(raw)==dict(bytes=artifact['size_in_bytes'],sha256=artifact['digest'][7:]),'entire retained checkpoint archive digest/length before parsing');end=zipfile._EndRecData(io.BytesIO(raw));need(end is not None and end[zipfile._ECD_DISK_NUMBER]==end[zipfile._ECD_DISK_START]==0 and end[zipfile._ECD_ENTRIES_THIS_DISK]==end[zipfile._ECD_ENTRIES_TOTAL]==2 and 0<=end[zipfile._ECD_SIZE]<=4096 and 0<=end[zipfile._ECD_OFFSET]and end[zipfile._ECD_OFFSET]+end[zipfile._ECD_SIZE]<=len(raw),'bounded closed two-file ZIP directory before allocation')
 with zipfile.ZipFile(io.BytesIO(raw))as archive:
  infos=archive.infolist();need(len(infos)==2 and {i.filename for i in infos}=={'checkpoint.json','export.json'},'only two literal checkpoint ZIP leaves')
  for info in infos:need(not info.is_dir()and info.orig_filename==info.filename and stat.S_IFMT(info.external_attr>>16)in(0,stat.S_IFREG)and not(info.external_attr>>16)&0o7000 and not info.flag_bits&1 and info.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)and 0<info.file_size<=(65536 if info.filename=='checkpoint.json'else 16384),'ordinary bounded unencrypted checkpoint member before decompression')
  need(archive.testzip()is None,'complete checkpoint CRC');bodies={name:archive.read(name)for name in('checkpoint.json','export.json')}
 result=checkpoint_contract().validate(bodies,expected);result.update(archive=pin(raw),body_GET_authority='NONE',Core_acceptance='UNCHANGED_CALLER_GATE_NOT_INFERRED');return result


# Exact pure producer validators; no process/proc/read/write observer is copied.
resilience_encoded=encoded

TELEMETRY_PHASE_PREFIX=b'CORE622_PHASE_MARKER_V1 '

TELEMETRY_PREFIX=b'CORE622_PHASE_RESOURCE_V1 '

TELEMETRY_PHASES=('AWAITING_INSTALLER_PHASE','FRESH_INSTALLER_ENTER','PRODUCER_PREPARE','TOOLING_SEED','CORE_HOST_PREPARE','CORE_EXECUTION','CORE_EVIDENCE_CLEANUP','CORE_EVIDENCE_RETENTION','CORE_HOST_RETURN','ORIGINAL_PRODUCER_CLEANUP','CURRENT_CONTEXT_RETIREMENT','OUTER_CALLER_RETURN','OUTER_CALLER_RAISE')

TELEMETRY_RESOURCES=('host_mem_total_kib','host_mem_available_kib','host_swap_total_kib','host_swap_free_kib','pump_vm_rss_kib','pump_vm_hwm_kib','pump_threads')

def telemetry_encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def telemetry_identity(value):
 return type(value)is dict and set(value)=={'pid','start_ticks'}and type(value['pid'])is int and 0<value['pid']<2**31 and(value['start_ticks']is None or type(value['start_ticks'])is int and 0<value['start_ticks']<2**63)

def telemetry_selection(value,intent):
 return type(value)is dict and set(value)=={'source','ref','run','attempt'}and type(value['source'])is str and len(value['source'])==40 and all(c in'0123456789abcdef'for c in value['source'])and type(value['ref'])is str and 6<len(value['ref'])<=96 and value['ref'].startswith('codex/')and all(c in'abcdefghijklmnopqrstuvwxyz0123456789-'for c in value['ref'][6:])and type(value['run'])is int and 0<value['run']<10**20 and type(value['attempt'])is int and value['attempt']==1 and value==intent['identity']

def telemetry_frame_value(value,intent):
 need(type(value)is dict and set(value)=={'schema','status','identity','nonce','sequence','kind','elapsed_ms','phase','installer_identity','pump_identity','resource_scope','resources','unavailable_fields','acceptance'},'exact finite live telemetry fields');need(type(value['schema'])is int and value['schema']==1 and value['status']=='BOUNDED_SOURCE_PHASE_RESOURCE_DATA_ONLY'and telemetry_selection(value['identity'],intent)and value['nonce']==intent['nonce']and value['acceptance']is False,'same Source/run/nonce live telemetry');need(type(value['sequence'])is int and 1<=value['sequence']<=294 and value['kind']in('INTERVAL','PHASE')and type(value['elapsed_ms'])is int and 0<=value['elapsed_ms']<=350*60*1000 and value['phase']in TELEMETRY_PHASES,'finite count/cadence/public phase');need(telemetry_identity(value['pump_identity'])and(value['installer_identity']is None or telemetry_identity(value['installer_identity'])and value['installer_identity']['start_ticks']is not None)and value['resource_scope']=='HOST_MEMINFO_PUMP_ONLY_INSTALLER_ID_ASSERTED','resource and actor identity scopes');resources=value['resources'];need(type(resources)is dict and set(resources)==set(TELEMETRY_RESOURCES)and all(v is None or type(v)is int and 0<=v<2**63 for v in resources.values())and value['unavailable_fields']==sorted(k for k,v in resources.items()if v is None),'fixed numeric resource allowlist with explicit availability');need(len(TELEMETRY_PREFIX+telemetry_encoded(value)+b'\n')<=1024,'bounded complete telemetry frame');return value

def telemetry_summary_value(value,intent):
 keys={'schema','status','identity','nonce','cadence_seconds','interval_cap','phase_marker_cap','frame_cap','total_frame_cap','interval_samples','phase_markers','emitted_frames','dropped_frames','rejected_markers','last_phase','installer_identity','pump_identity','recent','acceptance'};need(type(value)is dict and set(value)==keys and type(value['schema'])is int and value['schema']==1 and value['status']=='BOUNDED_STDOUT_PUMP_TELEMETRY_DATA_ONLY'and telemetry_selection(value['identity'],intent)and value['nonce']==intent['nonce']and value['acceptance']is False,'exact same-owner telemetry summary');need((value['cadence_seconds'],value['interval_cap'],value['phase_marker_cap'],value['frame_cap'],value['total_frame_cap'])==(60,262,32,1024,294)and all(type(value[k])is int for k in('cadence_seconds','interval_cap','phase_marker_cap','frame_cap','total_frame_cap','interval_samples','phase_markers','emitted_frames','dropped_frames','rejected_markers')),'fixed telemetry clocks/cap types');total=value['interval_samples']+value['phase_markers'];need(0<=value['interval_samples']<=262 and 0<=value['phase_markers']<=32 and 0<=value['emitted_frames']<=total and value['dropped_frames']==total-value['emitted_frames']and 0<=value['rejected_markers']<2**31 and value['last_phase']in TELEMETRY_PHASES and telemetry_identity(value['pump_identity'])and(value['installer_identity']is None or telemetry_identity(value['installer_identity'])),'finite event/output accounting');recent=value['recent'];need(type(recent)is list and len(recent)==min(8,total),'finite last-eight telemetry samples');previous=-1
 for i,row in enumerate(recent,total-len(recent)+1):
  telemetry_frame_value(row,intent);need(row['sequence']==i and row['elapsed_ms']>=previous and row['pump_identity']==value['pump_identity'],'same pump chronological sample suffix');previous=row['elapsed_ms']
 if recent:need(recent[-1]['phase']==value['last_phase']and recent[-1]['installer_identity']==value['installer_identity'],'latest exact phase/identity summary')
 need(len(resilience_encoded(value))<=12000,'summary inside existing16KiB pump receipt');return value

def resilience_receipt_value(value,identity,source_export):
 import math,re
 need(type(value)is dict,'sanitized receipt object');role=value.get('role');version=value.get('schema');keys={'schema','status','identity','nonce','role','source_export','intent','observer_deadline','observed_bytes','observed_sha256','eof','retained','complete','window','errors','acceptance'};need(type(version)is int and version in(1,2)and type(value)is dict and set(value)==keys|({'telemetry'}if version==2 else set())and role in('phase.stdout','phase.stderr')and(version==1 or role=='phase.stdout'),'exact versioned sanitized stream receipt');intent=dict(identity=identity);need(telemetry_selection(value['identity'],intent)and value['nonce']==hashlib.sha256(('current607-core622:'+identity['source']+':'+str(identity['run'])).encode()).hexdigest()[:32]and value['source_export']==source_export and value['status']=='BOUNDED_PRIVATE_STREAM_METADATA_DATA_ONLY'and value['acceptance']is False,'exact Source/run/nonce/writer public receipt')
 def checked(p,cap):need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and 0<=p['bytes']<=cap and type(p['sha256'])is str and re.fullmatch('[a-f0-9]{64}',p['sha256']),'finite receipt pin')
 checked(value['intent'],16384);need(type(value['observer_deadline'])in(int,float)and math.isfinite(value['observer_deadline'])and value['observer_deadline']>=0 and type(value['observed_bytes'])is int and 0<=value['observed_bytes']<2**63 and type(value['observed_sha256'])is str and re.fullmatch('[a-f0-9]{64}',value['observed_sha256'])and type(value['eof'])is type(value['complete'])is bool and value['window']in('FULL','PREFIX'),'typed observed stream metadata');retained=value['retained'];checked(retained,1024**2)if retained is not None else None;need(retained is None or retained['bytes']<=value['observed_bytes'],'private prefix not invented');errors=value['errors'];stages={'OPEN_PREFIX','BINDING','WRITE_PREFIX','CLOSE_PREFIX','PREFIX_PIN','DRAIN_DEADLINE'};classes={'OSError','FileNotFoundError','PermissionError','ValueError','TypeError','RuntimeError','TimeoutError','BrokenPipeError','BlockingIOError','InterruptedError','MemoryError','UNCLASSIFIED_OPTIONAL_ERROR'};need(type(errors)is list and len(errors)<=6 and all(type(r)is dict and set(r)=={'stage','error_type'}and r['stage']in stages and r['error_type']in classes for r in errors),'finite sanitized capture errors');complete=value['eof']and retained is not None and retained['bytes']==value['observed_bytes']and not errors;need(value['complete']is complete and value['window']==('FULL'if complete else'PREFIX')and(not complete or retained['sha256']==value['observed_sha256']),'exact EOF/complete/original observed hash semantics')
 if version==2:telemetry_summary_value(value['telemetry'],dict(identity=identity,nonce=value['nonce']))
 return value

RUNNER_TELEMETRY_ROLES=frozenset({'runner-telemetry/phase.stdout.json','runner-telemetry/phase.stderr.json'})

def checked_pin(value,cap):
 need(type(value)is dict and set(value)=={'bytes','sha256'}and integer(value['bytes'],0,cap)and type(value['sha256'])is str and re.fullmatch('[a-f0-9]{64}',value['sha256']),'bounded exact public role pin');return value

def validate_runner_telemetry(receipt_raws,export,expected,source_files):
 """Return only these two Source-bound roles for an external closure callback.

Private prefixes, process lineage, installer RSS and cleanup remain unproven.
Root authenticates the full Source/public map before this optional DATA parser.
"""
 expected_identity(expected);need(type(export)is dict and type(export.get('files'))is dict and len(export['files'])<=4096,'complete bounded caller-authenticated public map');files=export['files'];total=sum(checked_pin(row,128*M)['bytes']for row in files.values());need(type(export.get('bytes'))is int and export['bytes']==total<=768*M,'unchanged original public byte/member limits');roles=frozenset(name for name in files if name.startswith('runner-telemetry/'));need(roles<=RUNNER_TELEMETRY_ROLES and type(receipt_raws)is dict and set(receipt_raws)==set(roles),'only explicitly declared sanitized public receipts, no raw/private prefix')
 if not roles:need('runner_telemetry'not in export,'no fabricated optional telemetry declaration');return frozenset()
 need(roles==RUNNER_TELEMETRY_ROLES,'atomic complete two-receipt namespace');summary=export.get('runner_telemetry');need(type(summary)is dict and set(summary)=={'schema','status','roles','acceptance'}and type(summary['schema'])is int and summary['schema']==1 and summary['status']=='OPTIONAL_SANITIZED_RUNNER_METADATA_DATA_ONLY'and summary['roles']=={name:files[name]for name in sorted(roles)}and summary['acceptance']is False,'exact optional receipt/export descriptor');need(type(source_files)is dict and len(source_files)==66 and 'export622.py'in source_files,'complete caller-authenticated Source66 map');writer=checked_pin(source_files['export622.py'],4*M);values={}
 for name in sorted(roles):
  raw=receipt_raws[name];need(type(raw)is bytes and 0<len(raw)<=16384 and pin(raw)==files[name],'whole bounded original receipt/export pin');value=obj(raw);need(encoded(value)==raw,'canonical original receipt bytes');resilience_receipt_value(value,expected,writer);need(value['role']==name.removeprefix('runner-telemetry/').removesuffix('.json'),'same exact declared stdout/stderr receipt');values[value['role']]=value
 stdout,stderr=values['phase.stdout'],values['phase.stderr'];need(stderr['schema']==1 and stdout['intent']==stderr['intent']and stdout['observer_deadline']==stderr['observer_deadline'],'same observer intent/deadline; stderr remains schema1');return roles

def telemetry_frame(raw,expected):
 """Parse one explicit safe protocol line; never scan or acquire a job log."""
 expected_identity(expected);need(type(raw)is bytes and 0<len(raw)<=1024 and raw.startswith(TELEMETRY_PREFIX)and raw.endswith(b'\n')and raw.count(b'\n')==1,'one bounded explicit numeric telemetry line');value=obj(raw[len(TELEMETRY_PREFIX):-1]);nonce=hashlib.sha256(('current607-core622:'+expected['source']+':'+str(expected['run'])).encode()).hexdigest()[:32];telemetry_frame_value(value,dict(identity=expected,nonce=nonce));need(TELEMETRY_PREFIX+telemetry_encoded(value)+b'\n'==raw,'canonical Source protocol bytes');return dict(status='VALIDATED_SOURCE_ASSERTED_NUMERIC_RUNNER_TELEMETRY_DATA_ONLY',identity=dict(expected),frame=pin(raw),resources=value['resources'],resource_scope='HOST_MEMINFO_PUMP_ONLY',installer_identity='SOURCE_ASSERTED_NOT_VERIFIED_LINEAGE',cause='NOT_INFERRED',native_acceptance=False,acceptance=False)
