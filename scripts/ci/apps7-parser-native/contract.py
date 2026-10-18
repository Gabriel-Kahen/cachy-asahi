# SPDX-License-Identifier: MIT
"""Finite code-only parser experiment; NULL source authority forbids actors."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/apps7-parser-native';LABEL='org.cachy-asahi.apps-parser-native.job'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def digest(path):return pin(Path(path).read_bytes())['sha256']
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def safe(path):
 path=Path(path);need(path.is_absolute()and '..'not in path.parts and not any(c in str(path)for c in ',\n\r')and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute path');return path
def read(path,cap=1024**2):
 path=safe(Path(path).absolute());s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=cap,'bounded source input');raw=path.read_bytes();need(len(raw)==s.st_size,'source drift');return raw
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def policy(bound=True):
 p=obj(read(HERE/'input-policy.json'));need(not sys.flags.optimize and p['schema_version']==1 and set(p['sources'])=={'baseline','candidate'}and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'finite source-only policy')
 need((p['worker_seconds'],p['owner_seconds'],p['warmups_per_variant'],p['repeats_per_variant'],p['memory_bytes'],p['cpus'],p['pids'],p['report_bytes'])==(300,330,2,6,1073741824,1,64,65536),'fixed finite native microbenchmark profile')
 need(p['dataset_lock_sha256']=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac','exact574 input lock')
 for role,revision,sha in [('baseline','eac600bd4f256068a78eb793dd464277eed6ce23','986c8baea2921cf3f58f98c2e76a1adad9013fbe4b1f47743d12397e9e6c2516'),('candidate','134e02ba0c73dab4eb4a22cbfd562599b9e7a411','68f9b0bc6bd5c494ebfc10bdc1e243c014d7fa8e56b1386491b75cdb9ee2e3df')]:
  r=p['sources'][role];need(r['expected_public_source']==revision and r['sha256']==sha and r['operand']==role+'-inventory.py','exact public parser source roles')
  need(r['authority_source']==revision if bound else r['authority_source']in(None,revision),'parser source authority NULL/UNBOUND')
 need(p['status']=='ROOT_BOUND_PUBLIC_PARSER_SOURCES'if bound else p['status']in('UNBOUND_SOURCE_TEMPLATE','ROOT_BOUND_PUBLIC_PARSER_SOURCES'),'source binding status')
 return p
def verify_source(source,bound=True):
 p=policy(bound);m=obj(read(HERE/'source-manifest.json'));need(m['schema_version']==1 and 0<len(m['files'])<=128,'finite source manifest')
 for n,row in m['files'].items():need(not n.startswith('/')and all(x not in('','.','..')for x in n.split('/'))and pin(read(source/n,16*1024**2))==row,'source pin drift')
 for r in p['sources'].values():need(pin(read(HERE/r['operand']))=={k:r[k]for k in('bytes','sha256')},'parser operand drift')
 return m

def save(path,value):
 temporary=path.with_suffix('.pending')
 with temporary.open('xb')as f:f.write(encoded(value));f.flush();os.fsync(f.fileno())
 temporary.replace(path)

def metrics(v):
 need(set(v)=={'schema_version','status','sources','dataset','protocol','equivalence','timing','context','full_inventory','full_application','M2','performance_gain','release'}and v['schema_version']==1 and v['status']=='COMPLETED_NATIVE_ARM_PARSER_MICROBENCHMARK_NOT_GAIN_ACCEPTANCE','closed project-only result')
 p=policy();need(v['protocol']==dict(profile='PROSPECTIVE_NATIVE_CORPUS_PRODUCTION_PARSER_BOUNDS',max_record_bytes=4194304,max_FILES_values=32768,max_corpus_bytes=67108864,constant_origins=['MAX_RECORD','MAX_BYTES','scan:len(paths)<=32768'],original_microbenchmark_helper='BYTE_UNCHANGED_NATIVE_RECORD_LIMITS_EXPLICITLY_SEPARATE'),'exact declared prospective production corpus domain');need(v['sources']=={r:dict(revision=x['authority_source'],**{k:x[k]for k in('bytes','sha256')})for r,x in p['sources'].items()},'exact public source result digests')
 d=v['dataset'];need(set(d)=={'kind','records','bytes','lf_count','lock','records_sha256'}and d['kind']=='ACTUAL_ORIGINAL574_ALPM_FILES_RECORDS'and d['records']==574 and type(d['bytes'])is int and 0<=d['bytes']<=64*1024**2 and type(d['lf_count'])is int and 0<=d['lf_count']<=64*1024**2 and set(d['lock'])=={'bytes','sha256'}and d['lock']['sha256']==p['dataset_lock_sha256']and re.fullmatch('[a-f0-9]{64}',d['records_sha256']),'exact bounded574 dataset identities')
 e=v['equivalence'];need(set(e)=={'control_cases','records','exact_ordered_outputs','all_records_parsed','outcome_sha256'}and e['control_cases']==8 and e['records']==574 and e['exact_ordered_outputs']is True and e['all_records_parsed']is True and re.fullmatch('[a-f0-9]{64}',e['outcome_sha256']),'complete exact corpus equivalence')
 t=v['timing'];need(set(t)=={'wall_clock','process_clock','scope','order','warmups_per_variant','repeats_per_variant','samples'}and t['wall_clock']=='perf_counter_ns'and t['process_clock']=='process_time_ns'and t['scope']=='whole corpus sections plus identical outcome capture; comparison/hashing excluded'and t['order']=='ALTERNATING_AB_BA'and t['warmups_per_variant']==2 and t['repeats_per_variant']==6 and len(t['samples'])==12,'finite balanced native timing protocol')
 expected=[(i,r)for i in range(6)for r in(('baseline','candidate')if i%2==0 else('candidate','baseline'))]
 for row,(i,r)in zip(t['samples'],expected):need(set(row)=={'repeat','role','wall_ns','process_ns'}and row['repeat']==i and row['role']==r and all(type(row[k])is int and row[k]>=0 for k in('wall_ns','process_ns')),'exact ordered wall/process samples')
 c=v['context'];need(set(c)=={'architecture','page_size','python_version','implementation','capabilities','rootfs','inputs','network','physical_hardware','power_thermal_background','utc_start','utc_end'}and c['architecture']=='aarch64'and c['capabilities']=='ZERO'and c['rootfs']==c['inputs']=='READONLY'and c['network']=='NONE'and c['physical_hardware']=='NOT_ATTESTED'and c['power_thermal_background']=='UNCONTROLLED_NOT_EXPORTED','closed non-identifying native context')
 need(type(c['page_size'])is int and c['page_size']>0 and type(c['python_version'])is list and len(c['python_version'])==3 and all(type(x)is int and x>=0 for x in c['python_version'])and c['implementation']=='cpython'and all(type(c[k])is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00',c[k])for k in('utc_start','utc_end')),'bounded coarse toolchain/time statistics')
 need(v['full_inventory']==v['full_application']=='NOT_MEASURED'and v['M2']=='NOT_RUN'and v['performance_gain']=='NOT_EVALUATED'and v['release']=='NOT_ADMITTED','parser-only non-admission scope');need(len(encoded(v))<=65536,'bounded project result');return v
