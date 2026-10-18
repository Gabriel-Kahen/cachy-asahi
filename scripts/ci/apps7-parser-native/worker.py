#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only actual574 ALPM sections corpus, reviewed parser functions only."""
import ast,hashlib,importlib.util,json,os,re,signal,stat,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_held_sections_benchmark',HERE/'apps_inventory_parser.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)
MAX_CORPUS=64*1024**2
NATIVE_RECORD=4*1024**2
NATIVE_FILES=32768

def control_cases():
 tree=ast.parse((HERE/'apps_inventory_parser.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='benchmark');node=next(n for n in fn.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='controls'for t in n.targets));rows=ast.literal_eval(node.value);C.need(len(rows)==8,'original eight parser controls');return rows

def production_profile(sources):
 for raw in sources.values():
  tree=ast.parse(raw)
  for name,expression in [('MAX_RECORD','4*1024**2'),('MAX_BYTES','64*1024**2')]:
   selected=[n.value for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name];C.need(len(selected)==1 and ast.dump(selected[0],include_attributes=False)==ast.dump(ast.parse(expression,mode='eval').body,include_attributes=False),'exact production record/aggregate constants')
  expected=ast.dump(ast.parse('len(paths)<=32768',mode='eval').body,include_attributes=False);C.need(sum(isinstance(n,ast.Compare)and ast.dump(n,include_attributes=False)==expected for n in ast.walk(tree))==1,'exact production ownership count')
 return dict(profile='PROSPECTIVE_NATIVE_CORPUS_PRODUCTION_PARSER_BOUNDS',max_record_bytes=NATIVE_RECORD,max_FILES_values=NATIVE_FILES,max_corpus_bytes=MAX_CORPUS,constant_origins=['MAX_RECORD','MAX_BYTES','scan:len(paths)<=32768'],original_microbenchmark_helper='BYTE_UNCHANGED_NATIVE_RECORD_LIMITS_EXPLICITLY_SEPARATE')


def no_lock(db):
 try:(db.parent/'db.lck').lstat()
 except FileNotFoundError:return
 raise ValueError('ALPM lock exists')

def corpus(db,lock,packages=574):
 raw=B.read(lock,1024**2);rows=[r.split()for r in raw.decode('ascii','strict').splitlines()];C.need(len(rows)==packages and all(len(r)==2 and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:~-]{0,260}',x)for x in r)for r in rows)and len({r[0]for r in rows})==packages,'exact bounded package lock')
 expected=sorted(n+'-'+v for n,v in rows);C.need(not any(p.is_symlink()for p in(db,*db.parents))and db.is_dir(),'ordinary database root');no_lock(db)
 names=lambda:sorted(p.name for p in db.iterdir())
 C.need(names()==sorted([*expected,'ALPM_DB_VERSION'])and B.read(db/'ALPM_DB_VERSION',16)==b'9\n','exact complete574 local database')
 data=[];pins=[];spent=0;lines=0
 for name in expected:
  path=db/name;C.need(path.is_dir()and not path.is_symlink(),'ordinary package record directory');value=B.read(path/'files',NATIVE_RECORD);spent+=len(value);lines+=value.count(b'\n');C.need(spent<=MAX_CORPUS,'original record/corpus finite bounds')
  data.append(value);pins.append([name,B.pin(value)])
 no_lock(db);C.need(names()==sorted([*expected,'ALPM_DB_VERSION']),'database changed')
 return data,dict(records=len(data),bytes=spent,lf_count=lines,lock=B.pin(raw),records_sha256=B.pin(B.encoded(pins))['sha256']),[(db/n/'files',v)for n,v in zip(expected,data)],raw

def measure(sources,data,warmups=2,repeats=6):
 C.need(type(warmups)is int and 0<=warmups<=2 and type(repeats)is int and repeats in(2,6),'finite local/production timing protocol');functions={r:B.parser(raw,r)for r,raw in sources.items()};C.need(set(functions)=={'baseline','candidate'},'both variants')
 for raw,allowed in control_cases():C.need(B.outcome(functions['baseline'],raw,allowed)==B.outcome(functions['candidate'],raw,allowed),'control outputs/refusals differ before timing')
 def run(role):return[B.outcome(functions[role],raw,('FILES','BACKUP'))for raw in data]
 candidate=run('candidate')
 for raw,value in zip(data,candidate):
  C.need(value['status']=='PARSED','actual corpus record refused before timing');paths=dict(value['value']).get('FILES',[]if raw==b''else None);C.need(type(paths)is list and len(paths)<=NATIVE_FILES,'production FILES ownership bound before baseline/timing')
 expected=run('baseline');C.need(expected==candidate,'whole corpus outcomes differ or refuse before timing')
 for index in range(warmups):
  for role in(('baseline','candidate')if index%2==0 else('candidate','baseline')):C.need(run(role)==expected,'warmup changed outcome')
 samples=[]
 for repeat in range(repeats):
  for role in(('baseline','candidate')if repeat%2==0 else('candidate','baseline')):
   wall=time.perf_counter_ns();cpu=time.process_time_ns();value=run(role);cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall;C.need(value==expected,'timed parser outcome changed');samples.append(dict(repeat=repeat,role=role,wall_ns=wall,process_ns=cpu))
 return dict(equivalence=dict(control_cases=8,records=len(data),exact_ordered_outputs=True,all_records_parsed=True,outcome_sha256=B.pin(B.encoded(expected))['sha256']),timing=dict(wall_clock='perf_counter_ns',process_clock='process_time_ns',scope='whole corpus sections plus identical outcome capture; comparison/hashing excluded',order='ALTERNATING_AB_BA',warmups_per_variant=warmups,repeats_per_variant=repeats,samples=samples))

def native_guard():
 C.need(os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_APPS_PARSER_NATIVE')=='1','dedicated ordinary nativeARM worker')
 fields=dict(x.split(':',1)for x in Path('/proc/self/status').read_text().splitlines()if':'in x);C.need(all(int(fields[k].strip(),16)==0 for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb'))and fields['NoNewPrivs'].strip()=='1'and fields['Seccomp'].strip()=='2','zero-capability nnp/seccomp worker')
 C.need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'}and not any(Path(n).exists()for n in('/run/docker.sock','/var/run/docker.sock')),'no network or Docker socket')
 mounts={line.split(' - ',1)[0].split()[4]:line.split(' - ',1)[0].split()[5].split(',')for line in Path('/proc/self/mountinfo').read_text().splitlines()};C.need('ro'in mounts['/']and 'ro'in mounts['/inputs'],'readonly image/inputs')
 return dict(architecture='aarch64',page_size=os.sysconf('SC_PAGE_SIZE'),python_version=list(sys.version_info[:3]),implementation=sys.implementation.name,capabilities='ZERO',rootfs='READONLY',inputs='READONLY',network='NONE',physical_hardware='NOT_ATTESTED',power_thermal_background='UNCONTROLLED_NOT_EXPORTED')

def main():
 phase='POLICY';started=datetime.now(timezone.utc).isoformat();report=None
 def stop(*_):raise TimeoutError('finite worker deadline')
 try:
  p=C.policy();signal.signal(signal.SIGALRM,stop);signal.setitimer(signal.ITIMER_REAL,p['worker_seconds']);phase='GUARD';facts=native_guard();phase='SOURCE';sources={r:B.read(HERE/v['operand'],B.MAX_SOURCE)for r,v in p['sources'].items()};C.need(all(B.pin(sources[r])=={k:v[k]for k in('bytes','sha256')}for r,v in p['sources'].items()),'exact source operands');profile=production_profile(sources);phase='DATASET';data,identity,paths,lock=corpus(Path('/var/lib/pacman/local'),Path('/builder-packages.lock'));C.need(B.pin(lock)['sha256']==p['dataset_lock_sha256'],'exact574 builder dataset');phase='EQUIVALENCE_AND_TIMING';measurement=measure(sources,data,p['warmups_per_variant'],p['repeats_per_variant']);phase='READBACK';C.need(all(B.read(path,NATIVE_RECORD)==raw for path,raw in paths)and B.read(Path('/builder-packages.lock'),1024**2)==lock,'readonly dataset/source drift');no_lock(Path('/var/lib/pacman/local'));C.need(sorted(p.name for p in Path('/var/lib/pacman/local').iterdir())==sorted([*(p.parent.name for p,_ in paths),'ALPM_DB_VERSION']),'final complete database namespace');C.need(all(B.read(HERE/p['sources'][r]['operand'],B.MAX_SOURCE)==raw for r,raw in sources.items()),'source drift')
  report=dict(schema_version=1,status='COMPLETED_NATIVE_ARM_PARSER_MICROBENCHMARK_NOT_GAIN_ACCEPTANCE',sources={r:dict(revision=p['sources'][r]['authority_source'],**B.pin(raw))for r,raw in sources.items()},dataset=dict(kind='ACTUAL_ORIGINAL574_ALPM_FILES_RECORDS',**identity),protocol=profile,**measurement,context=dict(**facts,utc_start=started,utc_end=datetime.now(timezone.utc).isoformat()),full_inventory='NOT_MEASURED',full_application='NOT_MEASURED',M2='NOT_RUN',performance_gain='NOT_EVALUATED',release='NOT_ADMITTED');code=0
 except BaseException as e:report=dict(schema_version=1,status='REFUSED_OR_INCOMPLETE_PARSER_BENCHMARK',phase=phase,error_kind=type(e).__name__,raw_paths_records_environment='NOT_EXPORTED',performance_gain='NOT_EVALUATED',M2='NOT_RUN');code=1
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 raw=C.encoded(report);C.need(len(raw)<=65536,'bounded project-only report');sys.stdout.buffer.write(raw);return code
if __name__=='__main__':raise SystemExit(main())
