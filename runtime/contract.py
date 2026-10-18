# SPDX-License-Identifier: MIT
"""Finite source-owned KSM VM input and DATA contract; no authority from PASS."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
RECIPE='e753936b4d90d0b5127647581bed2a7fda64ce70';PROFILE='KSM_SCALAR_GENERIC16K_DIAGNOSTIC_V1';PACKAGE='cachy-asahi-ksmctl';VERSION='0.1.0-2'
NATIVE_STATUS='ROOT_ACCEPTED_NATIVE_KSM1_TO2_UPGRADE_RETAINED_SCOPE'
SHARED_SECONDS=3000;PRODUCT_SECONDS=5;CAP=16*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def pin(v):return dict(bytes=len(v),sha256=sha(v))
def decode(raw):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def relative(s):need(type(s)is str and s and not s.startswith('/')and '\\'not in s and all(p not in('','.','..')for p in s.split('/'))and '\0'not in s,'finite relative path');return s
def read(path,cap=4*1024**2):
 p=Path(path);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary source/input path');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link source/input');raw=p.read_bytes();b=p.lstat();ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(ident(a)==ident(b)and len(raw)==a.st_size,'input drift');return raw
def checked(root,row,cap=4*1024**2,allow_empty=False):
 need(type(row)is dict and set(row)=={'path','bytes','sha256'}and type(row['bytes'])is int and (0 if allow_empty else 1)<=row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256']or''),'exact bounded reference');raw=read(Path(root)/relative(row['path']),cap);need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'reference pin differs');return raw
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def support(root=HERE):
 root=Path(root);rows=decode(read(root/'support-pins.json'))['files']
 for n,p in rows.items():need(pin(read(root/relative(n),16*1024**2))==p,'whole borrowed source differs: '+n)
 return rows

def row(path):
 p=Path(path);a=p.lstat();need(not any(q.is_symlink()for q in(p,*p.parents))and stat.S_ISREG(a.st_mode)and a.st_nlink==1,'ordinary whole-file pin')
 with p.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
 b=p.lstat();need((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'whole-file drift');return dict(bytes=a.st_size,sha256=digest)
def save(path,value):Path(path).write_bytes(encoded(value))
def native_record(value,source,run,root=HERE):
 proposal=decode(read(Path(root)/'native-decision-contract.json',65536))
 need(source==proposal['known_source']and run==proposal['known_run'],'exact known native component source/run, no foreign acceptance')
 need(type(value)is dict and set(value)==set(proposal['required_fields'])and value['status']==NATIVE_STATUS and value['source']==source and type(value['run'])is int and value['run']==run,'exact genuine Root native qualification required')
 need(value['recipe_sources']==dict(baseline=RECIPE,candidate=RECIPE)and value['actual_architecture']=='aarch64'and value['actual_page_size']==4096,'exact native recipe/architecture/page scope')
 for name,expected in proposal['finite_expectations'].items():need(value[name]==expected,'finite native retained scope: '+name)
 for key in('strict_replay','lifecycle'):
  p=value[key];need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and 0<p['bytes']<=192*1024**2 and re.fullmatch('[0-9a-f]{64}',p['sha256']or''),'finite retained native receipt pin')
 transport=value['original_transport'];need(type(transport)is dict and set(transport)=={'metadata','artifact_metadata','artifact','logs'},'four original native transport pins')
 for p in transport.values():need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and p['bytes']>0 and re.fullmatch('[a-f0-9]{64}',p['sha256']or''),'original native transport stream pin')
 artifacts=value['native_artifacts'];need(type(artifacts)is dict and set(artifacts)==set(proposal['native_artifacts']),'exact native artifact roles')
 need(artifacts['package_name']==PACKAGE and artifacts['baseline_version']=='0.1.0-1'and artifacts['candidate_version']==VERSION and artifacts['path_scope']=='ORIGINAL_PUBLIC_ARTIFACT_ROOT_NOT_A_PUBLISHED_CARRIER','native artifact product scope')
 need(type(value['limits'])is list and value['limits'],'retained native limitations required')
 return value

def native_gate(selection,inputs,root=HERE):
 need(type(selection)is dict and all(selection.get(k)is not None for k in('native_source','native_run','native_decision','native_inputs')),'UNBOUND native qualification: no output or actors')
 need(re.fullmatch('[0-9a-f]{40}',selection['native_source']or'')and type(selection['native_run'])is int and selection['native_run']>0,'exact native source/run identity')
 authority=decode(checked(inputs,selection['native_decision'],65536));native_record(authority,selection['native_source'],selection['native_run'],root)
 index=decode(checked(inputs,selection['native_inputs'],2*1024**2));need(index.get('purpose')=='KSM2_NATIVE_INPUTS_ONLY_NO_VM_CREDIT'and index.get('source')==selection['native_source']and index.get('run')==selection['native_run']and index.get('name')==PACKAGE and index.get('version')==VERSION,'same accepted native input index')
 need(set(index['files'])=={'a','b','signature','public_key','control','runtime_report'}and re.fullmatch('[0-9A-F]{40}',index.get('signer')or''),'exact native archive/trust/report roles')
 artifacts=authority['native_artifacts'];joins=dict(a=artifacts['candidate']['a'],b=artifacts['candidate']['b'],signature=artifacts['signatures']['candidate'],public_key=artifacts['TEST_public_key'],control=artifacts['TEST_control'],runtime_report=artifacts['runtime_report'])
 refs=[artifacts['TEST_control'],artifacts['TEST_public_key'],artifacts['baseline']['a'],artifacts['baseline']['b'],artifacts['candidate']['a'],artifacts['candidate']['b'],artifacts['lifecycle'],artifacts['retained_package_output_index'],artifacts['runner_derivations'],artifacts['runtime_report'],artifacts['signatures']['baseline'],artifacts['signatures']['candidate']]
 need(index['native_decision']==selection['native_decision']and index['native_artifact_refs']==refs and index['recipe_sources']==dict(baseline=RECIPE,candidate=RECIPE),'exact index Root decision/artifact/recipe joins')
 for p in refs:checked(inputs,p,16*1024**2)
 recipe=index['recipe'];need(recipe['source']==RECIPE and recipe['path']=='recipes/cachy-asahi-ksmctl2'and len(recipe['files'])==14,'exact source-owned candidate recipe role')
 expected={p.name:pin(read(p,1024**2))for p in(Path(root)/'native-source/packages/tools/cachy-asahi-ksmctl2').iterdir()if p.is_file()};need(recipe['files']==expected,'whole native candidate recipe source table')
 for name,p in recipe['files'].items():checked(inputs,dict(path=recipe['path']+'/'+relative(name),**p),1024**2)
 need(index['files']==joins,'original retained artifact references must join Root decision without path remapping')
 data={k:checked(inputs,p,16*1024**2)for k,p in index['files'].items()};need(data['a']==data['b']and index['files']['a']['path']!=index['files']['b']['path'],'two exact native archives')
 transport=checked(inputs,index['transport'],1024**2);need(decode(transport)==authority['original_transport'],'exact four native transport pins in byte-pinned DATA receipt')
 control=decode(data['control']);need(control.get('signer')==index['signer'],'signer/control join')
 report=decode(data['runtime_report']);product=report['products']['cachy-asahi-ksmctl2'];need(index.get('product')==product,'whole native product payload/report join')
 need(product['version']==VERSION and len(product['builds'])==2 and type(product['builds'][0]['payload'])is dict,'actual native candidate version and full payload')
 need(all(p['sha256']==sha(data['a'])for p in product['builds']),'actual native report/archive byte hash join')
 need(product['builds'][0]['archive']==Path(index['files']['a']['path']).name and product['builds'][1]['archive']==Path(index['files']['b']['path']).name,'actual native archive basenames')
 return authority,index

def actual_identity(selection):
 need(re.fullmatch('[0-9a-f]{40}',selection.get('VM_source')or'')and type(selection.get('VM_run'))is int and selection['VM_run']>0 and re.fullmatch('codex/[a-z0-9-]+',selection.get('VM_ref')or''),'exact actual VM identity')

def actual_environment(s):
 actual_identity(s);need(all(os.environ.get(k)==s['VM_source']for k in('SOURCE_SHA','GITHUB_SHA','GITHUB_WORKFLOW_SHA'))and os.environ.get('GITHUB_RUN_ID')==str(s['VM_run'])and os.environ.get('GITHUB_RUN_ATTEMPT')=='1'and os.environ.get('GITHUB_REF_NAME')==s['VM_ref']and os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','genuine first-attempt same-source VM workflow environment required')

def source_check(root=HERE):
 root=Path(root);rows=decode(read(root/'source-files.json',1024**2))['files']
 actual={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()};need(actual==set(rows)|{'source-files.json'},'closed VM source files only')
 for name,p in rows.items():need(pin(read(root/relative(name),16*1024**2))==p,'VM source pin differs: '+name)
 return rows

def gate(selection,inputs,root=HERE):
 need(type(selection)is dict and all(selection.get(k)is not None for k in('native_decision','native_inputs','kernel_build','media','VM_source','VM_ref','VM_run')),'UNBOUND native qualification/kernel/media: no output or actors')
 actual_identity(selection);return native_gate(selection,inputs,root)

def guest_guard(s,worker=False):
 need((os.getpid()!=1 and os.getppid()==1 if worker else os.getpid()==1)and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'actual private generic16K PID1 only')
 need(type(s['nonce'])is str and re.fullmatch('[0-9a-f]{32}',s['nonce']),'fixed VM nonce')
 tokens=Path('/proc/cmdline').read_text().split();need(tokens.count('caa_ksm2_vm='+s['nonce'])==1 and 'init=/init-ksm2'in tokens,'owned boot marker')
 need({p.name for p in Path('/sys/class/net').iterdir()}<={'lo'}and s['kernel']['profile']==PROFILE and os.uname().release==s['kernel']['release'],'private noNIC/new kernel scope')
