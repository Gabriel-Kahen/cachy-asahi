#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source rebase and exact original input projection; no signing or actors."""
import argparse,ast,hashlib,importlib.util,json,re,shutil,sys,tempfile,zipfile
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-composition';NEW='scripts/ci/expanded604-current-management'
MODULES=('contract.py','inputs.py','materializer.py','lifecycle.py','installed_shells.py','run.py','gate.py')
OWN=('prepare.py','current_inputs.py','policy.json','source-pins.json','test_current.py','README.md')
OLD_SHA='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
NEW_SHA='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);sys.modules[name]=v;spec.loader.exec_module(v);return v
def source(repo):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(0<len(rows)<=512,'finite source closure')
 for n,row in rows.items():
  p=repo/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2 and pin(p.read_bytes())==row,'exact current604 input source: '+n)
 return rows

def replace(text,before,after,count):
 need(text.count(before)==count,'counted current604 source anchor: '+before[:100]);return text.replace(before,after)
def function(text,name,body):
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name);return replace(text,ast.get_source_segment(text,node),body.rstrip(),1)
def adapt(raw,name):
 text=raw.decode();original=ast.parse(text);a={n.name:ast.get_source_segment(text,n) for n in original.body if isinstance(n,ast.FunctionDef)}
 if name=='contract.py':
  text=replace(text,OLD_SHA,NEW_SHA,1);text=replace(text,"'cachy-asahi-orphans':'0.1.0-1'","'cachy-asahi-orphans':'0.1.0-2'",1);text=replace(text,"'cachy-asahi-welcome':'0.1.0-2'","'cachy-asahi-welcome':'0.1.0-4'",1)
  text=replace(text,"versions=MANAGEMENT)","versions=dict(MANAGEMENT, **{'cachy-asahi-orphans':'0.1.0-1'}))",1)
  text=replace(text,'ROOT_BOUND_FINAL604_ACCEPTED_INPUTS','ROOT_BOUND_CURRENT604_NATIVE_INPUTS',1);text=replace(text,'ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE','ROOT_ACCEPTED_WELCOME4_NATIVE_PAIR_AND_SIGNED_INSTALLED_CLI_ONLY',1);text=replace(text,'96aa3e7a81840b7eba6ba07188481fd89631fb6b','0b74d8ecea4f152bda4adfbd9bee488890db4363',1)
  text=replace(text,"welcome.get('candidate_source')=='0b74d8ecea4f152bda4adfbd9bee488890db4363'", "welcome.get('source')=='3c06dad15dec0dbfe47d5f064a9c56ce76f59756' and welcome.get('candidate_source')=='0b74d8ecea4f152bda4adfbd9bee488890db4363'",1)
  text=replace(text,'org.cachy-asahi.expanded604.job','org.cachy-asahi.expanded604.current-management.job',1)
 if name=='inputs.py':
  text=function(text,'require_welcome',"def require_welcome(policy):\n    return C.load('current604_inputs',C.HERE/'current_inputs.py').require(C,policy.get('welcome',{}))")
  text=function(text,'welcome_pair',"def welcome_pair(source,root,binding,checks,bind):\n    return C.load('current604_inputs',C.HERE/'current_inputs.py').validate(C,source,root,binding,checks,bind)[WELCOME]")
  text=replace(text,"for name,row in packet['packages'].items():\n        for filename", "for name,row in packet['packages'].items():\n        if name=='cachy-asahi-orphans':continue  # Original packet still fully validated; only old selection omitted.\n        for filename",1)
  anchor="        for rows,root in ((result['management'].values(),management),([result['setup']],setup),([result['welcome']],welcome)):"
  text=replace(text,anchor,"        result['management']['cachy-asahi-orphans']=C.load('current604_inputs',C.HERE/'current_inputs.py').validate(C,source,w,policy['welcome'],checks,bind)['cachy-asahi-orphans']\n"+anchor,1)
  text=replace(text,"for row in rows:row['archive']=str(C.checked(root,row['files']['a'],8*1024**2))","for row in rows:row['archive']=str(C.checked(welcome if row.get('name')=='cachy-asahi-orphans' else root,row['files']['a'],8*1024**2))",1)
 for before,after in ((OLD,NEW),):text=text.replace(before,after)
 if name in ('contract.py','lifecycle.py'):text=text.replace('PASS_EXPANDED604_METADATA_LIFECYCLE','PASS_CURRENT604_METADATA_LIFECYCLE')
 if name=='run.py':text=replace(text,'PASS_NATIVE_EXPANDED604_COMPOSITION','PASS_NATIVE_CURRENT604_COMPOSITION',1)
 ast.parse(text);b={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 return text.encode(),dict(unchanged=sorted(n for n in a if a[n]==b[n]),changed=sorted(n for n in a if a[n]!=b[n]))

def emit(repo,output):
 rows=source(repo);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output');output.mkdir(mode=0o700)
 for n in rows:
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((repo/n).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True,exist_ok=True)
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 ledger={}
 for n in MODULES:raw,ledger[n]=adapt((repo/OLD/n).read_bytes(),n);(lane/n).write_bytes(raw)
 (lane/'expected587.lock').write_bytes((repo/OLD/'expected587.lock').read_bytes());raw=(repo/OLD/'expected604.lock').read_bytes().replace(b'cachy-asahi-welcome 0.1.0-2\n',b'cachy-asahi-welcome 0.1.0-4\n').replace(b'cachy-asahi-orphans 0.1.0-1\n',b'cachy-asahi-orphans 0.1.0-2\n');need(pin(raw)['sha256']==NEW_SHA,'exact two-version current604 lock');(lane/'expected604.lock').write_bytes(raw)
 (lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes());held=json.loads((repo/OLD/'held-pins.json').read_bytes())
 for n in ('scripts/ci/welcome-management-native/native_contract.py','scripts/ci/welcome-management-native/input-policy.json'):held[n]=rows[n]
 (lane/'held-pins.json').write_bytes(encoded(held));files={n:pin((output/n).read_bytes()) for n in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()});manifest=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='CURRENT604_NATIVE_SOURCE_ONLY_NO_PRIOR604_CREDIT',native='NOT_RUN',hardware='NOT_RUN');(lane/'source-manifest.json').write_bytes(encoded(manifest))
 # Same complete builder/transaction workflow; only separate lane/name/current source hashes.
 wf=(repo/'.github/workflows/native-arm-expanded604.yml').read_text().replace('Welcome2','current Welcome4/Orphans2').replace('name: native-arm-expanded604\n','name: native-arm-expanded604-current-management\n',1).replace('group: native-arm-expanded604\n','group: native-arm-expanded604-current-management\n',1).replace(OLD,NEW)
 oldrun=pin((repo/OLD/'run.py').read_bytes())['sha256'];oldmanifest=pin((repo/OLD/'source-manifest.json').read_bytes())['sha256'];wf=replace(wf,oldrun,pin((lane/'run.py').read_bytes())['sha256'],1);wf=replace(wf,oldmanifest,pin((lane/'source-manifest.json').read_bytes())['sha256'],1)
 # Old tests assert historical versions. Execute this adapter's bounded controls instead.
 start=wf.index('      - name: Run hosted controls without native actors');end=wf.index('      - name:',start+10);wf=wf[:start]+'''      - name: Current604 source controls without native actors
        shell: bash
        env:
          CURRENT604_PACKET_ROOT: ${{ github.workspace }}/expanded604-welcome/payload
          CURRENT604_MANAGEMENT_ROOT: ${{ github.workspace }}/expanded604-management/payload
          CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code
        run: |
          set -euo pipefail
          python3 -I -B expanded604-code/scripts/ci/expanded604-current-management/test_current.py
'''+wf[end:]
 path=output/'.github/workflows/native-arm-expanded604-current-management.yml';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(wf)
 result=dict(status='SOURCE_ONLY_CURRENT604_NO_RUNTIME_CREDIT',input_authority=json.loads((HERE/'policy.json').read_bytes())['status'],source_files=len(rows),target_sha256=NEW_SHA,changed_versions={'cachy-asahi-welcome':['0.1.0-2','0.1.0-4'],'cachy-asahi-orphans':['0.1.0-1','0.1.0-2']},other_versions_unchanged=602,functions=ledger,workflow=pin(path.read_bytes()),native='NOT_RUN',GUI='NOT_ACCEPTED',installer='NOT_RUN',updater='NOT_RUN',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');(output/'adaptation.json').write_bytes(encoded(result));return result

def packet(repo,actual,accepted,output):
 source(repo);H=load('current604_packet_guards',HERE/'current_inputs.py');C=load('current604_original_contract',repo/OLD/'contract.py');reader=C.scoped_load('current604_original_inputs',repo/OLD/'inputs.py',{'contract':C});checks,bind=reader.tools(repo)
 C.safe(output);need(not output.exists() and output.parent.is_dir() and not any(output.is_relative_to(x.absolute()) or x.absolute().is_relative_to(output) for x in (actual,accepted)),'fresh separate packet output outside original evidence')
 decision=(accepted/'decision.json').read_bytes();need(pin(decision)==H.DECISION,'exact existing Root decision');value=json.loads(decision);frozen=accepted/'source';joins=json.loads((accepted/'source-joins.json').read_bytes());need(joins['source']==H.SOURCE and joins['status']=='PASS_SOURCE_ONLY_EXACT_113_GIT_JOINS' and len(joins['files'])==113,'Root frozen113 source proof required')
 raw_manifest=(frozen/'scripts/ci/welcome-management-native/source-manifest.json').read_bytes();need(pin(raw_manifest)==value['source_manifest'],'Root original113 source manifest pin');manifest=json.loads(raw_manifest);need(len(manifest['files'])==113 and set(manifest['files'])==set(joins['files']),'original113 source-map closure')
 for n,row in joins['files'].items():need(pin((frozen/C.relative(n)).read_bytes())==manifest['files'][n]=={k:row[k] for k in ('bytes','sha256')},'original frozen native source differs: '+n)
 for n in ('artifact.zip','logs.zip'):need(pin((actual/n).read_bytes())==value['originals'][n],'exact original collection digest')
 run=json.loads((actual/'run.json').read_bytes());need(run['id']==H.RUN and run['head_sha']==H.SOURCE and run['run_attempt']==1 and run['conclusion']=='failure','original overall FAIL retained')
 api=load('current604_original_native_guards',frozen/'scripts/ci/welcome-management-native/native_contract.py');files={};packages={}
 with zipfile.ZipFile(actual/'artifact.zip') as z:
  entries=z.infolist();need(len(entries)==265 and len({r.filename for r in entries})==265 and sum(r.file_size for r in entries)<=192*1024**2,'original closed native collection')
  retained=json.loads(z.read('retention.json'));need(set(retained['files'])|{'retention.json'}=={r.filename for r in entries},'original native public closure')
  for e in entries:
   n=C.relative(e.filename);need(not e.is_dir() and e.file_size<=96*1024**2,'original ordinary bounded ZIP member');raw=z.read(e)
   if n!='retention.json':need(pin(raw)==retained['files'][n],'original public hash: '+n)
   if n.startswith(('runtime/public-reports/','signed/')) or n in ('runtime/lifecycle.json','runtime/root-guard.tap','runtime/root-guard.json','ordered-cleanup.json','base/installed-packages.lock','source-proof.json','retention.json'):files[n]=raw
  for name,version in H.VERSIONS.items():
   refs={}
   for side in ('a','b'):
    names=[n for n in z.namelist() if n.startswith('packages/'+name+'-'+side+'/')];need(len(names)==1,'one exact actual pair archive');n=names[0];files[n]=z.read(n);refs[side]=dict(path=n,**pin(files[n]));n='runtime/'+name+'-'+side+'/build.log';files[n]=z.read(n)
   sources={}
   for n,row in api.product(name)['source_files'].items():
    path='source/'+name+'/'+n;files[path]=z.read(path);need(pin(files[path])==row,'actual retained package source');sources[n]=dict(path=path,**row)
   path='runtime/'+name+'-comparison.json';files[path]=z.read(path)
   with tempfile.TemporaryDirectory(prefix='current604-archive-',dir=output.parent) as temp:
    archive=Path(temp)/Path(refs['a']['path']).name;archive.write_bytes(files[refs['a']['path']]);report=checks.package(archive)
   packages[name]=dict(version=version,native_source=H.SOURCE,native_run=H.RUN,files=refs,source_files=sources,payload=api.payload(report,frozen,name),checks={side:dict(path='runtime/'+name+'-'+side+'/build.log',**pin(files['runtime/'+name+'-'+side+'/build.log'])) for side in ('a','b')},comparison=dict(path=path,**pin(files[path])))
 files['root-decision.json']=decision;files['original-collection.json']=(actual/'collection.json').read_bytes();files['root-source-joins.json']=(accepted/'source-joins.json').read_bytes()
 def ref(n):return dict(path=n,**pin(files[n]))
 index=dict(schema_version=1,kind='ROOT_ACCEPTED_CURRENT604_WELCOME4_ORPHANS2_INPUT_PROJECTION',native_source=H.SOURCE,candidate_source=H.PRODUCT,native_run=H.RUN,GUI='FAIL_NOT_ACCEPTED',packages=packages,decision=ref('root-decision.json'),evidence=dict(lifecycle=ref('runtime/lifecycle.json'),root_guard_tap=ref('runtime/root-guard.tap'),base_lock=ref('base/installed-packages.lock'),cleanup=ref('ordered-cleanup.json'),files=[ref(n) for n in sorted(files)]),scope='NATIVE_PAIR_AND_SIGNED_CLI_ONLY_NO_CURRENT604_OR_GUI_ADMISSION')
 need(len(files)<256 and sum(map(len,files.values()))<=64*1024**2 and not output.exists() and output.parent.is_dir(),'fresh bounded packet output');output.mkdir(mode=0o700)
 for n,raw in files.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 raw=encoded(index);(output/'index.json').write_bytes(raw);binding=dict(status=H.STATUS,source=H.SOURCE,candidate_source=H.PRODUCT,carrier_source=None,index=dict(path='index.json',**pin(raw)));H.validate(C,repo,output,binding,checks,bind,published=False,native_source=frozen)
 return dict(status='PRIVATE_CURRENT604_PACKET_PROJECTION_VALIDATED_UNPUBLISHED',files=len(files)+1,bytes=sum(map(len,files.values()))+len(raw),index=pin(raw),binding=binding,GUI='FAIL_NOT_ACCEPTED',current604='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('emit','packet'));p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--actual',type=Path);p.add_argument('--accepted',type=Path);a=p.parse_args();print(json.dumps(emit(a.repo.absolute(),a.output.absolute()) if a.action=='emit' else packet(a.repo.absolute(),a.actual,a.accepted,a.output.absolute()),sort_keys=True))
