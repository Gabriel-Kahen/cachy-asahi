# SPDX-License-Identifier: MIT
"""Whole355 inverse and exact published1197 source guard, never installed authority."""
import json,os,signal,subprocess,sys,tempfile
from pathlib import Path
import common as C
CHANGED={'README.md','implementation/profile.json','implementation/baseline.py','implementation/source_guard.py','source-manifest.json'}
ADDED={'implementation/namespace_context.py','implementation/parent355.json'}
def data():return json.loads(C.read(C.HERE/'parent355.json'))
def one(raw,before,after):
 C.need(raw.count(before.encode())==1,'one exact source-context seam');return raw.replace(before.encode(),after.encode(),1)
def old_body(name,raw,p):
 if name=='implementation/profile.json':
  v=json.loads(raw);C.need({k:v[k]for k in p['profile_after']}==p['profile_after'],'closed exact public1197 source context');v.update(p['profile_before']);return C.enc(v)
 if name=='README.md':
  raw=one(raw,p['before357']['readme_after'],p['before357']['readme_before']);oldp=dict(p,**p['before357']['parent_context']);return one(one(raw,oldp['README_after'],p['README_before']),oldp['README_after2'],p['README_before2'])
 if name=='implementation/baseline.py':return one(raw,"fresh=C.safe(fresh);__import__('namespace_context').fresh(fresh);p=C.profile();",'fresh=C.safe(fresh);p=C.profile();')
 if name=='implementation/source_guard.py':return one(one(raw," __import__('namespace_context').verify()\n",''),'whole corrected1197 fixed-target installer source','whole corrected1176 fixed-target installer source')
 return raw

def verify():
 return __import__('authority').source_preflight()

CONTEXT_CHANGED={'README.md','implementation/profile.json','implementation/namespace_context.py','implementation/parent355.json','implementation/source_guard.py','source-manifest.json'}
def verify357():
 p=data();b=p['before357'];before=b['files'];C.need(b['pin']==dict(bytes=61473,sha256='40937b8a895618c2d4498c5d62ae23ae2792afe01bd869788b72fe9d1cde0047')and C.pin(C.enc(before))==b['pin'],'exact frozen357 before map');actual=C.rows(C.ROOT);C.need(set(actual)==set(before)and len(actual)==357,'same closed357 namespace')
 for n,w in before.items():
  raw=C.read(C.ROOT/n)
  if n=='README.md':raw=one(raw,b['readme_after'],b['readme_before'])
  elif n=='implementation/profile.json':
   v=json.loads(raw);v.update(b['parent_context']['profile_after']);raw=C.enc(v)
  elif n=='implementation/namespace_context.py':raw=b['namespace_body'].encode()
  elif n=='implementation/parent355.json':
   v=dict(p);v.pop('before357');v.update(b['parent_context']);raw=C.enc(v)
  elif n=='implementation/source_guard.py':raw=one(raw,'whole corrected1197 fixed-target installer source','whole corrected1178 fixed-target installer source')
  elif n=='source-manifest.json':
   v=json.loads(raw);v['files']={k:r for k,r in before.items()if k!='source-manifest.json'};raw=C.enc(v)
  C.need(C.pin(raw)==w,'complete357 before-body inverse '+n)
 C.need({n for n in before if actual[n]!=before[n]}==CONTEXT_CHANGED,'only six context operands; all runtime bodies held');return dict(files=357,held=351,changed=6,added=0)

def fresh(root):
 root=C.safe(root);p=data();expected=p['profile_after']['fresh_source_files'];C.need(p['profile_after']['fresh_source']=='b9976eea34eaed4b6e56af3be21d4d652fa971d6'and p['profile_after']['fresh_ref']=='codex/latest607-fresh-tooling-inputs-v1'and C.pin(C.enc(expected))==CURRENT_MAP,'exact public1197 source input, never installed authority');C.need(C.rows(root)==expected and len(expected)==1197,'whole exact published1197 source, no old, baseline or foreign substitution')
 # Execute only this exact pinned SOURCE CLI, in a separate namespace and private copy.
 # No imported child aliases, Git command, collected code or package/runtime actor.
 with tempfile.TemporaryDirectory(prefix='updater-fixed1197-')as td:
  private=Path(td)/'source';private.mkdir(mode=0o700)
  for n,w in expected.items():
   q=private/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(C.checked(root/n,w))
  C.need(C.rows(private)==expected and C.rows(root)==expected,'whole source copy and late input identity before execution');env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')}
  proc=subprocess.Popen([sys.executable,'-I','-B','-Werror',str(private/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
  try:out,err=proc.communicate(timeout=300)
  except BaseException:
   try:os.killpg(proc.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   proc.communicate(timeout=10);raise
  C.need(proc.returncode==0 and not err and len(out)<65536,'complete exact1197/1192/1189/1185/1182/1180/1178 source CLI');fact=json.loads(out);C.need(fact['files']==1197 and fact['fresh607']=='NOT_RUN'and fact['status']=='PASS_SOURCE_ONLY_EXACT_ORIGINAL35_TOOLING_INPUT_PREPARATION'and all(fact[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'whole current source-only predicate, no installed/native authority');C.need(C.rows(private)==expected and C.rows(root)==expected,'whole source input preserved after full guard')
 return fact
CURRENT_MAP={'bytes': 221235, 'sha256': '26902de45f63d4873a3be035adad610f9b2ad76cd2c798676424a2e3edf39a85'}


def cache_before(parent,values):
 """One source-DATA inverse before the original357/355/208 proof, no runtime cache."""
 b=parent['producer_cleanup_binding'];C.need(b['source_files_pin']==dict(bytes=61920,sha256='1cc1d3e90399991e7cca6225de416e2da995c312fe70a2f2b7c7ba0bfa7b99a7')and C.pin(C.enc(b['files']))==b['source_files_pin']and len(b['files'])==360 and set(values)==set(b['files'])and b['acceptance']is False and all(b[k]is None for k in('actual_source','actual_ref','actual_run')),'exact frozen descriptor360 source DATA before cleanup, never runtime authority')
 previous=dict(parent);previous.pop('producer_cleanup_binding');restored={}
 for n,w in b['files'].items():
  if n=='implementation/parent355.json':raw=C.enc(previous)
  elif n in b['before_bodies']:raw=b['before_bodies'][n].encode()
  elif n=='source-manifest.json':
   m=json.loads(values[n]);m['files']={k:r for k,r in b['files'].items()if k!='source-manifest.json'};raw=C.enc(m)
  else:raw=values[n]
  C.need(C.pin(raw)==w,'whole descriptor360 before private cleanup inverse '+n);restored[n]=raw
 C.need({n for n in values if C.pin(values[n])!=b['files'][n]}==set(b['before_bodies'])|{'implementation/parent355.json','source-manifest.json'},'only cleanup runtime/guard/control/context/seal changes')
 raw=values['implementation/runtime.py'].decode()
 for row in reversed(b['runtime_seams']):C.need(raw.count(row['after'])==1,'one private cleanup runtime inverse');raw=raw.replace(row['after'],row['before'],1)
 C.need(C.pin(raw.encode())==b['files']['implementation/runtime.py'],'entire original runtime/normal86/87/security/clock body inverse')
 raw=values['implementation/namespace_context.py'].decode();C.need(raw.count(b['guard_insert'])==1 and C.pin(raw.replace(b['guard_insert'],'',1).encode())==b['files']['implementation/namespace_context.py'],'whole prior source guard body inverse')
 raw=values['test_source.py'].decode();C.need(raw.count(b['tests_append'])==1,'one cleanup controls insertion');raw=raw.replace(b['tests_append'],'',1);C.need(raw.count("countTestCases()==32,'nonzero exact32 source groups'")==1,'exact32 nonzero current controls');raw=raw.replace("countTestCases()==32,'nonzero exact32 source groups'","countTestCases()==26,'nonzero exact26 source groups'",1);C.need(raw.count('self.assertEqual(len(runtime.OWNER_EDITS),7)')==1,'exact additional cleanup owner seam assertion');raw=raw.replace('self.assertEqual(len(runtime.OWNER_EDITS),7)','self.assertEqual(len(runtime.OWNER_EDITS),6)',1);C.need(C.pin(raw.encode())==b['files']['test_source.py'],'all original26 controls unchanged')
 parent,values=previous,restored
 b=parent['descriptor_source_binding'];C.need(b['source']=='4ddc6297db8d72a571f7759c947fd63a094b9ebd'and b['ref']=='codex/latest607-updater-materializer-policy-binding-v1'and len(b['files'])==360 and set(values)==set(b['files'])and b['acceptance']is False and all(b[k]is None for k in('actual_source','actual_ref','actual_run')),'exact descriptor source parent360 and no actual authority')
 previous=dict(parent);previous.pop('descriptor_source_binding');restored={}
 for n,w in b['files'].items():
  if n=='implementation/parent355.json':raw=C.enc(previous)
  elif n in b['before_bodies']:raw=b['before_bodies'][n].encode()
  elif n=='source-manifest.json':
   m=json.loads(values[n]);m['files']={k:r for k,r in b['files'].items()if k!='source-manifest.json'};raw=C.enc(m)
  else:raw=values[n]
  C.need(C.pin(raw)==w,'entire descriptor-before360 source body inverse '+n);restored[n]=raw
 current=dict(values);need_changed=set(b['before_bodies'])|{'implementation/parent355.json','source-manifest.json'};C.need({n for n in current if C.pin(current[n])!=b['files'][n]}==need_changed,'only closed descriptor derivation/map/control operands')
 raw=current['implementation/namespace_context.py'].decode();C.need(raw.count(b['guard_insert'])==1 and C.pin(raw.replace(b['guard_insert'],'',1).encode())==b['files']['implementation/namespace_context.py'],'whole original namespace guard inverse')
 raw=current['implementation/adapter.py'].decode();C.need(raw.count(b['adapter_insert'])==1 and C.pin(raw.replace(b['adapter_insert'],'',1).encode())==b['files']['implementation/adapter.py'],'whole original typed adapter inverse')
 raw=current['test_source.py'].decode();C.need(raw.count(b['tests_append'])==1,'one exact descriptor control insertion');raw=raw.replace(b['tests_append'],'',1);C.need(raw.count("countTestCases()==26,'nonzero exact26 source groups'")==1,'exact current26 source controls');raw=raw.replace("countTestCases()==26,'nonzero exact26 source groups'","countTestCases()==22,'nonzero exact22 source groups'",1);C.need(C.pin(raw.encode())==b['files']['test_source.py'],'entire original22 control bodies inverse')
 profile=json.loads(current['implementation/profile.json']);old_profile=json.loads(b['before_bodies']['implementation/profile.json'])
 for case in C.CASES:
  name='cases/'+case+'/scripts/update/aux_copy.py';raw=current[name].decode();C.need(raw.count(b['descriptor_after'])==1 and C.pin(raw.replace(b['descriptor_after'],b['descriptor_before'],1).encode())==b['files'][name],'whole exact original descriptor body inverse '+case)
  name='cases/'+case+'/upgrade-config.json';cfg=json.loads(current[name]);C.need(cfg['code_pins']['scripts/update/aux_copy.py']==C.pin(current['cases/'+case+'/scripts/update/aux_copy.py'])['sha256'],'exact current descriptor code pin');cfg['code_pins']['scripts/update/aux_copy.py']=json.loads(b['before_bodies'][name])['code_pins']['scripts/update/aux_copy.py'];C.need(C.pin(C.enc(cfg))==b['files'][name],'whole original code-pin config and every clock inverse '+case)
  for name in ('scripts/update/aux_copy.py','upgrade-config.json'):profile['cases'][case][name]=old_profile['cases'][case][name]
  profile['old_source_lineage'][case]['scripts/update/aux_copy.py']=old_profile['old_source_lineage'][case]['scripts/update/aux_copy.py']
 C.need(C.pin(C.enc(profile))==b['files']['implementation/profile.json']and b['allowed_full_root']==dict(bytes=35970,sha256='cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'),'whole original exact profile inverse; fixed original descriptor seal held')
 parent,values=previous,restored
 b=parent['materializer_policy_binding'];C.need(b['source']=='ed981eb930d6efc3744c580e7d0f4cb3195cd081'and b['ref']=='codex/latest607-updater-runtime-cache-argument-v1'and b['scope']=='EXACT_ORIGINAL_COMPOSITION_POLICY_TO_MATERIALIZER_INSTALLER_POLICY_HELD'and len(b['files'])==360 and set(values)==set(b['files'])and all(b[k]is None for k in('actual_source','actual_ref','actual_run'))and b['acceptance']is False,'whole materializer policy parent source-only context')
 raw=values['implementation/runtime.py'].decode()
 for a,z in reversed(b['runtime_edits']):C.need(raw.count(z)==1,'one exact composition policy operand inverse');raw=raw.replace(z,a,1)
 C.need(C.pin(raw.encode())==b['files']['implementation/runtime.py'],'entire original runtime body policy inverse')
 raw=values['implementation/namespace_context.py'].decode();C.need(raw.count(b['guard_insert'])==1,'one complete policy guard insertion');C.need(C.pin(raw.replace(b['guard_insert'],'',1).encode())==b['files']['implementation/namespace_context.py'],'whole old namespace guard inverse')
 raw=values['test_source.py'].decode();C.need(raw.count(b['test_append']+'\n')==1,'one complete source regression insertion');raw=raw.replace(b['test_append']+'\n','',1);C.need(raw.count("countTestCases()==22,'nonzero exact22 source groups'")==1,'one current nonzero source suite');raw=raw.replace("countTestCases()==22,'nonzero exact22 source groups'","countTestCases()==19,'nonzero exact19 source groups'",1);C.need(C.pin(raw.encode())==b['files']['test_source.py'],'whole original19 source controls inverse')
 previous=dict(parent);previous.pop('materializer_policy_binding');restored={}
 for n,w in b['files'].items():
  if n=='implementation/parent355.json':raw=C.enc(previous)
  elif n in b['before_bodies']:raw=b['before_bodies'][n].encode()
  elif n=='source-manifest.json':
   m=json.loads(values[n]);m['files']={k:r for k,r in b['files'].items()if k!='source-manifest.json'};raw=C.enc(m)
  else:raw=values[n]
  C.need(C.pin(raw)==w,'whole original360 materializer policy inverse '+n);restored[n]=raw
 C.need(set(b['before_bodies'])=={'implementation/runtime.py','implementation/namespace_context.py','test_source.py'},'only current policy/guard/regression before operands');parent,values=previous,restored
 c=parent['dependency_cache_context'];b=c['argument_binding'];C.need(b['source']=='764da54af95f91ad7e72059b3c0eea0af0631774'and b['ref']=='codex/latest607-updater-dependency-cache-v1'and len(b['files'])==360 and set(values)==set(b['files'])and all(b[k]is None for k in('actual_source','actual_ref','actual_run'))and b['acceptance']is False,'whole published360 runtime-argument before context, actualNULL')
 previous=dict(parent);oldcache=dict(c);oldcache.pop('argument_binding');previous['dependency_cache_context']=oldcache;restored={}
 for n,w in b['files'].items():
  if n=='implementation/parent355.json':raw=C.enc(previous)
  elif n in b['before_bodies']:raw=b['before_bodies'][n].encode()
  elif n=='source-manifest.json':
   m=json.loads(values[n]);m['files']={k:r for k,r in b['files'].items()if k!='source-manifest.json'};raw=C.enc(m)
  else:raw=values[n]
  C.need(C.pin(raw)==w,'whole original360 argument-binding inverse '+n);restored[n]=raw
 C.need(set(b['before_bodies'])=={'implementation/runtime.py','implementation/namespace_context.py','test_source.py'},'only runtime argument/control/previous context operands');parent,values=previous,restored
 c=parent['dependency_cache_context'];before=c['files'];C.need(c['source']=='01afa13fc81831099dab2bacdcbb59a9b030b5b6'and c['ref']=='codex/latest607-updater-bound-v1'and len(before)==357 and set(values)==set(before)|{'implementation/compiler6.py','implementation/compiler6-profile.json','implementation/producer_diagnostic.py'},'whole bound357 plus only three cache operands')
 C.need(c['reused_source']=='ddfc78e30552356baa94fa123f17fd33efc2aedc'and c['reused_ref']=='codex/latest607-fresh-dependency-cache-v1'and C.profile()['dependency_cache']['operands']==c['operands'],'exact public source-owned cache/diagnostic operands')
 for n,w in c['operands'].items():C.need(C.pin(values['implementation/'+n])==w,'whole byte-held reused helper '+n)
 import cache
 cache.dependency_policy();helper=C.load('_source_only_dependency_policy',C.HERE/'compiler6.py');helper.dependency_configuration()
 prior=dict(parent);prior.pop('dependency_cache_context');restored={}
 for n,w in before.items():
  if n=='implementation/parent355.json':raw=C.enc(prior)
  elif n in c['before_bodies']:raw=c['before_bodies'][n].encode()
  elif n=='source-manifest.json':
   manifest=json.loads(values[n]);manifest['files']={k:r for k,r in before.items()if k!='source-manifest.json'};raw=C.enc(manifest)
  else:raw=values[n]
  C.need(C.pin(raw)==w,'entire bound357 dependency-before inverse '+n);restored[n]=raw
 return prior,restored
