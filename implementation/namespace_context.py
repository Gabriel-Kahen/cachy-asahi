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
