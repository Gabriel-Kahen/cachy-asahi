# SPDX-License-Identifier: MIT
"""Whole1189 source proof plus two finite import/cache-lifetime fixes."""
import base64,json,os,subprocess,sys,tempfile,zlib
from pathlib import Path
import common as C
PARENT_PIN='9a1d4e2f11ba9b8e001613ecb0dd5260a9a0d2355b1e6e57c914bc008b935776'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
SUFFIX=b'\n# BEGIN_SCOPED_LEGACY_TOOLING_AND_OWNED_CACHE_RETIREMENT\ndef verify():\n import runtime_source\n return runtime_source.verify()\n'
EDITS=(('source_guard,producer_diagnostic', 'source_guard,producer_diagnostic,runtime_context'), ('EDITS=(\n', 'EDITS=(\n ("auditor=C.load(\'_fresh604_tooling\',args.legacy_source/\'scripts/virtual/audit_tooling.py\')","auditor=Y.tooling()"),\n'), (' def candidate(self,path):return adapter.emit(path)', ' def candidate(self,path):return adapter.emit(path)\n def tooling(self):return runtime_context.tooling(self.contract,self.legacy)'), ('   materialize.prepare(base,api.public,producer,target,helper=helper,verifier_api=verifier,checks=checks,payload_api=payload);return target', '   lease=runtime_context.BaseCache(producer,base)\n   try:materialize.prepare(base,api.public,producer,target,helper=helper,verifier_api=verifier,checks=checks,payload_api=payload)\n   finally:lease.retire()\n   return target'))
TEST_OLD="with patch('run.load',return_value=object()),patch('run.materialize.prepare',side_effect=lambda *a,**k:calls.append(('new',a))):"
TEST_NEW="with patch('run.runtime_context.BaseCache'),patch('run.load',return_value=object()),patch('run.materialize.prepare',side_effect=lambda *a,**k:calls.append(('new',a))):"
def run_body(raw):
 out=raw
 for a,b in EDITS:
  C.need(out.count(a.encode())==1,'one fixed current runtime integration seam');out=out.replace(a.encode(),b.encode(),1)
 inverse=out
 for a,b in reversed(EDITS):
  C.need(inverse.count(b.encode())==1,'one runtime integration inverse');inverse=inverse.replace(b.encode(),a.encode(),1)
 C.need(inverse==raw,'whole1189 run body inverse');compile(out,'<fresh607-scoped-runtime>','exec');return out
def transformed(before,helper,proof,parent):
 out=dict(before);C.need(len(before)==1189,'whole1189 compiler-cache source')
 out['implementation/run.py']=run_body(before['implementation/run.py'])
 out['implementation/source_guard.py']=before['implementation/source_guard.py']+SUFFIX
 test=before['implementation/test_source.py'];C.need(test.count(TEST_OLD.encode())==1,'one existing mock fixture seam');out['implementation/test_source.py']=test.replace(TEST_OLD.encode(),TEST_NEW.encode(),1)
 out.update({'implementation/runtime_context.py':helper,'implementation/runtime_source.py':proof,'implementation/runtime-parent.json':parent})
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:C.pin(b)for n,b in out.items()if n not in(*ALIASES,'source-manifest.json')};out['source-manifest.json']=C.enc(manifest)
 for n in ALIASES:out[n]=out['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',C.pin(out['source-manifest.json'])['sha256'].encode())
 C.need(len(out)==1192 and len(set(out)-set(before))==3,'whole1192 source namespace');return out
def rows(root):
 out={}
 for p in root.rglob('*'):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  C.need('.git'not in n.parts and not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary closed source namespace')
  if p.is_file():out[n.as_posix()]=C.pin(C.read(p))
 return out
def inverse():
 raw=C.read(C.HERE/'runtime-parent.json');C.need(C.pin(raw)['sha256']==PARENT_PIN,'fixed whole1189 parent profile');p=json.loads(raw);before=p['before']
 C.need(len(before)==1189 and before==p['authorization']==p['git']['files']and p['publication']['source']=='606e31cf03f66043bdbc13a44dcc8559ebe81ec7','exact authentic public1189')
 old={}
 for n,w in before.items():
  if n in p['before_bodies_zlib']:
   d=zlib.decompressobj();b=d.decompress(base64.b64decode(p['before_bodies_zlib'][n],validate=True),16*1024**2+1);C.need(d.eof and not d.unused_data and not d.unconsumed_tail,'complete bounded before source')
  else:b=C.read(C.ROOT/n)
  C.need(C.pin(b)==w,'whole1189 before source '+n);old[n]=b
 helper=C.read(C.HERE/'runtime_context.py');proof=C.read(C.HERE/'runtime_source.py');C.need(C.pin(helper)==p['helper']and C.pin(proof.replace(PARENT_PIN.encode(),b'PARENT_PIN_PLACEHOLDER'))==p['guard_template'],'fixed helper and guard source')
 actual=rows(C.ROOT);C.need(actual=={n:C.pin(b)for n,b in transformed(old,helper,proof,raw).items()},'whole1192 finite inverse');return p,old,actual
def verify():
 p,old,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='runtime-whole1189-')as td:
  root=Path(td)/'source';root.mkdir(mode=0o700)
  for n,b in old.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  C.need(rows(root)==p['before'],'whole1189 before original entry')
  env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')}
  v=subprocess.run([sys.executable,'-I','-B','-Werror',str(root/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,capture_output=True,timeout=300,env=env)
  C.need(v.returncode==0 and not v.stderr and len(v.stdout)<65536,'whole1189 and all original source gates');parent=json.loads(v.stdout)
  C.need(parent['files']==1189 and parent['status']=='PASS_SOURCE_ONLY_EXACT_COMPILER6_CACHE_CHILD','original1189 proof')
  C.need(rows(root)==p['before']and rows(C.ROOT)==actual,'all old/current source held')
 return dict(parent,status='PASS_SOURCE_ONLY_SCOPED_LEGACY_TOOLING_OWNED_CACHE_RETIREMENT',files=1192,parent_files=1189,parent_status=parent['status'],parent_proof=parent,held=1183,changed=6,added=3,actual_source=None,actual_ref=None,actual_run=None,hardware='NOT_RUN',root_acceptance='NOT_ISSUED')
