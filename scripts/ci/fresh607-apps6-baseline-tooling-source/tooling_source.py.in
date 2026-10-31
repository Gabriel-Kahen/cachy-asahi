# SPDX-License-Identifier: MIT
"""Complete1192 source AND exact original35 tooling input preparation."""
import base64,json,os,subprocess,sys,tempfile,zlib
from pathlib import Path
import common as C
PARENT_PIN='fcb56e9a3ae395b0ecfb16a0688ac4fa61245df9511b60302c20cf62885a34f6'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
SUFFIX=b'\n# BEGIN_EXACT_ORIGINAL35_TOOLING_INPUT_PREPARATION\ndef verify():\n import tooling_source\n return tooling_source.verify()\n'
STEP='''      - name: Checkout exact retained original35 tooling inputs
        if: ${{ !cancelled() && steps.fdk_pair.outcome == 'success' }}
        timeout-minutes: 5
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: fb515d735a81194f06ea117539dee60438bb8d87
          path: fresh607-tooling-inputs
          persist-credentials: false
'''
OLD="template=__import__('compiler6_source').with_compiler6(__import__('baseline_cache').with_cache(workflow.derive(old)));self.assertEqual"
NEW="template=__import__('tooling_source').with_tooling(__import__('compiler6_source').with_compiler6(__import__('baseline_cache').with_cache(workflow.derive(old))));self.assertEqual"
SEED="            with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))"
EDITS=(
 ('source_guard,runtime_context','source_guard,runtime_context,tooling_inputs'),
 ('EDITS=(\n',"EDITS=(\n ("+repr(SEED)+","+repr("            Y.seed_tooling(auditor,downloads,cache,owner)\n"+SEED)+"),\n"),
 (" def tooling(self):return runtime_context.tooling(self.contract,self.legacy)"," def tooling(self):return runtime_context.tooling(self.contract,self.legacy)\n def seed_tooling(self,auditor,downloads,cache,owner):\n  C.need(self.tooling_root is not None,'explicit exact tooling carrier required');return tooling_inputs.seed(self.tooling_root,self.legacy,downloads,cache,owner)"),
 (" def __init__(self,record,public,legacy,contract,source=None,decision=None):self.record", " def __init__(self,record,public,legacy,contract,source=None,decision=None,tooling_root=None):self.tooling_root=tooling_root;self.record"),
 ("for n in('six-record','six-public','installer604-source'):","for n in('six-record','six-public','installer604-source','tooling-inputs'):"),
 ("record,public,oldroot=map(C.safe,(new.six_record,new.six_public,new.installer604_source))", "record,public,oldroot,tooling_root=map(C.safe,(new.six_record,new.six_public,new.installer604_source,new.tooling_inputs))"),
 ("contract=load('_latest607_complete_old_contract'", "revision(tooling_root,tooling_inputs.SOURCE);tooling_inputs.preflight(tooling_root,legacy)\n contract=load('_latest607_complete_old_contract'"),
 ("Integration(record,public,legacy,contract,new.fresh_source_revision,decision)","Integration(record,public,legacy,contract,new.fresh_source_revision,decision,tooling_root)"),
)
def run_body(before):
 out=before
 for a,b in EDITS:C.need(out.count(a.encode())==1,'one exact1192 tooling preparation seam');out=out.replace(a.encode(),b.encode(),1)
 restored=out
 for a,b in reversed(EDITS):C.need(restored.count(b.encode())==1,'one exact tooling preparation inverse');restored=restored.replace(b.encode(),a.encode(),1)
 C.need(restored==before,'whole1192 runtime owner inverse');compile(out,'<whole-original-owner-plus-tooling-cache>','exec');return out

def with_tooling(template):
 anchor=b'      - name: Required fresh latest607 installation in the separately owned VM\n';C.need(template.count(anchor)==1 and STEP.encode()not in template,'one whole1192 workflow preparation seam');out=template.replace(anchor,STEP.encode()+anchor,1)
 old=b'--installer604-source "$GITHUB_WORKSPACE/expanded604-installer" --fresh-source-revision "$FRESH_SOURCE" \\\n';new=old+b'              --tooling-inputs "$GITHUB_WORKSPACE/fresh607-tooling-inputs" \\\n';C.need(out.count(old)==1,'one source-owned tooling input selector');out=out.replace(old,new,1);C.need(out.replace(new,old,1).replace(STEP.encode(),b'',1)==template,'entire1192 workflow inverse');return out

def transformed(before,helper,guard,profile,builder,parent):
 C.need(len(before)==1192,'whole published1192 parent');out=dict(before);out['implementation/run.py']=run_body(before['implementation/run.py']);out['implementation/workflow-template.yml']=with_tooling(before['implementation/workflow-template.yml']);out['implementation/source_guard.py']=before['implementation/source_guard.py']+SUFFIX;test=before['implementation/test_source.py'];C.need(test.count(OLD.encode())==1,'one honest current workflow control expectation');out['implementation/test_source.py']=test.replace(OLD.encode(),NEW.encode(),1)
 out.update({'implementation/tooling_inputs.py':helper,'implementation/tooling_source.py':guard,'implementation/tooling-profile.json':profile,'implementation/tooling-builder574.lock':builder,'implementation/tooling-parent.json':parent});manifest=json.loads(before['source-manifest.json']);manifest['files']={n:C.pin(b)for n,b in out.items()if n not in(*ALIASES,'source-manifest.json')};out['source-manifest.json']=C.enc(manifest)
 for n in ALIASES:out[n]=out['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',C.pin(out['source-manifest.json'])['sha256'].encode())
 C.need(len(out)==1197 and len(set(out)-set(before))==5,'closed1197 source namespace');return out

def rows(root):
 out={}
 for p in root.rglob('*'):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  C.need('.git'not in n.parts and not p.is_symlink()and(p.is_dir()or p.is_file()),'closed ordinary source namespace')
  if p.is_file():out[n.as_posix()]=C.pin(C.read(p))
 return out

def inverse():
 raw=C.read(C.HERE/'tooling-parent.json');C.need(C.pin(raw)['sha256']==PARENT_PIN,'whole current1192 parent context');p=json.loads(raw);before=p['before'];C.need(len(before)==1192 and before==p['authorization']==p['git']['files']and p['publication']['source']=='412742e6320aaf8f546c537cdcda534a843b6dcd','exact public1192 source/auth/Git join');old={}
 for n,w in before.items():
  if n in p['before_bodies_zlib']:
   d=zlib.decompressobj();b=d.decompress(base64.b64decode(p['before_bodies_zlib'][n],validate=True),w['bytes']+1);C.need(d.eof and not d.unused_data and not d.unconsumed_tail,'bounded whole parent1192 operand')
  else:b=C.read(C.ROOT/n)
  C.need(C.pin(b)==w,'whole1192 source body '+n);old[n]=b
 guard=C.read(C.HERE/'tooling_source.py');C.need(C.pin(guard.replace(PARENT_PIN.encode(),b'PARENT_PIN_PLACEHOLDER'))==p['guard_template'],'whole tooling guard template');expected=transformed(old,C.read(C.HERE/'tooling_inputs.py'),guard,C.read(C.HERE/'tooling-profile.json'),C.read(C.HERE/'tooling-builder574.lock'),raw);actual=rows(C.ROOT);C.need(actual=={n:C.pin(b)for n,b in expected.items()},'complete1197 finite whole1192 inverse');return p,old,actual

def verify():
 import tooling_inputs
 tooling_inputs.configuration();p,old,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='tooling-whole1192-')as td:
  root=Path(td)/'source';root.mkdir(mode=0o700)
  for n,b in old.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  C.need(rows(root)==p['before'],'entire1192 before original preflight');env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')};v=subprocess.run([sys.executable,'-I','-B','-Werror',str(root/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,capture_output=True,timeout=300,env=env)
  C.need(v.returncode==0 and not v.stderr and len(v.stdout)<65536,'complete1192/1189/1185/1182/1180/1178 source guards');parent=json.loads(v.stdout);C.need(parent['files']==1192 and parent['status']=='PASS_SOURCE_ONLY_APPS6_BASELINE_SCOPED_LEGACY_TOOLING_OWNED_CACHE_RETIREMENT'and parent['Apps_version']=='0.1.0-6'and parent['other606']=='HELD','original1192 source guard remains mandatory');C.need(rows(root)==p['before']and rows(C.ROOT)==actual,'all source before/after unchanged')
 return dict(parent,status='PASS_SOURCE_ONLY_APPS6_BASELINE_EXACT_ORIGINAL35_TOOLING_INPUT_PREPARATION',files=1197,parent_files=1192,parent_status=parent['status'],parent_proof=parent,held=1185,changed=7,added=5,tooling='EXACT_PUBLIC35_DATA_ORIGINAL_FETCH_AND_GPG_VM_REQUIRED',actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN')
