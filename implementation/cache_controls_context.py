# SPDX-License-Identifier: MIT
"""Whole1180 AND1178 source entry; adapt one current workflow expectation only."""
import json,subprocess,sys,tempfile
from pathlib import Path
import common as C
import retained_cache as held
PARENT={'bytes': 218722, 'sha256': 'cb4b92b57048d8b6e14ec73d16d167a64d848829cd33535e8f92fa3f84fdab15'}
ALIASES=held.ALIASES
SUFFIX=b'\n# BEGIN_CURRENT_CACHE_WORKFLOW_CONTROL\ndef verify():\n import cache_controls_context\n return cache_controls_context.verify()\n'
OLD='template=workflow.derive(old);self.assertEqual'
NEW="template=__import__('cache_controls_context').with_cache(workflow.derive(old));self.assertEqual"
CHANGED={'implementation/test_source.py','implementation/source_guard.py','source-manifest.json',*ALIASES}
ADDED={'implementation/parent1180.json','implementation/cache_controls_context.py'}
rows=held.rows

def with_cache(template):
 anchor=b'      - name: Build the fresh native base and original package pairs\n';C.need(template.count(anchor)==1 and held.STEP.encode()not in template,'one original workflow cache expectation seam');return template.replace(anchor,held.STEP.encode()+anchor,1)

def inverse():
 before=json.loads(C.checked(C.HERE/'parent1180.json',PARENT));actual=rows(C.ROOT);C.need(len(before)==1180 and set(actual)==set(before)|ADDED,'whole1180 and exactly two current-control operands');C.need({n for n in before if before[n]!=actual[n]}==CHANGED,'only test expectation/guard/manifest/seals changed');bodies={}
 for n,w in before.items():
  if n in(*ALIASES,'source-manifest.json'):continue
  b=C.read(C.ROOT/n)
  if n=='implementation/test_source.py':C.need(b.count(NEW.encode())==1,'one current workflow expectation inverse');b=b.replace(NEW.encode(),OLD.encode(),1)
  if n=='implementation/source_guard.py':C.need(b.endswith(SUFFIX)and b.count(SUFFIX)==1,'complete original1180 guard prefix');b=b[:-len(SUFFIX)]
  C.need(C.pin(b)==w,'entire1180 body '+n);bodies[n]=b
 manifest=json.loads(C.read(C.ROOT/'source-manifest.json'));C.need(manifest['files']=={n:w for n,w in actual.items()if n not in(*ALIASES,'source-manifest.json')},'complete current1182 manifest');manifest['files']={n:w for n,w in before.items()if n not in(*ALIASES,'source-manifest.json')};bodies['source-manifest.json']=C.enc(manifest);C.need(C.pin(bodies['source-manifest.json'])==before['source-manifest.json'],'whole1180 manifest inverse')
 template=C.read(C.HERE/'workflow-template.yml');current=template.replace(b'@FRESH607_MANIFEST@',actual['source-manifest.json']['sha256'].encode());prior=template.replace(b'@FRESH607_MANIFEST@',before['source-manifest.json']['sha256'].encode())
 for n in ALIASES:C.need(C.read(C.ROOT/n)==current and C.pin(prior)==before[n],'whole1180/current aliases');bodies[n]=prior
 return before,bodies,actual

def verify():
 before,bodies,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='cache-control-parent-')as folder:
  parent=Path(folder)/'source';parent.mkdir(mode=0o700)
  for n,b in bodies.items():p=parent/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  C.need(rows(parent)==before,'whole1180 reconstruction before complete mandatory source entry')
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(parent/'implementation/run.py'),'--source-preflight'],capture_output=True,timeout=300);C.need(result.returncode==0 and not result.stderr and len(result.stdout)<65536,'entire1180 AND1178 source entry required');original=json.loads(result.stdout);C.need(rows(parent)==before and rows(C.ROOT)==actual,'whole source pre/post unchanged')
 return dict(original,status='PASS_SOURCE_ONLY_COMPLETE574_CACHE_CURRENT_CONTROLS_CHILD',files=len(actual),parent_files=1180,parent_status=original['status'],held=1175,changed=5,added=2,current_controls='CURRENT10_REQUIRED_SEPARATE_RECEIPTS',fresh607='NOT_RUN',actual_source=None,actual_ref=None,actual_run=None,hardware='NOT_RUN')
