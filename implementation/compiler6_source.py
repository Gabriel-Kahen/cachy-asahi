# SPDX-License-Identifier: MIT
"""Whole diagnostic1185 source AND exact compiler6 preparation-only successor."""
import base64,json,os,subprocess,sys,tempfile,zlib
from pathlib import Path
import common as C
PARENT_PIN='8e4981a4fada1049523289c4d3718acc333f21a35742d620775405f82ba80f9e'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
SUFFIX=b'\n# BEGIN_EXACT_COMPILER6_CACHE_PREPARATION\ndef verify():\n import compiler6_source\n return compiler6_source.verify()\n'
STEP='      - name: Checkout exact retained compiler6 archive and signature inputs\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 8ee14069b7a74455a7bea1171ba319932c9df304\n          path: retained-compiler6\n          persist-credentials: false\n      - name: Join six original354 compiler inputs into the same private cache\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        timeout-minutes: 5\n        shell: bash\n        run: |\n          set -euo pipefail\n          test "$(git -C "$GITHUB_WORKSPACE/retained-compiler6" rev-parse HEAD)" = 8ee14069b7a74455a7bea1171ba319932c9df304\n          test "$(git -C "$GITHUB_WORKSPACE/composition-updater" rev-parse HEAD)" = 1aea667aec50a62ba0ab2dad44be24a4dc3bd098\n          deadline=$(env -i PATH=/usr/bin:/bin python3 -I -B -c \'import time; print(time.monotonic()+240)\')\n          env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" LANG=C.UTF-8 TZ=UTC TMPDIR="$RUNNER_TEMP" \\\n            python3 -I -B "$GITHUB_WORKSPACE/fresh607-code/implementation/compiler6.py" \\\n              --carrier "$GITHUB_WORKSPACE/retained-compiler6" \\\n              --updater "$GITHUB_WORKSPACE/composition-updater" \\\n              --desktop-lock "$GITHUB_WORKSPACE/retained-complete574/desktop574-inputs.lock.json" \\\n              --cache "$RUNNER_TEMP/alarm-cache" --deadline "$deadline"\n'
OLD="template=__import__('cache_controls_context').with_cache(workflow.derive(old));self.assertEqual"
NEW="template=__import__('compiler6_source').with_compiler6(__import__('cache_controls_context').with_cache(workflow.derive(old)));self.assertEqual"

def with_compiler6(template):
 anchor=b'      - name: Checkout the proven 574-package runtime builder\n';C.need(template.count(anchor)==1 and STEP.encode()not in template,'one exact354 checkout-to-producer compiler6 preparation seam');return template.replace(anchor,STEP.encode()+anchor,1)
def transformed(before,helper,proof,profile,parent):
 out=dict(before);C.need(len(before)==1185,'whole original diagnostic1185 source');out['implementation/workflow-template.yml']=with_compiler6(before['implementation/workflow-template.yml']);out['implementation/source_guard.py']=before['implementation/source_guard.py']+SUFFIX;test=before['implementation/test_source.py'];C.need(test.count(OLD.encode())==1,'one whole current workflow expectation seam');out['implementation/test_source.py']=test.replace(OLD.encode(),NEW.encode(),1)
 out.update({'implementation/compiler6.py':helper,'implementation/compiler6_source.py':proof,'implementation/compiler6-profile.json':profile,'implementation/compiler6-parent.json':parent});manifest=json.loads(before['source-manifest.json']);manifest['files']={n:C.pin(b)for n,b in out.items()if n not in(*ALIASES,'source-manifest.json')};out['source-manifest.json']=C.enc(manifest)
 for n in ALIASES:out[n]=out['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',C.pin(out['source-manifest.json'])['sha256'].encode())
 C.need(len(out)==1189 and set(out)-set(before)=={'implementation/compiler6.py','implementation/compiler6_source.py','implementation/compiler6-profile.json','implementation/compiler6-parent.json'},'complete1189 namespace');return out

def rows(root):
 out={}
 for p in root.rglob('*'):
  n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  C.need('.git'not in n.parts and not p.is_symlink()and(p.is_dir()or p.is_file()),'closed ordinary source namespace')
  if p.is_file():out[n.as_posix()]=C.pin(C.read(p))
 return out

def inverse():
 raw=C.read(C.HERE/'compiler6-parent.json');C.need(C.pin(raw)['sha256']==PARENT_PIN,'whole compiler6 parent profile');p=json.loads(raw);before=p['before'];C.need(len(before)==1185 and before==p['authorization']==p['git']['files']and p['publication']['source']=='2235c1d3c3b3de6d8a2ff30f66c5fd0df56c2ef6','whole authentic diagnostic1185 publication');actual=rows(C.ROOT);old={}
 for n,w in before.items():
  if n in p['before_bodies_zlib']:
   d=zlib.decompressobj();b=d.decompress(base64.b64decode(p['before_bodies_zlib'][n],validate=True),16*1024**2+1);C.need(d.eof and not d.unused_data and not d.unconsumed_tail,'complete bounded before body')
  else:b=C.read(C.ROOT/n)
  C.need(C.pin(b)==w,'whole before1185 body '+n);old[n]=b
 proof=C.read(C.HERE/'compiler6_source.py');C.need(C.pin(proof.replace(PARENT_PIN.encode(),b'PARENT_PIN_PLACEHOLDER'))==p['guard_template'],'whole current compiler6 guard template');expected=transformed(old,C.read(C.HERE/'compiler6.py'),proof,C.read(C.HERE/'compiler6-profile.json'),raw);C.need(actual=={n:C.pin(b)for n,b in expected.items()},'whole1189 exact finite source inverse');return p,old,actual

def verify():
 import compiler6
 compiler6.configuration();p,old,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='compiler6-whole1185-')as td:
  root=Path(td)/'source';root.mkdir(mode=0o700)
  for n,b in old.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  C.need(rows(root)==p['before'],'complete1185 reconstruction before original source entry');env={k:v for k,v in os.environ.items()if k not in('GH_TOKEN','GITHUB_TOKEN','PYTHONPATH','PYTHONHOME')};v=subprocess.run([sys.executable,'-I','-B','-Werror',str(root/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,capture_output=True,timeout=300,env=env);C.need(v.returncode==0 and not v.stderr and len(v.stdout)<65536,'whole diagnostic1185 AND1182/1180/1178 source entry');parent=json.loads(v.stdout);C.need(parent['files']==1185 and parent['status']=='PASS_SOURCE_ONLY_FIXED_PRODUCER_BUILD_FAILURE_DIAGNOSTICS','exact original diagnostic source proof');C.need(rows(root)==p['before']and rows(C.ROOT)==actual,'all source before/after unchanged')
 return dict(parent,status='PASS_SOURCE_ONLY_EXACT_COMPILER6_CACHE_CHILD',files=1189,parent_files=1185,parent_status=parent['status'],parent_proof=parent,held=1179,changed=6,added=4,compiler6='UNAUTHENTICATED_DATA_ORIGINAL_GPG_METADATA_BUILD_MANDATORY',actual_source=None,actual_ref=None,actual_run=None,root_acceptance='NOT_ISSUED',hardware='NOT_RUN')
