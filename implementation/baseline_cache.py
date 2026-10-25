# SPDX-License-Identifier: MIT
"""Complete baseline1183 AND1178 source guard; exact retained complete574 cache step."""
import json,subprocess,sys,tempfile
from pathlib import Path
import common as C
PARENT={'bytes': 219185, 'sha256': '49d8d2f37c2eca201eac182b2e04d987e8c23459216ba59489b15b8c3b762025'}
STEP=r'''      - name: Checkout exact complete574 retained package inputs
        if: inputs.mode == 'build'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad
          path: retained-complete574
          persist-credentials: false
      - name: Join all complete574 retained cache inputs before original acquisition
        if: inputs.mode == 'build'
        timeout-minutes: 5
        shell: bash
        run: |
          set -euo pipefail
          test "$(git -C "$GITHUB_WORKSPACE/retained-complete574" rev-parse HEAD)" = ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad
          test "$(sha256sum retained-complete574/seed.py | cut -d ' ' -f 1)" = 76b787fa71b121ec1bf83b86e4d5db849913614bc90e03239b869d7061af1db4
          test "$(sha256sum retained-complete574/index.json | cut -d ' ' -f 1)" = 51a53c9e0d9eab1728f350f9ab8d3d7b8932891ab0ed68c7876a1440166ff486
          test "$(sha256sum retained-complete574/desktop574-inputs.lock.json | cut -d ' ' -f 1)" = b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9
          test "$(sha256sum scripts/ci/native_arm.py | cut -d ' ' -f 1)" = a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898
          test "$(sha256sum scripts/ci/inputs.lock.json | cut -d ' ' -f 1)" = beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f
          deadline=$(env -i PATH=/usr/bin:/bin python3 -I -B -c 'import time; print(time.monotonic()+240)')
          env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" LANG=C.UTF-8 TZ=UTC TMPDIR="$RUNNER_TEMP" \
            python3 -I -B "$GITHUB_WORKSPACE/retained-complete574/seed.py" \
              --lock "$GITHUB_WORKSPACE/retained-complete574/desktop574-inputs.lock.json" \
              --cache "$RUNNER_TEMP/alarm-cache" --mode desktop574 --deadline "$deadline"
'''
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
SUFFIX=b'\n# BEGIN_BASELINE_COMPLETE574_CACHE_PREPARATION\ndef verify():\n return __import__(\'baseline_cache\').verify()\n'
OLD='template=workflow.derive(old);self.assertEqual'
NEW="template=__import__('baseline_cache').with_cache(workflow.derive(old));self.assertEqual"
CHANGED={'implementation/workflow-template.yml','implementation/test_source.py','implementation/source_guard.py','source-manifest.json',*ALIASES}
ADDED={'implementation/baseline-cache-parent.json','implementation/baseline_cache.py'}
def rows(root):
 out={}
 for p in root.rglob('*'):
  rel=p.relative_to(root)
  if rel.parts[0]=='.git':continue
  C.need('.git'not in rel.parts and not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary closed source; foreign Git refused')
  if p.is_file():out[rel.as_posix()]=C.pin(C.read(p))
 return out

def with_cache(template):
 anchor=b'      - name: Build the fresh native base and original package pairs\n';C.need(template.count(anchor)==1 and STEP.encode()not in template,'one baseline original build anchor without cache prefix');return template.replace(anchor,STEP.encode()+anchor,1)

def inverse():
 before=json.loads(C.checked(C.HERE/'baseline-cache-parent.json',PARENT));actual=rows(C.ROOT);C.need(len(before)==1183 and set(actual)==set(before)|ADDED,'whole baseline1183 and exactly two cache operands');C.need({n for n in before if actual[n]!=before[n]}==CHANGED,'only six baseline workflow/test/guard/manifest changes');bodies={}
 for n,w in before.items():
  if n in(*ALIASES,'source-manifest.json'):continue
  b=C.read(C.ROOT/n)
  if n=='implementation/workflow-template.yml':C.need(b.count(STEP.encode())==1,'one fixed complete574 cache step');b=b.replace(STEP.encode(),b'',1)
  if n=='implementation/test_source.py':C.need(b.count(NEW.encode())==1,'one current baseline workflow control inverse');b=b.replace(NEW.encode(),OLD.encode(),1)
  if n=='implementation/source_guard.py':C.need(b.endswith(SUFFIX)and b.count(SUFFIX)==1,'whole baseline guard prefix');b=b[:-len(SUFFIX)]
  C.need(C.pin(b)==w,'entire original baseline1183 body '+n);bodies[n]=b
 manifest=json.loads(C.read(C.ROOT/'source-manifest.json'));C.need(manifest['files']=={n:w for n,w in actual.items()if n not in(*ALIASES,'source-manifest.json')},'whole current baseline1185 manifest');manifest['files']={n:w for n,w in before.items()if n not in(*ALIASES,'source-manifest.json')};bodies['source-manifest.json']=C.enc(manifest);C.need(C.pin(bodies['source-manifest.json'])==before['source-manifest.json'],'whole baseline1183 manifest inverse')
 current=C.read(C.HERE/'workflow-template.yml').replace(b'@FRESH607_MANIFEST@',actual['source-manifest.json']['sha256'].encode());prior=bodies['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',before['source-manifest.json']['sha256'].encode())
 for n in ALIASES:C.need(C.read(C.ROOT/n)==current and C.pin(prior)==before[n],'entire current/old baseline workflow seals');bodies[n]=prior
 return before,bodies,actual

def verify():
 before,bodies,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='baseline-cache-parent-')as folder:
  parent=Path(folder)/'source';parent.mkdir(mode=0o700)
  for n,b in bodies.items():p=parent/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  C.need(rows(parent)==before,'whole baseline1183 reconstruction before its complete source entry')
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(parent/'implementation/run.py'),'--source-preflight'],stdin=subprocess.DEVNULL,capture_output=True,timeout=300);C.need(result.returncode==0 and not result.stderr and len(result.stdout)<65536,'complete original1183 AND1178 source entry required');original=json.loads(result.stdout);C.need(original['files']==1183 and original['Apps_version']=='0.1.0-6'and original['other606']=='HELD','exact original baseline source scope');C.need(rows(parent)==before and rows(C.ROOT)==actual,'source pre/post wholly unchanged')
 return dict(original,status='PASS_SOURCE_ONLY_APPS6_BASELINE_COMPLETE574_CACHE_CHILD',files=len(actual),parent_files=1183,parent_status=original['status'],held=1177,changed=6,added=2,current_controls='ALL10_REQUIRED_SEPARATE_RECEIPTS',actual_source=None,actual_ref=None,actual_run=None,baseline_installation='NOT_RUN',Root_acceptance='NOT_ISSUED')
