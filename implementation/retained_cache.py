# SPDX-License-Identifier: MIT
"""Exact whole1178 inverse; complete574 cache inputs remain unauthenticated DATA."""
import json,subprocess,sys,tempfile
from pathlib import Path
import common as C
PARENT={'bytes': 218432, 'sha256': '63272955cd7e449332dbd7858d30ff3e03bf1916d46844370e279c67e0801835'}
STEP='      - name: Checkout exact complete574 retained package inputs\n        if: inputs.mode == \'build\'\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          ref: ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad\n          path: retained-complete574\n          persist-credentials: false\n      - name: Join all complete574 retained cache inputs before original acquisition\n        if: inputs.mode == \'build\'\n        timeout-minutes: 5\n        shell: bash\n        run: |\n          set -euo pipefail\n          test "$(git -C "$GITHUB_WORKSPACE/retained-complete574" rev-parse HEAD)" = ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad\n          test "$(sha256sum retained-complete574/seed.py | cut -d \' \' -f 1)" = 76b787fa71b121ec1bf83b86e4d5db849913614bc90e03239b869d7061af1db4\n          test "$(sha256sum retained-complete574/index.json | cut -d \' \' -f 1)" = 51a53c9e0d9eab1728f350f9ab8d3d7b8932891ab0ed68c7876a1440166ff486\n          test "$(sha256sum retained-complete574/desktop574-inputs.lock.json | cut -d \' \' -f 1)" = b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9\n          test "$(sha256sum scripts/ci/native_arm.py | cut -d \' \' -f 1)" = a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898\n          test "$(sha256sum scripts/ci/inputs.lock.json | cut -d \' \' -f 1)" = beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\n          deadline=$(env -i PATH=/usr/bin:/bin python3 -I -B -c \'import time; print(time.monotonic()+240)\')\n          env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" LANG=C.UTF-8 TZ=UTC TMPDIR="$RUNNER_TEMP" \\\n            python3 -I -B "$GITHUB_WORKSPACE/retained-complete574/seed.py" \\\n              --lock "$GITHUB_WORKSPACE/retained-complete574/desktop574-inputs.lock.json" \\\n              --cache "$RUNNER_TEMP/alarm-cache" --mode desktop574 --deadline "$deadline"\n'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
SUFFIX=b'\n# BEGIN_COMPLETE574_CACHE_PREPARATION\ndef verify():\n import retained_cache\n return retained_cache.verify()\n'
CHANGED={'implementation/workflow-template.yml','implementation/source_guard.py','source-manifest.json',*ALIASES}
ADDED={'implementation/parent1178.json','implementation/retained_cache.py'}
def rows(root):
 out={}
 for p in root.rglob('*'):
  rel=p.relative_to(root)
  if rel.parts[0]=='.git':continue
  C.need('.git'not in rel.parts and not p.is_symlink()and(p.is_dir()or p.is_file()),'closed ordinary source; foreign Git refused')
  if p.is_file():out[rel.as_posix()]=C.pin(C.read(p))
 return out

def inverse():
 before=json.loads(C.checked(C.HERE/'parent1178.json',PARENT));actual=rows(C.ROOT);C.need(len(before)==1178 and set(actual)==set(before)|ADDED,'complete1178 plus exactly two source helpers');C.need({n for n in before if actual[n]!=before[n]}==CHANGED,'exact five cache workflow/guard/manifest changes only');old={}
 for n,w in before.items():
  if n in(*ALIASES,'source-manifest.json'):continue
  raw=C.read(C.ROOT/n)
  if n=='implementation/workflow-template.yml':C.need(raw.count(STEP.encode())==1,'one fixed complete574 preparation');raw=raw.replace(STEP.encode(),b'',1)
  if n=='implementation/source_guard.py':C.need(raw.endswith(SUFFIX)and raw.count(SUFFIX)==1,'whole old guard prefix');raw=raw[:-len(SUFFIX)]
  C.need(C.pin(raw)==w,'entire1178 body '+n);old[n]=raw
 manifest=json.loads(C.read(C.ROOT/'source-manifest.json'));C.need(manifest['files']=={n:w for n,w in actual.items()if n not in(*ALIASES,'source-manifest.json')},'all current source manifest operands');manifest['files']={n:w for n,w in before.items()if n not in(*ALIASES,'source-manifest.json')};old['source-manifest.json']=C.enc(manifest);C.need(C.pin(old['source-manifest.json'])==before['source-manifest.json'],'whole old manifest inverse')
 current=C.read(C.HERE/'workflow-template.yml').replace(b'@FRESH607_MANIFEST@',actual['source-manifest.json']['sha256'].encode());prior=old['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',before['source-manifest.json']['sha256'].encode())
 for n in ALIASES:C.need(C.read(C.ROOT/n)==current and C.pin(prior)==before[n],'entire old/current workflow seal');old[n]=prior
 return before,old,actual

def verify():
 before,bodies,actual=inverse()
 with tempfile.TemporaryDirectory(prefix='complete574-parent-')as folder:
  parent=Path(folder)/'source';parent.mkdir(mode=0o700)
  for n,b in bodies.items():p=parent/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  C.need(rows(parent)==before,'whole reconstructed1178 before mandatory original entry')
  result=subprocess.run([sys.executable,'-I','-B','-Werror',str(parent/'implementation/run.py'),'--source-preflight'],capture_output=True,timeout=300)
  C.need(result.returncode==0 and not result.stderr and len(result.stdout)<65536,'complete original1178 source entry required');original=json.loads(result.stdout)
  C.need(rows(parent)==before and rows(C.ROOT)==actual,'whole source pre/post unchanged')
 return dict(original,status='PASS_SOURCE_ONLY_COMPLETE574_RETAINED_CACHE_CHILD',files=len(actual),parent_files=1178,parent_status=original['status'],held=1173,changed=5,added=2,cache='UNAUTHENTICATED_INPUTS_ONLY_ORIGINAL_GPG_AND_METADATA_REQUIRED',fresh607='NOT_RUN',actual_source=None,actual_ref=None,actual_run=None,hardware='NOT_RUN')
