#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one finite public-pair updater16K source successor; no actors or Git."""
import argparse,ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/current604-apps6-updater16k';NEW='scripts/ci/current604-public-pair-updater16k'
UPDATER='scripts/ci/expanded604-apps6-public-pair-updater'
WF='.github/workflows/native-arm-current604-public-pair-updater16k.yml'
KERNEL='.github/workflows/native-arm-current604-apps6-generic16k.yml'
OWN=('contract.py','adapter.py','cap_scope.py','disk.py','guest.py','input-policy.json','policy.json','run.py','vm.py','wiring.py','job.py','kernel_job.py','retain16k.py','prepare.py','freeze_wiring.py','README.md','WIRING.md','source-pins.json','test_lane.py','test_wiring.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(p):
 need(not any(q.is_symlink() for q in (p,*p.parents)),'ordinary source');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded single-link source');d=p.read_bytes();need(len(d)==s.st_size,'source length drift');return d

def source(root,updater):
 groups=json.loads(read(HERE/'source-pins.json'))['groups'];need(set(groups)=={'original','updater'},'two explicit source roles');blobs={}
 for role,base in (('original',root),('updater',updater)):
  for n,row in groups[role].items():
   need(not n.startswith('/') and all(p not in ('','.','..') for p in n.split('/')),'relative source path');d=read(base/n);need(pin(d)==row,'pinned source differs: '+role+':'+n)
   need(n not in blobs or blobs[n]==d,'source role conflict: '+n);blobs[n]=d
 recipes=json.loads(read(HERE/'source-pins.json'))['runtime_recipe_inputs'];need(len(recipes)==80,'exact complete runtime recipe closure')
 for n,row in recipes.items():need(n in blobs and pin(blobs[n])==row,'closed runtime recipe input differs: '+n)
 need(len(blobs)+len(OWN)+1<=512,'finite combined source');return blobs

def workflow(blobs,output,job,manifest):
 # Reuse only the original closed workflow transformer, never run its CLI/emitter.
 raw=blobs[OLD+'/freeze_wiring.py'];tree=ast.parse(raw);wanted={'need','encoded','pin','one','workflow'}
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted];need({n.name for n in nodes}==wanted,'exact held workflow functions')
 text='\n\n'.join(ast.get_source_segment(raw.decode(),n) for n in nodes)
 text=text.replace('current604-apps6-updater16k','current604-public-pair-updater16k').replace('expanded604-apps6-updater','expanded604-apps6-public-pair-updater')
 before="before='b1ea773a32aab27dfbdb78f63877528f3edd9484d5b71877514c73ed51796fa2' if path=='run.py' else '821f2e7e616f313993212103755ab8ed142f5c0886ec58f170193429b89e7354'"
 need(text.count(before)==1,'one finite prior stamp lookup');text=text.replace(before,"before=pin((root/'"+UPDATER+"'/path).read_bytes())['sha256']")
 namespace=dict(LANE=NEW,hashlib=hashlib,json=json);exec(compile(text,'<pinned-closed-public-pair-WF-transformer>','exec'),namespace)
 raw=namespace['workflow'](blobs['.github/workflows/native-arm-expanded604-apps6-public-pair-updater.yml'],blobs[KERNEL],output,job,manifest)
 text=raw.decode();anchor='      - name: Require five actual decisions and frozen installer before input retrieval'
 # The inherited transformer keeps this step and its complete decision gate.
 need(text.count(anchor)==1,'same early five-decision step')
 text=text.replace(anchor,'''      - name: Provision host ext4 test tools on disposable runner
        timeout-minutes: 9
        shell: bash
        run: |
          set -euo pipefail
          timeout --kill-after=10s 180s sudo apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 update -qq
          timeout --kill-after=10s 240s sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 install -y --no-install-recommends e2fsprogs
          command -v mkfs.ext4
          command -v debugfs
          dpkg-query -W e2fsprogs
      - name: Source-only public-pair updater16K controls
        shell: bash
        run: |
          python3 -B -m unittest discover -s expanded604-upgrade/'''+NEW+''' -p 'test_*.py' -v
'''+anchor)
 return text.encode()

def emit(root,updater,output):
 blobs=source(root,updater);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output')
 for name in OWN:need(NEW+'/'+name not in blobs,'new namespace collision');blobs[NEW+'/'+name]=read(HERE/name)
 output.mkdir(mode=0o700)
 for n,d in blobs.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(d)
 rows={n:pin(d) for n,d in blobs.items()};mf=encoded(dict(schema_version=1,status='SOURCE_ONLY_UNBOUND',files=rows,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));(output/NEW/'source-manifest.json').write_bytes(mf)
 rows[NEW+'/source-manifest.json']=pin(mf);wmf=encoded(dict(schema_version=1,status='FROZEN_SOURCE_ONLY_UNBOUND',files=rows,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));(output/NEW/'wiring-source-manifest.json').write_bytes(wmf)
 w=workflow(blobs,output,rows[NEW+'/job.py']['sha256'],pin(wmf)['sha256']);p=output/WF;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(w)
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIR_UPDATER16K_UNBOUND',source_rows=len(rows)-1,wiring_rows=len(rows),workflow=pin(w),cases=['normal','precommit-exit86','postcommit-exit87'],native='UNBOUND',fresh='UNBOUND',updater_actuals='UNBOUND',VM='NOT_RUN',hardware='NOT_RUN');(output/'source-emission.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','updater','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.updater.absolute(),a.output.absolute()),sort_keys=True))
