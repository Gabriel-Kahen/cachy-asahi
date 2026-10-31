#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actor-free two-source diagnostic workflow assembly; no Git or network."""
import argparse,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/apps-full574-github-cancel';WF='.github/workflows/native-arm-apps-full574-github-cancel.yml';NATIVE_WF='.github/workflows/native-arm-apps-full574-repair.yml'
OWN=('driver.py','observe.py','prepare.py','test_cancel.py','input-policy.json','source-pins.json','README.md')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def replace(s,a,b):need(s.count(a)==1,'one finite cancellation workflow seam');return s.replace(a,b)
def workflow(s):
 s=replace(s,'name: native-arm-apps-full574-repair\n','name: native-arm-apps-full574-github-cancel\n');s=replace(s,'  contents: read\n','  contents: read\n  actions: write\n')
 s=replace(s,'    inputs:\n','    inputs:\n      cancel_manifest_sha256:\n        description: Exact separate self-cancellation diagnostic source manifest\n        type: string\n        required: true\n');s=replace(s,'      MANIFEST_SHA256: ${{ inputs.manifest_sha256 }}','      CANCEL_MANIFEST_SHA256: ${{ inputs.cancel_manifest_sha256 }}\n      CANCEL_SLICE: '+LANE+'\n      MANIFEST_SHA256: ${{ inputs.manifest_sha256 }}')
 anchor='          python3 -I -B "$SLICE/job.py" proof';s=replace(s,anchor,'''          [[ $CANCEL_MANIFEST_SHA256 =~ ^[0-9a-f]{64}$ ]]
          printf '%s  %s\\n' "$CANCEL_MANIFEST_SHA256" "$CANCEL_SLICE/source-manifest.json" | sha256sum --check
          python3 -I -B "$CANCEL_SLICE/driver.py" preflight --case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"
'''+anchor)
 s=replace(s,"          python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/apps -p 'test_*.py' -v", "          python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/apps -p 'test_*.py' -v\n          python3 -B -Werror::ResourceWarning -m unittest discover -s \"$CANCEL_SLICE\" -p test_cancel.py -v")
 s=replace(s,'        id: repair_trial\n        timeout-minutes: 60\n','        id: repair_trial\n        timeout-minutes: 60\n        env:\n          GH_TOKEN: ${{ github.token }}\n')
 s=replace(s,'python3 -I -B "$SLICE/supervise.py" run --handoff','python3 -I -B "$CANCEL_SLICE/driver.py" run --component "$RUNNER_TEMP/apps574-github-cancel" --handoff')
 s=replace(s,'          timeout --signal=TERM --kill-after=30s 3550s\n','          exec timeout --signal=TERM --kill-after=30s 3550s\n')
 anchor='      - name: Upload only the bounded public evidence directory\n';s=replace(s,anchor,'''      - name: Preserve bounded original self-cancel frontier intent and response
        if: always() && steps.proof.outcome == 'success'
        timeout-minutes: 2
        run: >-
          python3 -I -B "$CANCEL_SLICE/driver.py" retain --case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"
          --component "$RUNNER_TEMP/apps574-github-cancel" --public "$RUNNER_TEMP/apps574-public"
'''+anchor)
 return replace(s,'name: apps-full574-repair-${{ github.run_id }}-${{ github.run_attempt }}','name: apps-full574-github-cancel-${{ github.run_id }}-${{ github.run_attempt }}')
def emit(native_source,implementation,output):
 native_source=Path(native_source).absolute();implementation=Path(implementation).absolute();output=Path(output).absolute();need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for r in (native_source,implementation,output) for p in (r,*r.parents)) and not any(output.is_relative_to(r) for r in (native_source,implementation)),'fresh disjoint ordinary source operands')
 value=json.loads((HERE/'source-pins.json').read_bytes());need(len(value['files'])==116 and len(value['origins'])==116,'exact original115 plus readonly helper');raws={}
 for n,row in value['files'].items():
  need(n and not n.startswith('/') and '\\' not in n and all(v not in ('','.','..') for v in n.split('/')),'finite source path');p=(native_source if value['origins'][n]=='FROZEN_NATIVE505' else implementation)/n;need(p.is_file() and not any(q.is_symlink() for q in (p,*p.parents)) and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2,'ordinary source object');raw=p.read_bytes();need(pin(raw)==row,'frozen diagnostic source differs: '+n);raws[n]=raw
 need(json.loads((HERE/'input-policy.json').read_bytes())['status']=='UNBOUND_DO_NOT_CANCEL_OR_START','default cancellation policy UNBOUND');output.mkdir(mode=0o700)
 def write(n,raw):p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 for n,raw in raws.items():write(n,raw)
 for n in OWN:write(LANE+'/'+n,(HERE/n).read_bytes())
 rows={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()};need(len(rows)==123,'exact complete diagnostic source123');write(LANE+'/source-manifest.json',encoded(dict(schema_version=1,status='FROZEN_SELF_GITHUB_CANCEL_DIAGNOSTIC_SOURCE',files=rows,native_acceptance='NOT_GRANTED',actual_cancel='NOT_RUN',cleanup='NOT_RUN',hardware='NOT_RUN')));write(WF,workflow(raws[NATIVE_WF].decode()).encode());return dict(status='SOURCE_ONLY_DEFAULT_UNBOUND',source_rows=len(rows),native113='UNCHANGED',actual='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('native-source','implementation','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.native_source,a.implementation,a.output),sort_keys=True))
