#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite manual workflow/source emitter over unchanged published13-file bridge."""
import argparse,hashlib,json,pathlib,shutil
HERE=pathlib.Path(__file__).resolve().parent
LANE='scripts/ci/current604-apps6-updater16k'
WF='.github/workflows/native-arm-current604-apps6-updater16k.yml'
OLD='.github/workflows/native-arm-expanded604-apps6-updater.yml'
KERNEL='.github/workflows/native-arm-current604-apps6-generic16k.yml'
OWN=('wiring.py','job.py','kernel_job.py','retain16k.py','freeze_wiring.py','test_wiring.py','WIRING.md','wiring-pins.json')
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def one(text,a,b):need(text.count(a)==1,'one wiring anchor: '+a[:110]);return text.replace(a,b)

def workflow(raw,kernel,root,job,manifest):
 text=raw.decode().replace('native-arm-expanded604-apps6-updater','native-arm-current604-apps6-updater16k')
 text=one(text,'One separate native604 copied-root case','One separate generic16K VM Apps5→6 current604 copied-root case')
 original_gate='python3 -B expanded604-upgrade/scripts/ci/expanded604-apps6-updater/gate.py';need(text.count(original_gate)==3,'three original input gates');text=text.replace(original_gate,'python3 -I -B expanded604-upgrade/'+LANE+'/job.py preflight',1)
 # Original own-source stamps stay, adding the complete new wiring stamp.
 marker='          python3 -I -B expanded604-upgrade/'+LANE+'/job.py preflight'
 text=one(text,marker,'          test "$(sha256sum expanded604-upgrade/'+LANE+'/job.py | cut -d \' \' -f 1)" = '+job+'\n          test "$(sha256sum expanded604-upgrade/'+LANE+'/wiring-source-manifest.json | cut -d \' \' -f 1)" = '+manifest+'\n'+marker)
 text=one(text,'--case "$UPGRADE_CASE" --preflight','--case "$UPGRADE_CASE"')
 # Replace both subsequent input gates, preserving all original operands.
 old='python3 -B expanded604-upgrade/scripts/ci/expanded604-apps6-updater/gate.py'
 need(text.count(old)==2,'exact original decision/input gates');text=text.replace(old,'python3 -I -B expanded604-upgrade/'+LANE+'/job.py '+ 'WIRED_GATE')
 text=one(text,'job.py WIRED_GATE','job.py decisions') if text.count('job.py WIRED_GATE')==1 else text.replace('job.py WIRED_GATE','job.py decisions',1)
 text=one(text,'job.py WIRED_GATE','job.py inputs')
 text=one(text,' --decisions-only','')
 # Both later gates now consume all three accepted new updater cases too.
 marker='--workflow-sha "$WORKFLOW_SOURCE"'
 need(text.count(marker)==3,'three original source assertions')
 # The preflight has no carrier checkout yet; add the operand only later.
 at=text.index('job.py decisions');text=text[:at]+text[at:].replace(marker,marker+' --updater-decisions "$GITHUB_WORKSPACE/apps6-updater-decisions"')
 checkout='''      - name: Checkout all three exact accepted Apps6 updater decisions
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.root_policy.outputs.updater_decisions }}
          path: apps6-updater-decisions
          persist-credentials: false
'''
 marker='      - name: Require five actual decisions and frozen installer before input retrieval';text=one(text,marker,checkout+marker)
 # Original kernel action/tool/cache/build bounds and fixed source asset are reused.
 k=kernel.decode();start=k.index('      - name: Provision existing accepted kernel tools');end=k.index('      - name: Required actual ALPM604',start);block=k[start:end]
 block=block.replace('current604-apps6-generic16k','expanded604-upgrade')
 block=one(block,'"scripts/ci/expanded604-upgrade"','"'+LANE+'"') if '"scripts/ci/expanded604-upgrade"' in block and block.count('"scripts/ci/expanded604-upgrade"')==1 else block.replace('"scripts/ci/expanded604-upgrade"','"'+LANE+'"')
 # Replace the two inline snippets with equivalent bounded entrypoints; actions,
 # environment, source keys and surrounding order remain unchanged.
 a=block.index('          python3 -I -B - ',block.index('name: Seed a true miss'));b=block.index('          PYSEED',a)+len('          PYSEED')
 base='          python3 -I -B "$GITHUB_WORKSPACE/expanded604-upgrade/'+LANE+'/kernel_job.py" '
 shared=' --implementation "$GITHUB_WORKSPACE/expanded604-upgrade" --source "${{ inputs.source }}" --case "${{ inputs.case }}" --work "$RUNNER_TEMP/managed-gui16k-kernel" --cache "$RUNNER_TEMP/kernel-source-cache/874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad/kernel.tar.gz" --output "/tmp/cachy-asahi-apps6-updater16k-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-${{ inputs.case }}"'
 block=block[:a]+base+'seed'+shared+' --receipt "$RUNNER_TEMP/updater16k-kernel-seed.json"'+block[b:]
 a=block.index('          python3 -I -B - ',block.index('name: Acquire exact'));b=block.index('          PYCODE',a)+len('          PYCODE')
 block=block[:a]+base+'acquire'+shared+' --receipt "$RUNNER_TEMP/updater16k-kernel-acquisition.json"'+block[b:]
 block=one(block,'      - name: Build only the separately derived managed GUI diagnostic16K kernel\n','      - name: Build only the separately derived managed GUI diagnostic16K kernel\n        id: kernel_build\n')
 marker='      - name: Required separate native604 copied-root updater case';text=one(text,marker,block+marker.replace('native604','generic16K Apps5→6 current604'))
 text=one(text,"id: composition\n        if: ${{ always() && !cancelled() && steps.root_inputs.outcome == 'success' }}","id: composition\n        if: ${{ always() && !cancelled() && steps.root_inputs.outcome == 'success' && steps.kernel_build.outcome == 'success' }}")
 text=one(text,'python3 -B "$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/expanded604-apps6-updater/run.py"','python3 -I -B "$GITHUB_WORKSPACE/expanded604-upgrade/'+LANE+'/job.py" run')
 text=one(text,'--output "/tmp/cachy-asahi-expanded604-root-upgrade-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"','--kernel-work "$RUNNER_TEMP/managed-gui16k-kernel" --kernel-receipt "$RUNNER_TEMP/managed-gui16k-kernel/helper/built/build-receipt.json" \\\n              --updater-decisions "$GITHUB_WORKSPACE/apps6-updater-decisions" \\\n              --output "/tmp/cachy-asahi-apps6-updater16k-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$UPGRADE_CASE"')
 # Replace only the final transport step; its seven original paths/raw8MiB bound
 # survive in retain16k.py, with structured extra facts in retention.json.
 marker='      - name: Retain bounded604 copied-root and original producer public receipts';at=text.index(marker)
 text=text[:at]+'''      - name: Retire only the exact completed kernel after all consumers
        if: always()
        timeout-minutes: 2
        shell: bash
        run: |
          set -euo pipefail
'''+base+'cleanup'+shared+' --receipt "$RUNNER_TEMP/updater16k-kernel-cleanup.json"\n'+'''      - name: Retain exactly seven bounded actual16K original receipt files
        if: always()
        timeout-minutes: 2
        shell: bash
        run: |
          set -euo pipefail
          python3 -I -B "$GITHUB_WORKSPACE/expanded604-upgrade/'''+LANE+'''/retain16k.py" \\
            --implementation "$GITHUB_WORKSPACE/expanded604-upgrade" --source-sha "${{ inputs.source }}" --case "${{ inputs.case }}" \\
            --source "/tmp/cachy-asahi-apps6-updater16k-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-${{ inputs.case }}" \\
            --target "$RUNNER_TEMP/apps6-current604-updater16k-public" \\
            --kernel-metadata "$RUNNER_TEMP/updater16k-kernel-metadata.json" --kernel-cleanup "$RUNNER_TEMP/updater16k-kernel-cleanup.json" \\
            --acquisition "$RUNNER_TEMP/updater16k-kernel-acquisition.json" --seed "$RUNNER_TEMP/updater16k-kernel-seed.json"
'''
 # These original stamps are data of the currently Root-frozen prior updater.
 for path in ('run.py','source-manifest.json'):
  before='b1ea773a32aab27dfbdb78f63877528f3edd9484d5b71877514c73ed51796fa2' if path=='run.py' else '821f2e7e616f313993212103755ab8ed142f5c0886ec58f170193429b89e7354'
  need(text.count(before)==1,'exact original source-stamp seam');text=text.replace(before,pin((root/'scripts/ci/expanded604-apps6-updater'/path).read_bytes())['sha256'])
 return text.encode()

def emit(source,output):
 pins=json.loads((HERE/'wiring-pins.json').read_bytes())
 base=json.loads((source/LANE/'source-manifest.json').read_bytes())['files']
 need(len(base)<=512 and not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh bounded source output')
 rows=dict(base);rows[LANE+'/source-manifest.json']=pin((source/LANE/'source-manifest.json').read_bytes())
 for n,row in pins['files'].items():
  need(n not in rows or rows[n]==row,'same source role joins');rows[n]=row
 for n,row in rows.items():
  p=source/n;need(not any(q.is_symlink() for q in (p,*p.parents)) and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'pinned wiring source differs: '+n)
 output.mkdir(mode=0o700)
 for n,row in rows.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/n,p)
 lane=output/LANE
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 files={str(p.relative_to(output)):pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()};need(len(files)<=512,'complete combined source bound')
 manifest=encoded(dict(schema_version=1,status='FROZEN_SOURCE_ONLY_UNBOUND',files=files,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));(lane/'wiring-source-manifest.json').write_bytes(manifest)
 wf=output/WF;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_bytes(workflow((source/OLD).read_bytes(),(source/KERNEL).read_bytes(),source,pin((lane/'job.py').read_bytes())['sha256'],pin(manifest)['sha256']))
 return dict(status='SOURCE_ONLY_UNBOUND',source_rows=len(files),workflow=pin(wf.read_bytes()),manifest=pin(manifest),base13='UNCHANGED',native='NOT_RUN',VM='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','output'):p.add_argument('--'+n,type=pathlib.Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
